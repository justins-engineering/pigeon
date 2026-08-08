#if defined(CONFIG_PIGEON_FOTA_NCS)
#include <dfu/dfu_target.h>
#include <dfu/dfu_target_mcuboot.h>
#if defined(CONFIG_PIGEON_FOTA_RESUME)
#include <dfu/dfu_target_stream.h>
#endif
#endif
#include <errno.h>
#include <pigeon.h>
#include <psa/crypto.h>
#include <string.h>
#include <zephyr/dfu/flash_img.h>
#include <zephyr/kernel.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>
#if !defined(CONFIG_PIGEON_FOTA_NCS) && defined(CONFIG_PIGEON_FOTA_RESUME)
#include <zephyr/storage/stream_flash.h>
#endif
#include <zephyr/sys/util.h>

#include "pigeon_internal.h"
#if defined(CONFIG_PIGEON_FOTA_RESUME)
#include "pigeon_fota_resume.h"
#endif

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

#if defined(CONFIG_PIGEON_FOTA_NCS)
/* Static (not stack) staging buffer handed to dfu_target_mcuboot_set_buf():
 * must stay valid for the whole DFU session, and a CONFIG_PIGEON_FOTA_CHUNK_SIZE
 * array on the stack would also eat a large fraction of CONFIG_MAIN_STACK_SIZE
 * (8192 by default in https_init) on top of the TLS/HTTP call frames already
 * live during the download loop below. dfu_target_stream uses this to batch
 * partial writes up to flash write-block granularity -- unrelated to
 * pigeon_https.c's own receive buffers, which land data here via
 * pigeon_fota_chunk_buf below before this one ever sees it. NCS-only: the
 * default (non-NCS) backend below uses upstream Zephyr's flash_img_context
 * instead, which carries its own equivalent staging buffer. */
static uint8_t pigeon_fota_flash_buf[CONFIG_PIGEON_FOTA_CHUNK_SIZE] __aligned(4);
#else
/* Default (vanilla Zephyr) backend: upstream flash_img/stream_flash writes
 * straight into the MCUboot secondary slot, and boot_request_upgrade()
 * (zephyr/dfu/mcuboot.h -- a thin wrapper around MCUboot's own bootutil,
 * not an NCS API) schedules the test-swap. Static, not stack, for the same
 * reason as pigeon_fota_flash_buf above: struct flash_img_context carries
 * its own CONFIG_IMG_BLOCK_BUF_SIZE staging buffer, too big to want living
 * on pigeon_fota_apply()'s stack frame alongside the TLS/HTTP call chain
 * already active during the download loop. */
static struct flash_img_context pigeon_fota_flash_ctx;
#endif

/* Network receive target for each chunk, handed to the active backend
 * (dfu_target_write() or flash_img_buffered_write()) once a full chunk has
 * arrived. Shared by both backends. */
static uint8_t pigeon_fota_chunk_buf[CONFIG_PIGEON_FOTA_CHUNK_SIZE];

static void pigeon_fota_hex_encode(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
  static const char hex_digits[] = "0123456789abcdef";
  size_t n = MIN(in_len, (out_len - 1) / 2);

  for (size_t i = 0; i < n; i++) {
    out[i * 2] = hex_digits[in[i] >> 4];
    out[i * 2 + 1] = hex_digits[in[i] & 0x0F];
  }
  out[n * 2] = '\0';
}

#if defined(CONFIG_PIGEON_FOTA_NCS)
/* Aborts an NCS dfu session. discard_progress mirrors the pre-resume
 * behavior (dfu_target_reset() deletes the backend's persisted stream
 * progress -- settings key "dfu/<target>" -- and flattens the slot's first
 * page, see NCS dfu_target_stream.c's dfu_target_stream_reset()); with
 * CONFIG_PIGEON_FOTA_RESUME a transient failure keeps the progress instead,
 * since dfu_target_done(false) alone both closes the session and stores the
 * flushed offset for the next attempt to resume from. */
static void pigeon_fota_ncs_abort(bool discard_progress) {
  dfu_target_done(false);
  if (discard_progress) {
    dfu_target_reset();
  }
}

#if defined(CONFIG_PIGEON_FOTA_RESUME)
#define PIGEON_FOTA_NCS_ABORT_KEEP() pigeon_fota_ncs_abort(false)
#else
#define PIGEON_FOTA_NCS_ABORT_KEEP() pigeon_fota_ncs_abort(true)
#endif
#endif /* CONFIG_PIGEON_FOTA_NCS */

#if defined(CONFIG_PIGEON_FOTA_RESUME)
/*
 * Rebuilds the streaming sha256 over the first `len` bytes already flushed
 * into the upload slot by a previous attempt, so a resumed download's final
 * digest covers the whole image without ever serializing crypto state.
 * Reads through the same flash_area the geometry check uses (and that both
 * write backends ultimately target), reusing the network chunk buffer --
 * no extra RAM.
 */
static int pigeon_fota_rehash_flashed(psa_hash_operation_t *hash_op, size_t len) {
  const struct flash_area *fa;
  int err = flash_area_open(flash_img_get_upload_slot(), &fa);

  if (err) {
    LOG_ERR("FOTA resume: flash_area_open for re-hash failed: %d", err);
    return err;
  }

  size_t off = 0;

  while (off < len) {
    size_t n = MIN(sizeof(pigeon_fota_chunk_buf), len - off);

    err = flash_area_read(fa, (off_t)off, pigeon_fota_chunk_buf, n);
    if (err) {
      LOG_ERR("FOTA resume: flash re-read failed at offset %zu: %d", off, err);
      break;
    }

    if (psa_hash_update(hash_op, pigeon_fota_chunk_buf, n) != PSA_SUCCESS) {
      err = -EIO;
      break;
    }

    off += n;
  }

  flash_area_close(fa);

  return err;
}

/* Flushed-to-flash byte count, per backend. NEVER bytes-received: a
 * RAM-buffered write-block tail is lost on reboot, so persisting a
 * received-bytes offset would make a resumed image skip those bytes.
 * - NCS: dfu_target_stream_offset_get() returns exactly
 *   stream_flash_bytes_written() (nrf/subsys/dfu/dfu_target/src/
 *   dfu_target_stream.c), which stream_flash only advances after a
 *   successful flash_write() (zephyr/subsys/storage/stream/stream_flash.c,
 *   flash_sync()). Deliberately NOT dfu_target_offset_get(), which adds the
 *   RAM-buffered tail when CONFIG_DFU_TARGET_STREAM_SYNCHRONOUS is off
 *   (dfu_target_mcuboot.c's stream_buf_bytes compensation).
 * - upstream: flash_img_bytes_written() is the same
 *   stream_flash_bytes_written() counter (zephyr/subsys/dfu/img_util/
 *   flash_img.c). */
static size_t pigeon_fota_flushed_offset(void) {
#if defined(CONFIG_PIGEON_FOTA_NCS)
  size_t off = 0;

  (void)dfu_target_stream_offset_get(&off);
  return off;
#else
  return flash_img_bytes_written(&pigeon_fota_flash_ctx);
#endif
}
#endif /* CONFIG_PIGEON_FOTA_RESUME */

bool pigeon_fota_update_available(const struct pigeon_fota_info *info) {
  if (!info) {
    return false;
  }

  return strcmp(info->version, CONFIG_PIGEON_FOTA_CURRENT_VERSION) != 0;
}

/*
 * Rejects a firmware target whose declared size can't possibly fit THIS
 * device's own MCUboot secondary slot, before pigeon_fota_apply() touches
 * flash or the network at all.
 *
 * Motivated by a real incident: a shadow firmware target sized for one
 * board's flash geometry, applied on a device provisioned with different
 * (smaller) partitions, made it past pigeon_fota_apply()'s prior checks and
 * into the flash write path, where it tripped a TF-M Secure Fault -- TF-M
 * failed safe (no corruption), but the device halted and stayed down until
 * a manual reset, i.e. a remotely-triggerable DoS from nothing more than a
 * mismatched (or malicious) shadow target. Both backends' own init path
 * (dfu_target_mcuboot_init() on NCS, flash_img_init() upstream) carry their
 * own size check against the same secondary slot and return -EFBIG/-ENOMEM
 * on the plain "image too big" case, but only after session state (a set
 * staging buffer, an opened flash_area) already exists -- this check runs
 * strictly before any of that, and is deliberately independent of it as
 * defense-in-depth: querying the slot geometry a second way (flash_area
 * directly, not either backend's own internal size table) means a bug in
 * one path doesn't silently defeat the other.
 *
 * flash_img_get_upload_slot() (upstream zephyr/dfu/flash_img.h) is the same
 * area-id resolution either backend ultimately targets -- it already
 * accounts for the slot0-vs-slot1/TF-M-_ns-2-image cases a hardcoded
 * partition label wouldn't, and is available unconditionally since
 * flash_img.c is always compiled whenever IMG_MANAGER is on (a dependency
 * both backends already share via CONFIG_PIGEON_FOTA's Kconfig).
 */
static int pigeon_fota_check_geometry(const struct pigeon_fota_info *info) {
  const struct flash_area *secondary_fa;
  int err = flash_area_open(flash_img_get_upload_slot(), &secondary_fa);

  if (err) {
    LOG_ERR("FOTA: flash_area_open(upload slot) failed: %d", err);
    return err;
  }

  size_t slot_size = secondary_fa->fa_size;

  flash_area_close(secondary_fa);

  if ((size_t)info->size > slot_size) {
    LOG_ERR(
        "FOTA: firmware target %s (%d bytes) exceeds this device's MCUboot "
        "secondary slot (%zu bytes) -- refusing a geometry-mismatched target",
        info->version, info->size, slot_size
    );
    return -EFBIG;
  }

  return 0;
}

int pigeon_fota_apply(const struct pigeon_fota_info *info) {
  if (!info || info->size <= 0) {
    return -EINVAL;
  }

  LOG_INF("FOTA: applying firmware %s (%d bytes)", info->version, info->size);

  int err = pigeon_fota_check_geometry(info);

  if (err) {
    return err;
  }

  size_t total_size = (size_t)info->size;
  size_t resume_from = 0;

#if defined(CONFIG_PIGEON_FOTA_RESUME)
  struct pigeon_fota_resume_record resume_rec;

  (void)pigeon_fota_resume_load(&resume_rec);
#endif

#if defined(CONFIG_PIGEON_FOTA_NCS)
  err = dfu_target_mcuboot_set_buf(pigeon_fota_flash_buf, sizeof(pigeon_fota_flash_buf));

  if (err) {
    LOG_ERR("FOTA: dfu_target_mcuboot_set_buf failed: %d", err);
    return err;
  }

  /* With CONFIG_DFU_TARGET_STREAM_SAVE_PROGRESS (pulled in by
   * CONFIG_PIGEON_FOTA_RESUME) this init restores the persisted flushed
   * offset from settings into the stream (dfu_target_stream_init ->
   * settings_load_subtree, NCS dfu_target_stream.c). Same-boot retries
   * skip re-init entirely and keep the live stream state instead
   * (dfu_target.c's same-target early return) -- both cases are then
   * reconciled identically below off the queried flushed offset. */
  err = dfu_target_init(DFU_TARGET_IMAGE_TYPE_MCUBOOT, 0, total_size, NULL);
  if (err) {
    LOG_ERR("FOTA: dfu_target_init failed: %d", err);
#if defined(CONFIG_PIGEON_FOTA_RESUME)
    /* An init failure with progress pending suggests the slot/backend
     * state changed outside this download -- don't let the next attempt
     * trust it (directive: fail toward a clean restart). */
    (void)pigeon_fota_resume_clear();
#endif
    return err;
  }
#else
  err = flash_img_init(&pigeon_fota_flash_ctx);
  if (err) {
    LOG_ERR("FOTA: flash_img_init failed: %d", err);
#if defined(CONFIG_PIGEON_FOTA_RESUME)
    (void)pigeon_fota_resume_clear();
#endif
    return err;
  }
#if defined(CONFIG_PIGEON_FOTA_RESUME)
  /* Upstream flash_img restores nothing by itself (flash_img_init zeroes
   * the stream) -- load the persisted stream progress explicitly, but only
   * when the record vouches that it belongs to THIS version; a stale key
   * is otherwise left for the invalidate path below to delete.
   * stream_flash_progress_load also recomputes erased_up_to so progressive
   * erase won't wipe already-written pages (zephyr/subsys/storage/stream/
   * stream_flash.c, settings_direct_loader). */
  if (resume_rec.version[0] != '\0' &&
      strncmp(resume_rec.version, info->version, sizeof(resume_rec.version) - 1) == 0) {
    (void)stream_flash_progress_load(&pigeon_fota_flash_ctx.stream, PIGEON_FOTA_RESUME_STREAM_KEY);
  }
#endif
#endif

#if defined(CONFIG_PIGEON_FOTA_RESUME)
  size_t backend_off = pigeon_fota_flushed_offset();

#if defined(CONFIG_PIGEON_FOTA_NCS) && !defined(CONFIG_DFU_TARGET_STREAM_SYNCHRONOUS)
  /* Same-boot retry with synchronous flushing disabled (a deliberate
   * override -- SAVE_PROGRESS defaults it on): the live stream may hold a
   * RAM-buffered tail past the flushed offset, and stream writes are
   * append-only, so re-requesting from the flushed offset would duplicate
   * the tail. No public API discards it; treat as not-resumable. */
  size_t received_off = 0;

  (void)dfu_target_offset_get(&received_off);
  if (received_off != backend_off) {
    LOG_WRN("FOTA resume: un-flushed RAM tail present (%zu > %zu); restarting clean",
            received_off, backend_off);
    backend_off = total_size + 1; /* force the invalidate path below */
  }
#endif

  enum pigeon_fota_resume_action resume_act = pigeon_fota_resume_reconcile(
      &resume_rec, info->version, total_size, backend_off, &resume_from
  );

  if (resume_act == PIGEON_FOTA_RESUME_INVALIDATE) {
    LOG_WRN(
        "FOTA resume: discarding stale progress (had %s at %u, backend at %zu; target %s)",
        resume_rec.version[0] ? resume_rec.version : "<none>", resume_rec.offset, backend_off,
        info->version
    );
    (void)pigeon_fota_resume_clear();
#if defined(CONFIG_PIGEON_FOTA_NCS)
    /* Deletes the backend's own persisted progress, flattens the slot's
     * first page, and clears the session so the re-init below runs the
     * full init path (dfu_target_reset() nulls current_target). */
    dfu_target_reset();
    err = dfu_target_init(DFU_TARGET_IMAGE_TYPE_MCUBOOT, 0, total_size, NULL);
    if (err) {
      LOG_ERR("FOTA: dfu_target_init after progress reset failed: %d", err);
      return err;
    }
#else
    (void)stream_flash_progress_clear(&pigeon_fota_flash_ctx.stream, PIGEON_FOTA_RESUME_STREAM_KEY);
    /* Re-init zeroes bytes_written/erased_up_to in case the stale progress
     * was already loaded into the live stream above. */
    err = flash_img_init(&pigeon_fota_flash_ctx);
    if (err) {
      LOG_ERR("FOTA: flash_img_init after progress reset failed: %d", err);
      return err;
    }
#endif
    resume_from = 0;
  }

  if (resume_from > 0) {
    LOG_INF(
        "FOTA resume: continuing %s at %zu/%zu (record said %u)", info->version, resume_from,
        total_size, resume_rec.offset
    );
  }

  /* Seed/refresh the record before any network traffic, so even a
   * first-chunk crash leaves attributable state behind. */
  (void)pigeon_fota_resume_save(info->version, resume_from);
#endif /* CONFIG_PIGEON_FOTA_RESUME */

  psa_status_t pstatus = psa_crypto_init();

  if (pstatus != PSA_SUCCESS) {
    LOG_ERR("FOTA: psa_crypto_init failed: %d", pstatus);
#if defined(CONFIG_PIGEON_FOTA_NCS)
    PIGEON_FOTA_NCS_ABORT_KEEP();
#endif
    return -EIO;
  }

  psa_hash_operation_t hash_op = {0};

  pstatus = psa_hash_setup(&hash_op, PSA_ALG_SHA_256);
  if (pstatus != PSA_SUCCESS) {
    LOG_ERR("FOTA: psa_hash_setup failed: %d", pstatus);
#if defined(CONFIG_PIGEON_FOTA_NCS)
    PIGEON_FOTA_NCS_ABORT_KEEP();
#endif
    return -EIO;
  }

#if defined(CONFIG_PIGEON_FOTA_RESUME)
  if (resume_from > 0) {
    err = pigeon_fota_rehash_flashed(&hash_op, resume_from);
    if (err) {
      /* Can't trust what's in the slot if it can't even be read back --
       * clear so the next attempt restarts clean. */
      psa_hash_abort(&hash_op);
      (void)pigeon_fota_resume_clear();
#if defined(CONFIG_PIGEON_FOTA_NCS)
      pigeon_fota_ncs_abort(true);
#else
      (void)stream_flash_progress_clear(
          &pigeon_fota_flash_ctx.stream, PIGEON_FOTA_RESUME_STREAM_KEY
      );
      if (pigeon_fota_flash_ctx.flash_area) {
        flash_area_close(pigeon_fota_flash_ctx.flash_area);
        pigeon_fota_flash_ctx.flash_area = NULL;
      }
#endif
      return err;
    }
  }
#endif

  size_t offset = resume_from;
  bool failed = false;

  while (offset < total_size) {
    size_t want = MIN(sizeof(pigeon_fota_chunk_buf), total_size - offset);
    size_t got = 0;
    size_t server_total = 0;

    err = pigeon_transport_download_firmware(
        offset, pigeon_fota_chunk_buf, want, &got, &server_total
    );
    if (err) {
      LOG_ERR("FOTA: chunk download failed at offset %zu: %d", offset, err);
      failed = true;
      break;
    }

    if (got == 0) {
      LOG_ERR("FOTA: chunk download returned 0 bytes at offset %zu", offset);
      err = -ENODATA;
      failed = true;
      break;
    }

    if (server_total != 0 && server_total != total_size) {
      LOG_ERR(
          "FOTA: server-reported total size %zu doesn't match shadow-declared size %zu",
          server_total, total_size
      );
      err = -EBADMSG;
      failed = true;
      break;
    }

#if defined(CONFIG_PIGEON_FOTA_NCS) && defined(CONFIG_DFU_TARGET_STREAM_SYNCHRONOUS)
    /* Synchronous mode (SAVE_PROGRESS's default) flushes every write
     * immediately, padding a non-write-block-multiple tail -- after which
     * the next write's flash address would be unaligned and fail (see the
     * alignment note on CONFIG_DFU_TARGET_STREAM_SYNCHRONOUS's own help).
     * Chunk sizes are write-block multiples, so only a short non-final
     * body can break that invariant: treat it as the transport error it
     * is and let the next attempt resume from the last flushed chunk. */
    if (got < want && offset + got < total_size) {
      LOG_ERR("FOTA: short chunk body (%zu < %zu) at offset %zu", got, want, offset);
      err = -EIO;
      failed = true;
      break;
    }
#endif

#if defined(CONFIG_PIGEON_FOTA_NCS)
    err = dfu_target_write(pigeon_fota_chunk_buf, got);
#else
    /* flush only on the very last chunk -- flash_img_buffered_write() closes
     * the flash_area itself once flush is set, mirroring dfu_target_done(). */
    err = flash_img_buffered_write(
        &pigeon_fota_flash_ctx, pigeon_fota_chunk_buf, got, offset + got >= total_size
    );
#endif
    if (err) {
      LOG_ERR("FOTA: flash write failed at offset %zu: %d", offset, err);
      failed = true;
      break;
    }

    pstatus = psa_hash_update(&hash_op, pigeon_fota_chunk_buf, got);
    if (pstatus != PSA_SUCCESS) {
      LOG_ERR("FOTA: psa_hash_update failed at offset %zu: %d", offset, pstatus);
      err = -EIO;
      failed = true;
      break;
    }

    offset += got;
    LOG_INF("FOTA: downloaded %zu/%zu bytes", offset, total_size);

#if defined(CONFIG_PIGEON_FOTA_RESUME)
    /* Persist after every chunk, flushed offset only (the NCS backend
     * already stored its own counter inside dfu_target_write()). Both
     * saves are best-effort, same posture as NCS's store_progress() --
     * a miss just means the next resume starts a little further back. */
#if !defined(CONFIG_PIGEON_FOTA_NCS)
    (void)stream_flash_progress_save(&pigeon_fota_flash_ctx.stream, PIGEON_FOTA_RESUME_STREAM_KEY);
#endif
    (void)pigeon_fota_resume_save(info->version, pigeon_fota_flushed_offset());
#endif

#if CONFIG_PIGEON_FOTA_CHUNK_YIELD_MS > 0
    /* Give the rest of the system periodic airtime -- see this option's
     * Kconfig help for the starvation this prevents on narrow links. */
    if (offset < total_size) {
      k_sleep(K_MSEC(CONFIG_PIGEON_FOTA_CHUNK_YIELD_MS));
    }
#endif
  }

  if (failed) {
    psa_hash_abort(&hash_op);
#if defined(CONFIG_PIGEON_FOTA_NCS)
    /* With CONFIG_PIGEON_FOTA_RESUME this keeps the persisted progress (a
     * transient transport/flash failure is exactly what resume is for);
     * without it, behavior is unchanged from before (full reset). */
    PIGEON_FOTA_NCS_ABORT_KEEP();
#else
    /* Only close here if the loop broke before ever reaching a flush=true
     * write -- once that happens flash_img_buffered_write() already closed
     * the area and nulled the pointer, same guard it uses internally. */
    if (pigeon_fota_flash_ctx.flash_area) {
      flash_area_close(pigeon_fota_flash_ctx.flash_area);
      pigeon_fota_flash_ctx.flash_area = NULL;
    }
#endif
    return err;
  }

#if !defined(CONFIG_PIGEON_FOTA_NCS) && defined(CONFIG_PIGEON_FOTA_RESUME)
  /* A verify-only resume (a prior attempt flushed everything but died
   * before the verify) never reaches the flush=true write that normally
   * closes the area. */
  if (pigeon_fota_flash_ctx.flash_area) {
    flash_area_close(pigeon_fota_flash_ctx.flash_area);
    pigeon_fota_flash_ctx.flash_area = NULL;
  }
#endif

  uint8_t digest[32];
  size_t digest_len = 0;

  pstatus = psa_hash_finish(&hash_op, digest, sizeof(digest), &digest_len);
  if (pstatus != PSA_SUCCESS || digest_len != sizeof(digest)) {
    LOG_ERR("FOTA: psa_hash_finish failed: %d", pstatus);
#if defined(CONFIG_PIGEON_FOTA_NCS)
    PIGEON_FOTA_NCS_ABORT_KEEP();
#endif
    return -EIO;
  }

  char digest_hex[PIGEON_FOTA_SHA256_HEX_LEN + 1];

  pigeon_fota_hex_encode(digest, sizeof(digest), digest_hex, sizeof(digest_hex));

  /* Case-sensitive: both sides are expected to produce lowercase hex (see
   * pigeon.h's pigeon_fota_info doc and the shadow wire contract) --
   * strcasecmp isn't guaranteed to exist under picolibc, and enforcing
   * lowercase here catches a platform-side encoding bug instead of
   * silently tolerating it. */
  if (strcmp(digest_hex, info->sha256) != 0) {
    LOG_ERR("FOTA: sha256 mismatch: expected %s, got %s", info->sha256, digest_hex);
#if defined(CONFIG_PIGEON_FOTA_NCS)
    /* Full reset on purpose, even with resume enabled: a resumed-but-
     * corrupt image must not seed the NEXT attempt -- it starts clean
     * from byte 0 (dfu_target_reset() also deletes the backend's own
     * persisted progress). */
    pigeon_fota_ncs_abort(true);
#endif
#if defined(CONFIG_PIGEON_FOTA_RESUME)
    (void)pigeon_fota_resume_clear();
#if !defined(CONFIG_PIGEON_FOTA_NCS)
    (void)stream_flash_progress_clear(&pigeon_fota_flash_ctx.stream, PIGEON_FOTA_RESUME_STREAM_KEY);
#endif
#endif
    return -EBADMSG;
  }

  LOG_INF("FOTA: sha256 verified (%s)", digest_hex);

#if defined(CONFIG_PIGEON_FOTA_NCS)
  err = dfu_target_done(true);
  if (err) {
    LOG_ERR("FOTA: dfu_target_done failed: %d", err);
    dfu_target_reset();
    return err;
  }

  err = dfu_target_schedule_update(0);
  if (err) {
    LOG_ERR("FOTA: dfu_target_schedule_update failed: %d", err);
    return err;
  }
#else
  /* Upstream Zephyr/MCUboot equivalent of dfu_target_schedule_update(0):
   * flash_img_buffered_write()'s final flush=true call above already closed
   * out the write session, this just marks the secondary slot for a
   * one-time test-swap on next boot. */
  err = boot_request_upgrade(BOOT_UPGRADE_TEST);
  if (err) {
    LOG_ERR("FOTA: boot_request_upgrade failed: %d", err);
    return err;
  }
#endif

#if defined(CONFIG_PIGEON_FOTA_RESUME)
  /* The staged image is final -- nothing left to resume. (The NCS
   * backend's own progress key was already deleted by dfu_target_done(true),
   * NCS dfu_target_stream.c.) */
  (void)pigeon_fota_resume_clear();
#if !defined(CONFIG_PIGEON_FOTA_NCS)
  (void)stream_flash_progress_clear(&pigeon_fota_flash_ctx.stream, PIGEON_FOTA_RESUME_STREAM_KEY);
#endif
#endif

  LOG_INF("FOTA: image staged and scheduled for test-swap; ready for graceful reboot");

  return 0;
}

int pigeon_fota_confirm_boot(void) {
  if (boot_is_img_confirmed()) {
    return 0;
  }

  int err = boot_write_img_confirmed();

  if (err) {
    LOG_ERR("FOTA: boot_write_img_confirmed failed: %d", err);
    return err;
  }

  LOG_INF("FOTA: confirmed current image (MCUboot will not revert it)");

  return 0;
}
