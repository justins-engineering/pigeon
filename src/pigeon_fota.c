#if defined(CONFIG_PIGEON_FOTA_NCS)
#include <dfu/dfu_target.h>
#include <dfu/dfu_target_mcuboot.h>
#endif
#include <errno.h>
#include <pigeon.h>
#include <psa/crypto.h>
#include <string.h>
#include <zephyr/dfu/flash_img.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/util.h>

#include "pigeon_internal.h"

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

#if defined(CONFIG_PIGEON_FOTA_NCS)
  err = dfu_target_mcuboot_set_buf(pigeon_fota_flash_buf, sizeof(pigeon_fota_flash_buf));

  if (err) {
    LOG_ERR("FOTA: dfu_target_mcuboot_set_buf failed: %d", err);
    return err;
  }

  err = dfu_target_init(DFU_TARGET_IMAGE_TYPE_MCUBOOT, 0, (size_t)info->size, NULL);
  if (err) {
    LOG_ERR("FOTA: dfu_target_init failed: %d", err);
    return err;
  }
#else
  err = flash_img_init(&pigeon_fota_flash_ctx);
  if (err) {
    LOG_ERR("FOTA: flash_img_init failed: %d", err);
    return err;
  }
#endif

  psa_status_t pstatus = psa_crypto_init();

  if (pstatus != PSA_SUCCESS) {
    LOG_ERR("FOTA: psa_crypto_init failed: %d", pstatus);
#if defined(CONFIG_PIGEON_FOTA_NCS)
    dfu_target_done(false);
    dfu_target_reset();
#endif
    return -EIO;
  }

  psa_hash_operation_t hash_op = {0};

  pstatus = psa_hash_setup(&hash_op, PSA_ALG_SHA_256);
  if (pstatus != PSA_SUCCESS) {
    LOG_ERR("FOTA: psa_hash_setup failed: %d", pstatus);
#if defined(CONFIG_PIGEON_FOTA_NCS)
    dfu_target_done(false);
    dfu_target_reset();
#endif
    return -EIO;
  }

  size_t offset = 0;
  size_t total_size = (size_t)info->size;
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
  }

  if (failed) {
    psa_hash_abort(&hash_op);
#if defined(CONFIG_PIGEON_FOTA_NCS)
    dfu_target_done(false);
    dfu_target_reset();
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

  uint8_t digest[32];
  size_t digest_len = 0;

  pstatus = psa_hash_finish(&hash_op, digest, sizeof(digest), &digest_len);
  if (pstatus != PSA_SUCCESS || digest_len != sizeof(digest)) {
    LOG_ERR("FOTA: psa_hash_finish failed: %d", pstatus);
#if defined(CONFIG_PIGEON_FOTA_NCS)
    dfu_target_done(false);
    dfu_target_reset();
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
    dfu_target_done(false);
    dfu_target_reset();
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
