#include <dfu/dfu_target.h>
#include <dfu/dfu_target_mcuboot.h>
#include <errno.h>
#include <pigeon.h>
#include <psa/crypto.h>
#include <string.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include "pigeon_internal.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

/* Static (not stack) staging buffer handed to dfu_target_mcuboot_set_buf():
 * must stay valid for the whole DFU session, and a CONFIG_PIGEON_FOTA_CHUNK_SIZE
 * array on the stack would also eat a large fraction of CONFIG_MAIN_STACK_SIZE
 * (8192 by default in https_init) on top of the TLS/HTTP call frames already
 * live during the download loop below. dfu_target_stream uses this to batch
 * partial writes up to flash write-block granularity -- unrelated to
 * pigeon_https.c's own receive buffers, which land data here via
 * pigeon_fota_chunk_buf below before this one ever sees it. */
static uint8_t pigeon_fota_flash_buf[CONFIG_PIGEON_FOTA_CHUNK_SIZE] __aligned(4);

/* Network receive target for each chunk, handed to dfu_target_write() once
 * a full chunk has arrived. */
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

int pigeon_fota_apply(const struct pigeon_fota_info *info) {
  if (!info || info->size <= 0) {
    return -EINVAL;
  }

  LOG_INF("FOTA: applying firmware %s (%d bytes)", info->version, info->size);

  int err = dfu_target_mcuboot_set_buf(pigeon_fota_flash_buf, sizeof(pigeon_fota_flash_buf));

  if (err) {
    LOG_ERR("FOTA: dfu_target_mcuboot_set_buf failed: %d", err);
    return err;
  }

  err = dfu_target_init(DFU_TARGET_IMAGE_TYPE_MCUBOOT, 0, (size_t)info->size, NULL);
  if (err) {
    LOG_ERR("FOTA: dfu_target_init failed: %d", err);
    return err;
  }

  psa_status_t pstatus = psa_crypto_init();

  if (pstatus != PSA_SUCCESS) {
    LOG_ERR("FOTA: psa_crypto_init failed: %d", pstatus);
    dfu_target_done(false);
    dfu_target_reset();
    return -EIO;
  }

  psa_hash_operation_t hash_op = {0};

  pstatus = psa_hash_setup(&hash_op, PSA_ALG_SHA_256);
  if (pstatus != PSA_SUCCESS) {
    LOG_ERR("FOTA: psa_hash_setup failed: %d", pstatus);
    dfu_target_done(false);
    dfu_target_reset();
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

    err = dfu_target_write(pigeon_fota_chunk_buf, got);
    if (err) {
      LOG_ERR("FOTA: dfu_target_write failed at offset %zu: %d", offset, err);
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
    dfu_target_done(false);
    dfu_target_reset();
    return err;
  }

  uint8_t digest[32];
  size_t digest_len = 0;

  pstatus = psa_hash_finish(&hash_op, digest, sizeof(digest), &digest_len);
  if (pstatus != PSA_SUCCESS || digest_len != sizeof(digest)) {
    LOG_ERR("FOTA: psa_hash_finish failed: %d", pstatus);
    dfu_target_done(false);
    dfu_target_reset();
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
    dfu_target_done(false);
    dfu_target_reset();
    return -EBADMSG;
  }

  LOG_INF("FOTA: sha256 verified (%s)", digest_hex);

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
