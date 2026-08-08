#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>

#include "pigeon_fota_resume.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

enum pigeon_fota_resume_action pigeon_fota_resume_reconcile(
    const struct pigeon_fota_resume_record *rec, const char *target_version, size_t total_size,
    size_t backend_offset, size_t *resume_from
) {
  *resume_from = 0;

  if (rec->version[0] == '\0') {
    /* Backend progress nobody's record vouches for (e.g. the record's
     * settings write never landed, or was cleared by a failed verify)
     * can't be attributed to any version -- wipe it rather than resuming
     * into unknown bytes. */
    return (backend_offset == 0) ? PIGEON_FOTA_RESUME_FRESH : PIGEON_FOTA_RESUME_INVALIDATE;
  }

  /* Compare only what the record can store: an over-long target version
   * was necessarily truncated at save time, and must still match its own
   * record on the next attempt. (Two distinct versions sharing a
   * 31-char prefix would wrongly match -- the completion sha256 verify is
   * the backstop for that, as for any same-version content change.) */
  if (strncmp(rec->version, target_version, sizeof(rec->version) - 1) != 0) {
    return PIGEON_FOTA_RESUME_INVALIDATE;
  }

  if (backend_offset > total_size) {
    /* More bytes flushed than the target declares -- the catalog image
     * changed under the same version string, or the slot was written
     * outside this download. Nothing trustworthy to resume. */
    return PIGEON_FOTA_RESUME_INVALIDATE;
  }

  if (backend_offset == 0) {
    return PIGEON_FOTA_RESUME_FRESH;
  }

  /* backend_offset == total_size is a valid resume: the download finished
   * but the verify/schedule never did (e.g. reboot between the last chunk
   * and psa_hash_finish) -- the caller's loop no-ops and goes straight to
   * the sha256 verify over the fully-flushed slot. */
  *resume_from = backend_offset;
  return PIGEON_FOTA_RESUME_CONTINUE;
}

struct pigeon_fota_resume_load_ctx {
  struct pigeon_fota_resume_record *rec;
  bool found;
};

static int pigeon_fota_resume_load_cb(
    const char *key, size_t len, settings_read_cb read_cb, void *cb_arg, void *param
) {
  struct pigeon_fota_resume_load_ctx *ctx = param;

  /* Exact-key subtree load (same pattern as stream_flash's own
   * settings_direct_loader): only the record key itself, no children. */
  if (settings_name_next(key, NULL) != 0) {
    return 0;
  }

  if (len != sizeof(*ctx->rec)) {
    LOG_WRN("FOTA resume: record size mismatch (%zu != %zu); ignoring it", len,
            sizeof(*ctx->rec));
    return 0;
  }

  if (read_cb(cb_arg, ctx->rec, sizeof(*ctx->rec)) == (ssize_t)sizeof(*ctx->rec)) {
    ctx->found = true;
  }

  return 0;
}

int pigeon_fota_resume_load(struct pigeon_fota_resume_record *rec) {
  struct pigeon_fota_resume_load_ctx ctx = {.rec = rec, .found = false};

  memset(rec, 0, sizeof(*rec));

  int err = settings_subsys_init();

  if (err == 0) {
    err = settings_load_subtree_direct(
        PIGEON_FOTA_RESUME_RECORD_KEY, pigeon_fota_resume_load_cb, &ctx
    );
  }

  if (err) {
    LOG_WRN("FOTA resume: record load failed: %d (treating as no record)", err);
    memset(rec, 0, sizeof(*rec));
    return err;
  }

  if (!ctx.found) {
    memset(rec, 0, sizeof(*rec));
  } else {
    /* Defensive: a corrupt record must never yield an unterminated
     * version string. */
    rec->version[sizeof(rec->version) - 1] = '\0';
  }

  return 0;
}

int pigeon_fota_resume_save(const char *version, size_t offset) {
  struct pigeon_fota_resume_record rec = {.offset = (uint32_t)offset};

  strncpy(rec.version, version, sizeof(rec.version) - 1);

  int err = settings_subsys_init();

  if (err == 0) {
    err = settings_save_one(PIGEON_FOTA_RESUME_RECORD_KEY, &rec, sizeof(rec));
  }

  if (err) {
    /* Same posture as the NCS backend's own store_progress(): a failed
     * save just means the next resume starts further back (or over). */
    LOG_WRN("FOTA resume: record save failed: %d", err);
  }

  return err;
}

int pigeon_fota_resume_clear(void) {
  int err = settings_subsys_init();

  if (err == 0) {
    err = settings_delete(PIGEON_FOTA_RESUME_RECORD_KEY);
  }

  if (err) {
    LOG_WRN("FOTA resume: record clear failed: %d", err);
  }

  return err;
}
