#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>

#include "pigeon_fota_attempts.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

enum pigeon_fota_attempt_decision pigeon_fota_attempt_evaluate(
    const struct pigeon_fota_attempt_record *rec, const char *version,
    int32_t shadow_target_version, uint8_t max_attempts
) {
  if (max_attempts == 0) {
    return PIGEON_FOTA_ATTEMPT_ALLOW;
  }

  if (rec->version[0] == '\0') {
    return PIGEON_FOTA_ATTEMPT_ALLOW_RESET;
  }

  /* Compare only what the record can hold: an over-long version was
   * truncated on the way in and has to match its own truncated form. Two
   * versions sharing a 31-character prefix would collide, which costs at
   * most a shared budget -- the sha256 verify remains the backstop for
   * anything that actually matters. */
  if (strncmp(rec->version, version, sizeof(rec->version) - 1) != 0) {
    return PIGEON_FOTA_ATTEMPT_ALLOW_RESET;
  }

  /* Any change, not just an increase. A target_version that went backwards
   * means the shadow was rebuilt underneath this device, and the stored
   * count no longer describes anything real; reopening the budget is the
   * safe direction, since the failure being prevented here is refusing
   * forever. */
  if (rec->shadow_target_version != shadow_target_version) {
    return PIGEON_FOTA_ATTEMPT_ALLOW_RESET;
  }

  if (rec->count >= max_attempts) {
    return PIGEON_FOTA_ATTEMPT_REFUSE;
  }

  return PIGEON_FOTA_ATTEMPT_ALLOW;
}

struct pigeon_fota_attempts_load_ctx {
  struct pigeon_fota_attempt_record *rec;
  bool found;
};

static int pigeon_fota_attempts_load_cb(
    const char *key, size_t len, settings_read_cb read_cb, void *cb_arg, void *param
) {
  struct pigeon_fota_attempts_load_ctx *ctx = param;

  /* Exact-key subtree load, no children -- same shape as the resume
   * record's loader. */
  if (settings_name_next(key, NULL) != 0) {
    return 0;
  }

  if (len != sizeof(*ctx->rec)) {
    LOG_WRN("FOTA attempts: record size mismatch (%zu != %zu); ignoring it", len,
            sizeof(*ctx->rec));
    return 0;
  }

  if (read_cb(cb_arg, ctx->rec, sizeof(*ctx->rec)) == (ssize_t)sizeof(*ctx->rec)) {
    ctx->found = true;
  }

  return 0;
}

int pigeon_fota_attempts_load(struct pigeon_fota_attempt_record *rec) {
  struct pigeon_fota_attempts_load_ctx ctx = {.rec = rec, .found = false};

  memset(rec, 0, sizeof(*rec));

  int err = settings_subsys_init();

  if (err == 0) {
    err = settings_load_subtree_direct(
        PIGEON_FOTA_ATTEMPTS_RECORD_KEY, pigeon_fota_attempts_load_cb, &ctx
    );
  }

  if (err) {
    /* Degrade toward allowing an attempt: a device that cannot read its own
     * budget must not conclude it has spent one. */
    LOG_WRN("FOTA attempts: record load failed: %d (treating as no record)", err);
    memset(rec, 0, sizeof(*rec));
    return err;
  }

  if (!ctx.found) {
    memset(rec, 0, sizeof(*rec));
  } else {
    rec->version[sizeof(rec->version) - 1] = '\0';
  }

  return 0;
}

int pigeon_fota_attempts_store(
    const char *version, int32_t shadow_target_version, uint8_t count
) {
  struct pigeon_fota_attempt_record rec;

  /* Zero the whole record, reserved bytes included, so what lands in flash
   * is exactly what a later size check expects. */
  memset(&rec, 0, sizeof(rec));
  strncpy(rec.version, version, sizeof(rec.version) - 1);
  rec.shadow_target_version = shadow_target_version;
  rec.count = count;

  int err = settings_subsys_init();

  if (err == 0) {
    err = settings_save_one(PIGEON_FOTA_ATTEMPTS_RECORD_KEY, &rec, sizeof(rec));
  }

  if (err) {
    /* A budget that cannot be persisted is a budget that resets on reboot,
     * which is the lenient direction; log it and carry on rather than
     * failing the download over bookkeeping. */
    LOG_WRN("FOTA attempts: record save failed: %d", err);
  }

  return err;
}

int pigeon_fota_attempts_charge(const char *version) {
  struct pigeon_fota_attempt_record rec;

  (void)pigeon_fota_attempts_load(&rec);

  int32_t target_version = 0;
  uint8_t count = 0;

  if (strncmp(rec.version, version, sizeof(rec.version) - 1) == 0) {
    /* Keep the operator intent the gate recorded: only the count moves. */
    target_version = rec.shadow_target_version;
    count = rec.count;
  }

  if (count < UINT8_MAX) {
    count++;
  }

  return pigeon_fota_attempts_store(version, target_version, count);
}

#if defined(CONFIG_PIGEON_FOTA_ATTEMPT_BUDGET)

bool pigeon_fota_attempt_allowed(
    const struct pigeon_fota_info *info, int32_t shadow_target_version
) {
  if (!info) {
    return false;
  }

  struct pigeon_fota_attempt_record rec;

  (void)pigeon_fota_attempts_load(&rec);

  enum pigeon_fota_attempt_decision decision = pigeon_fota_attempt_evaluate(
      &rec, info->version, shadow_target_version,
      (uint8_t)CONFIG_PIGEON_FOTA_MAX_ATTEMPTS_PER_VERSION
  );

  switch (decision) {
    case PIGEON_FOTA_ATTEMPT_ALLOW_RESET:
      /* Record the intent now, before the attempt is charged against it, so
       * a crash between here and the first chunk still leaves the budget
       * attributable to this shadow write rather than the previous one. */
      (void)pigeon_fota_attempts_store(info->version, shadow_target_version, 0);
      return true;

    case PIGEON_FOTA_ATTEMPT_REFUSE:
      LOG_WRN(
          "FOTA: %u attempts already spent on this firmware target; waiting for a new shadow "
          "write or a different version before trying again",
          rec.count
      );
      return false;

    case PIGEON_FOTA_ATTEMPT_ALLOW:
    default:
      return true;
  }
}

void pigeon_fota_attempts_clear(void) {
  int err = settings_subsys_init();

  if (err == 0) {
    err = settings_delete(PIGEON_FOTA_ATTEMPTS_RECORD_KEY);
  }

  if (err) {
    LOG_WRN("FOTA attempts: record clear failed: %d", err);
  }
}

#endif /* CONFIG_PIGEON_FOTA_ATTEMPT_BUDGET */
