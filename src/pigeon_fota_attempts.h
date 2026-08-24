#ifndef PIDGEIOT_PIGEON_FOTA_ATTEMPTS_H_
#define PIDGEIOT_PIGEON_FOTA_ATTEMPTS_H_

#include <stdint.h>

#include <pigeon.h>

/*
 * Per-version FOTA attempt budget (CONFIG_PIGEON_FOTA_ATTEMPT_BUDGET).
 *
 * The problem a budget solves is real: an image that downloads, verifies,
 * test-swaps, and then boot-loops until MCUboot reverts will otherwise
 * re-download itself on every shadow poll, forever, over whatever link the
 * device has. Counting attempts and stopping is the only thing a device can
 * do about that on its own.
 *
 * The problem a NAIVE budget creates is just as real, and is what this
 * module exists to avoid: a counter that only ever goes up turns three
 * unlucky timeouts into a firmware version the device will refuse for the
 * rest of its life, recoverable only by publishing the same bytes again
 * under a different version string. That is a worse failure than the one
 * being prevented, because it is silent and it is permanent.
 *
 * So the budget is scoped to an operator's expressed intent rather than to
 * a version string alone. The record binds a count to BOTH the firmware
 * version and the shadow target_version that last asked for it; the shadow's
 * target_version advances on every dashboard write, so an operator who looks
 * at a stuck device and pushes its shadow again -- with the same firmware
 * target still named in it -- has said "try again" in the only vocabulary
 * the device understands, and the count starts over. Nothing device-side can
 * forge that signal: target_version is server-assigned, and a device that
 * merely reboots, reconnects, or re-polls sees the same value it saw before.
 *
 * Kept free of CONFIG_PIGEON_FOTA* symbols (the decision function takes its
 * cap as an argument) so tests/fota_attempts can build it on native_sim,
 * where MCUboot -- and therefore the whole FOTA path -- cannot exist. Same
 * split, and same reason, as pigeon_fota_resume.{c,h}.
 */

/* Settings key holding struct pigeon_fota_attempt_record. Sits alongside
 * the resume module's own "pigeon/fota" keys. */
#define PIGEON_FOTA_ATTEMPTS_RECORD_KEY "pigeon/fota/attempts"

struct pigeon_fota_attempt_record {
  /* NUL-terminated firmware version the count belongs to; "" means no
   * record at all. */
  char version[PIGEON_FOTA_VERSION_MAX];
  /* The shadow target_version that last named this firmware target. A
   * change here is the operator re-push that resets the count. */
  int32_t shadow_target_version;
  /* Attempts spent on this (version, shadow_target_version) pair,
   * saturating rather than wrapping -- a wrap would silently hand out a
   * fresh budget. */
  uint8_t count;
  /* Keeps the on-flash record size explicit rather than
   * compiler-determined, since a size change is what makes an existing
   * record unreadable. */
  uint8_t reserved[3];
};

enum pigeon_fota_attempt_decision {
  /* Proceed; the stored record already describes this target. */
  PIGEON_FOTA_ATTEMPT_ALLOW,
  /* Proceed, and rewrite the record with a zero count: either nothing was
   * recorded, the target names a different version, or the operator
   * re-asserted this one with a new shadow write. */
  PIGEON_FOTA_ATTEMPT_ALLOW_RESET,
  /* The budget for this exact (version, shadow_target_version) pair is
   * spent. A new version or another shadow write reopens it. */
  PIGEON_FOTA_ATTEMPT_REFUSE,
};

/*
 * Decides whether another attempt at version/shadow_target_version is
 * allowed, given the stored record and a cap. A max_attempts of 0 disables
 * the budget entirely and always allows.
 *
 * Pure function: no settings access, no clock. Exercised by
 * tests/fota_attempts.
 */
enum pigeon_fota_attempt_decision pigeon_fota_attempt_evaluate(
    const struct pigeon_fota_attempt_record *rec, const char *version,
    int32_t shadow_target_version, uint8_t max_attempts
);

/*
 * Record persistence, best-effort over the settings subsystem in the same
 * style as pigeon_fota_resume_*(): load() zeroes *rec and returns 0 when no
 * record exists, and zeroes it on a settings failure too, so a caller that
 * ignores the return value degrades toward allowing an attempt rather than
 * refusing one.
 */
int pigeon_fota_attempts_load(struct pigeon_fota_attempt_record *rec);
int pigeon_fota_attempts_store(const char *version, int32_t shadow_target_version, uint8_t count);

/*
 * Spends one attempt on version, preserving the recorded
 * shadow_target_version when the stored record already names this version.
 * Called by pigeon_fota_apply() -- see there for what does and does not
 * count as an attempt.
 */
int pigeon_fota_attempts_charge(const char *version);

#endif /* PIDGEIOT_PIGEON_FOTA_ATTEMPTS_H_ */
