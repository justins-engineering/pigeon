/*
 * Unit tests for the per-version FOTA attempt budget
 * (src/pigeon_fota_attempts.c).
 *
 * The behavior worth pinning down here is not "does it count" but "can it
 * ever stop counting down forever": a budget with no way back turns a few
 * unlucky timeouts into a firmware version the device refuses permanently.
 * So the cases below lean on the recovery paths -- a new shadow write
 * naming the same version, a version change, a cleared record -- at least
 * as hard as on the refusal itself.
 *
 * Build (from the pigeon-examples west workspace):
 *   west build -d build_fota_attempts -b native_sim/native/64 \
 *     /home/justin/pigeon/tests/fota_attempts
 *   ./build_fota_attempts/zephyr/zephyr.exe
 */
#include <string.h>
#include <zephyr/settings/settings.h>
#include <zephyr/ztest.h>

#include "pigeon_fota_attempts.h"

#define MAX 3
#define V_A "1.2.3"
#define V_B "1.2.4"

static struct pigeon_fota_attempt_record rec_of(
    const char *version, int32_t target_version, uint8_t count
) {
  struct pigeon_fota_attempt_record rec;

  memset(&rec, 0, sizeof(rec));
  if (version) {
    strncpy(rec.version, version, sizeof(rec.version) - 1);
  }
  rec.shadow_target_version = target_version;
  rec.count = count;

  return rec;
}

static struct pigeon_fota_info info_of(const char *version) {
  struct pigeon_fota_info info;

  memset(&info, 0, sizeof(info));
  strncpy(info.version, version, sizeof(info.version) - 1);
  info.size = 4096;

  return info;
}

ZTEST_SUITE(fota_attempt_decision, NULL, NULL, NULL, NULL, NULL);

ZTEST(fota_attempt_decision, test_no_record_starts_a_budget) {
  struct pigeon_fota_attempt_record rec = rec_of(NULL, 0, 0);

  zassert_equal(
      pigeon_fota_attempt_evaluate(&rec, V_A, 7, MAX), PIGEON_FOTA_ATTEMPT_ALLOW_RESET
  );
}

ZTEST(fota_attempt_decision, test_within_budget_allows) {
  for (uint8_t spent = 0; spent < MAX; spent++) {
    struct pigeon_fota_attempt_record rec = rec_of(V_A, 7, spent);

    zassert_equal(
        pigeon_fota_attempt_evaluate(&rec, V_A, 7, MAX), PIGEON_FOTA_ATTEMPT_ALLOW,
        "%u of %u spent should still allow", spent, MAX
    );
  }
}

ZTEST(fota_attempt_decision, test_exhausted_budget_refuses) {
  struct pigeon_fota_attempt_record rec = rec_of(V_A, 7, MAX);

  zassert_equal(pigeon_fota_attempt_evaluate(&rec, V_A, 7, MAX), PIGEON_FOTA_ATTEMPT_REFUSE);

  /* Over the cap (a record written by a build with a larger cap, or a
   * charge that raced the gate) still refuses rather than wrapping. */
  rec.count = MAX + 5;
  zassert_equal(pigeon_fota_attempt_evaluate(&rec, V_A, 7, MAX), PIGEON_FOTA_ATTEMPT_REFUSE);

  rec.count = UINT8_MAX;
  zassert_equal(pigeon_fota_attempt_evaluate(&rec, V_A, 7, MAX), PIGEON_FOTA_ATTEMPT_REFUSE);
}

ZTEST(fota_attempt_decision, test_operator_re_push_reopens_an_exhausted_budget) {
  /* The finding this module exists for: an exhausted version must be
   * recoverable without inventing a new version string for unchanged
   * bytes. A later shadow write is that signal. */
  struct pigeon_fota_attempt_record rec = rec_of(V_A, 7, MAX);

  zassert_equal(
      pigeon_fota_attempt_evaluate(&rec, V_A, 8, MAX), PIGEON_FOTA_ATTEMPT_ALLOW_RESET,
      "the same version under a newer shadow target_version must be attemptable again"
  );
}

ZTEST(fota_attempt_decision, test_target_version_going_backwards_also_reopens) {
  /* A shadow rebuilt underneath the device (a recreated pigeon, a restored
   * Durable Object) can hand back a lower target_version. The stored count
   * describes nothing real at that point, and refusing forever is the
   * failure being designed against, so reopening is the safe direction. */
  struct pigeon_fota_attempt_record rec = rec_of(V_A, 7, MAX);

  zassert_equal(
      pigeon_fota_attempt_evaluate(&rec, V_A, 2, MAX), PIGEON_FOTA_ATTEMPT_ALLOW_RESET
  );
}

ZTEST(fota_attempt_decision, test_same_shadow_write_does_not_reopen) {
  /* The counterweight to the two cases above: nothing the device does by
   * itself may reopen the budget. Re-polling the same shadow yields the
   * same target_version, and must keep refusing. */
  struct pigeon_fota_attempt_record rec = rec_of(V_A, 7, MAX);

  for (int poll = 0; poll < 5; poll++) {
    zassert_equal(pigeon_fota_attempt_evaluate(&rec, V_A, 7, MAX), PIGEON_FOTA_ATTEMPT_REFUSE);
  }
}

ZTEST(fota_attempt_decision, test_different_version_starts_fresh) {
  struct pigeon_fota_attempt_record rec = rec_of(V_A, 7, MAX);

  zassert_equal(
      pigeon_fota_attempt_evaluate(&rec, V_B, 7, MAX), PIGEON_FOTA_ATTEMPT_ALLOW_RESET
  );
}

ZTEST(fota_attempt_decision, test_zero_cap_disables_the_budget) {
  struct pigeon_fota_attempt_record rec = rec_of(V_A, 7, UINT8_MAX);

  zassert_equal(pigeon_fota_attempt_evaluate(&rec, V_A, 7, 0), PIGEON_FOTA_ATTEMPT_ALLOW);
}

ZTEST(fota_attempt_decision, test_over_long_version_matches_its_own_truncation) {
  /* Versions are stored truncated to the record width, so the comparison
   * has to be against the truncated form or a long version could never
   * match its own record and would retry without limit. */
  static const char long_v[] = "0.0.0-a-very-long-release-candidate-label-indeed";
  struct pigeon_fota_attempt_record rec = rec_of(long_v, 7, MAX);

  zassert_true(strlen(long_v) > sizeof(rec.version) - 1, "vector must actually overflow");
  zassert_equal(pigeon_fota_attempt_evaluate(&rec, long_v, 7, MAX), PIGEON_FOTA_ATTEMPT_REFUSE);
}

/* Persistence and the gate itself, against the real settings/NVS backend. */

static void attempts_before(void *fixture) {
  ARG_UNUSED(fixture);
  (void)settings_subsys_init();
  (void)settings_delete(PIGEON_FOTA_ATTEMPTS_RECORD_KEY);
}

ZTEST_SUITE(fota_attempt_record, NULL, NULL, attempts_before, NULL, NULL);

ZTEST(fota_attempt_record, test_absent_record_loads_empty) {
  struct pigeon_fota_attempt_record rec = rec_of(V_A, 9, 2);

  zassert_equal(pigeon_fota_attempts_load(&rec), 0);
  zassert_equal(rec.version[0], '\0', "load must zero the record when nothing is stored");
  zassert_equal(rec.count, 0);
  zassert_equal(rec.shadow_target_version, 0);
}

ZTEST(fota_attempt_record, test_store_load_round_trip) {
  zassert_equal(pigeon_fota_attempts_store(V_A, 42, 2), 0);

  struct pigeon_fota_attempt_record rec;

  zassert_equal(pigeon_fota_attempts_load(&rec), 0);
  zassert_str_equal(rec.version, V_A);
  zassert_equal(rec.shadow_target_version, 42);
  zassert_equal(rec.count, 2);
}

ZTEST(fota_attempt_record, test_charge_increments_and_keeps_operator_intent) {
  zassert_equal(pigeon_fota_attempts_store(V_A, 42, 0), 0);
  zassert_equal(pigeon_fota_attempts_charge(V_A), 0);

  struct pigeon_fota_attempt_record rec;

  zassert_equal(pigeon_fota_attempts_load(&rec), 0);
  zassert_equal(rec.count, 1);
  zassert_equal(
      rec.shadow_target_version, 42,
      "charging an attempt must not forget which shadow write authorized it"
  );

  zassert_equal(pigeon_fota_attempts_charge(V_A), 0);
  zassert_equal(pigeon_fota_attempts_load(&rec), 0);
  zassert_equal(rec.count, 2);
  zassert_equal(rec.shadow_target_version, 42);
}

ZTEST(fota_attempt_record, test_charge_on_a_new_version_restarts_the_count) {
  zassert_equal(pigeon_fota_attempts_store(V_A, 42, 3), 0);
  zassert_equal(pigeon_fota_attempts_charge(V_B), 0);

  struct pigeon_fota_attempt_record rec;

  zassert_equal(pigeon_fota_attempts_load(&rec), 0);
  zassert_str_equal(rec.version, V_B);
  zassert_equal(rec.count, 1);
}

ZTEST(fota_attempt_record, test_charge_saturates_instead_of_wrapping) {
  /* A wrap would silently hand out a whole fresh budget, which is exactly
   * the runaway the cap exists to stop. */
  zassert_equal(pigeon_fota_attempts_store(V_A, 42, UINT8_MAX), 0);
  zassert_equal(pigeon_fota_attempts_charge(V_A), 0);

  struct pigeon_fota_attempt_record rec;

  zassert_equal(pigeon_fota_attempts_load(&rec), 0);
  zassert_equal(rec.count, UINT8_MAX);
}

ZTEST(fota_attempt_record, test_gate_spends_then_refuses_then_recovers) {
  /* The whole lifecycle an operator would see, through the real API and
   * real NVS: a target is attempted its budget's worth of times, starts
   * being refused, and comes back after the next shadow write. */
  struct pigeon_fota_info info = info_of(V_A);

  for (int attempt = 0; attempt < CONFIG_PIGEON_FOTA_MAX_ATTEMPTS_PER_VERSION; attempt++) {
    zassert_true(
        pigeon_fota_attempt_allowed(&info, 7), "attempt %d should be allowed", attempt
    );
    zassert_equal(pigeon_fota_attempts_charge(info.version), 0);
  }

  zassert_false(pigeon_fota_attempt_allowed(&info, 7), "the budget must actually run out");
  zassert_false(pigeon_fota_attempt_allowed(&info, 7), "and stay out while nothing changes");

  zassert_true(
      pigeon_fota_attempt_allowed(&info, 8), "a new shadow write must reopen the budget"
  );

  /* The reopen is not a one-shot: the gate rewrote the record, so the full
   * budget is available again from here. */
  struct pigeon_fota_attempt_record rec;

  zassert_equal(pigeon_fota_attempts_load(&rec), 0);
  zassert_equal(rec.count, 0);
  zassert_equal(rec.shadow_target_version, 8);
}

ZTEST(fota_attempt_record, test_gate_recovers_on_a_new_version_too) {
  struct pigeon_fota_info info_a = info_of(V_A);
  struct pigeon_fota_info info_b = info_of(V_B);

  for (int attempt = 0; attempt < CONFIG_PIGEON_FOTA_MAX_ATTEMPTS_PER_VERSION; attempt++) {
    zassert_true(pigeon_fota_attempt_allowed(&info_a, 7));
    zassert_equal(pigeon_fota_attempts_charge(info_a.version), 0);
  }

  zassert_false(pigeon_fota_attempt_allowed(&info_a, 7));
  zassert_true(pigeon_fota_attempt_allowed(&info_b, 7), "a different version is a new target");
}

ZTEST(fota_attempt_record, test_clear_restores_a_full_budget) {
  struct pigeon_fota_info info = info_of(V_A);

  for (int attempt = 0; attempt < CONFIG_PIGEON_FOTA_MAX_ATTEMPTS_PER_VERSION; attempt++) {
    zassert_true(pigeon_fota_attempt_allowed(&info, 7));
    zassert_equal(pigeon_fota_attempts_charge(info.version), 0);
  }
  zassert_false(pigeon_fota_attempt_allowed(&info, 7));

  /* What an application calls once it sees the offered version actually
   * running, so a later re-offer of the same string is not born spent. */
  pigeon_fota_attempts_clear();

  zassert_true(pigeon_fota_attempt_allowed(&info, 7));
}

ZTEST(fota_attempt_record, test_gate_rejects_a_null_target) {
  zassert_false(pigeon_fota_attempt_allowed(NULL, 7));
}
