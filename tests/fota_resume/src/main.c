/*
 * Unit tests for the CONFIG_PIGEON_FOTA_RESUME reconcile/record logic
 * (src/pigeon_fota_resume.c). Runs on native_sim -- the full FOTA apply
 * path can't (MCUboot), so everything flash/dfu-backend-shaped is covered
 * by the source-trace citations in pigeon_fota.c instead; what THIS suite
 * proves is the decision logic those backends feed:
 *
 *   - which persisted/queried offset combinations resume, restart, or
 *     invalidate (including persisted > queried and persisted < queried);
 *   - version-change invalidation;
 *   - record persistence round-trips through the real settings/NVS
 *     subsystem (save/load/overwrite/clear -- clear being the same call
 *     pigeon_fota_apply() makes when the completion sha256 verify fails).
 *
 * Build (from the pigeon-examples west workspace):
 *   west build -d build_fota_resume -b native_sim/native/64 \
 *     /home/justin/pigeon/tests/fota_resume
 *   ./build_fota_resume/zephyr/zephyr.exe
 */
#include <string.h>
#include <zephyr/ztest.h>

#include "pigeon_fota_resume.h"

#define TOTAL 393353u /* deliberately not a multiple of any chunk size */

static struct pigeon_fota_resume_record rec_of(const char *version, uint32_t offset) {
  struct pigeon_fota_resume_record rec = {.offset = offset};

  if (version) {
    strncpy(rec.version, version, sizeof(rec.version) - 1);
  }
  return rec;
}

ZTEST_SUITE(fota_resume_reconcile, NULL, NULL, NULL, NULL, NULL);

ZTEST(fota_resume_reconcile, test_no_record_fresh) {
  struct pigeon_fota_resume_record rec = rec_of(NULL, 0);
  size_t from = 1234;

  zassert_equal(
      pigeon_fota_resume_reconcile(&rec, "1.2.3", TOTAL, 0, &from), PIGEON_FOTA_RESUME_FRESH
  );
  zassert_equal(from, 0);
}

ZTEST(fota_resume_reconcile, test_no_record_but_backend_progress_invalidates) {
  /* Backend progress nobody's record vouches for must be wiped, not
   * resumed into. */
  struct pigeon_fota_resume_record rec = rec_of(NULL, 0);
  size_t from = 1234;

  zassert_equal(
      pigeon_fota_resume_reconcile(&rec, "1.2.3", TOTAL, 2048, &from),
      PIGEON_FOTA_RESUME_INVALIDATE
  );
  zassert_equal(from, 0);
}

ZTEST(fota_resume_reconcile, test_version_change_invalidates) {
  struct pigeon_fota_resume_record rec = rec_of("1.2.3", 4096);
  size_t from = 1234;

  zassert_equal(
      pigeon_fota_resume_reconcile(&rec, "2.0.0", TOTAL, 4096, &from),
      PIGEON_FOTA_RESUME_INVALIDATE
  );
  zassert_equal(from, 0);
}

ZTEST(fota_resume_reconcile, test_persisted_greater_than_queried_resumes_from_queried) {
  /* Record save raced ahead of a failed backend save: the backend counter
   * is flushed-only ground truth -- trust the smaller. */
  struct pigeon_fota_resume_record rec = rec_of("1.2.3", 4096);
  size_t from = 0;

  zassert_equal(
      pigeon_fota_resume_reconcile(&rec, "1.2.3", TOTAL, 2048, &from),
      PIGEON_FOTA_RESUME_CONTINUE
  );
  zassert_equal(from, 2048);
}

ZTEST(fota_resume_reconcile, test_persisted_less_than_queried_resumes_from_queried) {
  /* The record save (which follows the backend's own save each chunk)
   * never landed: bytes up to the backend counter are still flushed-only
   * ground truth, the stream can only continue from there, and the
   * completion sha256 verify remains the backstop. */
  struct pigeon_fota_resume_record rec = rec_of("1.2.3", 2048);
  size_t from = 0;

  zassert_equal(
      pigeon_fota_resume_reconcile(&rec, "1.2.3", TOTAL, 4096, &from),
      PIGEON_FOTA_RESUME_CONTINUE
  );
  zassert_equal(from, 4096);
}

ZTEST(fota_resume_reconcile, test_unaligned_offset_resumes_exactly) {
  struct pigeon_fota_resume_record rec = rec_of("1.2.3", 12345);
  size_t from = 0;

  zassert_equal(
      pigeon_fota_resume_reconcile(&rec, "1.2.3", TOTAL, 12345, &from),
      PIGEON_FOTA_RESUME_CONTINUE
  );
  zassert_equal(from, 12345);
}

ZTEST(fota_resume_reconcile, test_backend_past_total_invalidates) {
  /* Catalog image changed under the same version string, or the slot was
   * written outside the download. */
  struct pigeon_fota_resume_record rec = rec_of("1.2.3", TOTAL + 4096);
  size_t from = 1234;

  zassert_equal(
      pigeon_fota_resume_reconcile(&rec, "1.2.3", TOTAL, TOTAL + 4096, &from),
      PIGEON_FOTA_RESUME_INVALIDATE
  );
  zassert_equal(from, 0);
}

ZTEST(fota_resume_reconcile, test_backend_at_total_is_verify_only_resume) {
  /* Death between the last flushed chunk and the verify: resume at ==
   * total, so the caller's download loop no-ops and goes straight to the
   * sha256 verify. */
  struct pigeon_fota_resume_record rec = rec_of("1.2.3", TOTAL);
  size_t from = 0;

  zassert_equal(
      pigeon_fota_resume_reconcile(&rec, "1.2.3", TOTAL, TOTAL, &from),
      PIGEON_FOTA_RESUME_CONTINUE
  );
  zassert_equal(from, TOTAL);
}

ZTEST(fota_resume_reconcile, test_record_with_zero_backend_is_fresh) {
  /* A record with no flushed bytes behind it (e.g. seeded, then the first
   * chunk never landed) restarts without invalidation ceremony. */
  struct pigeon_fota_resume_record rec = rec_of("1.2.3", 2048);
  size_t from = 1234;

  zassert_equal(
      pigeon_fota_resume_reconcile(&rec, "1.2.3", TOTAL, 0, &from), PIGEON_FOTA_RESUME_FRESH
  );
  zassert_equal(from, 0);
}

/* Persistence round-trips against the real settings/NVS subsystem. Each
 * test leaves the record cleared so ordering doesn't matter. */
static void record_before(void *fixture) {
  ARG_UNUSED(fixture);
  (void)pigeon_fota_resume_clear();
}

ZTEST_SUITE(fota_resume_record, NULL, NULL, record_before, NULL, NULL);

ZTEST(fota_resume_record, test_load_without_record_is_empty) {
  struct pigeon_fota_resume_record rec = rec_of("stale", 99);

  zassert_ok(pigeon_fota_resume_load(&rec));
  zassert_equal(rec.version[0], '\0');
  zassert_equal(rec.offset, 0);
}

ZTEST(fota_resume_record, test_save_load_round_trip) {
  struct pigeon_fota_resume_record rec;

  zassert_ok(pigeon_fota_resume_save("1.2.3", 12345));
  zassert_ok(pigeon_fota_resume_load(&rec));
  zassert_str_equal(rec.version, "1.2.3");
  zassert_equal(rec.offset, 12345);
}

ZTEST(fota_resume_record, test_save_overwrites) {
  struct pigeon_fota_resume_record rec;

  zassert_ok(pigeon_fota_resume_save("1.2.3", 2048));
  zassert_ok(pigeon_fota_resume_save("1.2.3", 4096));
  zassert_ok(pigeon_fota_resume_load(&rec));
  zassert_equal(rec.offset, 4096);
}

ZTEST(fota_resume_record, test_clear_removes_record) {
  struct pigeon_fota_resume_record rec;

  /* The same clear pigeon_fota_apply() issues when the completion sha256
   * verify fails -- afterwards the next attempt must see no record. */
  zassert_ok(pigeon_fota_resume_save("1.2.3", 12345));
  zassert_ok(pigeon_fota_resume_clear());
  zassert_ok(pigeon_fota_resume_load(&rec));
  zassert_equal(rec.version[0], '\0');
  zassert_equal(rec.offset, 0);
}

ZTEST(fota_resume_record, test_max_length_version_stays_terminated) {
  struct pigeon_fota_resume_record rec;
  char long_version[PIGEON_FOTA_VERSION_MAX + 8];

  memset(long_version, 'v', sizeof(long_version) - 1);
  long_version[sizeof(long_version) - 1] = '\0';

  zassert_ok(pigeon_fota_resume_save(long_version, 1));
  zassert_ok(pigeon_fota_resume_load(&rec));
  zassert_equal(strlen(rec.version), PIGEON_FOTA_VERSION_MAX - 1);

  /* And the truncated stored version still reconciles as a match against
   * the same over-long target string (both truncate identically). */
  size_t from = 0;

  zassert_equal(
      pigeon_fota_resume_reconcile(&rec, long_version, TOTAL, 64, &from),
      PIGEON_FOTA_RESUME_CONTINUE
  );
  zassert_equal(from, 64);
}
