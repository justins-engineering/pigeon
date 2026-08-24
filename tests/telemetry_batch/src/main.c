/*
 * Unit tests for the telemetry batch buffer and its flush policy
 * (src/pigeon_telemetry_batch.c) -- the accumulate/overflow/age/backoff
 * decisions behind CONFIG_PIGEON_TELEMETRY_BATCH.
 *
 * Worth testing in isolation because every one of these decisions is about
 * data that has already been sampled and cannot be re-taken. Getting the age
 * arithmetic wrong misplaces readings on a graph the operator trusts; getting
 * the overflow direction wrong throws away the newest readings instead of the
 * stalest; getting the retry classification wrong either wedges a device
 * behind a batch the platform will never accept, or discards readings the
 * platform only asked it to send later. None of that is observable from a
 * successful build, and reproducing it on hardware means arranging an outage.
 *
 * The module takes `now_ms` from its caller rather than reading the uptime
 * itself, so time here is an argument and every case is deterministic.
 *
 * Build (from the pigeon-examples west workspace):
 *   west build -d build_telemetry_batch -b native_sim/native/64 \
 *     /home/justin/pigeon/tests/telemetry_batch
 *   ./build_telemetry_batch/zephyr/zephyr.exe
 */
#include <errno.h>
#include <string.h>
#include <zephyr/ztest.h>

#include "pigeon_telemetry_batch.h"

/* Mirrors of the per-target definitions in CMakeLists.txt, kept as named
 * constants so a case reads as "one past the depth" rather than as a literal
 * that has to be checked against the build. */
#define DEPTH CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH
#define BUF_SIZE CONFIG_PIGEON_TELEMETRY_BATCH_BUF_SIZE
#define MAX_AGE_SEC CONFIG_PIGEON_TELEMETRY_BATCH_MAX_AGE_SEC
#define BACKOFF_MAX_SEC CONFIG_PIGEON_TELEMETRY_BATCH_BACKOFF_MAX_SEC

/* High-water trigger, restated from the implementation: three quarters of the
 * arena. Restated rather than exported because a test that computed it from
 * the same expression the code uses would agree with a wrong one. */
#define HIGH_WATER ((size_t)(BUF_SIZE - (BUF_SIZE / 4)))

#define SMALL_FRAG "{\"a\":\"1\"}"
#define SMALL_LEN (sizeof(SMALL_FRAG) - 1)

/* Large enough that three fill the arena past the high-water mark and four do
 * not fit at all, so the byte-bound paths are reachable well before the depth
 * bound is. */
#define BIG_LEN 70u

static char body[PIGEON_TELEMETRY_BATCH_BODY_MAX];

/* Builds a distinguishable fragment of exactly `len` bytes: {"n":"<tag...>"}
 * is 8 bytes of framing plus fill, so each reading carries a tag that says
 * which one it was and a length the caller controls. */
static void make_frag(char *out, char tag, size_t len) {
  zassert_true(len >= 9, "fragment framing needs at least one fill byte");

  size_t fill = len - 8;

  memcpy(out, "{\"n\":\"", 6);
  memset(out + 6, tag, fill);
  memcpy(out + 6 + fill, "\"}", 2);
  out[len] = '\0';
}

static void reset_before(void *fixture) {
  ARG_UNUSED(fixture);
  pigeon_telemetry_batch_reset();
}

ZTEST_SUITE(telemetry_batch, NULL, NULL, reset_before, NULL, NULL);

/* ---- accumulation and serialization ---- */

ZTEST(telemetry_batch, test_empty_buffer_builds_nothing) {
  int readings = -1;

  zassert_equal(pigeon_telemetry_batch_count(), 0);
  zassert_equal(pigeon_telemetry_batch_used(), 0);
  zassert_false(pigeon_telemetry_batch_due(0));
  zassert_equal(pigeon_telemetry_batch_build(body, sizeof(body), 0, &readings), 0);
  zassert_equal(readings, 0);
}

ZTEST(telemetry_batch, test_single_reading_body) {
  zassert_ok(pigeon_telemetry_batch_record("{\"t\":\"21.5\"}", 12, 1000));

  int readings = 0;
  size_t len = pigeon_telemetry_batch_build(body, sizeof(body), 4000, &readings);

  zassert_equal(readings, 1);
  zassert_equal(
      strcmp(body, "{\"reports\":[{\"age_secs\":3,\"metrics\":{\"t\":\"21.5\"}}]}"), 0, "got %s",
      body
  );
  zassert_equal(len, strlen(body));
}

ZTEST(telemetry_batch, test_readings_are_emitted_oldest_first) {
  zassert_ok(pigeon_telemetry_batch_record("{\"n\":\"1\"}", 9, 0));
  zassert_ok(pigeon_telemetry_batch_record("{\"n\":\"2\"}", 9, 10000));
  zassert_ok(pigeon_telemetry_batch_record("{\"n\":\"3\"}", 9, 20000));

  int readings = 0;

  (void)pigeon_telemetry_batch_build(body, sizeof(body), 20000, &readings);

  zassert_equal(readings, 3);
  /* Ages descend as the readings advance -- the oldest reading carries the
   * largest age, which is what "sent in chronological order" looks like on a
   * wire whose timestamps count backwards from the delivery. */
  zassert_equal(
      strcmp(
          body,
          "{\"reports\":[{\"age_secs\":20,\"metrics\":{\"n\":\"1\"}},"
          "{\"age_secs\":10,\"metrics\":{\"n\":\"2\"}},"
          "{\"age_secs\":0,\"metrics\":{\"n\":\"3\"}}]}"
      ),
      0, "got %s", body
  );
}

ZTEST(telemetry_batch, test_build_does_not_consume) {
  zassert_ok(pigeon_telemetry_batch_record(SMALL_FRAG, SMALL_LEN, 0));
  zassert_ok(pigeon_telemetry_batch_record(SMALL_FRAG, SMALL_LEN, 0));

  char first[sizeof(body)];
  size_t len = pigeon_telemetry_batch_build(body, sizeof(body), 5000, NULL);

  memcpy(first, body, len + 1);

  /* A refused batch is retried from the same buffer, so building must be a
   * pure read -- if it consumed, a 500 would silently cost the readings it
   * was meant to preserve. */
  zassert_equal(pigeon_telemetry_batch_count(), 2);
  zassert_equal(pigeon_telemetry_batch_used(), 2 * SMALL_LEN);
  zassert_equal(pigeon_telemetry_batch_build(body, sizeof(body), 5000, NULL), len);
  zassert_equal(strcmp(body, first), 0);
}

ZTEST(telemetry_batch, test_build_refuses_a_buffer_it_would_overrun) {
  zassert_ok(pigeon_telemetry_batch_record(SMALL_FRAG, SMALL_LEN, 0));
  zassert_ok(pigeon_telemetry_batch_record(SMALL_FRAG, SMALL_LEN, 0));

  char tiny[24];
  int readings = -1;

  /* Truncating would emit a body the platform answers with a 400, so a
   * too-small destination is reported as 0 and the readings are left alone. */
  zassert_equal(pigeon_telemetry_batch_build(tiny, sizeof(tiny), 0, &readings), 0);
  zassert_equal(readings, 0);
  zassert_equal(pigeon_telemetry_batch_count(), 2);
}

ZTEST(telemetry_batch, test_record_rejects_unusable_input) {
  zassert_equal(pigeon_telemetry_batch_record(NULL, 5, 0), -EINVAL);
  zassert_equal(pigeon_telemetry_batch_record(SMALL_FRAG, 0, 0), -EINVAL);
  zassert_equal(pigeon_telemetry_batch_count(), 0);
}

ZTEST(telemetry_batch, test_record_rejects_a_fragment_bigger_than_the_arena) {
  static char huge[BUF_SIZE + 32];

  memset(huge, 'x', sizeof(huge));

  zassert_ok(pigeon_telemetry_batch_record(SMALL_FRAG, SMALL_LEN, 0));
  /* Evicting the whole buffer for a reading that still would not fit helps
   * nobody, so this is refused with the existing readings intact. */
  zassert_equal(pigeon_telemetry_batch_record(huge, sizeof(huge), 0), -EMSGSIZE);
  zassert_equal(pigeon_telemetry_batch_count(), 1);
  zassert_equal(pigeon_telemetry_batch_take_dropped(), 0);
}

ZTEST(telemetry_batch, test_reset_clears_everything) {
  zassert_ok(pigeon_telemetry_batch_record(SMALL_FRAG, SMALL_LEN, 0));
  pigeon_telemetry_batch_reset();

  zassert_equal(pigeon_telemetry_batch_count(), 0);
  zassert_equal(pigeon_telemetry_batch_used(), 0);
  zassert_equal(pigeon_telemetry_batch_take_dropped(), 0);
}

/* ---- overflow ---- */

ZTEST(telemetry_batch, test_depth_overflow_drops_oldest) {
  char frag[16];

  for (int i = 0; i < DEPTH + 2; i++) {
    make_frag(frag, (char)('a' + i), 9);
    zassert_ok(pigeon_telemetry_batch_record(frag, 9, i * 1000));
  }

  zassert_equal(pigeon_telemetry_batch_count(), DEPTH);
  zassert_equal(pigeon_telemetry_batch_take_dropped(), 2);

  (void)pigeon_telemetry_batch_build(body, sizeof(body), 0, NULL);

  /* The two oldest went; the newest is always kept, because the freshest
   * reading is the one a dashboard, an alert rule and a connection badge all
   * actually read. */
  zassert_is_null(strstr(body, "\"a\""), "oldest reading survived: %s", body);
  zassert_is_null(strstr(body, "\"b\""), "second-oldest reading survived: %s", body);
  zassert_not_null(strstr(body, "\"c\""));
  zassert_not_null(strstr(body, "\"n\":\""));
}

ZTEST(telemetry_batch, test_byte_overflow_drops_oldest_and_compacts) {
  char frag[BIG_LEN + 1];
  size_t fits = BUF_SIZE / BIG_LEN;

  zassert_true(fits < DEPTH, "sizing must make the byte bound bite before the depth bound");

  for (size_t i = 0; i < fits + 1; i++) {
    make_frag(frag, (char)('a' + i), BIG_LEN);
    zassert_ok(pigeon_telemetry_batch_record(frag, BIG_LEN, (int64_t)i * 1000));
  }

  zassert_equal((size_t)pigeon_telemetry_batch_count(), fits);
  zassert_equal(pigeon_telemetry_batch_take_dropped(), 1);
  zassert_equal(pigeon_telemetry_batch_used(), fits * BIG_LEN);

  int readings = 0;
  size_t len = pigeon_telemetry_batch_build(body, sizeof(body), 0, &readings);

  /* The arena is compacted on a drop, so a stale offset would show up here as
   * a fragment reading off the wrong bytes rather than as a crash. */
  zassert_equal((size_t)readings, fits);
  zassert_equal(len, strlen(body));
  zassert_is_null(strstr(body, "aaa"), "dropped reading's bytes are still in the body: %s", body);
  zassert_not_null(strstr(body, "bbb"));
}

ZTEST(telemetry_batch, test_take_dropped_reports_once) {
  char frag[16];

  for (int i = 0; i < DEPTH + 1; i++) {
    make_frag(frag, (char)('a' + i), 9);
    zassert_ok(pigeon_telemetry_batch_record(frag, 9, 0));
  }

  zassert_equal(pigeon_telemetry_batch_take_dropped(), 1);
  /* Read-and-clear: the flush that reported it must not report it again on
   * the next one. */
  zassert_equal(pigeon_telemetry_batch_take_dropped(), 0);
}

/* ---- flush triggers ---- */

ZTEST(telemetry_batch, test_due_at_depth) {
  for (int i = 0; i < DEPTH - 1; i++) {
    zassert_ok(pigeon_telemetry_batch_record(SMALL_FRAG, SMALL_LEN, 0));
    zassert_false(pigeon_telemetry_batch_due(0), "due at %d readings", i + 1);
  }

  zassert_ok(pigeon_telemetry_batch_record(SMALL_FRAG, SMALL_LEN, 0));
  zassert_true(pigeon_telemetry_batch_due(0));
}

ZTEST(telemetry_batch, test_due_at_max_age) {
  zassert_ok(pigeon_telemetry_batch_record(SMALL_FRAG, SMALL_LEN, 0));

  zassert_false(pigeon_telemetry_batch_due((MAX_AGE_SEC - 1) * 1000));
  zassert_true(pigeon_telemetry_batch_due(MAX_AGE_SEC * 1000));
}

ZTEST(telemetry_batch, test_due_age_measured_from_the_oldest_reading) {
  zassert_ok(pigeon_telemetry_batch_record(SMALL_FRAG, SMALL_LEN, 0));
  zassert_ok(pigeon_telemetry_batch_record(SMALL_FRAG, SMALL_LEN, MAX_AGE_SEC * 1000));

  /* A steady trickle of new readings must not keep resetting the clock on the
   * ones already waiting -- otherwise a device that never stops sampling
   * never delivers. */
  zassert_true(pigeon_telemetry_batch_due(MAX_AGE_SEC * 1000));
}

ZTEST(telemetry_batch, test_due_at_high_water) {
  char frag[BIG_LEN + 1];
  int recorded = 0;

  make_frag(frag, 'z', BIG_LEN);

  while (pigeon_telemetry_batch_used() + BIG_LEN <= HIGH_WATER) {
    zassert_ok(pigeon_telemetry_batch_record(frag, BIG_LEN, 0));
    recorded++;
    zassert_false(pigeon_telemetry_batch_due(0), "due below the high-water mark");
  }

  zassert_ok(pigeon_telemetry_batch_record(frag, BIG_LEN, 0));
  recorded++;

  /* The point of this trigger: an arena too small for DEPTH readings delivers
   * what it has instead of dropping its oldest on every record while it waits
   * out the age trigger. */
  zassert_true(recorded < DEPTH, "high water must bite before the depth trigger here");
  zassert_true(pigeon_telemetry_batch_due(0));
  zassert_equal(pigeon_telemetry_batch_take_dropped(), 0, "high water fired too late to prevent a drop");
}

/* ---- age arithmetic ---- */

ZTEST(telemetry_batch, test_age_rounds_to_nearest_second) {
  zassert_equal(pigeon_telemetry_batch_age_secs(0, 0), 0);
  zassert_equal(pigeon_telemetry_batch_age_secs(0, 400), 0);
  zassert_equal(pigeon_telemetry_batch_age_secs(0, 500), 1, "the half-second rounds up");
  zassert_equal(pigeon_telemetry_batch_age_secs(0, 1499), 1);
  zassert_equal(pigeon_telemetry_batch_age_secs(0, 1500), 2);
  zassert_equal(pigeon_telemetry_batch_age_secs(1000, 11000), 10);
}

ZTEST(telemetry_batch, test_age_floors_at_zero) {
  /* k_uptime_get() is monotonic so this should be unreachable, but a negative
   * age would serialize as a huge unsigned one and land the reading at the
   * far end of the platform's backdate window. */
  zassert_equal(pigeon_telemetry_batch_age_secs(5000, 1000), 0);
  zassert_equal(pigeon_telemetry_batch_age_secs(1, 0), 0);
}

ZTEST(telemetry_batch, test_age_clamps_to_the_platform_backdate_window) {
  int64_t day_ms = 86400LL * 1000;

  zassert_equal(pigeon_telemetry_batch_age_secs(0, day_ms), PIGEON_TELEMETRY_BATCH_MAX_AGE_SECS);
  /* A device that held readings through a week-long outage still delivers
   * them; the platform clamps to the same boundary, so agreeing with it here
   * keeps the wire value plausible rather than merely large. */
  zassert_equal(
      pigeon_telemetry_batch_age_secs(0, 7 * day_ms), PIGEON_TELEMETRY_BATCH_MAX_AGE_SECS
  );
}

ZTEST(telemetry_batch, test_build_clamps_an_ancient_reading) {
  zassert_ok(pigeon_telemetry_batch_record(SMALL_FRAG, SMALL_LEN, 0));

  (void)pigeon_telemetry_batch_build(body, sizeof(body), 30LL * 86400 * 1000, NULL);

  zassert_not_null(strstr(body, "\"age_secs\":86400"), "got %s", body);
}

/* ---- retry policy ---- */

ZTEST(telemetry_batch, test_backoff_doubles_to_the_cap) {
  uint32_t base = PIGEON_TELEMETRY_BATCH_BACKOFF_BASE_SEC;
  uint32_t seen = 0;

  /* Doubling has to actually reach the cap and then stay there: a schedule
   * that overshoots would park a device for longer than its configured
   * maximum, and one that never settles would keep growing. */
  for (int i = 0; i < 16; i++) {
    uint32_t next = pigeon_telemetry_batch_backoff_next(base);

    zassert_true(next >= base, "backoff went backwards: %u -> %u", base, next);
    zassert_true(next <= BACKOFF_MAX_SEC, "backoff %u exceeded the cap", next);

    if (next == base) {
      seen = next;
      break;
    }

    zassert_equal(next, MIN(base * 2, (uint32_t)BACKOFF_MAX_SEC));
    base = next;
  }

  zassert_equal(seen, (uint32_t)BACKOFF_MAX_SEC, "backoff never settled at the cap");
}

ZTEST(telemetry_batch, test_backoff_never_returns_zero) {
  zassert_equal(pigeon_telemetry_batch_backoff_next(0), 1);
  zassert_equal(pigeon_telemetry_batch_backoff_jitter(0), 1);
  zassert_equal(pigeon_telemetry_batch_backoff_jitter(1), 1);
}

ZTEST(telemetry_batch, test_backoff_jitter_stays_within_a_quarter) {
  uint32_t base = 40;

  for (int i = 0; i < 200; i++) {
    uint32_t jittered = pigeon_telemetry_batch_backoff_jitter(base);

    /* +-25%, so a fleet sharing one outage spreads its retries instead of
     * rebuilding the spike it is backing off from. */
    zassert_true(jittered >= base - (base / 4), "jitter %u below the window", jittered);
    zassert_true(jittered <= base + (base / 4), "jitter %u above the window", jittered);
  }
}

ZTEST(telemetry_batch, test_only_a_refused_batch_is_fatal) {
  /* 400 and 413 are the platform's "these bytes break a cap" answers -- too
   * many readings, too many distinct keys across the union, an oversized key,
   * value or body. Resending them unchanged fails identically forever. */
  zassert_true(pigeon_telemetry_batch_status_is_fatal(400));
  zassert_true(pigeon_telemetry_batch_status_is_fatal(413));

  /* Everything else is about the moment, not the batch: a rotated token, a
   * tier limit an operator can lift, an allowance fuse that resets with the
   * billing period, a server having a bad minute. Dropping readings for any
   * of those would discard data the platform never rejected. */
  zassert_false(pigeon_telemetry_batch_status_is_fatal(0));
  zassert_false(pigeon_telemetry_batch_status_is_fatal(200));
  zassert_false(pigeon_telemetry_batch_status_is_fatal(202));
  zassert_false(pigeon_telemetry_batch_status_is_fatal(401));
  zassert_false(pigeon_telemetry_batch_status_is_fatal(403));
  zassert_false(pigeon_telemetry_batch_status_is_fatal(404));
  zassert_false(pigeon_telemetry_batch_status_is_fatal(429));
  zassert_false(pigeon_telemetry_batch_status_is_fatal(500));
  zassert_false(pigeon_telemetry_batch_status_is_fatal(502));
}

/* ---- sizing invariants ---- */

ZTEST(telemetry_batch, test_a_full_buffer_always_fits_the_body_buffer) {
  char frag[BIG_LEN + 1];

  make_frag(frag, 'q', BIG_LEN);

  for (int i = 0; i < DEPTH; i++) {
    zassert_ok(pigeon_telemetry_batch_record(frag, BIG_LEN, (int64_t)i * 1000));
  }

  int readings = 0;
  /* The framing allowance per reading is a constant, so this is really a
   * check that it covers a worst-case age (five digits) plus the separators
   * -- the one part of the body size that is not just the arena. */
  size_t len = pigeon_telemetry_batch_build(
      body, sizeof(body), 99999LL * 1000, &readings
  );

  zassert_true(len > 0, "a full buffer must always be framable");
  zassert_equal(readings, pigeon_telemetry_batch_count());
  zassert_true(len < sizeof(body));
}
