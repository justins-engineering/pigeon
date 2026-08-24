/*
 * Unit tests for the Retry-After grammar (src/pigeon_http_status.c), the
 * piece of the rate-limit response the FOTA download loop actually acts on.
 *
 * Worth testing in isolation because every input here arrives from the
 * network: the parser has to be as certain about what it REFUSES (an
 * HTTP-date whose leading digits would otherwise read as a plausible delay,
 * a signed value, a digit run long enough to wrap a counter) as about what
 * it accepts. A wrong answer either parks a device for an unbounded time or
 * sends it straight back into a rate limit.
 *
 * Build (from the pigeon-examples west workspace):
 *   west build -d build_http_status -b native_sim/native/64 \
 *     /home/justin/pigeon/tests/http_status
 *   ./build_http_status/zephyr/zephyr.exe
 */
#include <string.h>
#include <zephyr/ztest.h>

#include "pigeon_http_status.h"

#define CAP 60u

/* Every case below passes strlen() as the length, matching how the
 * connector hands over exactly the bytes it captured. */
static uint32_t parse(const char *v) {
  return pigeon_http_parse_retry_after(v, strlen(v), CAP);
}

ZTEST_SUITE(http_retry_after, NULL, NULL, NULL, NULL, NULL);

ZTEST(http_retry_after, test_plain_delta_seconds) {
  zassert_equal(parse("30"), 30);
  zassert_equal(parse("1"), 1);
  zassert_equal(parse("007"), 7, "leading zeros are still delta-seconds");
}

ZTEST(http_retry_after, test_surrounding_whitespace) {
  zassert_equal(parse(" 30"), 30);
  zassert_equal(parse("30 "), 30);
  zassert_equal(parse("\t 30 \t"), 30);
  zassert_equal(parse("30\r\n"), 30, "a captured value may still carry its line ending");
}

ZTEST(http_retry_after, test_http_date_form_is_refused) {
  /* The dangerous case: a date's leading digits must not be read as a
   * delay. Both orderings of the two common formats. */
  zassert_equal(parse("Fri, 31 Dec 1999 23:59:59 GMT"), 0);
  zassert_equal(parse("31 Dec 1999 23:59:59 GMT"), 0);
  zassert_equal(parse("1999-12-31T23:59:59Z"), 0);
}

ZTEST(http_retry_after, test_non_numeric_and_signed_refused) {
  zassert_equal(parse("-5"), 0, "a negative delay is not delta-seconds");
  zassert_equal(parse("+5"), 0);
  zassert_equal(parse("30s"), 0, "a trailing unit is not part of the grammar");
  zassert_equal(parse("abc"), 0);
  zassert_equal(parse("1 2"), 0, "an interior space is not whitespace to trim");
}

ZTEST(http_retry_after, test_empty_and_blank) {
  zassert_equal(parse(""), 0);
  zassert_equal(parse("   "), 0);
  zassert_equal(parse("\r\n"), 0);
}

ZTEST(http_retry_after, test_zero_reads_as_no_usable_value) {
  /* A literal 0 deliberately collapses to the same answer as an absent
   * header, so the caller falls back to its own backoff instead of coming
   * straight back at a server that just rate-limited it. */
  zassert_equal(parse("0"), 0);
  zassert_equal(parse("00"), 0);
}

ZTEST(http_retry_after, test_clamped_to_cap) {
  zassert_equal(parse("59"), 59, "just under the cap passes through");
  zassert_equal(parse("60"), CAP, "exactly the cap is the cap");
  zassert_equal(parse("61"), CAP);
  zassert_equal(parse("3600"), CAP);
}

ZTEST(http_retry_after, test_absurd_digit_run_cannot_overflow) {
  /* 40 nines: far past UINT32_MAX. Clamping mid-parse is what keeps this
   * from wrapping to a small delay. */
  const char *huge = "9999999999999999999999999999999999999999";

  zassert_equal(parse(huge), CAP);
  /* Same length, but all zeros until the end -- exercises the accumulator
   * staying small for a long time before it grows. */
  zassert_equal(parse("00000000000000000000000000000000000000061"), CAP);
}

ZTEST(http_retry_after, test_length_bounds_the_parse) {
  /* The connector passes a captured length, not a NUL-terminated string:
   * only those bytes may be read. */
  zassert_equal(pigeon_http_parse_retry_after("30xyz", 2, CAP), 30);
  zassert_equal(pigeon_http_parse_retry_after("30xyz", 5, CAP), 0);
  zassert_equal(pigeon_http_parse_retry_after("30", 0, CAP), 0);
}

ZTEST(http_retry_after, test_degenerate_arguments) {
  zassert_equal(pigeon_http_parse_retry_after(NULL, 4, CAP), 0);
  zassert_equal(pigeon_http_parse_retry_after("30", 2, 0), 0, "a zero cap disables the parse");
}
