#include <stdbool.h>

#include "pigeon_http_status.h"

/* Optional whitespace around a field value, per RFC 9110 sec 5.5. The CR/LF
 * pair is not part of the value the parser hands over, but is cheap to
 * tolerate and keeps a hand-built test vector from being a special case. */
static bool pigeon_http_is_ows(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

uint32_t pigeon_http_parse_retry_after(const char *value, size_t len, uint32_t cap_sec) {
  if (!value || cap_sec == 0) {
    return 0;
  }

  size_t start = 0;
  size_t end = len;

  while (start < end && pigeon_http_is_ows(value[start])) {
    start++;
  }
  while (end > start && pigeon_http_is_ows(value[end - 1])) {
    end--;
  }

  if (start == end) {
    return 0;
  }

  /* Validate the whole run before accumulating any of it. Doing this in one
   * pass looks tempting and is wrong: the clamp below returns as soon as the
   * value passes the cap, so a leading digit run would decide the answer
   * before the bytes that disqualify it were ever examined -- "1999-12-31"
   * would come back as a perfectly plausible delay instead of a refusal.
   * Nothing partially parsed is safe to act on. */
  for (size_t i = start; i < end; i++) {
    if (value[i] < '0' || value[i] > '9') {
      return 0;
    }
  }

  uint32_t secs = 0;

  for (size_t i = start; i < end; i++) {
    /* Clamp before the multiply, never after, so no input length can wrap
     * the accumulator on its way to being clamped. */
    if (secs > cap_sec / 10) {
      return cap_sec;
    }

    secs = secs * 10 + (uint32_t)(value[i] - '0');

    if (secs >= cap_sec) {
      return cap_sec;
    }
  }

  return secs;
}
