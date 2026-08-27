#ifndef PIDGEIOT_PIGEON_HTTP_STATUS_H_
#define PIDGEIOT_PIGEON_HTTP_STATUS_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Per-request HTTP outcome for callers that can act on more than "it
 * failed".
 *
 * Collapsing every non-2xx into a bare -EIO leaves a rate-limited
 * response indistinguishable from a corrupt body or a dead link, so the
 * only available reaction is to treat it as a failure and burn a download
 * attempt, at the exact moment the server has said in as many words how
 * long to wait instead.
 */
struct pigeon_http_result {
  /* Status code from the response line, or 0 when the request failed
   * before any status arrived (socket, TLS, or timeout). */
  uint16_t status;
  /* Server-requested delay in seconds, already clamped to the cap the
   * caller passed. 0 means no usable Retry-After came back -- absent,
   * malformed, or the HTTP-date form -- and specifically does NOT mean
   * "retry immediately"; the caller falls back to its own backoff. */
  uint32_t retry_after_sec;
};

/*
 * Parses an RFC 9110 sec 10.2.3 Retry-After field value from [value, value+len),
 * returning whole seconds clamped to cap_sec (a cap_sec of 0 disables the
 * parse entirely and returns 0).
 *
 * Only the delta-seconds form is understood. The alternative HTTP-date form
 * is deliberately rejected rather than parsed: converting it to a delay
 * needs a trusted wall clock to subtract from, and these devices have no
 * reliable one -- a device whose clock is a year off would compute a delay
 * a year long, or none at all. Returning 0 hands the decision back to the
 * caller's own backoff, which is bounded by construction.
 *
 * The value is validated in full before any of it is accumulated, so a
 * malformed field can never be answered from its leading digits alone, and
 * clamping happens mid-accumulate, so an absurd or hostile digit run can
 * never overflow on its way to being clamped.
 *
 * A literal "Retry-After: 0" collapses to the same 0 as an absent header,
 * and so lands on the caller's own backoff rather than an immediate retry.
 * That is the safe direction: the one thing a device must not do with a
 * rate-limit response is come straight back.
 *
 * Pure function -- no clock, no allocation, no I/O -- so the whole
 * grammar is exercised by tests/http_status on native_sim.
 */
uint32_t pigeon_http_parse_retry_after(const char *value, size_t len, uint32_t cap_sec);

#endif /* PIDGEIOT_PIGEON_HTTP_STATUS_H_ */
