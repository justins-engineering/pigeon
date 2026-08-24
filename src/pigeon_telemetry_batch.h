#ifndef PIDGEIOT_PIGEON_TELEMETRY_BATCH_H_
#define PIDGEIOT_PIGEON_TELEMETRY_BATCH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Accumulation buffer and flush policy behind CONFIG_PIGEON_TELEMETRY_BATCH:
 * the device half of dovecote's batched telemetry body
 * ({"reports":[{"age_secs":N,"metrics":{...}},...]}, see docs/api.md in the
 * pidgeiot repo).
 *
 * Why a batch exists at all: a delivery costs the platform one worker
 * request, one verify hop, one queue message, one Durable Object round trip
 * and one history write REGARDLESS of how many readings it carries, while
 * the billable message count follows the readings. Collapsing six readings
 * into one delivery is therefore ~3.4x cheaper to serve and bills the
 * account exactly what six separate reports would have -- it changes what
 * delivery costs the platform, not what the customer is charged.
 *
 * Why age_secs rather than a timestamp: this library has no wall clock (no
 * RTC, and NTP was removed in 0.13.6), so the only honest thing it can say
 * about a reading is how long ago it was taken. Ages are measured from
 * k_uptime_get() deltas, which are monotonic and immune to a clock that was
 * never set; the server resolves them against its own receive time.
 *
 * Everything here is deliberately transport-free and clock-free -- every
 * entry point takes `now_ms` from its caller rather than reading the uptime
 * itself -- so the whole accumulate/flush/overflow/age policy is exercised
 * as a unit on native_sim (tests/telemetry_batch) instead of only on a
 * device with a network behind it.
 *
 * Single-threaded by contract, exactly like the pending-key store it feeds
 * from: pigeon_telemetry_set()/_record()/_flush() are documented as
 * single-app-thread calls (see pigeon.h), and nothing here takes a lock.
 */

/* Envelope ({"reports":[ ]} plus NUL) and per-reading framing
 * ({"age_secs":86400,"metrics":} plus a separating comma = 30 bytes; 32 for
 * margin). Public so pigeon_core.c can size the one shared body buffer it
 * hands to pigeon_telemetry_batch_build(). */
#define PIGEON_TELEMETRY_BATCH_ENVELOPE_MAX 16
#define PIGEON_TELEMETRY_BATCH_ENTRY_MAX 32
#define PIGEON_TELEMETRY_BATCH_BODY_MAX                                                  \
  (CONFIG_PIGEON_TELEMETRY_BATCH_BUF_SIZE +                                              \
   (CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH * PIGEON_TELEMETRY_BATCH_ENTRY_MAX) +            \
   PIGEON_TELEMETRY_BATCH_ENVELOPE_MAX)

/* Server-side ceiling on a batched body (capsules::MAX_TELEMETRY_BATCH_BYTES,
 * 413 over it). Checked at build time rather than discovered in the field:
 * both knobs the body scales with are compile-time, so a configuration that
 * could ever emit an over-cap batch is a build error, not a runtime
 * surprise on a device that has already buffered the readings. */
#define PIGEON_TELEMETRY_BATCH_SERVER_BYTES_MAX 16384

/* Server-side ceiling on readings per batch (capsules::MAX_TELEMETRY_BATCH_READINGS,
 * 400 over it). CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH's own Kconfig range
 * enforces this; asserted here so the two cannot drift apart silently. */
#define PIGEON_TELEMETRY_BATCH_SERVER_READINGS_MAX 64

/* Longest age the platform will accept before clamping to the boundary
 * (capsules::MAX_TELEMETRY_BACKDATE_SECS). Clamped on this side too, so a
 * reading held through a very long outage is delivered as "as old as can be
 * expressed" rather than as an implausible number the server has to fix. */
#define PIGEON_TELEMETRY_BATCH_MAX_AGE_SECS 86400u

/*
 * Discards every buffered reading and resets the drop counter. Called on
 * a delivered batch, and by tests between cases.
 */
void pigeon_telemetry_batch_reset(void);

/*
 * Appends one reading: `metrics` is an already-escaped, already-framed flat
 * JSON object ({"k":"v",...}, built by pigeon_core.c's body builder), copied
 * into this module's own arena, stamped with `now_ms`.
 *
 * Never fails for lack of room. When the new reading does not fit -- either
 * arena bytes or the depth cap -- the OLDEST buffered readings are dropped
 * until it does, and each drop is counted (see
 * pigeon_telemetry_batch_take_dropped()). Dropping the oldest is the right
 * direction for telemetry specifically: the freshest readings are the ones
 * a dashboard, an alert rule, and a connection-state badge all read, so a
 * device riding out an outage should surface what is true now rather than
 * what was true when the outage began.
 *
 * Returns 0, or -EINVAL on a NULL/empty fragment, or -EMSGSIZE if the
 * fragment alone cannot fit an empty arena (unreachable at any Kconfig
 * setting the build asserts permit -- defensive against a sizing
 * regression, and reported rather than silently truncating a body that
 * would then be invalid JSON).
 */
int pigeon_telemetry_batch_record(const char *metrics, size_t metrics_len, int64_t now_ms);

/* Readings currently buffered. */
int pigeon_telemetry_batch_count(void);

/* Arena bytes currently held, for the sizing assertions in tests. */
size_t pigeon_telemetry_batch_used(void);

/*
 * Readings dropped since the last call, and resets the counter -- the same
 * read-and-clear shape pigeon_log_backend.c uses for its own ring-buffer
 * drops, so a caller reports a total for the window rather than one line
 * per lost reading.
 */
uint32_t pigeon_telemetry_batch_take_dropped(void);

/*
 * Whether the buffer should be delivered now. Three independent triggers,
 * any one of which is enough:
 *
 *  - depth: CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH readings are buffered, the
 *    "M readings per delivery" the COGS model is priced on;
 *  - age: the OLDEST buffered reading has reached
 *    CONFIG_PIGEON_TELEMETRY_BATCH_MAX_AGE_SEC, so a device that samples
 *    slowly still delivers instead of holding data indefinitely;
 *  - high water: the arena is at least three quarters full. This one exists
 *    so a buffer sized smaller than depth x a reading spends its capacity on
 *    a delivery rather than on drops -- without it, an arena that fills
 *    before the depth trigger would quietly drop its oldest reading on every
 *    record while waiting out the age trigger.
 */
bool pigeon_telemetry_batch_due(int64_t now_ms);

/*
 * Serializes every buffered reading into `out` as one batched body:
 * {"reports":[{"age_secs":N,"metrics":{...}},...]}. Readings are emitted in
 * the order they were recorded, which is chronological -- the contract
 * permits any order, but sending them sorted costs nothing and keeps a
 * captured body readable.
 *
 * Nothing is consumed: a failed delivery leaves the buffer exactly as it
 * was, which is what lets a refused batch be retried without the caller
 * having to stage a copy of it.
 *
 * Returns the body length excluding the NUL, or 0 if `out` is too small
 * (unreachable when sized as PIGEON_TELEMETRY_BATCH_BODY_MAX above).
 * *out_readings, when non-NULL, receives the number of readings emitted.
 */
size_t pigeon_telemetry_batch_build(
    char *out, size_t out_len, int64_t now_ms, int *out_readings
);

/*
 * age_secs for a reading taken at `taken_ms`, as the wire form wants it:
 * seconds before the batch is sent, rounded to nearest (unbiased against a
 * sampling cadence that jitters either side of a second), floored at 0 for
 * a reading that somehow stamps in the future, and clamped to the 24 h the
 * platform accepts.
 */
uint32_t pigeon_telemetry_batch_age_secs(int64_t taken_ms, int64_t now_ms);

/*
 * Next backoff base after a failed delivery: doubles from
 * PIGEON_TELEMETRY_BATCH_BACKOFF_BASE_SEC, capped at
 * CONFIG_PIGEON_TELEMETRY_BATCH_BACKOFF_MAX_SEC. Kept separate from the
 * jitter below so the schedule itself is exactly assertable in a test while
 * the value actually slept on stays randomized.
 */
#define PIGEON_TELEMETRY_BATCH_BACKOFF_BASE_SEC 5u

uint32_t pigeon_telemetry_batch_backoff_next(uint32_t base_sec);

/*
 * `base_sec` +-25%, never 0. A fleet that shares an outage -- or a free-tier
 * account whose allowance fuse blows for every one of its devices at
 * once -- otherwise retries in lockstep and rebuilds the spike it is
 * backing off from.
 */
uint32_t pigeon_telemetry_batch_backoff_jitter(uint32_t base_sec);

/*
 * Whether an HTTP status means THIS batch is the problem, rather than the
 * moment. True only for 400 and 413: the platform refuses a batch whole for
 * a cap violation (too many readings, too many distinct keys across the
 * union, an oversized key or value, a reading with no metrics) or an
 * oversized body, and every one of those is a property of the bytes being
 * sent -- resending them unchanged fails identically forever, so the caller
 * drops the batch loudly instead of retrying into a permanent wedge.
 *
 * Everything else retries: 401/403 (a rotated token, or a per-tier limit an
 * operator can lift), 429 (explicitly a pacing signal), 5xx and transport
 * errors. Retrying is bounded by the buffer itself, which sheds its oldest
 * readings rather than growing, so a device that is refused forever still
 * uses fixed memory.
 */
bool pigeon_telemetry_batch_status_is_fatal(uint16_t status);

#endif /* PIDGEIOT_PIGEON_TELEMETRY_BATCH_H_ */
