#ifndef PIDGEIOT_PIGEON_H_
#define PIDGEIOT_PIGEON_H_

#include <stdbool.h>
#include <zephyr/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Mirrors capsules::Connector in ~/pidgeiot/capsules/src/lib.rs. Order matters
 * only for readability here (the wire tag is the JSON variant name, not this
 * value), but keep it Https-then-Coap to match the Rust enum declaration.
 */
enum pigeon_connector_type {
  PIGEON_CONNECTOR_HTTPS,
  PIGEON_CONNECTOR_COAP
};

/*
 * Mirrors capsules::HttpsConfig/CoapConfig's endpoint+token fields, sourced
 * from CONFIG_PIGEON_ENDPOINT/CONFIG_PIGEON_TOKEN instead of runtime struct
 * fields: PIGEON_CONNECTOR_TYPE is already a build-time choice (only one of
 * pigeon_coap.c/pigeon_https.c is compiled in), so there is never more than
 * one live endpoint/token pair to configure. On CoAP builds the token may
 * be empty: the PSK handshake authenticates the device, and requests carry
 * no in-band token.
 */

/*
 * PSK credentials for the CoAP connector's secured transport -- either
 * CoAP-over-DTLS/UDP (RFC 7252, coaps://, CONFIG_PIGEON_COAP_TRANSPORT_UDP,
 * the primary choice for constrained battery/cellular devices) or
 * CoAP-over-TLS/TCP (RFC 8323, coaps+tcp://,
 * CONFIG_PIGEON_COAP_TRANSPORT_TCP). The handshake these complete is the
 * device's ENTIRE authentication on CoAP: the platform maps the PSK
 * identity (the pigeon's id) to the pigeon and holds the bearer token
 * server-side, so no credential ever rides inside a CoAP message. Field
 * names match capsules::CoapConfig's tls_psk_identity/tls_psk_secret --
 * identity is the pigeon id, secret the short key minted alongside the
 * bearer token (deliberately not the token itself: RFC 4279 only obliges
 * TLS stacks to accept PSKs up to 64 bytes). The same pair feeds whichever
 * transport is compiled in, registered natively via tls_credential_add()
 * or -- CONFIG_MODEM_KEY_MGMT builds -- written into the nRF91 modem's own
 * credential store, where the TLS/DTLS stack actually lives on those
 * boards. NULL when absent (Option<String>::None).
 */
struct pigeon_coap_config {
  const char *tls_psk_identity;
  const char *tls_psk_secret;
};

/* Mirrors capsules::Connector (tagged union: Https(HttpsConfig) | Coap(CoapConfig)). */
struct pigeon_connector {
  enum pigeon_connector_type type;
  struct pigeon_coap_config coap; /* only consulted when type == PIGEON_CONNECTOR_COAP */
};

struct pigeon_config {
  const char *device_id; /* Durable Object / pigeon ID */
  struct pigeon_connector connector;
};

/**
 * Mirrors capsules::PigeonShadow as returned by GET /pigeon/shadow/get.
 * target_config/current_config are raw JSON object text (capsules::JsonString
 * is a validated-but-unparsed string on the Rust side); this library does not
 * parse them, only stores/forwards the bytes.
 */
struct pigeon_shadow_doc {
  int32_t target_version;
  int32_t current_version;
  const char *target_config;
  const char *current_config;
  int64_t updated_at; /* unix seconds */
};

/**
 * Mirrors capsules::PigeonShadowUpdateRequest, the body POSTed to
 * /pigeon/shadow/update.
 */
struct pigeon_shadow_update_request {
  const char *target_config; /* raw JSON object */
};

/**
 * @brief Initialize the physical Pigeon client agent and restore shadow states
 * @param config Pointer to the instantiation parameters
 * @return 0 on success, negative error code on transport/auth initialization failure
 */
int pigeon_init(const struct pigeon_config *config);

/**
 * @brief Queue one telemetry key/value to report to the platform.
 *
 * Stages key=val in a CONFIG_PIGEON_TELEMETRY_MAX_KEYS-slot pending store,
 * to be sent -- together with every other pending key -- by the next
 * pigeon_telemetry_flush(). Latest-value-per-key: setting a key that is
 * already pending overwrites its value in place, mirroring the backend's
 * own latest-value-per-key telemetry store; distinct keys accumulate into
 * one batched report instead of costing one request each.
 *
 * Not thread-safe: call this (and pigeon_telemetry_flush()) from a single
 * application thread, the same implicit contract the old single-slot
 * pigeon_set_shadow_param() store always had.
 *
 * Under CONFIG_PIGEON_TELEMETRY_BATCH the pending store becomes the reading
 * being assembled rather than the report about to be sent: the keys set here
 * are closed into one timestamped reading by the next
 * pigeon_telemetry_record() or pigeon_telemetry_flush(). Setting a key twice
 * before that still overwrites, so one reading holds one value per key.
 *
 * @param key Telemetry key (at most 31 bytes).
 * @param val Value payload string (at most 127 bytes).
 * @return 0 on success; -EINVAL on NULL key/val; -ENODEV before
 * pigeon_init(); -ENOSPC if key/val exceed the per-slot limits; -ENOMEM if
 * every slot already holds a DIFFERENT pending key (flush, then retry --
 * nothing is evicted to make room, deliberately, so no queued value is
 * ever silently dropped).
 */
int pigeon_telemetry_set(const char *key, const char *val);

/**
 * @brief Send every pending telemetry key/value to the platform in one report.
 *
 * Builds ONE flat JSON object of all pending keys ({"k1":"v1","k2":"v2",...})
 * and sends it as a single POST <CONFIG_PIGEON_ENDPOINT>/telemetry
 * (device-authenticated: bearer CONFIG_PIGEON_TOKEN on HTTPS, the PSK
 * session itself on CoAP) -- or, when CONFIG_PIGEON_WS
 * is enabled and the socket is up, as a single WS telemetry frame carrying
 * the same object as its metrics map, falling back to the HTTPS/CoAP
 * transport when it isn't. Matches dovecote's report_telemetry_device
 * (latest-value-per-key upsert of every key in the body, not a time-series
 * log), and is what makes an N-key report cycle cost one radio round trip
 * instead of N. Not the same endpoint as pigeon_shadow_report(), which acks
 * shadow config, not arbitrary metrics.
 *
 * Clear-on-success, per report: keys carried by a successfully-sent report
 * are cleared immediately; on a send failure, that report's keys (and any
 * not yet attempted) all stay queued for the next flush. A pending value
 * is therefore never silently lost, and a key is never re-sent after the
 * report carrying it succeeded (unless set again). Caveat: over WS,
 * "success" means the frame was written to the socket (telemetry-over-WS
 * is fire-and-forget by design, see pigeon_ws_start()) -- unchanged from
 * the single-key behavior.
 *
 * Normally the whole batch goes in exactly one report: the internal body
 * buffer is sized so a full store of max-length values needing no JSON
 * escaping always fits (see PIGEON_TELEMETRY_BODY_MAX in pigeon_internal.h).
 * Pathologically escape-heavy values (raw control bytes escaping to \u00XX,
 * up to 6x growth) may split one flush into consecutive reports, each with
 * the same clear-on-success semantics -- never a truncated or invalid body.
 *
 * Under CONFIG_PIGEON_TELEMETRY_BATCH this call means something slightly
 * different, and an application written against it needs no change to get
 * the new behavior: the pending keys are closed into one timestamped
 * READING (see pigeon_telemetry_record()), and the accumulated readings are
 * delivered as ONE batched report only when a batch is due -- at
 * CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH readings, or once the oldest reaches
 * CONFIG_PIGEON_TELEMETRY_BATCH_MAX_AGE_SEC. A call that buffers without
 * delivering returns 0: the reading was accepted and nothing was lost, which
 * is what an existing "if (err) LOG_ERR" caller should keep quiet about. Use
 * pigeon_telemetry_batch_pending() to see how much is waiting, and
 * pigeon_telemetry_flush_now() to deliver regardless.
 *
 * @return 0 on success (all pending keys sent and cleared; under
 * CONFIG_PIGEON_TELEMETRY_BATCH, also when the reading was buffered and no
 * batch is due yet), -ENODATA if nothing is queued, -ENODEV before
 * pigeon_init(), negative error code on transport/auth failure (unsent keys
 * kept queued).
 */
int pigeon_telemetry_flush(void);

#if defined(CONFIG_PIGEON_TELEMETRY_BATCH)

/**
 * @brief Close the pending telemetry keys into one timestamped reading.
 *
 * Takes a snapshot of every key set since the last reading, stamps it with
 * the current uptime, and buffers it for a later batched delivery -- then
 * empties the pending store so the next pigeon_telemetry_set() begins a
 * fresh reading. Sends nothing.
 *
 * Call this only when sampling faster than delivering: an application whose
 * every sample is followed by pigeon_telemetry_flush() never needs it, since
 * flush closes the pending keys itself. It exists for the app that wants,
 * say, a reading every 10 s but a delivery every minute, on one thread with
 * one timer.
 *
 * The reading's age travels as seconds-before-delivery, computed from
 * k_uptime_get() deltas. That is the whole reason the platform's batched
 * wire form is relative rather than absolute: this library has no wall
 * clock, and a monotonic delta is the one time measurement it can make
 * honestly.
 *
 * Buffering is bounded by CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH readings and
 * CONFIG_PIGEON_TELEMETRY_BATCH_BUF_SIZE bytes. Past either, the OLDEST
 * buffered readings are dropped to make room and counted -- the next flush
 * warns with the total. That only happens while deliveries are failing; in
 * the steady state a full buffer is a delivery, not a drop.
 *
 * Compiles to a no-op returning 0 unless CONFIG_PIGEON_TELEMETRY_BATCH is
 * enabled, so an application can call it unconditionally and let Kconfig
 * decide whether readings are timestamped separately or collapse into the
 * next flat report.
 *
 * @return 0 on success, -ENODATA if no keys are pending, -ENODEV before
 * pigeon_init(), or a negative error if the reading could not be buffered
 * (its keys stay pending for the next attempt).
 */
int pigeon_telemetry_record(void);

/**
 * @brief Deliver the buffered readings now, whether or not a batch is due.
 *
 * Same delivery as pigeon_telemetry_flush(), with the depth/age triggers and
 * the post-failure backoff bypassed. Intended for the moments an application
 * knows are its last: before a deliberate reboot, before
 * pigeon_fota_apply()'s swap, or when shutting down connectivity -- anywhere
 * buffered readings would otherwise be discarded with the RAM holding them.
 *
 * Bypassing the backoff makes this an explicit, one-shot request rather than
 * a loop to sit in; calling it repeatedly against a refusing server is the
 * behavior the backoff exists to prevent.
 *
 * Without CONFIG_PIGEON_TELEMETRY_BATCH this is exactly
 * pigeon_telemetry_flush(), which already delivers on every call.
 *
 * @return as pigeon_telemetry_flush(), except that a buffered-but-not-due
 * batch cannot be the reason for a 0.
 */
int pigeon_telemetry_flush_now(void);

/**
 * @brief How many readings are buffered awaiting delivery.
 *
 * The observability half of pigeon_telemetry_flush() returning 0 for a
 * reading it only buffered: an application that wants to know whether its
 * data has actually left the device can watch this instead of inferring it
 * from a return code that deliberately does not distinguish. Returns 0
 * without CONFIG_PIGEON_TELEMETRY_BATCH, where nothing is ever buffered
 * between flushes.
 */
int pigeon_telemetry_batch_pending(void);

#else /* !CONFIG_PIGEON_TELEMETRY_BATCH */

/* No batching compiled in: a reading is whatever the next flush sends, there
 * is never a buffered batch to force out or to count. Inline rather than
 * absent so an application calls all three unconditionally and Kconfig alone
 * decides whether readings are timestamped separately. */
static inline int pigeon_telemetry_record(void) { return 0; }

static inline int pigeon_telemetry_flush_now(void) { return pigeon_telemetry_flush(); }

static inline int pigeon_telemetry_batch_pending(void) { return 0; }

#endif /* CONFIG_PIGEON_TELEMETRY_BATCH */

/**
 * @brief Queue data or metrics to push to the digital twin edge instance.
 *
 * Backward-compatible alias for pigeon_telemetry_set() -- the historical
 * name, from when the pending store was a single slot and telemetry rode
 * the shadow vocabulary. Prefer pigeon_telemetry_set() in new code.
 */
int pigeon_set_shadow_param(const char *key, const char *val);

/**
 * @brief Flush queued telemetry to the platform.
 *
 * Backward-compatible alias for pigeon_telemetry_flush() -- see it for the
 * batching and clear-on-success semantics. Note the behavior change from
 * the single-slot era: with several distinct keys pending, this now sends
 * ONE combined report rather than one request per key, and setting a
 * second, different key before flushing no longer overwrites the first.
 * Prefer pigeon_telemetry_flush() in new code.
 */
int pigeon_shadow_flush(void);

/**
 * @brief Fetch the current shadow document from the platform.
 *
 * Issues GET <CONFIG_PIGEON_ENDPOINT>/shadow (device-authenticated: bearer
 * CONFIG_PIGEON_TOKEN on HTTPS, the PSK session itself on CoAP). Applying
 * target_config is the caller's job (this
 * library does not parse it, see pigeon_shadow_doc); call pigeon_shadow_report()
 * afterwards to confirm what was applied.
 *
 * target_config/current_config point into a static buffer owned by this
 * function: valid only until the next call, and only for the connector type
 * actually compiled in (pigeon_https.c or pigeon_coap.c).
 *
 * @param out Filled with the fetched shadow on success.
 * @return 0 on success, negative error code on transport/parse failure.
 */
int pigeon_shadow_get(struct pigeon_shadow_doc *out);

/**
 * @brief Report back the shadow config the device has actually applied.
 *
 * Issues POST <CONFIG_PIGEON_ENDPOINT>/shadow (device-authenticated: bearer
 * CONFIG_PIGEON_TOKEN on HTTPS, the PSK session itself on CoAP), body
 * {"current_config": <current_config, raw JSON>,
 * "current_version": current_version} -- mirrors capsules::
 * PigeonShadowReportRequest / dovecote's report_shadow_device. Call this
 * after applying a target_config fetched via pigeon_shadow_get(), passing
 * the target_version you just applied as current_version (see
 * pigeon_shadow_doc's docs on why the platform doesn't just re-derive this
 * from target_version itself). current_config is a caller-owned raw JSON
 * object string, not parsed or validated by this library.
 *
 * @param current_version The target_version that was just applied.
 * @param current_config Raw JSON object string describing the applied config.
 * @return 0 on success, negative error code on transport/auth failure.
 */
int pigeon_shadow_report(int32_t current_version, const char *current_config);

#define PIGEON_FOTA_VERSION_MAX 32
#define PIGEON_FOTA_SHA256_HEX_LEN 64

/**
 * Mirrors the "firmware" sub-object of the shadow's target_config (see
 * capsules/dovecote's shadow-driven FOTA route, ~/pidgeiot/capsules):
 * {"firmware": {"version": "...", "size": N, "sha256": "<64 lowercase hex
 * chars>"}}. Like the rest of target_config, this key is opaque to
 * pigeon_shadow_get() -- the app decodes it itself (same as
 * log/telemetry_interval/reboot), using this struct as the JSON decode
 * target, then hands the result to pigeon_fota_update_available()/
 * pigeon_fota_apply() below. size uses JSON_TOK_NUMBER's int32_t width
 * (see Zephyr's zephyr/data/json.h), not size_t -- comfortably wide enough
 * for the ~300KB-2MB images this is meant for.
 */
struct pigeon_fota_info {
  char version[PIGEON_FOTA_VERSION_MAX];
  int32_t size;
  char sha256[PIGEON_FOTA_SHA256_HEX_LEN + 1];
};

/**
 * @brief Whether info describes a firmware version other than this build's.
 *
 * Compares info->version against CONFIG_PIGEON_FOTA_CURRENT_VERSION (a
 * build-time string, not read from MCUboot's own image header -- see
 * zephyr/Kconfig). Keeping that string in sync with whatever version the
 * platform is told about at upload/release time is the caller's
 * responsibility.
 *
 * Only declared when CONFIG_PIGEON_FOTA is enabled.
 */
bool pigeon_fota_update_available(const struct pigeon_fota_info *info);

/**
 * @brief Download, flash, and verify the firmware image info describes.
 *
 * Issues chunked device-authed HTTP Range GETs (CONFIG_PIGEON_FOTA_CHUNK_SIZE
 * bytes at a time) against <CONFIG_PIGEON_ENDPOINT>/firmware, writing each
 * chunk straight into MCUboot's secondary slot via Zephyr's dfu_target/
 * flash_img as it arrives -- the image is never held whole in RAM.
 * Verifies the downloaded byte count against info->size and a streamed
 * sha256 against info->sha256 before finalizing; on any failure
 * (transport, size mismatch, hash mismatch, flash write) the secondary
 * slot is left un-schedulable and the running image is untouched --
 * MCUboot never sees a partial/corrupt image as a boot candidate.
 *
 * On success, schedules a one-time test-swap (equivalent to
 * boot_request_upgrade(BOOT_UPGRADE_TEST)) and returns 0 -- it does NOT
 * reboot. The caller must gracefully tear down its own connectivity (e.g.
 * lte_disconnect()) and call sys_reboot() itself, exactly like the
 * existing shadow "reboot": true convention, and should report its shadow
 * current_config back to the platform first (via pigeon_shadow_report())
 * so the shadow converges before the device goes offline for the swap.
 *
 * Not safe to call concurrently with itself. Individual chunks are
 * retried in place rather than ending the transfer, and an HTTP 429 is
 * waited out on the server's own Retry-After rather than counted as a
 * failure (see CONFIG_PIGEON_FOTA_CHUNK_RETRIES and
 * CONFIG_PIGEON_FOTA_RATE_LIMIT_RETRIES).
 *
 * With CONFIG_PIGEON_FOTA_RESUME -- on by default wherever a settings
 * backend exists -- the bytes already flushed to the secondary slot
 * survive failures AND reboots: the next call re-hashes them from flash
 * and Range-requests only the remainder, restarting from 0 only when the
 * target version changed, the completion verify failed, or the persisted
 * state can't be trusted (see that option's help). Without it, a failed
 * or interrupted call restarts from byte 0 on the next shadow poll.
 *
 * @return 0 on success, negative errno on failure.
 */
int pigeon_fota_apply(const struct pigeon_fota_info *info);

/**
 * @brief Permanently confirm the currently running image, once healthy.
 *
 * Call once per boot after establishing the device is actually working
 * (e.g. after a successful pigeon_shadow_get()) -- MCUboot will otherwise
 * revert a test-swapped image back to the previous one on the next reset.
 * Safe to call every boot, including on images that were never
 * test-swapped in the first place (a no-op per boot_is_img_confirmed()).
 *
 * @return 0 on success (including "already confirmed"), negative errno on
 * failure to write the confirmation.
 */
int pigeon_fota_confirm_boot(void);

#if defined(CONFIG_PIGEON_FOTA_ATTEMPT_BUDGET)

/**
 * @brief Whether another attempt at this firmware target is still allowed.
 *
 * Call before pigeon_fota_apply() to bound how many times a device will
 * chase one firmware target. Without a bound, an image that downloads,
 * verifies, test-swaps, and then boot-loops until MCUboot reverts it will
 * re-download itself on every shadow poll for as long as the target stands.
 *
 * @param shadow_target_version The shadow's own target_version (see
 * struct pigeon_shadow_doc), NOT the firmware version string. It is what
 * makes the budget recoverable: the count is bound to the specific shadow
 * write that asked for this firmware, so an operator who sees a device
 * stuck and pushes its shadow again -- with the same firmware target still
 * in it -- gets a fresh budget without having to invent a new version
 * string for bytes that have not changed. A device cannot manufacture that
 * signal for itself; target_version is assigned by the platform, and
 * rebooting, reconnecting, or re-polling all leave it exactly as it was.
 *
 * A different firmware version resets the budget too, as does having no
 * record at all. Call pigeon_fota_attempts_clear() once the target is
 * confirmed to be the version actually running, so a later re-offer of that
 * same version starts clean.
 *
 * What counts as one attempt is decided inside pigeon_fota_apply(): a
 * download that starts from byte 0 spends one up front, while a
 * CONFIG_PIGEON_FOTA_RESUME continuation spends nothing as long as it moves
 * the flushed offset forward. A continuation that ends exactly where it
 * began is not making progress and does spend one, which is what keeps a
 * transfer stuck at a fixed offset from retrying without limit.
 *
 * Compiles to a no-op returning true unless
 * CONFIG_PIGEON_FOTA_ATTEMPT_BUDGET is enabled, so an application can call
 * it unconditionally and let Kconfig decide whether a budget exists.
 *
 * @return true if pigeon_fota_apply() may be called for this target.
 */
bool pigeon_fota_attempt_allowed(
    const struct pigeon_fota_info *info, int32_t shadow_target_version
);

/**
 * @brief Forget the attempt budget for whatever target it was tracking.
 *
 * Call when the device observes that it IS running the offered version
 * (pigeon_fota_update_available() answering false), so that the same
 * version being offered again later -- after a rollback, a reflash, or a
 * catalog change under the same string -- starts from a full budget rather
 * than an exhausted one.
 *
 * Compiles to a no-op unless CONFIG_PIGEON_FOTA_ATTEMPT_BUDGET is enabled.
 */
void pigeon_fota_attempts_clear(void);

#else /* !CONFIG_PIGEON_FOTA_ATTEMPT_BUDGET */

/* No budget compiled in: every attempt is allowed and there is nothing to
 * clear. Inline rather than absent so an application calls both
 * unconditionally and Kconfig alone decides whether a budget exists. */
static inline bool pigeon_fota_attempt_allowed(
    const struct pigeon_fota_info *info, int32_t shadow_target_version
) {
  (void)info;
  (void)shadow_target_version;
  return true;
}

static inline void pigeon_fota_attempts_clear(void) {
}

#endif /* CONFIG_PIGEON_FOTA_ATTEMPT_BUDGET */

#if defined(CONFIG_PIGEON_WS) || defined(CONFIG_PIGEON_CONNECTOR_MQTT)

/**
 * Events delivered to the callback passed to pigeon_ws_start() or
 * pigeon_mqtt_start(). Invoked from that channel's worker thread -- do not
 * block in the callback, signal your own thread instead (see
 * pigeon_event_cb_t below).
 *
 * One enum for both channels because an app that watches a pushed shadow
 * cares about the same three things either way; only which Kconfig option
 * supplies the push differs.
 */
enum pigeon_event {
  /** The channel just came up (initial connect or a reconnect). Over WS
   * the server sends no state snapshot on accept, so the app should
   * re-sync via pigeon_shadow_get() now to pick up anything pushed while
   * disconnected; over MQTT the retained target arrives on its own and
   * pigeon_shadow_get() will already be serving it. */
  PIGEON_EVENT_CONNECTED,
  /** The channel dropped. Reconnect with backoff is automatic; this is
   * purely informational. */
  PIGEON_EVENT_DISCONNECTED,
  /** The platform pushed a new shadow (a dashboard PUT landed): a
   * shadow_update frame over WS, a retained pigeon/shadow/target publish
   * over MQTT. */
  PIGEON_EVENT_SHADOW_UPDATE,
};

/*
 * Invoked from the channel's worker thread. For
 * PIGEON_EVENT_SHADOW_UPDATE, shadow points at module-static storage valid
 * only for the duration of the callback (same aliasing contract as
 * pigeon_shadow_get(), but a tighter lifetime -- copy out anything you
 * need before returning); NULL for the other two events. Do not block in
 * this callback.
 */
typedef void (*pigeon_event_cb_t)(
    enum pigeon_event ev, const struct pigeon_shadow_doc *shadow
);

#endif /* CONFIG_PIGEON_WS || CONFIG_PIGEON_CONNECTOR_MQTT */

#if defined(CONFIG_PIGEON_WS)

/*
 * The WS-specific names these events shipped under before the MQTT
 * connector needed the same shape. Kept so existing consumers compile
 * unchanged rather than duplicating an identical enum per channel; new
 * code should use the pigeon_event names above.
 */
#define pigeon_ws_event              pigeon_event
#define PIGEON_WS_EVENT_CONNECTED    PIGEON_EVENT_CONNECTED
#define PIGEON_WS_EVENT_DISCONNECTED PIGEON_EVENT_DISCONNECTED
#define PIGEON_WS_EVENT_SHADOW_UPDATE PIGEON_EVENT_SHADOW_UPDATE

typedef pigeon_event_cb_t pigeon_ws_event_cb_t;

/**
 * @brief Start the persistent WebSocket push channel.
 *
 * Spawns a dedicated worker thread that connects to
 * <CONFIG_PIGEON_ENDPOINT>/ws (device-authenticated the same way as the
 * HTTPS connector) and reconnects forever with backoff on any drop. Safe
 * to call once per boot, after pigeon_init(). Frame protocol, keepalive,
 * and reconnect policy are internal -- see pigeon_ws.c.
 *
 * @param cb Event callback, invoked from the worker thread. May be NULL if
 *           the app doesn't care about events (telemetry-over-WS via
 *           pigeon_shadow_flush() still works either way).
 * @return 0 on success, negative errno if the worker thread could not be
 *         started.
 */
int pigeon_ws_start(pigeon_ws_event_cb_t cb);

/**
 * @brief Gracefully stop the WebSocket push channel.
 *
 * Sends a proper CLOSE frame (rather than just dropping the connection)
 * and joins the worker thread. Call before sys_reboot() (e.g. the shadow
 * "reboot": true path) so the server sees a clean close.
 *
 * @return 0 on success, negative errno on failure to tear down cleanly
 *         (the thread is still joined either way).
 */
int pigeon_ws_stop(void);

/**
 * @brief Whether the WS socket is currently up.
 * @return true if connected, false if disconnected/reconnecting/not started.
 */
bool pigeon_ws_connected(void);

#endif /* CONFIG_PIGEON_WS */

#ifdef __cplusplus
}
#endif

#endif /* PIDGEIOT_PIGEON_H_ */
