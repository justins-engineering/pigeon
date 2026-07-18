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
 * one live endpoint/token pair to configure.
 */

/*
 * No on-device UDP support yet, so this connector speaks CoAP over TLS/TCP
 * (RFC 8323 coaps+tcp://) instead of the usual CoAP-over-DTLS/UDP. Matches
 * capsules::CoapConfig's tls_psk_identity/tls_psk_secret and dovecote's
 * coaps+tcp:// endpoints as of 2026-07-15 — though dovecote still has no
 * actual CoAP listener, so this transport has nothing to talk to yet.
 * NULL when absent (Option<String>::None).
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
 * @brief Queue data or metrics to push to the digital twin edge instance
 * @param key The state key identifier
 * @param val The value payload string
 */
int pigeon_set_shadow_param(const char *key, const char *val);

/**
 * @brief Flush the most recently queued pigeon_set_shadow_param() value to the platform.
 *
 * Issues POST <CONFIG_PIGEON_ENDPOINT>/telemetry, body {"key": "val"}
 * (device-authenticated with CONFIG_PIGEON_TOKEN) -- a flat single key/value
 * report, matching dovecote's report_telemetry_device (latest-value-per-key
 * store, not a time-series log). Not the same endpoint as
 * pigeon_shadow_report(), which acks shadow config, not arbitrary metrics.
 * On failure the pending value is kept queued for the next flush.
 *
 * @return 0 on success, -ENODATA if nothing is queued, negative error code
 * on transport/auth failure.
 */
int pigeon_shadow_flush(void);

/**
 * @brief Fetch the current shadow document from the platform.
 *
 * Issues GET <CONFIG_PIGEON_ENDPOINT>/shadow (device-authenticated with
 * CONFIG_PIGEON_TOKEN). Applying target_config is the caller's job (this
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
 * Issues POST <CONFIG_PIGEON_ENDPOINT>/shadow (device-authenticated with
 * CONFIG_PIGEON_TOKEN), body {"current_config": <current_config, raw JSON>,
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
 * Not safe to call concurrently with itself, and progress is not
 * persisted across a reboot -- a failed or interrupted call must be
 * retried from byte 0 on the next shadow poll.
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

#ifdef __cplusplus
}
#endif

#endif /* PIDGEIOT_PIGEON_H_ */
