#ifndef PIDGEIOT_PIGEON_H_
#define PIDGEIOT_PIGEON_H_

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
 * (RFC 8323 coaps+tcp://) instead of the usual CoAP-over-DTLS/UDP. These
 * fields are ahead of the backend: capsules::CoapConfig still names them
 * dtls_psk_identity/dtls_psk_secret (coaps:// over UDP) as of this writing —
 * update this comment once dovecote/capsules gain coaps+tcp:// support and
 * rename their fields to match. NULL when absent (Option<String>::None).
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
  const char *device_id; /* Durable Object / pigeon ID; also the JWT audience */
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
 * dovecote does not yet expose a device-authenticated endpoint to report
 * current_config/current_version back (see pigeon_shadow_get()'s docs) --
 * this sends a best-effort request against <CONFIG_PIGEON_ENDPOINT>/shadow
 * using the same device bearer token as pigeon_shadow_get(), so it will
 * presently fail against the real backend until that endpoint lands. The
 * client-side plumbing is in place so nothing else needs to change once it
 * does. On failure the pending value is kept queued for the next flush.
 *
 * @return 0 on success, -ENODATA if nothing is queued, negative error code
 * on transport failure (expected for now, see above).
 */
int pigeon_shadow_flush(void);

/**
 * @brief Fetch the current shadow document from the platform.
 *
 * Issues GET <CONFIG_PIGEON_ENDPOINT>/shadow (device-authenticated with
 * CONFIG_PIGEON_TOKEN). There is currently no device-facing endpoint to push
 * current_config/current_version back to the platform (dovecote only offers
 * that via the user-facing dashboard API), so this only reads the target the
 * platform has set; applying target_config is the caller's job (this library
 * does not parse it, see pigeon_shadow_doc).
 *
 * target_config/current_config point into a static buffer owned by this
 * function: valid only until the next call, and only for the connector type
 * actually compiled in (pigeon_https.c or pigeon_coap.c).
 *
 * @param out Filled with the fetched shadow on success.
 * @return 0 on success, negative error code on transport/parse failure.
 */
int pigeon_shadow_get(struct pigeon_shadow_doc *out);

#ifdef __cplusplus
}
#endif

#endif /* PIDGEIOT_PIGEON_H_ */
