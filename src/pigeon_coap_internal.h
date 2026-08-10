#ifndef PIDGEIOT_PIGEON_COAP_INTERNAL_H_
#define PIDGEIOT_PIGEON_COAP_INTERNAL_H_

#include <stddef.h>
#include <stdint.h>
#include <zephyr/net/coap.h>

#include "pigeon_internal.h"

/*
 * Shared internals of the CoAP connector, split (2026-08) between the
 * transport-agnostic core (pigeon_coap.c: endpoint parse, request option
 * building, shadow decode, the public pigeon_* entry points) and exactly one
 * compiled-in transport (pigeon_coap_tcp.c: RFC 8323 CoAP-over-TLS/TCP, or
 * pigeon_coap_udp.c: RFC 7252 CoAP-over-DTLS/UDP -- see zephyr/Kconfig's
 * PIGEON_COAP_TRANSPORT choice).
 */

#define PIGEON_COAP_HOST_MAX 128
#define PIGEON_COAP_PATH_MAX 128
#define PIGEON_COAP_PORT_MAX 6
#define PIGEON_COAP_QUERY_MAX 160
/* Request/response frame ceiling. The request side must fit a full batched
 * telemetry body (built and sized by pigeon_core.c -- see
 * PIGEON_TELEMETRY_BODY_MAX in pigeon_internal.h) plus CoAP framing: 384
 * bytes of headroom comfortably covers the option caps above (Uri-Path
 * segments up to PIGEON_COAP_PATH_MAX, the auth Uri-Query up to
 * PIGEON_COAP_QUERY_MAX, Content-Format, payload marker, and either
 * transport's message header). The 640 floor preserves the pre-batching
 * response headroom for shadow GETs even when
 * CONFIG_PIGEON_TELEMETRY_MAX_KEYS is configured tiny. Note the transports'
 * request buffers live on the caller's stack, so this scales that stack
 * cost with CONFIG_PIGEON_TELEMETRY_MAX_KEYS (~1.7KB at the default 8). */
#define PIGEON_COAP_MSG_MAX MAX(640, PIGEON_TELEMETRY_BODY_MAX + 384)
#define PIGEON_COAP_CONFIG_MAX 256

/* Parsed once (lazily) from CONFIG_PIGEON_ENDPOINT by
 * pigeon_coap_parse_endpoint() below. */
extern char pigeon_coap_host[PIGEON_COAP_HOST_MAX];
extern char pigeon_coap_port[PIGEON_COAP_PORT_MAX];
extern char pigeon_coap_path[PIGEON_COAP_PATH_MAX];

/*
 * Splits CONFIG_PIGEON_ENDPOINT ("<scheme>://host[:port]/path...") into the
 * globals above, once. Validates the scheme against the compiled-in
 * transport (coaps+tcp:// for TCP, coaps:// for UDP/DTLS) so a token/config
 * minted for one transport can't be silently pointed at the other -- the
 * mismatch fails loudly at first use instead of as a connect timeout.
 */
int pigeon_coap_parse_endpoint(void);

/*
 * Registers PSK credentials from pigeon_init()'s config under
 * CONFIG_PIGEON_COAP_SEC_TAG, if the app supplied any (no-op otherwise, or
 * when already registered). Called by each transport before connecting;
 * also called eagerly from pigeon_init() on CONFIG_MODEM_KEY_MGMT builds,
 * where the modem's credential store is only writable pre-LTE (see
 * pigeon_coap.c's pigeon_coap_psk_write_modem()).
 */
int pigeon_coap_register_psk(void);

/*
 * Appends this connector's standard request options to an
 * already-initialized packet: one Uri-Path option per
 * pigeon_coap_path segment plus the leaf ("shadow"/"telemetry"),
 * Content-Format (JSON, only when a payload will follow), and the device
 * bearer token as an "auth=<token>" Uri-Query (CoAP has no header mechanism
 * to mirror pigeon_https.c's "Authorization: Bearer"). Works on any
 * coap_packet regardless of how its header was framed (RFC 7252 or 8323).
 */
int pigeon_coap_append_request_options(struct coap_packet *cpkt, const char *leaf, bool has_payload);

/*
 * Implemented by the compiled-in transport. Performs one full request/
 * response exchange: builds the transport's own framing around the shared
 * options (pigeon_coap_append_request_options() above), sends it, and
 * blocks for the response. On success (return 0), rsp_code holds the CoAP
 * response code, and rsp_payload/rsp_payload_len the response payload
 * region (NULL/0 when the response carried none), pointing into
 * transport-owned static storage valid until the next exchange.
 */
int pigeon_coap_transport_exchange(
    uint8_t code, const char *leaf, const uint8_t *payload, size_t payload_len, uint8_t *rsp_code,
    const uint8_t **rsp_payload, size_t *rsp_payload_len
);

#endif /* PIDGEIOT_PIGEON_COAP_INTERNAL_H_ */
