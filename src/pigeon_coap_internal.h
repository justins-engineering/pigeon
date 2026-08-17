#ifndef PIDGEIOT_PIGEON_COAP_INTERNAL_H_
#define PIDGEIOT_PIGEON_COAP_INTERNAL_H_

#include <stddef.h>
#include <stdint.h>
#include <zephyr/net/coap.h>

#include "pigeon_internal.h"

/*
 * Shared internals of the CoAP connector: a transport-agnostic core
 * (pigeon_coap.c -- endpoint parse, request option building, shadow decode,
 * the public pigeon_* entry points) plus exactly one compiled-in transport
 * (pigeon_coap_tcp.c: RFC 8323 CoAP-over-TLS/TCP, or pigeon_coap_udp.c:
 * RFC 7252 CoAP-over-DTLS/UDP -- the PIGEON_COAP_TRANSPORT choice in
 * zephyr/Kconfig).
 */

#define PIGEON_COAP_HOST_MAX 128
#define PIGEON_COAP_PATH_MAX 128
#define PIGEON_COAP_PORT_MAX 6
/* RFC 4279 sec 5.3 only obliges TLS stacks to support PSKs up to 64 bytes;
 * the platform mints 32-hex-char secrets, well inside that. */
#define PIGEON_COAP_PSK_MAX 64
/* Request/response frame ceiling. The request side must fit a full batched
 * telemetry body (built and sized by pigeon_core.c -- see
 * PIGEON_TELEMETRY_BODY_MAX in pigeon_internal.h) plus CoAP framing: 384
 * bytes of headroom comfortably covers the option caps above (Uri-Path
 * segments up to PIGEON_COAP_PATH_MAX, Content-Format, payload marker, and
 * either transport's message header). The 640 floor preserves response
 * headroom for shadow GETs even when CONFIG_PIGEON_TELEMETRY_MAX_KEYS is
 * configured tiny. Note the transports' request buffers live on the
 * caller's stack, so this scales that stack cost with
 * CONFIG_PIGEON_TELEMETRY_MAX_KEYS (~1.7KB at the default 8). */
#define PIGEON_COAP_MSG_MAX MAX(640, PIGEON_TELEMETRY_BODY_MAX + 384)
#define PIGEON_COAP_CONFIG_MAX 256

#if defined(CONFIG_PIGEON_LOG_UPLOAD)
/* Block1 payload size for the log upload (RFC 7959 szx 5). Block-wise
 * transfer exists to keep a message inside the path MTU, so the bound that
 * matters is the link's, not this module's buffer: 512 payload bytes plus
 * CoAP options, DTLS record overhead and IP/UDP headers still clears the
 * 1280-byte IPv6 minimum MTU, so no datagram here can provoke IP
 * fragmentation on a conforming path. The next size up (1024) would not.
 *
 * The terminator imposes no block size of its own -- it concatenates
 * whatever arrives in sequence -- so this is the client's choice alone. */
#define PIGEON_COAP_LOG_BLOCK_SIZE COAP_BLOCK_512

/* Ceiling on how long one log batch may occupy the system workqueue.
 *
 * Checked before each block rather than enforced inside an exchange, so the
 * real bound is this plus one exchange's own retransmission budget. That is
 * the point: it stops a multi-block upload on a lossy-but-alive link from
 * serializing several full retransmission budgets back to back while every
 * other system work item waits. A healthy upload finishes in a few round
 * trips and never approaches it, and a batch abandoned here is dropped like
 * any other failure -- see pigeon_log_backend.c for why that is the
 * deliberate contract rather than a gap. */
#define PIGEON_COAP_LOG_UPLOAD_BUDGET_MS 30000

/* How long the log-upload path waits for the shared transport lock before
 * giving up on a batch, mirroring pigeon_https.c's identically-reasoned
 * bound: it runs on the system workqueue, so it must not sit behind a
 * foreground exchange's full timeout. Comfortably longer than a healthy
 * exchange, so contention normally delays a flush rather than dropping
 * one. */
#define PIGEON_COAP_LOG_LOCK_TIMEOUT_MS 3000
#endif /* CONFIG_PIGEON_LOG_UPLOAD */

/*
 * Per-request extras for pigeon_coap_append_request_options() and
 * pigeon_coap_transport_exchange() below. NULL means the shape every
 * request but the log upload uses: a JSON body, no block-wise transfer.
 */
struct pigeon_coap_req_opts {
  /* COAP_CONTENT_FORMAT_APP_*, appended only when a payload follows. */
  uint16_t content_format;
  /* State for one block of a multi-block request body, or NULL for a
   * request that fits a single message. The option append reads it and
   * never advances it -- stepping ctx->current between blocks belongs to
   * the caller driving the sequence. */
  struct coap_block_context *block1;
};

/* Parsed once (lazily) from CONFIG_PIGEON_ENDPOINT by
 * pigeon_coap_parse_endpoint() below. */
extern char pigeon_coap_host[PIGEON_COAP_HOST_MAX];
extern char pigeon_coap_port[PIGEON_COAP_PORT_MAX];
extern char pigeon_coap_path[PIGEON_COAP_PATH_MAX];

/*
 * Splits CONFIG_PIGEON_ENDPOINT ("<scheme>://host[:port]/path...") into the
 * globals above, once. Validates the scheme against the compiled-in
 * transport (coaps+tcp:// for TCP, coaps:// for UDP/DTLS) so a config
 * minted for one transport can't be silently pointed at the other -- the
 * mismatch fails loudly at first use instead of as a connect timeout.
 */
int pigeon_coap_parse_endpoint(void);

/*
 * Registers PSK credentials from pigeon_init()'s config under
 * CONFIG_PIGEON_COAP_SEC_TAG, if the app supplied any (no-op otherwise, or
 * when already registered). Called by each transport before connecting; on
 * CONFIG_MODEM_KEY_MGMT builds also called eagerly from pigeon_init(),
 * because the modem's credential store only accepts writes while the modem
 * is offline.
 */
int pigeon_coap_register_psk(void);

/*
 * Appends this connector's standard request options to an
 * already-initialized packet: one Uri-Path option per pigeon_coap_path
 * segment plus the leaf ("shadow"/"telemetry"/"logs"), then whatever opts
 * asks for -- Content-Format (only when a payload will follow) and Block1.
 * Appended in ascending option number, as coap_packet_append_* requires. No
 * credential rides in the message: the PSK handshake authenticates the
 * device, and the platform maps the handshake identity (the pigeon's id) to
 * the pigeon, rejecting any request whose Uri-Path names a different one.
 * Works on any coap_packet regardless of how its header was framed (RFC
 * 7252 or 8323).
 */
int pigeon_coap_append_request_options(
    struct coap_packet *cpkt, const char *leaf, bool has_payload,
    const struct pigeon_coap_req_opts *opts
);

/*
 * Implemented by the compiled-in transport. Performs one full request/
 * response exchange: builds the transport's own framing around the shared
 * options (pigeon_coap_append_request_options() above), sends it, and
 * blocks for the response. On success (return 0), rsp_code holds the CoAP
 * response code, and rsp_payload/rsp_payload_len the response payload
 * region (NULL/0 when the response carried none), pointing into
 * transport-owned static storage valid until the next exchange.
 *
 * Callers hold the shared transport lock across this -- pigeon_coap.c's
 * public entry points do it for them. Both transports keep their session
 * and their response buffer in module-globals, so two concurrent exchanges
 * would not merely interleave, they would consume each other's responses.
 */
int pigeon_coap_transport_exchange(
    uint8_t code, const char *leaf, const uint8_t *payload, size_t payload_len,
    const struct pigeon_coap_req_opts *opts, uint8_t *rsp_code, const uint8_t **rsp_payload,
    size_t *rsp_payload_len
);

#endif /* PIDGEIOT_PIGEON_COAP_INTERNAL_H_ */
