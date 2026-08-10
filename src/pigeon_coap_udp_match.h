#ifndef PIDGEIOT_PIGEON_COAP_UDP_MATCH_H_
#define PIDGEIOT_PIGEON_COAP_UDP_MATCH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * The RFC 7252 message-layer decision logic of the UDP/DTLS transport
 * (pigeon_coap_udp.c), factored into a pure, socket-free translation unit
 * so tests/coap_udp can exercise the CON/ACK matching, separate-response,
 * and duplicate-detection rules directly on native_sim -- the same pattern
 * pigeon_fota_resume.c uses for its reconcile logic. Retransmission
 * *timing* (ACK_TIMEOUT/ACK_RANDOM_FACTOR/backoff/MAX_RETRANSMIT) is
 * deliberately NOT re-implemented here: that lives in Zephyr's own
 * coap_pending helpers (subsys/net/lib/coap), which this transport reuses.
 */

/* One in-flight confirmable exchange, from the client's point of view. */
struct pigeon_coap_udp_exchange {
  uint16_t req_id;    /* message ID of the CON request */
  uint8_t token[8];   /* request token (response correlation, RFC 7252 5.3.1) */
  uint8_t tkl;        /* request token length */
  bool separated;     /* an Empty ACK arrived; response will come separately */
  /* Duplicate detection (RFC 7252 4.5) for separate CON responses: the
   * message ID of the last CON response this exchange already processed.
   * A strictly-serial client has at most one separate response in flight,
   * so one remembered ID (plus token mismatch rejection for anything
   * stale) is the full required dedup state -- a retransmitted duplicate
   * must be re-ACKed (the server keeps retransmitting otherwise) but not
   * re-processed. */
  uint16_t last_rsp_id;
  bool have_last_rsp_id;
};

/* What pigeon_coap_udp.c should do with one received datagram. */
enum pigeon_coap_udp_action {
  /* Not ours (unknown token/ID, or noise): drop silently. */
  PIGEON_COAP_UDP_ACTION_IGNORE,
  /* A stale/duplicate CON (e.g. a late separate response from a previous
   * exchange, or one we already processed): send an Empty ACK so the
   * server stops retransmitting, but do not process the content. */
  PIGEON_COAP_UDP_ACTION_ACK_ONLY,
  /* Empty ACK for our CON request: stop retransmitting, keep waiting for
   * the separate response (RFC 7252 5.2.2). */
  PIGEON_COAP_UDP_ACTION_SEPARATED,
  /* The response to this exchange (piggybacked ACK or NON): deliver. */
  PIGEON_COAP_UDP_ACTION_RESPONSE,
  /* The response, delivered as its own CON (separate response): ACK it,
   * then deliver. */
  PIGEON_COAP_UDP_ACTION_RESPONSE_ACK,
  /* RST matching our request: the peer rejected it; fail the exchange. */
  PIGEON_COAP_UDP_ACTION_RESET,
};

/*
 * Initializes ex for a freshly-built CON request. token/tkl are the
 * request's token bytes (tkl capped at 8 per RFC 7252).
 */
void pigeon_coap_udp_exchange_init(
    struct pigeon_coap_udp_exchange *ex, uint16_t req_id, const uint8_t *token, uint8_t tkl
);

/*
 * Classifies one received message against the in-flight exchange and
 * updates the exchange's own bookkeeping (separated flag, dedup ID) as a
 * side effect of the classification. rsp_type is the RFC 7252 message
 * type (COAP_TYPE_*), rsp_code the header code (COAP_CODE_EMPTY for Empty
 * messages), rsp_id the message ID, rsp_token/rsp_tkl the token.
 */
enum pigeon_coap_udp_action pigeon_coap_udp_classify(
    struct pigeon_coap_udp_exchange *ex, uint8_t rsp_type, uint8_t rsp_code, uint16_t rsp_id,
    const uint8_t *rsp_token, uint8_t rsp_tkl
);

#endif /* PIDGEIOT_PIGEON_COAP_UDP_MATCH_H_ */
