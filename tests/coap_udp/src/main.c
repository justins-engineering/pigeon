#include <string.h>
#include <zephyr/net/coap.h>
#include <zephyr/ztest.h>

#include "pigeon_coap_udp_match.h"

/* RFC 7252 message-layer classification/dedup matrix for the CoAP DTLS/UDP
 * transport (pigeon_coap_udp_match.c). Retransmission timing is Zephyr's
 * own coap_pending machinery and deliberately not re-tested here -- these
 * tests own exactly the decisions pigeon_coap_udp.c makes per received
 * datagram: response correlation (ID for ACK/RST, token for responses),
 * piggybacked vs separate responses, and duplicate handling. */

#define REQ_ID 0x1234
#define RSP_ID 0x5678

static const uint8_t req_token[8] = {1, 2, 3, 4, 5, 6, 7, 8};
static const uint8_t other_token[8] = {9, 9, 9, 9, 9, 9, 9, 9};

/* 2.05 Content */
#define CODE_CONTENT COAP_RESPONSE_CODE_CONTENT

static struct pigeon_coap_udp_exchange ex;

static void fresh_exchange(void *fixture) {
  ARG_UNUSED(fixture);
  pigeon_coap_udp_exchange_init(&ex, REQ_ID, req_token, 8);
}

ZTEST_SUITE(coap_udp_match, NULL, NULL, fresh_exchange, NULL, NULL);

ZTEST(coap_udp_match, test_init_caps_token_length) {
  pigeon_coap_udp_exchange_init(&ex, REQ_ID, req_token, 12);
  zassert_equal(ex.tkl, 8, "token length must cap at the RFC 7252 max");
  zassert_equal(ex.req_id, REQ_ID);
  zassert_false(ex.separated);
}

ZTEST(coap_udp_match, test_piggybacked_response_matches) {
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_ACK, CODE_CONTENT, REQ_ID, req_token, 8);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_RESPONSE);
  zassert_false(ex.separated);
}

ZTEST(coap_udp_match, test_ack_with_wrong_id_ignored) {
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_ACK, CODE_CONTENT, RSP_ID, req_token, 8);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_IGNORE);
}

ZTEST(coap_udp_match, test_piggybacked_with_wrong_token_ignored) {
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_ACK, CODE_CONTENT, REQ_ID, other_token, 8);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_IGNORE);
}

ZTEST(coap_udp_match, test_piggybacked_with_short_token_ignored) {
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_ACK, CODE_CONTENT, REQ_ID, req_token, 4);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_IGNORE);
}

ZTEST(coap_udp_match, test_empty_ack_separates) {
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_ACK, COAP_CODE_EMPTY, REQ_ID, NULL, 0);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_SEPARATED);
  zassert_true(ex.separated, "empty ACK must move the exchange to the separate-response phase");
}

ZTEST(coap_udp_match, test_empty_ack_wrong_id_ignored) {
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_ACK, COAP_CODE_EMPTY, RSP_ID, NULL, 0);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_IGNORE);
  zassert_false(ex.separated);
}

ZTEST(coap_udp_match, test_separate_con_response_needs_ack) {
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_CON, CODE_CONTENT, RSP_ID, req_token, 8);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_RESPONSE_ACK);
}

ZTEST(coap_udp_match, test_duplicate_separate_response_reacked_not_redelivered) {
  (void)pigeon_coap_udp_classify(&ex, COAP_TYPE_CON, CODE_CONTENT, RSP_ID, req_token, 8);

  /* The server didn't get our ACK and retransmits the same CON: it must
   * be ACKed again (or it keeps retransmitting) but not delivered again
   * (RFC 7252 sec 4.5). */
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_CON, CODE_CONTENT, RSP_ID, req_token, 8);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_ACK_ONLY);
}

ZTEST(coap_udp_match, test_new_con_message_id_is_not_a_duplicate) {
  (void)pigeon_coap_udp_classify(&ex, COAP_TYPE_CON, CODE_CONTENT, RSP_ID, req_token, 8);

  /* A different message ID is a different message, not a retransmission --
   * dedup keys on the ID, not the token. */
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_CON, CODE_CONTENT, RSP_ID + 1, req_token, 8);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_RESPONSE_ACK);
}

ZTEST(coap_udp_match, test_stale_con_with_foreign_token_acked_but_dropped) {
  /* E.g. a late separate response to a previous, already-abandoned
   * exchange: quiet the server's retransmissions without delivering. */
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_CON, CODE_CONTENT, RSP_ID, other_token, 8);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_ACK_ONLY);
}

ZTEST(coap_udp_match, test_non_response_matches_by_token) {
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_NON_CON, CODE_CONTENT, RSP_ID, req_token, 8);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_RESPONSE);
}

ZTEST(coap_udp_match, test_non_response_foreign_token_ignored) {
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_NON_CON, CODE_CONTENT, RSP_ID, other_token, 8);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_IGNORE);
}

ZTEST(coap_udp_match, test_rst_fails_exchange) {
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_RESET, COAP_CODE_EMPTY, REQ_ID, NULL, 0);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_RESET);
}

ZTEST(coap_udp_match, test_rst_wrong_id_ignored) {
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_RESET, COAP_CODE_EMPTY, RSP_ID, NULL, 0);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_IGNORE);
}

ZTEST(coap_udp_match, test_full_separate_response_flow) {
  /* The canonical slow-server sequence (RFC 7252 sec 5.2.2): empty ACK,
   * then the CON response, then a duplicate of that CON (our ACK was
   * lost). */
  enum pigeon_coap_udp_action a =
      pigeon_coap_udp_classify(&ex, COAP_TYPE_ACK, COAP_CODE_EMPTY, REQ_ID, NULL, 0);

  zassert_equal(a, PIGEON_COAP_UDP_ACTION_SEPARATED);

  a = pigeon_coap_udp_classify(&ex, COAP_TYPE_CON, CODE_CONTENT, RSP_ID, req_token, 8);
  zassert_equal(a, PIGEON_COAP_UDP_ACTION_RESPONSE_ACK);

  a = pigeon_coap_udp_classify(&ex, COAP_TYPE_CON, CODE_CONTENT, RSP_ID, req_token, 8);
  zassert_equal(a, PIGEON_COAP_UDP_ACTION_ACK_ONLY);
}
