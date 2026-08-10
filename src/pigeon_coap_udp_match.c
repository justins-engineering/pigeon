#include <string.h>
#include <zephyr/net/coap.h>

#include "pigeon_coap_udp_match.h"

void pigeon_coap_udp_exchange_init(
    struct pigeon_coap_udp_exchange *ex, uint16_t req_id, const uint8_t *token, uint8_t tkl
) {
  memset(ex, 0, sizeof(*ex));
  ex->req_id = req_id;
  ex->tkl = tkl > 8 ? 8 : tkl;
  memcpy(ex->token, token, ex->tkl);
}

static bool token_matches(
    const struct pigeon_coap_udp_exchange *ex, const uint8_t *rsp_token, uint8_t rsp_tkl
) {
  return rsp_tkl == ex->tkl && memcmp(rsp_token, ex->token, ex->tkl) == 0;
}

enum pigeon_coap_udp_action pigeon_coap_udp_classify(
    struct pigeon_coap_udp_exchange *ex, uint8_t rsp_type, uint8_t rsp_code, uint16_t rsp_id,
    const uint8_t *rsp_token, uint8_t rsp_tkl
) {
  switch (rsp_type) {
    case COAP_TYPE_ACK:
      /* An ACK is bound to our request by message ID (RFC 7252 4.2), not
       * token; an ACK for some other ID is not ours. */
      if (rsp_id != ex->req_id) {
        return PIGEON_COAP_UDP_ACTION_IGNORE;
      }
      if (rsp_code == COAP_CODE_EMPTY) {
        /* Empty ACK: the server needs time; a separate response follows
         * (RFC 7252 5.2.2). Stop retransmitting, keep listening. */
        ex->separated = true;
        return PIGEON_COAP_UDP_ACTION_SEPARATED;
      }
      /* Piggybacked response (5.2.1): the ACK itself carries the
       * response, correlated by token as well as ID. */
      if (!token_matches(ex, rsp_token, rsp_tkl)) {
        return PIGEON_COAP_UDP_ACTION_IGNORE;
      }
      return PIGEON_COAP_UDP_ACTION_RESPONSE;

    case COAP_TYPE_RESET:
      /* RST rejects the message it names by ID (4.2): our request was
       * received but the peer couldn't process it. */
      if (rsp_id != ex->req_id) {
        return PIGEON_COAP_UDP_ACTION_IGNORE;
      }
      return PIGEON_COAP_UDP_ACTION_RESET;

    case COAP_TYPE_CON:
      /* A CON from the server is a separate response (5.2.2): correlated
       * to our request purely by token, carrying its own (server-chosen)
       * message ID which we must ACK -- and which is the dedup key: the
       * server retransmits this CON until an ACK arrives, so a duplicate
       * (same ID, already processed) must be re-ACKed without being
       * re-delivered (4.5). A CON whose token isn't ours (e.g. a late
       * separate response to a PREVIOUS, already-abandoned exchange whose
       * token we no longer track) is also ACKed -- silence would leave
       * that server retransmitting for the full MAX_RETRANSMIT span --
       * but never delivered. */
      if (!token_matches(ex, rsp_token, rsp_tkl)) {
        return PIGEON_COAP_UDP_ACTION_ACK_ONLY;
      }
      if (ex->have_last_rsp_id && ex->last_rsp_id == rsp_id) {
        return PIGEON_COAP_UDP_ACTION_ACK_ONLY;
      }
      ex->last_rsp_id = rsp_id;
      ex->have_last_rsp_id = true;
      return PIGEON_COAP_UDP_ACTION_RESPONSE_ACK;

    case COAP_TYPE_NON_CON:
      /* A NON response needs no ACK; correlate by token (5.2.3). */
      if (!token_matches(ex, rsp_token, rsp_tkl)) {
        return PIGEON_COAP_UDP_ACTION_IGNORE;
      }
      return PIGEON_COAP_UDP_ACTION_RESPONSE;

    default:
      return PIGEON_COAP_UDP_ACTION_IGNORE;
  }
}
