#include <errno.h>
#include <pigeon.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>

#include "pigeon_coap_internal.h"
#include "pigeon_coap_udp_match.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

/* RFC 7252 sec 4.8.2 MAX_TRANSMIT_WAIT: the longest a client can possibly
 * still be interested in this exchange -- retransmission span plus the final
 * timeout -- and therefore the budget for a separate response to arrive
 * after an Empty ACK told us to stop retransmitting. Derived from the same
 * Zephyr CoAP Kconfigs that drive coap_pending's retransmission timing
 * (ACK_TIMEOUT * ((2^(MAX_RETRANSMIT+1)) - 1) * ACK_RANDOM_FACTOR; 93s at
 * the defaults), not a separate knob. */
#if defined(CONFIG_COAP_RANDOMIZE_ACK_TIMEOUT)
#define PIGEON_COAP_UDP_ACK_RANDOM_PERCENT CONFIG_COAP_ACK_RANDOM_PERCENT
#else
#define PIGEON_COAP_UDP_ACK_RANDOM_PERCENT 100
#endif
#define PIGEON_COAP_UDP_MAX_TRANSMIT_WAIT_MS                              \
  ((uint32_t)CONFIG_COAP_INIT_ACK_TIMEOUT_MS *                            \
   ((1UL << (CONFIG_COAP_MAX_RETRANSMIT + 1)) - 1UL) *                    \
   PIGEON_COAP_UDP_ACK_RANDOM_PERCENT / 100UL)

#define PIGEON_COAP_UDP_TKL 8

/* The DTLS session is long-lived, unlike the TCP transport's
 * connect-per-exchange: the handshake is paid once and every subsequent
 * exchange rides the established session (with CONFIG_PIGEON_COAP_DTLS_CID,
 * even across NAT rebinds/PSM sleeps -- see zephyr/Kconfig). -1 when down;
 * any transport-level failure closes it so the next exchange re-handshakes
 * rather than throwing requests into a dead session forever. */
static int pigeon_coap_udp_sock = -1;

/* Response datagram storage. Payload pointers returned from
 * pigeon_coap_transport_exchange() alias into this, valid until the next
 * exchange (same contract as the TCP transport's body buffer). */
static uint8_t pigeon_coap_udp_rsp[PIGEON_COAP_MSG_MAX];

static void pigeon_coap_udp_close(void) {
  if (pigeon_coap_udp_sock >= 0) {
    zsock_close(pigeon_coap_udp_sock);
    pigeon_coap_udp_sock = -1;
  }
}

static int pigeon_coap_udp_connect(void) {
  if (pigeon_coap_udp_sock >= 0) {
    return 0;
  }

  int err = pigeon_coap_register_psk();

  if (err) {
    return err;
  }

  /* AF_UNSPEC, not AF_INET: a hard-coded v4 hint makes zsock_getaddrinfo()
   * itself fail here on an IPv6-only cellular PDN, which hands back only
   * AAAA records for this host -- every exchange -EHOSTUNREACH, no
   * fallback. Below, each candidate the resolver returns (in its own
   * ranked order, RFC 6724) gets a real connect attempt; the loop moves on
   * to the next one on any failure instead of giving up on the first. */
  struct zsock_addrinfo hints = {
      .ai_family = AF_UNSPEC,
      .ai_socktype = SOCK_DGRAM,
  };
  struct zsock_addrinfo *addr_list;

  err = zsock_getaddrinfo(pigeon_coap_host, pigeon_coap_port, &hints, &addr_list);

  if (err) {
    LOG_ERR("Failed to resolve %s: %d", pigeon_coap_host, err);
    return -EHOSTUNREACH;
  }

  /* SNI/hostname verification is an X.509 concept and meaningless for PSK
   * ciphersuites -- same reasoning as the TCP transport's connect path.
   * Family-independent, so computed once rather than per candidate. */
  const struct pigeon_coap_config *coap_cfg = pigeon_active_coap_config();
  bool using_psk = coap_cfg->tls_psk_identity && coap_cfg->tls_psk_secret;
  int sock = -1;
  int last_errno = EHOSTUNREACH;

  for (struct zsock_addrinfo *res = addr_list; res; res = res->ai_next) {
    sock = zsock_socket(res->ai_family, SOCK_DGRAM, IPPROTO_DTLS_1_2);

    if (sock < 0) {
      LOG_WRN("Failed to create DTLS socket (family %d): %d", res->ai_family, -errno);
      last_errno = errno;
      continue;
    }

    sec_tag_t sec_tag_list[] = {CONFIG_PIGEON_COAP_SEC_TAG};

    err = zsock_setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_list, sizeof(sec_tag_list));
    if (err) {
      LOG_ERR("Failed to set DTLS sec_tag %d: %d", CONFIG_PIGEON_COAP_SEC_TAG, -errno);
      last_errno = errno;
      zsock_close(sock);
      sock = -1;
      continue;
    }

#if defined(CONFIG_PIGEON_COAP_DTLS_CID)
    /* Offer RFC 9146 Connection ID as a client: an empty own CID ("echo
     * yours, don't send me one") is all a NAT-traversing client needs --
     * see this option's help in zephyr/Kconfig for the per-backend support
     * matrix. Unsupported stacks (mbedTLS built without
     * MBEDTLS_SSL_DTLS_CONNECTION_ID, pre-1.3.5 nRF9160 modem firmware)
     * fail here, deliberately non-fatally: the session still works, it
     * just won't survive an address rebind without a re-handshake. */
    int cid_val = TLS_DTLS_CID_SUPPORTED;

    err = zsock_setsockopt(sock, SOL_TLS, TLS_DTLS_CID, &cid_val, sizeof(cid_val));
    if (err) {
      LOG_WRN("DTLS CID unsupported on this stack (%d); continuing without", -errno);
    }
#endif

    if (!using_psk) {
      err = zsock_setsockopt(
          sock, SOL_TLS, TLS_HOSTNAME, pigeon_coap_host, strlen(pigeon_coap_host)
      );
      if (err) {
        LOG_ERR("Failed to set TLS hostname: %d", -errno);
        last_errno = errno;
        zsock_close(sock);
        sock = -1;
        continue;
      }
    }

    /* Blocking DTLS handshake. */
    err = zsock_connect(sock, res->ai_addr, res->ai_addrlen);
    if (err) {
      LOG_WRN(
          "DTLS handshake with %s (family %d) failed: %d, trying next address",
          pigeon_coap_host, res->ai_family, -errno
      );
      last_errno = errno;
      zsock_close(sock);
      sock = -1;
      continue;
    }

    break;
  }

  zsock_freeaddrinfo(addr_list);

  if (sock < 0) {
    LOG_ERR(
        "DTLS handshake with %s failed on every resolved address: %d", pigeon_coap_host,
        last_errno
    );
    return -last_errno;
  }

#if defined(CONFIG_PIGEON_COAP_DTLS_CID)
  /* Log what actually got negotiated, so "is CID protecting this session"
   * is observable per connection instead of assumed. UPLINK means the
   * server gave us a CID to echo -- the state that survives a rebind.
   * Caveat on native-stack builds: Zephyr's status getsockopt reads
   * uninitialized memory when the server did NOT negotiate CID, so a
   * positive answer here can be spurious -- a rebind surviving without a
   * re-handshake is the authoritative signal. The nRF91 modem implements
   * the status option itself and is unaffected. */
  int cid_status = TLS_DTLS_CID_STATUS_DISABLED;
  socklen_t cid_status_len = sizeof(cid_status);

  if (zsock_getsockopt(sock, SOL_TLS, TLS_DTLS_CID_STATUS, &cid_status, &cid_status_len) == 0) {
    LOG_INF(
        "DTLS session up, CID status: %s",
        cid_status == TLS_DTLS_CID_STATUS_DISABLED        ? "disabled"
        : cid_status == TLS_DTLS_CID_STATUS_UPLINK        ? "uplink"
        : cid_status == TLS_DTLS_CID_STATUS_DOWNLINK      ? "downlink"
                                                          : "bidirectional"
    );
  } else {
    LOG_INF("DTLS session up (CID status unavailable: %d)", -errno);
  }
#else
  LOG_INF("DTLS session up");
#endif

  /* IANA ciphersuite id of what actually got negotiated (0xC0A8 =
   * TLS_PSK_WITH_AES_128_CCM_8, the constrained-device target) --
   * observability for exactly the kind of "which suite did the peer
   * really pick" question a PSK deployment hits. Optional on some
   * offloaded stacks, hence best-effort. */
  int suite = 0;
  socklen_t suite_len = sizeof(suite);

  if (zsock_getsockopt(sock, SOL_TLS, TLS_CIPHERSUITE_USED, &suite, &suite_len) == 0) {
    LOG_INF("DTLS ciphersuite: 0x%04x", suite);
  }

  pigeon_coap_udp_sock = sock;

  return 0;
}

/* Sends an Empty ACK for the given received CON message. Best-effort: a
 * lost ACK only costs the server another retransmission, which dedup
 * re-ACKs. */
static void pigeon_coap_udp_send_ack(const struct coap_packet *rsp) {
  uint8_t ack_buf[4];
  struct coap_packet ack;

  if (coap_ack_init(&ack, rsp, ack_buf, sizeof(ack_buf), COAP_CODE_EMPTY) == 0) {
    (void)zsock_send(pigeon_coap_udp_sock, ack.data, ack.offset, 0);
  }
}

/* Waits up to wait_ms for one datagram and classifies it against ex.
 * Returns a PIGEON_COAP_UDP_ACTION_* on a delivered classification, -EAGAIN
 * when the wait expired quietly, or a negative transport error (socket
 * dead). On RESPONSE/RESPONSE_ACK, *rsp_out holds the parsed packet
 * (pointing into pigeon_coap_udp_rsp). */
static int pigeon_coap_udp_wait_one(
    struct pigeon_coap_udp_exchange *ex, int32_t wait_ms, struct coap_packet *rsp_out
) {
  if (wait_ms < 0) {
    wait_ms = 0;
  }

  struct zsock_pollfd pfd = {
      .fd = pigeon_coap_udp_sock,
      .events = ZSOCK_POLLIN,
  };

  int ret = zsock_poll(&pfd, 1, wait_ms);

  if (ret < 0) {
    return -errno;
  }
  if (ret == 0) {
    return -EAGAIN;
  }

  ssize_t n = zsock_recv(pigeon_coap_udp_sock, pigeon_coap_udp_rsp, sizeof(pigeon_coap_udp_rsp), 0);

  if (n < 0) {
    return -errno;
  }
  if (n == 0) {
    return -ECONNRESET;
  }

  struct coap_packet rsp;

  if (coap_packet_parse(&rsp, pigeon_coap_udp_rsp, (uint16_t)n, NULL, 0) < 0) {
    /* Garbage inside an authenticated DTLS session; drop it, not the
     * session. */
    return -EAGAIN;
  }

  uint8_t rsp_token[COAP_TOKEN_MAX_LEN];
  uint8_t rsp_tkl = coap_header_get_token(&rsp, rsp_token);

  enum pigeon_coap_udp_action action = pigeon_coap_udp_classify(
      ex, coap_header_get_type(&rsp), coap_header_get_code(&rsp), coap_header_get_id(&rsp),
      rsp_token, rsp_tkl
  );

  switch (action) {
    case PIGEON_COAP_UDP_ACTION_ACK_ONLY:
      pigeon_coap_udp_send_ack(&rsp);
      return -EAGAIN;
    case PIGEON_COAP_UDP_ACTION_IGNORE:
      return -EAGAIN;
    case PIGEON_COAP_UDP_ACTION_RESPONSE_ACK:
      pigeon_coap_udp_send_ack(&rsp);
      *rsp_out = rsp;
      return (int)action;
    case PIGEON_COAP_UDP_ACTION_RESPONSE:
      *rsp_out = rsp;
      return (int)action;
    default:
      return (int)action;
  }
}

/* One full confirmable exchange on the established session: send the CON
 * request, retransmit per RFC 7252 sec 4.2 (timing owned by Zephyr's
 * coap_pending helpers), correlate/dedup the response (logic owned by
 * pigeon_coap_udp_match.c), handle both piggybacked and separate
 * responses. */
static int pigeon_coap_udp_do_exchange(
    uint8_t code, const char *leaf, const uint8_t *payload, size_t payload_len,
    const struct pigeon_coap_req_opts *opts, uint8_t *rsp_code, const uint8_t **rsp_payload,
    size_t *rsp_payload_len
) {
  uint8_t req_buf[PIGEON_COAP_MSG_MAX];
  struct coap_packet req;
  uint8_t *token = coap_next_token();
  uint16_t req_id = coap_next_id();

  int err = coap_packet_init(
      &req, req_buf, sizeof(req_buf), COAP_VERSION_1, COAP_TYPE_CON, PIGEON_COAP_UDP_TKL, token,
      code, req_id
  );

  if (err) {
    return err;
  }

  err = pigeon_coap_append_request_options(&req, leaf, payload && payload_len, opts);
  if (err) {
    return err;
  }

  if (payload && payload_len) {
    err = coap_packet_append_payload_marker(&req);
    if (err) {
      return err;
    }
    err = coap_packet_append_payload(&req, payload, payload_len);
    if (err) {
      return err;
    }
  }

  struct pigeon_coap_udp_exchange ex;

  pigeon_coap_udp_exchange_init(&ex, req_id, token, PIGEON_COAP_UDP_TKL);

  /* coap_pending only tracks timing/retries here -- the send itself stays
   * ours (connected DTLS socket, not sendto), so the addr is an unused
   * placeholder (the init unconditionally copies it, NULL would fault). */
  struct sockaddr unused_addr;
  struct coap_pending pending;

  memset(&unused_addr, 0, sizeof(unused_addr));
  err = coap_pending_init(&pending, &req, &unused_addr, NULL);
  if (err) {
    return err;
  }

  int64_t deadline = k_uptime_get() + PIGEON_COAP_UDP_MAX_TRANSMIT_WAIT_MS;
  struct coap_packet rsp;

  /* Transmission phase: (re)send until something decisive arrives, the
   * retransmission budget runs out, or an Empty ACK moves this exchange to
   * the separate-response phase below. */
  while (!ex.separated) {
    if (!coap_pending_cycle(&pending)) {
      return -ETIMEDOUT;
    }

    ssize_t sent = zsock_send(pigeon_coap_udp_sock, pending.data, pending.len, 0);

    if (sent < 0 || (size_t)sent != pending.len) {
      return sent < 0 ? -errno : -EIO;
    }

    int64_t cycle_end = k_uptime_get() + pending.timeout;

    if (cycle_end > deadline) {
      cycle_end = deadline;
    }

    while (!ex.separated) {
      int32_t remaining = (int32_t)(cycle_end - k_uptime_get());

      if (remaining <= 0) {
        break;
      }

      int ret = pigeon_coap_udp_wait_one(&ex, remaining, &rsp);

      if (ret == -EAGAIN) {
        continue;
      }
      if (ret == (int)PIGEON_COAP_UDP_ACTION_RESET) {
        LOG_ERR("CoAP request rejected with RST");
        return -ECONNREFUSED;
      }
      if (ret == (int)PIGEON_COAP_UDP_ACTION_RESPONSE ||
          ret == (int)PIGEON_COAP_UDP_ACTION_RESPONSE_ACK) {
        goto deliver;
      }
      if (ret == (int)PIGEON_COAP_UDP_ACTION_SEPARATED) {
        break;
      }
      if (ret < 0) {
        return ret;
      }
    }

    if (!ex.separated && k_uptime_get() >= deadline) {
      return -ETIMEDOUT;
    }
  }

  /* Separate-response phase (RFC 7252 sec 5.2.2): the request is
   * acknowledged, retransmission is over; all that's left is waiting for
   * the server's own CON/NON response within the overall exchange
   * budget. */
  for (;;) {
    int32_t remaining = (int32_t)(deadline - k_uptime_get());

    if (remaining <= 0) {
      return -ETIMEDOUT;
    }

    int ret = pigeon_coap_udp_wait_one(&ex, remaining, &rsp);

    if (ret == -EAGAIN) {
      continue;
    }
    if (ret == (int)PIGEON_COAP_UDP_ACTION_RESET) {
      LOG_ERR("CoAP request rejected with RST");
      return -ECONNREFUSED;
    }
    if (ret == (int)PIGEON_COAP_UDP_ACTION_RESPONSE ||
        ret == (int)PIGEON_COAP_UDP_ACTION_RESPONSE_ACK) {
      break;
    }
    if (ret < 0) {
      return ret;
    }
  }

deliver:
  *rsp_code = coap_header_get_code(&rsp);

  uint16_t found_len = 0;
  const uint8_t *found = coap_packet_get_payload(&rsp, &found_len);

  *rsp_payload = found_len ? found : NULL;
  *rsp_payload_len = found_len;

  return 0;
}

int pigeon_coap_transport_exchange(
    uint8_t code, const char *leaf, const uint8_t *payload, size_t payload_len,
    const struct pigeon_coap_req_opts *opts, uint8_t *rsp_code, const uint8_t **rsp_payload,
    size_t *rsp_payload_len
) {
  int err = pigeon_coap_parse_endpoint();

  if (err) {
    return err;
  }

  err = pigeon_coap_udp_connect();
  if (err) {
    return err;
  }

  err = pigeon_coap_udp_do_exchange(
      code, leaf, payload, payload_len, opts, rsp_code, rsp_payload, rsp_payload_len
  );

  if (err) {
    /* Whatever went wrong (retransmits exhausted, socket error, RST), the
     * session can't be trusted anymore -- and without CID, a NAT rebind
     * during a long sleep looks exactly like this. Tear it down so the
     * next exchange pays one re-handshake instead of failing forever. */
    LOG_WRN("CoAP exchange failed (%d); closing DTLS session for re-handshake", err);
    pigeon_coap_udp_close();
  }

  return err;
}
