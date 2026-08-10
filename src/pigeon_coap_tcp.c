#include <errno.h>
#include <pigeon.h>
#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/sys/byteorder.h>

#include "pigeon_coap_internal.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

/* RFC 8323 sec 3.2 message framing: Token length is fixed at the RFC 7252
 * max (8 bytes), and the Len/TKL byte is followed by 0/1/2/4 Extended Length
 * bytes depending on how big Options+Payload turns out to be. Reserving the
 * worst case up front and writing Code/Token right after it lets the header
 * be filled in right-aligned once the final body length is known, with no
 * memmove -- see pigeon_coap_tcp_build_request(). */
#define PIGEON_COAP_TCP_TKL 8
#define PIGEON_COAP_TCP_HDR_MAX 5
#define PIGEON_COAP_TCP_PRE_OPTS (PIGEON_COAP_TCP_HDR_MAX + 1 + PIGEON_COAP_TCP_TKL)

/* Response body (Options+Payload, per RFC 8323 framing) accumulated by
 * pigeon_coap_tcp_read_frame(). */
static uint8_t pigeon_coap_tcp_body[PIGEON_COAP_MSG_MAX];
static size_t pigeon_coap_tcp_body_len;

static int pigeon_coap_tcp_connect(void) {
  int err = pigeon_coap_register_psk();

  if (err) {
    return err;
  }

  struct zsock_addrinfo hints = {
      .ai_family = AF_INET,
      .ai_socktype = SOCK_STREAM,
  };
  struct zsock_addrinfo *res;

  err = zsock_getaddrinfo(pigeon_coap_host, pigeon_coap_port, &hints, &res);

  if (err) {
    LOG_ERR("Failed to resolve %s: %d", pigeon_coap_host, err);
    return -EHOSTUNREACH;
  }

  int sock = zsock_socket(res->ai_family, SOCK_STREAM, IPPROTO_TLS_1_2);

  if (sock < 0) {
    LOG_ERR("Failed to create TLS socket: %d", -errno);
    zsock_freeaddrinfo(res);
    return -errno;
  }

  sec_tag_t sec_tag_list[] = {CONFIG_PIGEON_COAP_SEC_TAG};

  err = zsock_setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_list, sizeof(sec_tag_list));
  if (err) {
    LOG_ERR("Failed to set TLS sec_tag %d: %d", CONFIG_PIGEON_COAP_SEC_TAG, -errno);
    goto cleanup;
  }

  /* SNI/hostname verification is an X.509 concept and meaningless for PSK
   * ciphersuites -- skip it when PSK credentials are configured. Confirmed by
   * an actual PSK build failure: minimal PSK-only builds may not enable
   * CONFIG_MBEDTLS_X509_CRT_PARSE_C at all, and Zephyr's TLS_HOSTNAME option
   * hard-fails with -ENOPROTOOPT without it (see tls_opt_hostname_set() in
   * subsys/net/lib/sockets/sockets_tls.c). */
  const struct pigeon_coap_config *coap_cfg = pigeon_active_coap_config();
  bool using_psk = coap_cfg->tls_psk_identity && coap_cfg->tls_psk_secret;

  if (!using_psk) {
    err = zsock_setsockopt(
        sock, SOL_TLS, TLS_HOSTNAME, pigeon_coap_host, strlen(pigeon_coap_host)
    );
    if (err) {
      LOG_ERR("Failed to set TLS hostname: %d", -errno);
      goto cleanup;
    }
  }

  err = zsock_connect(sock, res->ai_addr, res->ai_addrlen);
  zsock_freeaddrinfo(res);
  if (err) {
    LOG_ERR("Failed to connect to %s: %d", pigeon_coap_host, -errno);
    zsock_close(sock);
    return -errno;
  }

  return sock;

cleanup:
  zsock_freeaddrinfo(res);
  zsock_close(sock);
  return -errno;
}

static int pigeon_coap_tcp_recv_exact(int sock, uint8_t *buf, size_t len) {
  size_t got = 0;

  while (got < len) {
    ssize_t n = zsock_recv(sock, buf + got, len - got, 0);

    if (n < 0) {
      return -errno;
    }
    if (n == 0) {
      return -ECONNRESET;
    }

    got += (size_t)n;
  }

  return 0;
}

/* Builds an RFC 8323 CoAP-over-TLS/TCP request frame into buf. Uri-Path/
 * Uri-Query/Content-Format come from the shared
 * pigeon_coap_append_request_options() (pigeon_coap.c).
 *
 * Returns (via out_start/out_len) a pointer into buf and length ready to
 * send as-is -- the length header is written right-aligned into the
 * PIGEON_COAP_TCP_HDR_MAX-byte reserve immediately before the fixed
 * Code/Token position, so nothing needs to be shifted once the final size
 * is known. */
static int pigeon_coap_tcp_build_request(
    uint8_t *buf, size_t buf_len, uint8_t code, const char *leaf, const uint8_t *payload,
    size_t payload_len, uint8_t **out_start, size_t *out_len
) {
  if (buf_len < PIGEON_COAP_TCP_PRE_OPTS) {
    return -ENOSPC;
  }

  uint8_t *token = coap_next_token();

  buf[PIGEON_COAP_TCP_HDR_MAX] = code;
  memcpy(buf + PIGEON_COAP_TCP_HDR_MAX + 1, token, PIGEON_COAP_TCP_TKL);

  struct coap_packet cpkt = {
      .data = buf,
      .offset = PIGEON_COAP_TCP_PRE_OPTS,
      .max_len = (uint16_t)buf_len,
      .hdr_len = PIGEON_COAP_TCP_PRE_OPTS,
  };

  int err = pigeon_coap_append_request_options(&cpkt, leaf, payload && payload_len);

  if (err) {
    return err;
  }

  if (payload && payload_len) {
    err = coap_packet_append_payload_marker(&cpkt);
    if (err) {
      return err;
    }
    err = coap_packet_append_payload(&cpkt, payload, payload_len);
    if (err) {
      return err;
    }
  }

  /* Len/Extended Length (RFC 8323 sec 3.2) covers Options+Payload only --
   * not Code or Token. */
  size_t body_len = cpkt.offset - PIGEON_COAP_TCP_PRE_OPTS;
  uint8_t len_nibble;
  size_t ext_len_bytes;
  uint32_t ext_val = 0;

  if (body_len < 13) {
    len_nibble = (uint8_t)body_len;
    ext_len_bytes = 0;
  } else if (body_len < 269) {
    len_nibble = 13;
    ext_len_bytes = 1;
    ext_val = (uint32_t)(body_len - 13);
  } else if (body_len < 65805) {
    len_nibble = 14;
    ext_len_bytes = 2;
    ext_val = (uint32_t)(body_len - 269);
  } else {
    len_nibble = 15;
    ext_len_bytes = 4;
    ext_val = (uint32_t)(body_len - 65805);
  }

  size_t hdr_size = 1 + ext_len_bytes;
  uint8_t *hdr = buf + PIGEON_COAP_TCP_HDR_MAX - hdr_size;

  hdr[0] = (uint8_t)((len_nibble << 4) | (PIGEON_COAP_TCP_TKL & 0x0F));

  if (ext_len_bytes == 1) {
    hdr[1] = (uint8_t)ext_val;
  } else if (ext_len_bytes == 2) {
    sys_put_be16((uint16_t)ext_val, &hdr[1]);
  } else if (ext_len_bytes == 4) {
    sys_put_be32(ext_val, &hdr[1]);
  }

  *out_start = hdr;
  *out_len = hdr_size + 1 + PIGEON_COAP_TCP_TKL + body_len;

  return 0;
}

/* RFC 8323 sec 5 signaling codes (class 7). */
#define PIGEON_COAP_TCP_CODE_CSM COAP_MAKE_RESPONSE_CODE(7, 1)
#define PIGEON_COAP_TCP_CODE_PING COAP_MAKE_RESPONSE_CODE(7, 2)
#define PIGEON_COAP_TCP_CODE_PONG COAP_MAKE_RESPONSE_CODE(7, 3)

/* RFC 8323 sec 5.3: each side MUST send a CSM as its first message on the
 * connection. An empty CSM (no options) advertises the spec defaults
 * (Max-Message-Size 1152, no block-wise), which matches this transport's
 * one-frame-per-exchange usage. The peer's own CSM is skipped by
 * pigeon_coap_tcp_read_message() below. */
static int pigeon_coap_tcp_send_csm(int sock) {
  const uint8_t csm[2] = {0x00, PIGEON_COAP_TCP_CODE_CSM};
  ssize_t sent = zsock_send(sock, csm, sizeof(csm), 0);

  return (sent == (ssize_t)sizeof(csm)) ? 0 : (sent < 0 ? -errno : -EIO);
}

/* Replies to an RFC 8323 Ping with a Pong carrying the same token (sec
 * 5.4). Best-effort: this transport closes the connection right after its
 * one exchange anyway. */
static void pigeon_coap_tcp_send_pong(int sock, const uint8_t *token, uint8_t tkl) {
  uint8_t pong[2 + 8];

  pong[0] = (uint8_t)(tkl & 0x0F);
  pong[1] = PIGEON_COAP_TCP_CODE_PONG;
  memcpy(&pong[2], token, tkl);
  (void)zsock_send(sock, pong, (size_t)(2 + tkl), 0);
}

/* Reads one RFC 8323 frame from sock into body_buf (the Options+Payload
 * region only -- Len/Extended Length are consumed here; Code and Token are
 * returned via code_out/token_buf but not copied into body_buf). */
static int pigeon_coap_tcp_read_frame(
    int sock, uint8_t *body_buf, size_t body_buf_len, size_t *body_len_out, uint8_t *code_out,
    uint8_t *token_buf, uint8_t *tkl_out
) {
  uint8_t first;
  int err = pigeon_coap_tcp_recv_exact(sock, &first, 1);

  if (err) {
    return err;
  }

  uint8_t len_nibble = first >> 4;
  uint8_t tkl = first & 0x0F;
  size_t body_len;

  if (len_nibble < 13) {
    body_len = len_nibble;
  } else if (len_nibble == 13) {
    uint8_t ext;

    err = pigeon_coap_tcp_recv_exact(sock, &ext, 1);
    if (err) {
      return err;
    }
    body_len = 13 + ext;
  } else if (len_nibble == 14) {
    uint8_t ext[2];

    err = pigeon_coap_tcp_recv_exact(sock, ext, sizeof(ext));
    if (err) {
      return err;
    }
    body_len = 269 + sys_get_be16(ext);
  } else {
    uint8_t ext[4];

    err = pigeon_coap_tcp_recv_exact(sock, ext, sizeof(ext));
    if (err) {
      return err;
    }
    body_len = 65805 + sys_get_be32(ext);
  }

  if (tkl > 8) {
    LOG_ERR("CoAP response TKL %u exceeds RFC 7252 max (8)", tkl);
    return -EBADMSG;
  }

  uint8_t code_and_token[1 + 8];

  err = pigeon_coap_tcp_recv_exact(sock, code_and_token, (size_t)(1 + tkl));
  if (err) {
    return err;
  }

  if (body_len > body_buf_len) {
    LOG_ERR("CoAP response body (%zu) exceeds buffer (%zu)", body_len, body_buf_len);
    return -ENOSPC;
  }

  err = pigeon_coap_tcp_recv_exact(sock, body_buf, body_len);
  if (err) {
    return err;
  }

  *body_len_out = body_len;
  *code_out = code_and_token[0];
  *tkl_out = tkl;
  memcpy(token_buf, &code_and_token[1], tkl);

  return 0;
}

/* Reads frames until a non-signaling (class != 7) message arrives --
 * i.e. the actual response. The server's own CSM is consumed here (RFC
 * 8323 sec 5.3), a Ping gets its Pong (sec 5.4), and Release/Abort (sec
 * 5.5/5.6) fail the exchange. Bounded so a pathological peer spraying
 * signaling frames can't wedge the caller forever. */
static int pigeon_coap_tcp_read_message(
    int sock, uint8_t *body_buf, size_t body_buf_len, size_t *body_len_out, uint8_t *code_out
) {
  for (int i = 0; i < 8; i++) {
    uint8_t token[8];
    uint8_t tkl;
    int err = pigeon_coap_tcp_read_frame(
        sock, body_buf, body_buf_len, body_len_out, code_out, token, &tkl
    );

    if (err) {
      return err;
    }

    if ((*code_out >> 5) != 7) {
      return 0;
    }

    if (*code_out == PIGEON_COAP_TCP_CODE_CSM) {
      continue;
    }
    if (*code_out == PIGEON_COAP_TCP_CODE_PING) {
      pigeon_coap_tcp_send_pong(sock, token, tkl);
      continue;
    }

    /* Release/Abort (or unknown signaling): the peer is done with this
     * connection. */
    LOG_ERR("CoAP connection signaling %u.%02u", *code_out >> 5, *code_out & 0x1F);
    return -ECONNRESET;
  }

  return -EBADMSG;
}

/* Skips over the (delta/length-encoded, RFC 7252 sec 3.1) Options in body to
 * find the payload, if any. This client never needs an option's own value
 * (mirroring pigeon_https.c not caring about response headers beyond
 * status), only where it ends. */
static int pigeon_coap_tcp_find_payload(
    uint8_t *body, size_t body_len, uint8_t **payload, size_t *payload_len
) {
  size_t off = 0;

  while (off < body_len) {
    uint8_t opt_hdr = body[off];

    if (opt_hdr == 0xFF) {
      *payload = body + off + 1;
      *payload_len = body_len - off - 1;
      return 0;
    }

    off++;

    uint16_t delta = opt_hdr >> 4;
    uint16_t len = opt_hdr & 0x0F;

    if (delta == 13) {
      if (off >= body_len) {
        return -EBADMSG;
      }
      delta = 13 + body[off++];
    } else if (delta == 14) {
      if (off + 1 >= body_len) {
        return -EBADMSG;
      }
      delta = 269 + sys_get_be16(&body[off]);
      off += 2;
    } else if (delta == 15) {
      return -EBADMSG;
    }
    ARG_UNUSED(delta);

    if (len == 13) {
      if (off >= body_len) {
        return -EBADMSG;
      }
      len = 13 + body[off++];
    } else if (len == 14) {
      if (off + 1 >= body_len) {
        return -EBADMSG;
      }
      len = 269 + sys_get_be16(&body[off]);
      off += 2;
    } else if (len == 15) {
      return -EBADMSG;
    }

    if (off + len > body_len) {
      return -EBADMSG;
    }
    off += len;
  }

  *payload = NULL;
  *payload_len = 0;

  return 0;
}

int pigeon_coap_transport_exchange(
    uint8_t code, const char *leaf, const uint8_t *payload, size_t payload_len, uint8_t *rsp_code,
    const uint8_t **rsp_payload, size_t *rsp_payload_len
) {
  int err = pigeon_coap_parse_endpoint();

  if (err) {
    return err;
  }

  int sock = pigeon_coap_tcp_connect();

  if (sock < 0) {
    return sock;
  }

  err = pigeon_coap_tcp_send_csm(sock);
  if (err) {
    LOG_ERR("CoAP CSM send failed: %d", err);
    zsock_close(sock);
    return err;
  }

  uint8_t req_buf[PIGEON_COAP_MSG_MAX];
  uint8_t *req_start;
  size_t req_len;

  err = pigeon_coap_tcp_build_request(
      req_buf, sizeof(req_buf), code, leaf, payload, payload_len, &req_start, &req_len
  );
  if (err) {
    zsock_close(sock);
    return err;
  }

  ssize_t sent = zsock_send(sock, req_start, req_len, 0);

  if (sent < 0 || (size_t)sent != req_len) {
    err = sent < 0 ? -errno : -EIO;
    LOG_ERR("CoAP request send failed: %d", err);
    zsock_close(sock);
    return err;
  }

  pigeon_coap_tcp_body_len = 0;
  err = pigeon_coap_tcp_read_message(
      sock, pigeon_coap_tcp_body, sizeof(pigeon_coap_tcp_body), &pigeon_coap_tcp_body_len, rsp_code
  );
  zsock_close(sock);

  if (err) {
    return err;
  }

  uint8_t *found;
  size_t found_len;

  err = pigeon_coap_tcp_find_payload(
      pigeon_coap_tcp_body, pigeon_coap_tcp_body_len, &found, &found_len
  );
  if (err) {
    return err;
  }

  *rsp_payload = found;
  *rsp_payload_len = found_len;

  return 0;
}
