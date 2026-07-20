#include <errno.h>
#include <pigeon.h>
#include <string.h>
#include <zephyr/data/json.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/sys/byteorder.h>

#include "pigeon_internal.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

#define PIGEON_COAP_HOST_MAX 128
#define PIGEON_COAP_PATH_MAX 128
#define PIGEON_COAP_PORT_MAX 6
#define PIGEON_COAP_QUERY_MAX 160
#define PIGEON_COAP_MSG_MAX 640
#define PIGEON_COAP_CONFIG_MAX 256

/* RFC 8323 sec 3.2 message framing: Token length is fixed at the RFC 7252
 * max (8 bytes), and the Len/TKL byte is followed by 0/1/2/4 Extended Length
 * bytes depending on how big Options+Payload turns out to be. Reserving the
 * worst case up front and writing Code/Token right after it lets the header
 * be filled in right-aligned once the final body length is known, with no
 * memmove -- see pigeon_coap_build_request(). */
#define PIGEON_COAP_TKL 8
#define PIGEON_COAP_HDR_MAX 5
#define PIGEON_COAP_PRE_OPTS (PIGEON_COAP_HDR_MAX + 1 + PIGEON_COAP_TKL)

/* Parsed once (lazily) from CONFIG_PIGEON_ENDPOINT, e.g.
 * "coaps+tcp://api.pidgeiot.com/device/pigeons/<id>" -> host + port + path. */
static char pigeon_coap_host[PIGEON_COAP_HOST_MAX];
static char pigeon_coap_port[PIGEON_COAP_PORT_MAX];
static char pigeon_coap_path[PIGEON_COAP_PATH_MAX];
static bool pigeon_coap_endpoint_parsed;

static bool pigeon_coap_psk_registered;

/* Response body (Options+Payload, per RFC 8323 framing) accumulated by
 * pigeon_coap_read_frame(). */
static uint8_t pigeon_coap_body[PIGEON_COAP_MSG_MAX];
static size_t pigeon_coap_body_len;

/* Wire shape of the JSON payload a shadow GET returns (mirrors
 * capsules::PigeonShadow; see pigeon_shadow_doc in pigeon.h and the matching
 * copy of this in pigeon_https.c). target_config/current_config are
 * themselves JSON objects serialized as a string on the wire (e.g.
 * "target_config":"{\"log\":true}") -- decoding them with JSON_TOK_STRING
 * (as this used to) hands back a raw, still-escaped pointer into
 * pigeon_coap_body: '{\"log\":true}' is not valid JSON, so the app's own
 * json_obj_parse() on target_config always failed downstream regardless of
 * which keys/values it held. JSON_TOK_STRING_BUF actually unescapes into a
 * fixed-size buffer instead, so these are plain arrays (not pointers) and
 * this whole struct is a static instance (not a local), decoded into
 * directly -- pigeon_shadow_doc's target_config/current_config pointers
 * (see pigeon_shadow_get() below) alias straight into it, which is what
 * keeps them valid "until the next call" as pigeon.h documents, without a
 * separate copy-out step. */
struct pigeon_coap_shadow_wire {
  int32_t target_version;
  int32_t current_version;
  char target_config[PIGEON_COAP_CONFIG_MAX];
  char current_config[PIGEON_COAP_CONFIG_MAX];
  int64_t updated_at;
};

static struct pigeon_coap_shadow_wire pigeon_coap_shadow_wire;

static const struct json_obj_descr pigeon_coap_shadow_wire_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct pigeon_coap_shadow_wire, target_version, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct pigeon_coap_shadow_wire, current_version, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct pigeon_coap_shadow_wire, target_config, JSON_TOK_STRING_BUF),
    JSON_OBJ_DESCR_PRIM(struct pigeon_coap_shadow_wire, current_config, JSON_TOK_STRING_BUF),
    JSON_OBJ_DESCR_PRIM(struct pigeon_coap_shadow_wire, updated_at, JSON_TOK_INT64),
};

/* Splits CONFIG_PIGEON_ENDPOINT ("coaps+tcp://host[:port]/path...") into
 * pigeon_coap_host / pigeon_coap_port / pigeon_coap_path once. */
static int pigeon_coap_parse_endpoint(void) {
  if (pigeon_coap_endpoint_parsed) {
    return 0;
  }

  const char *endpoint = CONFIG_PIGEON_ENDPOINT;
  const char *scheme_end = strstr(endpoint, "://");

  if (!scheme_end) {
    LOG_ERR("CONFIG_PIGEON_ENDPOINT missing scheme: %s", endpoint);
    return -EINVAL;
  }

  const char *host_start = scheme_end + 3;
  const char *path_start = strchr(host_start, '/');
  size_t host_port_len = path_start ? (size_t)(path_start - host_start) : strlen(host_start);

  if (host_port_len == 0) {
    LOG_ERR("CONFIG_PIGEON_ENDPOINT host empty");
    return -EINVAL;
  }

  const char *colon = memchr(host_start, ':', host_port_len);
  size_t host_len = colon ? (size_t)(colon - host_start) : host_port_len;

  if (host_len == 0 || host_len >= sizeof(pigeon_coap_host)) {
    LOG_ERR("CONFIG_PIGEON_ENDPOINT host empty or too long");
    return -EINVAL;
  }

  memcpy(pigeon_coap_host, host_start, host_len);
  pigeon_coap_host[host_len] = '\0';

  if (colon) {
    size_t port_len = host_port_len - (size_t)(colon - host_start) - 1;

    if (port_len == 0 || port_len >= sizeof(pigeon_coap_port)) {
      LOG_ERR("CONFIG_PIGEON_ENDPOINT port empty or too long");
      return -EINVAL;
    }

    memcpy(pigeon_coap_port, colon + 1, port_len);
    pigeon_coap_port[port_len] = '\0';
  } else {
    /* RFC 8323 sec 8.4: coaps+tcp's default port matches coaps (DTLS), 5684. */
    strcpy(pigeon_coap_port, "5684");
  }

  if (path_start) {
    if (strlen(path_start) >= sizeof(pigeon_coap_path)) {
      LOG_ERR("CONFIG_PIGEON_ENDPOINT path too long");
      return -EINVAL;
    }
    strcpy(pigeon_coap_path, path_start);
  } else {
    pigeon_coap_path[0] = '\0';
  }

  pigeon_coap_endpoint_parsed = true;

  return 0;
}

/* Registers PSK credentials from pigeon_init()'s config, if the app supplied
 * any -- tls_psk_identity/tls_psk_secret are optional (NULL when the app
 * relies on a CA cert it provisioned itself under the same sec_tag instead,
 * matching pigeon_https.c's provisioning model). */
static int pigeon_coap_register_psk(void) {
  if (pigeon_coap_psk_registered) {
    return 0;
  }

  const struct pigeon_coap_config *cfg = pigeon_active_coap_config();

  if (!cfg->tls_psk_identity || !cfg->tls_psk_secret) {
    return 0;
  }

  int err = tls_credential_add(
      CONFIG_PIGEON_COAP_SEC_TAG, TLS_CREDENTIAL_PSK_ID, cfg->tls_psk_identity,
      strlen(cfg->tls_psk_identity)
  );

  if (err) {
    LOG_ERR("Failed to register CoAP PSK identity: %d", err);
    return err;
  }

  err = tls_credential_add(
      CONFIG_PIGEON_COAP_SEC_TAG, TLS_CREDENTIAL_PSK, cfg->tls_psk_secret,
      strlen(cfg->tls_psk_secret)
  );

  if (err) {
    LOG_ERR("Failed to register CoAP PSK secret: %d", err);
    return err;
  }

  pigeon_coap_psk_registered = true;

  return 0;
}

static int pigeon_coap_connect(void) {
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

static int pigeon_coap_recv_exact(int sock, uint8_t *buf, size_t len) {
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

/* Uri-Path has no single "/a/b" option like HTTP (RFC 7252 sec 6.4) -- one
 * option per path segment, in order. Appends a final leaf segment ("shadow"
 * or "telemetry"), mirroring pigeon_https.c's "<path>/<leaf>".
 *
 * Splits path by hand (rather than strtok_r) since strtok_r isn't visible
 * under this project's -std=c17 build without libc-specific feature-test
 * macros -- confirmed by an actual build failure on native_sim's host libc. */
static int pigeon_coap_append_uri_path(
    struct coap_packet *cpkt, const char *path, const char *leaf
) {
  char path_copy[PIGEON_COAP_PATH_MAX];

  strncpy(path_copy, path, sizeof(path_copy) - 1);
  path_copy[sizeof(path_copy) - 1] = '\0';

  char *p = path_copy;

  while (*p) {
    while (*p == '/') {
      p++;
    }
    if (!*p) {
      break;
    }

    char *seg_start = p;

    while (*p && *p != '/') {
      p++;
    }

    bool at_end = (*p == '\0');

    *p = '\0';

    int err = coap_packet_append_option(
        cpkt, COAP_OPTION_URI_PATH, (const uint8_t *)seg_start, strlen(seg_start)
    );
    if (err) {
      return err;
    }

    if (at_end) {
      break;
    }

    p++;
  }

  return coap_packet_append_option(cpkt, COAP_OPTION_URI_PATH, (const uint8_t *)leaf, strlen(leaf));
}

/* Builds an RFC 8323 CoAP-over-TLS/TCP request frame into buf. Uri-Path is
 * pigeon_coap_path + "/<leaf>"; the device bearer token rides in a
 * Uri-Query option (CoAP has no header mechanism to mirror pigeon_https.c's
 * "Authorization: Bearer" -- this shape is a placeholder pending backend
 * CoAP support, since dovecote has no CoAP listener at all yet).
 *
 * Returns (via out_start/out_len) a pointer into buf and length ready to
 * send as-is -- the length header is written right-aligned into the
 * PIGEON_COAP_HDR_MAX-byte reserve immediately before the fixed Code/Token
 * position, so nothing needs to be shifted once the final size is known. */
static int pigeon_coap_build_request(
    uint8_t *buf, size_t buf_len, uint8_t code, const char *leaf, const uint8_t *payload,
    size_t payload_len, uint8_t **out_start, size_t *out_len
) {
  if (buf_len < PIGEON_COAP_PRE_OPTS) {
    return -ENOSPC;
  }

  uint8_t *token = coap_next_token();

  buf[PIGEON_COAP_HDR_MAX] = code;
  memcpy(buf + PIGEON_COAP_HDR_MAX + 1, token, PIGEON_COAP_TKL);

  struct coap_packet cpkt = {
      .data = buf,
      .offset = PIGEON_COAP_PRE_OPTS,
      .max_len = (uint16_t)buf_len,
      .hdr_len = PIGEON_COAP_PRE_OPTS,
  };

  int err = pigeon_coap_append_uri_path(&cpkt, pigeon_coap_path, leaf);

  if (err) {
    return err;
  }

  if (payload && payload_len) {
    err = coap_append_option_int(&cpkt, COAP_OPTION_CONTENT_FORMAT, COAP_CONTENT_FORMAT_APP_JSON);
    if (err) {
      return err;
    }
  }

  char query[PIGEON_COAP_QUERY_MAX];

  snprintk(query, sizeof(query), "auth=%s", CONFIG_PIGEON_TOKEN);
  err = coap_packet_append_option(
      &cpkt, COAP_OPTION_URI_QUERY, (const uint8_t *)query, strlen(query)
  );
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
  size_t body_len = cpkt.offset - PIGEON_COAP_PRE_OPTS;
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
  uint8_t *hdr = buf + PIGEON_COAP_HDR_MAX - hdr_size;

  hdr[0] = (uint8_t)((len_nibble << 4) | (PIGEON_COAP_TKL & 0x0F));

  if (ext_len_bytes == 1) {
    hdr[1] = (uint8_t)ext_val;
  } else if (ext_len_bytes == 2) {
    sys_put_be16((uint16_t)ext_val, &hdr[1]);
  } else if (ext_len_bytes == 4) {
    sys_put_be32(ext_val, &hdr[1]);
  }

  *out_start = hdr;
  *out_len = hdr_size + 1 + PIGEON_COAP_TKL + body_len;

  return 0;
}

/* Reads one RFC 8323 frame from sock into body_buf (the Options+Payload
 * region only -- Len/Extended Length, Code, and Token are consumed here and
 * not copied out). */
static int pigeon_coap_read_frame(
    int sock, uint8_t *body_buf, size_t body_buf_len, size_t *body_len_out, uint8_t *code_out
) {
  uint8_t first;
  int err = pigeon_coap_recv_exact(sock, &first, 1);

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

    err = pigeon_coap_recv_exact(sock, &ext, 1);
    if (err) {
      return err;
    }
    body_len = 13 + ext;
  } else if (len_nibble == 14) {
    uint8_t ext[2];

    err = pigeon_coap_recv_exact(sock, ext, sizeof(ext));
    if (err) {
      return err;
    }
    body_len = 269 + sys_get_be16(ext);
  } else {
    uint8_t ext[4];

    err = pigeon_coap_recv_exact(sock, ext, sizeof(ext));
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

  err = pigeon_coap_recv_exact(sock, code_and_token, (size_t)(1 + tkl));
  if (err) {
    return err;
  }

  if (body_len > body_buf_len) {
    LOG_ERR("CoAP response body (%zu) exceeds buffer (%zu)", body_len, body_buf_len);
    return -ENOSPC;
  }

  err = pigeon_coap_recv_exact(sock, body_buf, body_len);
  if (err) {
    return err;
  }

  *body_len_out = body_len;
  *code_out = code_and_token[0];

  return 0;
}

/* Skips over the (delta/length-encoded, RFC 7252 sec 3.1) Options in body to
 * find the payload, if any. This client never needs an option's own value
 * (mirroring pigeon_https.c not caring about response headers beyond
 * status), only where it ends. */
static int pigeon_coap_find_payload(
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

static int pigeon_coap_exchange(
    uint8_t code, const char *leaf, const uint8_t *payload, size_t payload_len, uint8_t *rsp_code
) {
  int err = pigeon_coap_parse_endpoint();

  if (err) {
    return err;
  }

  int sock = pigeon_coap_connect();

  if (sock < 0) {
    return sock;
  }

  uint8_t req_buf[PIGEON_COAP_MSG_MAX];
  uint8_t *req_start;
  size_t req_len;

  err = pigeon_coap_build_request(
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

  pigeon_coap_body_len = 0;
  err = pigeon_coap_read_frame(
      sock, pigeon_coap_body, sizeof(pigeon_coap_body), &pigeon_coap_body_len, rsp_code
  );
  zsock_close(sock);

  return err;
}

int pigeon_shadow_get(struct pigeon_shadow_doc *out) {
  if (!out) {
    return -EINVAL;
  }

  uint8_t rsp_code;
  int err = pigeon_coap_exchange(COAP_METHOD_GET, "shadow", NULL, 0, &rsp_code);

  if (err) {
    return err;
  }

  if ((rsp_code >> 5) != 2) {
    LOG_ERR("Shadow GET returned CoAP %u.%02u", rsp_code >> 5, rsp_code & 0x1F);
    return -EIO;
  }

  uint8_t *payload;
  size_t payload_len;

  err = pigeon_coap_find_payload(pigeon_coap_body, pigeon_coap_body_len, &payload, &payload_len);
  if (err) {
    return err;
  }

  if (!payload || payload_len == 0) {
    LOG_ERR("Shadow GET returned no payload");
    return -ENODATA;
  }

  int64_t decoded = json_obj_parse(
      (char *)payload, payload_len, pigeon_coap_shadow_wire_descr,
      ARRAY_SIZE(pigeon_coap_shadow_wire_descr), &pigeon_coap_shadow_wire
  );

  /* All 5 descriptor fields must decode: bits 0-4 set (0x1F). */
  if (decoded < 0 || (decoded & 0x1F) != 0x1F) {
    LOG_ERR("Failed to parse shadow response JSON (decoded=%lld)", decoded);
    return decoded < 0 ? (int)decoded : -EBADMSG;
  }

  out->target_version = pigeon_coap_shadow_wire.target_version;
  out->current_version = pigeon_coap_shadow_wire.current_version;
  out->target_config = pigeon_coap_shadow_wire.target_config;
  out->current_config = pigeon_coap_shadow_wire.current_config;
  out->updated_at = pigeon_coap_shadow_wire.updated_at;

  return 0;
}

int pigeon_transport_report_shadow(const char *key, const char *val) {
  /* Escaped forms can be up to ~6x the raw key/val in the worst case (every
   * byte a control character needing \u00XX -- pigeon_json_escape()'s only
   * unescaped-length guarantee is truncation, never overflow, but sizing
   * for the true worst case avoids silently losing most of an otherwise-
   * legitimate value). PIGEON_SHADOW_KEY_MAX=32/PIGEON_SHADOW_VAL_MAX=128
   * in pigeon_core.c -- 32*6+1=193, 128*6+1=769, rounded up. Note this
   * doesn't change PIGEON_COAP_MSG_MAX's own 640-byte frame ceiling below
   * -- a pathological all-control-character value can still legitimately
   * fail to fit a single CoAP frame, same bounded (non-overflowing)
   * behavior as before, just via a different, already-safe failure path
   * (coap_packet_append_payload()'s own bounds check) instead of silent
   * mid-string truncation. */
  char key_esc[200];
  char val_esc[800];

  pigeon_json_escape(key, key_esc, sizeof(key_esc));
  pigeon_json_escape(val, val_esc, sizeof(val_esc));

  char body[sizeof(key_esc) + sizeof(val_esc) + 8];

  snprintk(body, sizeof(body), "{\"%s\":\"%s\"}", key_esc, val_esc);

  uint8_t rsp_code;
  int err = pigeon_coap_exchange(
      COAP_METHOD_POST, "telemetry", (const uint8_t *)body, strlen(body), &rsp_code
  );

  if (err) {
    return err;
  }

  /* dovecote's telemetry route exists over HTTPS (report_telemetry_device),
   * but it still has no CoAP listener at all -- until one exists this can
   * only fail at connect(), never reach a real 2.xx. */
  if ((rsp_code >> 5) != 2) {
    LOG_ERR("Telemetry report POST returned CoAP %u.%02u", rsp_code >> 5, rsp_code & 0x1F);
    return -EIO;
  }

  return 0;
}

int pigeon_shadow_report(int32_t current_version, const char *current_config) {
  /* current_config is embedded verbatim as a raw JSON object -- not
   * quote-escaped, trusted to already be valid JSON (the caller's
   * responsibility; see the matching note in pigeon_https.c). The margin
   * covers the fixed JSON framing plus an 11-char int32 (49 bytes). */
  char body[PIGEON_COAP_CONFIG_MAX + 64];

  snprintk(
      body, sizeof(body), "{\"current_config\":%s,\"current_version\":%d}", current_config,
      current_version
  );

  uint8_t rsp_code;
  int err = pigeon_coap_exchange(
      COAP_METHOD_POST, "shadow", (const uint8_t *)body, strlen(body), &rsp_code
  );

  if (err) {
    return err;
  }

  if ((rsp_code >> 5) != 2) {
    LOG_ERR("Shadow report POST returned CoAP %u.%02u", rsp_code >> 5, rsp_code & 0x1F);
    return -EIO;
  }

  return 0;
}
