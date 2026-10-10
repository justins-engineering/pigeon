#include <errno.h>
#include <pigeon.h>
#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#include "pigeon_coap_internal.h"
#include "pigeon_internal.h"
#include "pigeon_psk.h"
#include "pigeon_shadow_wire.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

/* The transport determines the endpoint scheme: RFC 8323 TLS/TCP endpoints
 * are coaps+tcp://, RFC 7252 DTLS/UDP endpoints are coaps://. Both default
 * to port 5684 (RFC 8323 sec 8.4 gives coaps+tcp the same default as
 * coaps). */
#if defined(CONFIG_PIGEON_COAP_TRANSPORT_UDP)
#define PIGEON_COAP_SCHEME "coaps"
#else
#define PIGEON_COAP_SCHEME "coaps+tcp"
#endif
#define PIGEON_COAP_DEFAULT_PORT "5684"

/* A literal endpoint naming the other transport is a build error where the compiler folds a
 * string comparison (GCC and Clang do); pigeon_coap_parse_endpoint() still checks at first use
 * elsewhere. An empty endpoint is an unprovisioned build and stays legal. */
#if defined(__GNUC__)
BUILD_ASSERT(
    sizeof(CONFIG_PIGEON_ENDPOINT) == 1 ||
        __builtin_strncmp(
            CONFIG_PIGEON_ENDPOINT, PIGEON_COAP_SCHEME "://", sizeof(PIGEON_COAP_SCHEME "://") - 1
        ) == 0,
    "CONFIG_PIGEON_ENDPOINT must start with " PIGEON_COAP_SCHEME
    "://, the scheme of the CoAP transport this build selected"
);
#endif

char pigeon_coap_host[PIGEON_COAP_HOST_MAX];
char pigeon_coap_port[PIGEON_COAP_PORT_MAX];
char pigeon_coap_path[PIGEON_COAP_PATH_MAX];
static bool pigeon_coap_endpoint_parsed;

static bool pigeon_coap_psk_registered;

/* Decoded into here, so the pointers pigeon_shadow_get() hands out stay valid until the next
 * call, as pigeon.h documents. */
static struct pigeon_shadow_wire pigeon_coap_shadow_wire;

/* A block-wise shadow response, reassembled. No larger than the largest document the config cap
 * allows, so a terminator cannot make the device hold more. Dead once the GET has decoded it into
 * pigeon_coap_shadow_wire, so the shadow report builds its body here, under the same lock. */
static uint8_t pigeon_coap_shadow_blocks[PIGEON_SHADOW_DOC_MAX];

BUILD_ASSERT(PIGEON_SHADOW_DOC_MAX >= PIGEON_COAP_REPORT_BODY_MAX);

#if defined(CONFIG_PIGEON_COAP_BLOCK2_SIZE)
BUILD_ASSERT(
    (CONFIG_PIGEON_COAP_BLOCK2_SIZE & (CONFIG_PIGEON_COAP_BLOCK2_SIZE - 1)) == 0,
    "CONFIG_PIGEON_COAP_BLOCK2_SIZE must be 16, 32, 64, 128, 256, 512 or 1024"
);
/* RFC 7959 sec 2.2: a block of 2^(szx + 4) bytes. */
#define PIGEON_COAP_BLOCK2_SZX ((uint32_t)LOG2(CONFIG_PIGEON_COAP_BLOCK2_SIZE) - 4U)
#endif

BUILD_ASSERT(
    (CONFIG_PIGEON_COAP_BLOCK2_MIN_SIZE & (CONFIG_PIGEON_COAP_BLOCK2_MIN_SIZE - 1)) == 0,
    "CONFIG_PIGEON_COAP_BLOCK2_MIN_SIZE must be 16, 32, 64, 128, 256, 512 or 1024"
);
#if defined(CONFIG_PIGEON_COAP_BLOCK2_SIZE)
BUILD_ASSERT(
    CONFIG_PIGEON_COAP_BLOCK2_MIN_SIZE <= CONFIG_PIGEON_COAP_BLOCK2_SIZE,
    "CONFIG_PIGEON_COAP_BLOCK2_MIN_SIZE must not exceed CONFIG_PIGEON_COAP_BLOCK2_SIZE"
);
#endif
#define PIGEON_COAP_BLOCK2_MIN_SZX ((uint32_t)LOG2(CONFIG_PIGEON_COAP_BLOCK2_MIN_SIZE) - 4U)

/* RFC 7959 sec 2.2's Block option value: num << 4 | m << 3 | szx. */
#define PIGEON_COAP_BLOCK_NUM(v) ((v) >> 4)
#define PIGEON_COAP_BLOCK_MORE(v) (((v) & 0x08U) != 0)
#define PIGEON_COAP_BLOCK_SZX(v) ((v) & 0x07U)

int pigeon_coap_parse_endpoint(void) {
  if (pigeon_coap_endpoint_parsed) {
    return 0;
  }

  const char *endpoint = CONFIG_PIGEON_ENDPOINT;
  const char *scheme_end = strstr(endpoint, "://");

  if (!scheme_end) {
    LOG_ERR("CONFIG_PIGEON_ENDPOINT missing scheme: %s", endpoint);
    return -EINVAL;
  }

  size_t scheme_len = (size_t)(scheme_end - endpoint);

  if (scheme_len != strlen(PIGEON_COAP_SCHEME) ||
      strncmp(endpoint, PIGEON_COAP_SCHEME, scheme_len) != 0) {
    LOG_ERR(
        "CONFIG_PIGEON_ENDPOINT scheme mismatch: this build's CoAP transport wants " PIGEON_COAP_SCHEME
        "://, got %s",
        endpoint
    );
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
    strcpy(pigeon_coap_port, PIGEON_COAP_DEFAULT_PORT);
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

int pigeon_coap_register_psk(void) {
  if (pigeon_coap_psk_registered) {
    return 0;
  }

  const struct pigeon_coap_config *cfg = pigeon_active_coap_config();

  if (!cfg->tls_psk_identity || !cfg->tls_psk_secret) {
    return 0;
  }

  int err = pigeon_psk_register(
      CONFIG_PIGEON_COAP_SEC_TAG, cfg->tls_psk_identity, cfg->tls_psk_secret
  );

  if (err) {
    return err;
  }

  pigeon_coap_psk_registered = true;

  return 0;
}

/* Uri-Path has no single "/a/b" option like HTTP (RFC 7252 sec 6.4) -- one
 * option per path segment, in order. Appends a final leaf segment ("shadow"
 * or "telemetry"), mirroring pigeon_https.c's "<path>/<leaf>".
 *
 * Splits path by hand (rather than strtok_r) since strtok_r isn't visible
 * under this project's -std=c17 build without libc-specific feature-test
 * macros. */
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

int pigeon_coap_append_request_options(
    struct coap_packet *cpkt, const char *leaf, bool has_payload,
    const struct pigeon_coap_req_opts *opts
) {
  int err = pigeon_coap_append_uri_path(cpkt, pigeon_coap_path, leaf);

  if (err) {
    return err;
  }

  if (has_payload) {
    uint16_t format = opts ? opts->content_format : COAP_CONTENT_FORMAT_APP_JSON;

    err = coap_append_option_int(cpkt, COAP_OPTION_CONTENT_FORMAT, format);
    if (err) {
      return err;
    }
  }

  /* Block2 (23) and Block1 (27) go on after Content-Format (12): options must be appended in
   * ascending option number. */
  if (opts && opts->has_block2) {
    err = coap_append_option_int(cpkt, COAP_OPTION_BLOCK2, opts->block2);
    if (err) {
      return err;
    }
  }

  if (opts && opts->block1) {
    return coap_append_block1_option(cpkt, opts->block1);
  }

  return 0;
}

/* An extended option delta or length (RFC 7252 sec 3.1): 13 and 14 take one and two more bytes,
 * 15 is reserved. */
static int pigeon_coap_read_ext(
    const uint8_t *body, size_t len, size_t *off, uint8_t nibble, uint32_t *out
) {
  if (nibble < 13) {
    *out = nibble;
  } else if (nibble == 13 && len - *off >= 1) {
    *out = 13U + body[*off];
    *off += 1;
  } else if (nibble == 14 && len - *off >= 2) {
    *out = 269U + sys_get_be16(&body[*off]);
    *off += 2;
  } else {
    return -EBADMSG;
  }

  return 0;
}

/* A uint option (RFC 7252 sec 3.2): big-endian, leading zeros dropped. Block2 and Size2 both
 * fit four bytes. */
static int pigeon_coap_read_uint(const uint8_t *val, uint32_t len, uint32_t *out) {
  if (len > sizeof(*out)) {
    return -EBADMSG;
  }

  *out = 0;
  for (uint32_t i = 0; i < len; i++) {
    *out = (*out << 8) | val[i];
  }

  return 0;
}

int pigeon_coap_read_body(
    uint8_t code, const uint8_t *body, size_t len, struct pigeon_coap_rsp *rsp
) {
  size_t off = 0;
  uint32_t number = 0;

  memset(rsp, 0, sizeof(*rsp));
  rsp->code = code;

  while (off < len) {
    uint8_t head = body[off++];

    if (head == 0xFF) {
      if (off < len) {
        rsp->payload = body + off;
        rsp->payload_len = len - off;
      }
      return 0;
    }

    uint32_t delta;
    uint32_t opt_len;

    if (pigeon_coap_read_ext(body, len, &off, head >> 4, &delta) ||
        pigeon_coap_read_ext(body, len, &off, head & 0x0F, &opt_len) || opt_len > len - off) {
      return -EBADMSG;
    }

    const uint8_t *val = body + off;
    int err = 0;

    off += opt_len;
    number += delta;

    switch (number) {
      case COAP_OPTION_ETAG:
        if (opt_len == 0 || opt_len > sizeof(rsp->etag)) {
          return -EBADMSG;
        }
        memcpy(rsp->etag, val, opt_len);
        rsp->etag_len = (uint8_t)opt_len;
        break;
      case COAP_OPTION_BLOCK2:
        err = pigeon_coap_read_uint(val, opt_len, &rsp->block2);
        rsp->has_block2 = true;
        break;
      case COAP_OPTION_SIZE2:
        err = pigeon_coap_read_uint(val, opt_len, &rsp->size2);
        rsp->has_size2 = true;
        break;
      default:
        break;
    }

    if (err) {
      return err;
    }
  }

  return 0;
}

int pigeon_coap_read_packet(const struct coap_packet *pkt, struct pigeon_coap_rsp *rsp) {
  return pigeon_coap_read_body(
      coap_header_get_code(pkt), pkt->data + pkt->hdr_len, pkt->offset - pkt->hdr_len, rsp
  );
}

BUILD_ASSERT(
    CONFIG_PIGEON_COAP_AUTH_BACKOFF_FIRST_SEC <= CONFIG_PIGEON_COAP_AUTH_BACKOFF_SEC,
    "CONFIG_PIGEON_COAP_AUTH_BACKOFF_FIRST_SEC must not exceed CONFIG_PIGEON_COAP_AUTH_BACKOFF_SEC"
);

/* Uptime until which every request answers -EACCES with no radio access, once the platform has
 * refused this device's credentials or identity. Written under the transport lock, as is the
 * count of refusals since the platform last answered otherwise. */
static int64_t pigeon_coap_auth_hold_until;
static uint8_t pigeon_coap_auth_refusals;

/* The first hold, doubled for each refusal after it, at most the ceiling. */
static int64_t pigeon_coap_auth_hold_ms(void) {
  const int64_t ceiling = (int64_t)CONFIG_PIGEON_COAP_AUTH_BACKOFF_SEC * MSEC_PER_SEC;
  int64_t hold = (int64_t)CONFIG_PIGEON_COAP_AUTH_BACKOFF_FIRST_SEC * MSEC_PER_SEC;

  for (uint8_t i = 1; i < pigeon_coap_auth_refusals && hold < ceiling; i++) {
    hold *= 2;
  }

  return MIN(hold, ceiling);
}

/* Every request goes through here. A refusal that names the credentials or the identity answers
 * the same to every retry until something changes off the device (a re-provisioned PSK, a
 * refreshed token, an undeleted pigeon), so retrying at the application's cadence only spends
 * radio and the terminator's patience: hold off instead, as the MQTT connector does. The same
 * refusal can come from an outage that ends on its own, so the hold starts short and grows. */
static int pigeon_coap_exchange(
    uint8_t code, const char *leaf, const uint8_t *payload, size_t payload_len,
    const struct pigeon_coap_req_opts *opts, struct pigeon_coap_rsp *rsp
) {
  if (k_uptime_get() < pigeon_coap_auth_hold_until) {
    return -EACCES;
  }

  int err = pigeon_coap_transport_exchange(code, leaf, payload, payload_len, opts, rsp);

  if (err == PIGEON_COAP_HANDSHAKE_REFUSED ||
      (err == 0 && (rsp->code == COAP_RESPONSE_CODE_UNAUTHORIZED ||
                    rsp->code == COAP_RESPONSE_CODE_FORBIDDEN))) {
    if (pigeon_coap_auth_refusals < UINT8_MAX) {
      pigeon_coap_auth_refusals++;
    }

    int64_t hold_ms = pigeon_coap_auth_hold_ms();

    LOG_ERR(
        "Platform refused this device's credentials (%s); holding every CoAP request for %d s",
        err ? "handshake" : (rsp->code == COAP_RESPONSE_CODE_UNAUTHORIZED ? "4.01" : "4.03"),
        (int)(hold_ms / MSEC_PER_SEC)
    );
    pigeon_coap_auth_hold_until = k_uptime_get() + hold_ms;
    return -EACCES;
  }

  if (err == 0) {
    pigeon_coap_auth_refusals = 0;
  }

  return err;
}

static int pigeon_shadow_get_locked(struct pigeon_shadow_doc *out) {
  struct pigeon_coap_req_opts opts = {0};
  struct pigeon_coap_rsp rsp;
  /* What block 0 said, which every later block must agree with. */
  uint8_t etag[PIGEON_COAP_ETAG_MAX];
  uint8_t etag_len = 0;
  bool has_size2 = false;
  uint32_t size2 = 0;
  uint32_t szx = 0;
  uint32_t num = 0;
  size_t len = 0;
  /* The terminator picks the block size and so the number of exchanges, all under the lock. */
  int64_t deadline =
      k_uptime_get() + (int64_t)CONFIG_PIGEON_COAP_SHADOW_GET_BUDGET_SEC * MSEC_PER_SEC;

#if defined(CONFIG_PIGEON_COAP_BLOCK2_SIZE)
  /* Asked for on the first request, so the terminator never sends the whole document in one
   * datagram the link cannot carry. */
  opts.has_block2 = true;
  opts.block2 = PIGEON_COAP_BLOCK2_SZX;
#endif

  for (;;) {
    if (num > 0 && k_uptime_get() >= deadline) {
      LOG_WRN("Shadow GET abandoned at block %u: budget spent", num);
      return -ETIMEDOUT;
    }

    int err = pigeon_coap_exchange(COAP_METHOD_GET, "shadow", NULL, 0, &opts, &rsp);

    if (err) {
      return err;
    }

    if ((rsp.code >> 5) != 2) {
      LOG_ERR("Shadow GET returned CoAP %u.%02u", rsp.code >> 5, rsp.code & 0x1F);
      return -EIO;
    }

    if (!rsp.has_block2) {
      if (num > 0) {
        LOG_ERR("Shadow block %u came back without Block2", num);
        return -EBADMSG;
      }

      if (!rsp.payload) {
        LOG_ERR("Shadow GET returned no payload");
        return -ENODATA;
      }

      /* The whole document in one response. It sits in the transport's static response buffer,
       * which the next exchange overwrites anyway, so the parse may rewrite it. */
      return pigeon_shadow_wire_decode(
          (char *)rsp.payload, rsp.payload_len, &pigeon_coap_shadow_wire, out
      );
    }

    uint32_t got = PIGEON_COAP_BLOCK_SZX(rsp.block2);

    if (num == 0) {
      /* A server may answer in smaller blocks than asked, never larger (RFC 7959 sec 2.4), and
       * below the floor the exchanges are not worth it; 7 is RFC 8323's BERT, which this client
       * does not offer. */
      if (PIGEON_COAP_BLOCK_NUM(rsp.block2) != 0 || got == 7 || got < PIGEON_COAP_BLOCK2_MIN_SZX ||
          (opts.has_block2 && got > PIGEON_COAP_BLOCK_SZX(opts.block2))) {
        LOG_ERR("Shadow GET answered with Block2 0x%x", rsp.block2);
        return -EBADMSG;
      }

      szx = got;
      etag_len = rsp.etag_len;
      memcpy(etag, rsp.etag, etag_len);
      has_size2 = rsp.has_size2;
      size2 = rsp.size2;

      if (has_size2 && size2 > sizeof(pigeon_coap_shadow_blocks)) {
        LOG_ERR("Shadow of %u bytes does not fit (see CONFIG_PIGEON_SHADOW_CONFIG_MAX)", size2);
        return -EMSGSIZE;
      }
    } else if (PIGEON_COAP_BLOCK_NUM(rsp.block2) != num || got != szx) {
      LOG_ERR("Shadow block %u answered with Block2 0x%x", num, rsp.block2);
      return -EBADMSG;
    } else if (rsp.etag_len != etag_len || memcmp(rsp.etag, etag, etag_len) != 0) {
      LOG_WRN("Shadow changed between blocks");
      return -EAGAIN;
    }

    size_t block_len = (size_t)1 << (szx + 4);

    /* Every block but the last is full (RFC 7959 sec 2.2), so a short one lost bytes. */
    if (rsp.payload_len > block_len ||
        (PIGEON_COAP_BLOCK_MORE(rsp.block2) && rsp.payload_len != block_len)) {
      LOG_ERR("Shadow block %u carries %u bytes", num, (unsigned)rsp.payload_len);
      return -EBADMSG;
    }

    if (rsp.payload_len > sizeof(pigeon_coap_shadow_blocks) - len) {
      LOG_ERR("Shadow does not fit (see CONFIG_PIGEON_SHADOW_CONFIG_MAX)");
      return -EMSGSIZE;
    }

    if (rsp.payload_len) {
      memcpy(pigeon_coap_shadow_blocks + len, rsp.payload, rsp.payload_len);
      len += rsp.payload_len;
    }

    if (!PIGEON_COAP_BLOCK_MORE(rsp.block2)) {
      break;
    }

    num++;
    opts.has_block2 = true;
    opts.block2 = (num << 4) | szx;
  }

  /* Without an ETag, a document that changed length between blocks shows only here. */
  if (has_size2 && len != size2) {
    LOG_WRN("Shadow changed between blocks (%u of %u bytes)", (unsigned)len, size2);
    return -EAGAIN;
  }

  if (len == 0) {
    LOG_ERR("Shadow GET returned no payload");
    return -ENODATA;
  }

  return pigeon_shadow_wire_decode(
      (char *)pigeon_coap_shadow_blocks, len, &pigeon_coap_shadow_wire, out
  );
}

int pigeon_shadow_get(struct pigeon_shadow_doc *out) {
  if (!out) {
    return -EINVAL;
  }

  (void)pigeon_transport_lock(K_FOREVER);

  int err = pigeon_shadow_get_locked(out);

  pigeon_transport_unlock();

  /* The lock covers the exchange and the decode, but out's config pointers
   * alias pigeon_coap_shadow_wire and escape it -- they stay valid only
   * until the next call into this module, exactly as pigeon.h documents and
   * exactly as pigeon_https.c's equivalent behaves. A caller that shares
   * them with another thread must copy them out first. */
  return err;
}

static int pigeon_transport_report_telemetry_locked(const char *body, size_t body_len) {
  /* body arrives pre-escaped and pre-framed (one flat JSON object of every
   * pending key, at most PIGEON_TELEMETRY_BODY_MAX bytes) from
   * pigeon_core.c's pigeon_telemetry_flush(). PIGEON_COAP_REQ_MAX is sized
   * off PIGEON_TELEMETRY_BODY_MAX (see pigeon_coap_internal.h) so a full
   * batch always fits the frame; coap_packet_append_payload()'s own bounds
   * check remains the safe failure path regardless. */
  struct pigeon_coap_rsp rsp;
  int err = pigeon_coap_exchange(
      COAP_METHOD_POST, "telemetry", (const uint8_t *)body, body_len, NULL, &rsp
  );

  if (err) {
    return err;
  }

  if ((rsp.code >> 5) != 2) {
    LOG_ERR("Telemetry report POST returned CoAP %u.%02u", rsp.code >> 5, rsp.code & 0x1F);
    return -EIO;
  }

  return 0;
}

int pigeon_transport_report_telemetry(
    const char *body, size_t body_len, struct pigeon_http_result *res
) {
  if (!body || !body_len) {
    return -EINVAL;
  }

  /* CoAP answers in response codes, not HTTP statuses, and nothing on this
   * transport consumes the result yet (CONFIG_PIGEON_TELEMETRY_BATCH, the
   * only caller that reads it, depends on the HTTPS connector). Zeroed
   * rather than left untouched so a future caller reads "no status" instead
   * of whatever the caller happened to initialize it with. */
  if (res) {
    res->status = 0;
    res->retry_after_sec = 0;
  }

  (void)pigeon_transport_lock(K_FOREVER);

  int err = pigeon_transport_report_telemetry_locked(body, body_len);

  pigeon_transport_unlock();

  return err;
}

static int pigeon_shadow_report_locked(int32_t current_version, const char *current_config) {
  /* current_config is embedded verbatim as a raw JSON object -- not
   * quote-escaped, trusted to already be valid JSON (the caller's
   * responsibility; see the matching note in pigeon_https.c). */
  char *body = (char *)pigeon_coap_shadow_blocks;

  /* The cap pigeon.h documents and PIGEON_COAP_REPORT_BODY_MAX is sized for. A cut body is not
   * JSON: the platform would refuse it, and the same bytes again. */
  int err = pigeon_shadow_report_fits(current_config);

  if (err) {
    return err;
  }

  int len = snprintk(
      body, PIGEON_COAP_REPORT_BODY_MAX, "{\"current_config\":%s,\"current_version\":%d}",
      current_config, current_version
  );

  /* The answer echoes the whole shadow, as large as a GET's, and only its code is read. Asking
   * for its smallest block (16 bytes) leaves the rest on the terminator, so it is never a
   * datagram the link cannot carry, whatever the terminator's own ceiling. */
  struct pigeon_coap_req_opts opts = {
      .content_format = COAP_CONTENT_FORMAT_APP_JSON,
      .has_block2 = true,
      .block2 = 0,
  };
  struct pigeon_coap_rsp rsp;

  err = pigeon_coap_exchange(
      COAP_METHOD_POST, "shadow", (const uint8_t *)body, (size_t)len, &opts, &rsp
  );

  if (err) {
    return err;
  }

  if ((rsp.code >> 5) != 2) {
    LOG_ERR("Shadow report POST returned CoAP %u.%02u", rsp.code >> 5, rsp.code & 0x1F);
    return -EIO;
  }

  return 0;
}

int pigeon_shadow_report(int32_t current_version, const char *current_config) {
  if (!current_config) {
    return -EINVAL;
  }

  (void)pigeon_transport_lock(K_FOREVER);

  int err = pigeon_shadow_report_locked(current_version, current_config);

  pigeon_transport_unlock();

  return err;
}

#if defined(CONFIG_PIGEON_LOG_UPLOAD)
/* Sends one already-drained log batch as an RFC 7959 Block1 sequence.
 *
 * Block-wise rather than one message because a batch is sized by
 * CONFIG_PIGEON_LOG_UPLOAD_BUF_SIZE, which answers to how much log volume to
 * buffer, not to what fits a datagram -- the two have no reason to agree,
 * and at the 2048-byte default they do not. A batch that fits one block
 * still carries a Block1 option (num 0, more 0), which RFC 7959 permits and
 * the terminator treats exactly as the plain no-Block1 case.
 *
 * The terminator keys its reassembly on (connection, leaf) and refuses any
 * block that is not the next in sequence, so a failed block cannot be
 * retried in place -- this abandons the whole batch, and the next flush
 * starts a fresh num 0. That matches the backend's existing best-effort
 * contract rather than growing a retry path of its own. */
static int pigeon_transport_upload_logs_locked(const uint8_t *data, size_t len) {
  struct coap_block_context ctx;
  int err = coap_block_transfer_init(&ctx, PIGEON_COAP_LOG_BLOCK_SIZE, len);

  if (err) {
    return err;
  }

  const uint16_t block_bytes = coap_block_size_to_bytes(PIGEON_COAP_LOG_BLOCK_SIZE);
  int64_t deadline = k_uptime_get() + PIGEON_COAP_LOG_UPLOAD_BUDGET_MS;
  struct pigeon_coap_req_opts opts = {
      /* Dictionary-encoded binary records, not the JSON every other request
       * on this connector carries. */
      .content_format = COAP_CONTENT_FORMAT_APP_OCTET_STREAM,
      .block1 = &ctx,
  };

  while (ctx.current < len) {
    if (k_uptime_get() >= deadline) {
      LOG_WRN(
          "Log upload abandoned after %u of %u bytes: budget spent", (unsigned)ctx.current,
          (unsigned)len
      );
      return -ETIMEDOUT;
    }

    size_t remaining = len - ctx.current;
    size_t this_block = MIN(remaining, (size_t)block_bytes);
    bool last = (this_block == remaining);
    struct pigeon_coap_rsp rsp;

    err = pigeon_coap_exchange(
        COAP_METHOD_POST, "logs", data + ctx.current, this_block, &opts, &rsp
    );

    if (err) {
      return err;
    }

    if ((rsp.code >> 5) != 2) {
      LOG_ERR("Log upload POST returned CoAP %u.%02u", rsp.code >> 5, rsp.code & 0x1F);
      return -EIO;
    }

    /* 2.31 Continue is what acknowledges a non-final block; anything else
     * means the server stopped reassembling early, so every byte still
     * queued behind this one would be appended to nothing. */
    if (!last && rsp.code != COAP_RESPONSE_CODE_CONTINUE) {
      LOG_ERR(
          "Log upload block %u answered %u.%02u, expected 2.31 Continue",
          (unsigned)(ctx.current / block_bytes), rsp.code >> 5, rsp.code & 0x1F
      );
      return -EIO;
    }

    ctx.current += this_block;
  }

  return 0;
}

int pigeon_transport_upload_logs(const uint8_t *data, size_t len) {
  if (!data || !len) {
    return -EINVAL;
  }

  /* The one caller that waits with a bound instead of K_FOREVER, for the
   * reason PIGEON_COAP_LOG_LOCK_TIMEOUT_MS documents. -EBUSY lands in the
   * same best-effort "this batch is lost" path pigeon_log_backend.c already
   * applies to any other upload failure. */
  if (pigeon_transport_lock(K_MSEC(PIGEON_COAP_LOG_LOCK_TIMEOUT_MS)) != 0) {
    return -EBUSY;
  }

  int err = pigeon_transport_upload_logs_locked(data, len);

  pigeon_transport_unlock();

  return err;
}
#endif /* CONFIG_PIGEON_LOG_UPLOAD */
