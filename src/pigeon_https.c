#include <errno.h>
#include <pigeon.h>
#include <string.h>
#include <strings.h>
#include <zephyr/data/json.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/http/client.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>

#include "pigeon_internal.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

#define PIGEON_HTTPS_HOST_MAX 128
#define PIGEON_HTTPS_PATH_MAX 128
/* Sizes both the HTTP parser scratch buffer and the accumulated-body buffer
 * below off CONFIG_PIGEON_SHADOW_CONFIG_MAX (via PIGEON_HTTPS_CONFIG_MAX,
 * pigeon_internal.h), since a shadow GET body is by far the largest thing
 * either ever holds: two configs -- each up to CONFIG_MAX raw, and carried
 * on the wire as an escaped JSON string, where the dashboard-authored
 * quote/backslash density observed in real configs stays well under the
 * +25% growth budgeted here -- plus ~110 bytes of version/timestamp/key
 * framing, rounded up to 128. A fixed size with no escape headroom sits
 * one quote-dense config away from silent truncation; this formula gives
 * 2*400 + 128 = 928 bytes at the 320-byte default. */
#define PIGEON_HTTPS_RECV_BUF_LEN \
  (2 * (PIGEON_HTTPS_CONFIG_MAX + PIGEON_HTTPS_CONFIG_MAX / 4) + 128)
/* PIGEON_HTTPS_CONFIG_MAX itself now lives in pigeon_internal.h -- pigeon_ws.c's
 * shadow_update frame decode (see zephyr/Kconfig: CONFIG_PIGEON_WS) shares the
 * same cap on target_config/current_config, so one file owns the definition. */
#define PIGEON_HTTPS_AUTH_HEADER_MAX 384

/* This module's requests run under the shared transport lock
 * (pigeon_transport_lock(), pigeon_core.c) rather than a lock of their own,
 * because it has two jobs here and they need the same mutex.
 *
 * The first is this module's own state -- the lazily-parsed host/path, the
 * HTTP parser's scratch buffer, the accumulated body and its length, the
 * decoded shadow. All of it is module-global and was shared with no lock at
 * all across two genuinely concurrent callers: the log backend uploads from
 * the system workqueue (cooperative, higher priority than any pigeon
 * thread) while the poller thread fetches and reports the shadow. The
 * workqueue preempting the poller mid-request left the poller parsing a
 * body some other request had overwritten, or a body length belonging to
 * neither.
 *
 * The second is the modem's one-handshake-at-a-time limit, which is not
 * this module's alone to enforce: pigeon_ws.c opens its own TLS socket to
 * the same host with the same sec_tag, so a lock private to this file
 * would leave a WS reconnect free to handshake underneath an HTTPS
 * request.
 *
 * Held for one connect/request/close only, never across a multi-chunk
 * download, so a FOTA transfer still interleaves with shadow polling. */

/* How long the log-upload path waits for the lock before giving up on a
 * batch. Bounded rather than K_FOREVER because it runs on the system
 * workqueue: a request that stalls out its full 10s timeout must not hold
 * every other system work item behind it for that long. Comfortably longer
 * than a healthy request, so contention normally just delays a flush
 * instead of dropping one -- and a wait this long only happens when the
 * link is already sick, which is exactly when a lost log batch matters
 * least. The handler already occupies the workqueue for the upload itself,
 * so this bound keeps total occupancy in the same range as before. */
#define PIGEON_HTTPS_LOG_LOCK_TIMEOUT_MS 3000

/* Parsed once (lazily, on first use) from CONFIG_PIGEON_ENDPOINT, e.g.
 * "https://api.pidgeiot.com/device/pigeons/<id>" -> host + path, since
 * http_client_req() wants them separately. */
static char pigeon_https_host[PIGEON_HTTPS_HOST_MAX];
static char pigeon_https_path[PIGEON_HTTPS_PATH_MAX];
static bool pigeon_https_endpoint_parsed;

static uint8_t pigeon_https_recv_buf[PIGEON_HTTPS_RECV_BUF_LEN];

/* Body accumulated across (possibly multiple) http_response_cb_t calls. */
static char pigeon_https_body[PIGEON_HTTPS_RECV_BUF_LEN];
static size_t pigeon_https_body_len;

/* Wire shape of the JSON body GET <endpoint>/shadow returns (mirrors
 * capsules::PigeonShadow; see pigeon_shadow_doc in pigeon.h). target_config/
 * current_config are themselves JSON objects serialized as a string on the
 * wire (e.g. "target_config":"{\"log\":true}") -- decoding them with
 * JSON_TOK_STRING would hand back a raw, still-escaped pointer into
 * pigeon_https_body: '{\"log\":true}' is not valid JSON, so the app's own
 * json_obj_parse() on target_config would fail downstream regardless of
 * which keys/values it held. JSON_TOK_STRING_BUF actually unescapes into
 * a fixed-size buffer instead, so these are plain arrays (not pointers) and
 * this whole struct is a static instance (not a local), decoded into
 * directly -- pigeon_shadow_doc's target_config/current_config pointers
 * (see pigeon_shadow_get() below) alias straight into it, which is what
 * keeps them valid "until the next call" as pigeon.h documents, without a
 * separate copy-out step. */
struct pigeon_shadow_wire {
  int32_t target_version;
  int32_t current_version;
  char target_config[PIGEON_HTTPS_CONFIG_MAX];
  char current_config[PIGEON_HTTPS_CONFIG_MAX];
  int64_t updated_at;
};

static struct pigeon_shadow_wire pigeon_shadow_wire;

static const struct json_obj_descr pigeon_shadow_wire_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct pigeon_shadow_wire, target_version, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct pigeon_shadow_wire, current_version, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct pigeon_shadow_wire, target_config, JSON_TOK_STRING_BUF),
    JSON_OBJ_DESCR_PRIM(struct pigeon_shadow_wire, current_config, JSON_TOK_STRING_BUF),
    JSON_OBJ_DESCR_PRIM(struct pigeon_shadow_wire, updated_at, JSON_TOK_INT64),
};

/* Splits CONFIG_PIGEON_ENDPOINT ("https://host[:port]/path...") into
 * pigeon_https_host / pigeon_https_path once. */
static int pigeon_https_parse_endpoint(void) {
  if (pigeon_https_endpoint_parsed) {
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
  size_t host_len = path_start ? (size_t)(path_start - host_start) : strlen(host_start);

  if (host_len == 0 || host_len >= sizeof(pigeon_https_host)) {
    LOG_ERR("CONFIG_PIGEON_ENDPOINT host empty or too long");
    return -EINVAL;
  }

  memcpy(pigeon_https_host, host_start, host_len);
  pigeon_https_host[host_len] = '\0';

  if (path_start) {
    if (strlen(path_start) >= sizeof(pigeon_https_path)) {
      LOG_ERR("CONFIG_PIGEON_ENDPOINT path too long");
      return -EINVAL;
    }
    strcpy(pigeon_https_path, path_start);
  } else {
    pigeon_https_path[0] = '\0';
  }

  pigeon_https_endpoint_parsed = true;

  return 0;
}

static int pigeon_https_connect(void) {
  /* AF_UNSPEC, not AF_INET: a hard-coded v4 hint fails the resolve outright
   * on an IPv6-only cellular PDN, which hands back only AAAA records for
   * this host -- every request -EHOSTUNREACH, no fallback. Below,
   * each candidate the resolver returns (in its own ranked order, RFC
   * 6724) gets a real connect attempt; the loop moves on to the next one
   * on any failure instead of giving up on the first. */
  struct zsock_addrinfo hints = {
      .ai_family = AF_UNSPEC,
      .ai_socktype = SOCK_STREAM,
  };
  struct zsock_addrinfo *addr_list;

  int err = zsock_getaddrinfo(pigeon_https_host, "443", &hints, &addr_list);

  if (err) {
    LOG_ERR("Failed to resolve %s: %d", pigeon_https_host, err);
    return -EHOSTUNREACH;
  }

  /* SOCK_NATIVE_TLS (NCS-only, see CONFIG_PIGEON_HTTPS_NATIVE_TLS's help):
   * TLS in Zephyr's own mbedTLS over an offloaded TCP socket, for boards
   * whose CA cert lives in the native credential store, not the modem's.
   * Family-independent, so computed once rather than per candidate. */
  int sock_type = SOCK_STREAM;

#if defined(CONFIG_PIGEON_HTTPS_NATIVE_TLS)
  sock_type |= SOCK_NATIVE_TLS;
#endif

  int sock = -1;
  int last_errno = EHOSTUNREACH;

  for (struct zsock_addrinfo *res = addr_list; res; res = res->ai_next) {
    sock = zsock_socket(res->ai_family, sock_type, IPPROTO_TLS_1_2);

    if (sock < 0) {
      LOG_WRN("Failed to create TLS socket (family %d): %d", res->ai_family, -errno);
      last_errno = errno;
      continue;
    }

    sec_tag_t sec_tag_list[] = {CONFIG_PIGEON_HTTPS_SEC_TAG};

    err = zsock_setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_list, sizeof(sec_tag_list));
    if (err) {
      LOG_ERR("Failed to set TLS sec_tag %d: %d", CONFIG_PIGEON_HTTPS_SEC_TAG, -errno);
      last_errno = errno;
      zsock_close(sock);
      sock = -1;
      continue;
    }

    err = zsock_setsockopt(
        sock, SOL_TLS, TLS_HOSTNAME, pigeon_https_host, strlen(pigeon_https_host)
    );
    if (err) {
      LOG_ERR("Failed to set TLS hostname: %d", -errno);
      last_errno = errno;
      zsock_close(sock);
      sock = -1;
      continue;
    }

    err = zsock_connect(sock, res->ai_addr, res->ai_addrlen);
    if (err) {
      LOG_WRN(
          "Failed to connect to %s (family %d): %d, trying next address", pigeon_https_host,
          res->ai_family, -errno
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
        "Failed to connect to %s on every resolved address: %d", pigeon_https_host, last_errno
    );
    return -last_errno;
  }

  return sock;
}

static int pigeon_https_response_cb(
    struct http_response *rsp, enum http_final_call final_data, void *user_data
) {
  ARG_UNUSED(final_data);
  ARG_UNUSED(user_data);

  if (rsp->body_frag_start && rsp->body_frag_len) {
    size_t copy_len = rsp->body_frag_len;

    if (pigeon_https_body_len + copy_len >= sizeof(pigeon_https_body)) {
      copy_len = sizeof(pigeon_https_body) - pigeon_https_body_len - 1;
    }

    memcpy(pigeon_https_body + pigeon_https_body_len, rsp->body_frag_start, copy_len);
    pigeon_https_body_len += copy_len;
    pigeon_https_body[pigeon_https_body_len] = '\0';
  }

  return 0;
}

static int pigeon_shadow_get_locked(struct pigeon_shadow_doc *out) {
  int err = pigeon_https_parse_endpoint();

  if (err) {
    return err;
  }

  int sock = pigeon_https_connect();

  if (sock < 0) {
    return sock;
  }

  char url[PIGEON_HTTPS_PATH_MAX + sizeof("/shadow")];

  snprintk(url, sizeof(url), "%s/shadow", pigeon_https_path);

  char auth_header[PIGEON_HTTPS_AUTH_HEADER_MAX];

  /* dovecote's get_shadow_device() does auth_header.strip_prefix("Bearer
   * ") -- CONFIG_PIGEON_TOKEN is the raw opaque bearer credential (not a
   * JWT), so the prefix is added here, not stored in the token itself (a
   * bare token with no prefix produces a 401 here). */
  snprintk(auth_header, sizeof(auth_header), "Authorization: Bearer %s\r\n", CONFIG_PIGEON_TOKEN);
  const char *headers[] = {auth_header, NULL};

  pigeon_https_body_len = 0;
  pigeon_https_body[0] = '\0';

  struct http_request req = {
      .method = HTTP_GET,
      .url = url,
      .host = pigeon_https_host,
      .protocol = "HTTP/1.1",
      .header_fields = headers,
      .response = pigeon_https_response_cb,
      .recv_buf = pigeon_https_recv_buf,
      .recv_buf_len = sizeof(pigeon_https_recv_buf),
  };

  err = http_client_req(sock, &req, 10000, NULL);
  zsock_close(sock);

  if (err < 0) {
    LOG_ERR("Shadow GET request failed: %d", err);
    return err;
  }

  if (req.internal.response.http_status_code != 200) {
    LOG_ERR(
        "Shadow GET returned HTTP %u %s", req.internal.response.http_status_code,
        req.internal.response.http_status
    );
    return -EIO;
  }

  if (pigeon_https_body_len == 0) {
    LOG_ERR("Shadow GET returned an empty body");
    return -ENODATA;
  }

  int64_t decoded =
      json_obj_parse(
          pigeon_https_body, pigeon_https_body_len, pigeon_shadow_wire_descr,
          ARRAY_SIZE(pigeon_shadow_wire_descr), &pigeon_shadow_wire
      );

  /* All 5 descriptor fields must decode: bits 0-4 set (0x1F). */
  if (decoded < 0 || (decoded & 0x1F) != 0x1F) {
    LOG_ERR("Failed to parse shadow response JSON (decoded=%lld)", decoded);
    return decoded < 0 ? (int)decoded : -EBADMSG;
  }

  out->target_version = pigeon_shadow_wire.target_version;
  out->current_version = pigeon_shadow_wire.current_version;
  out->target_config = pigeon_shadow_wire.target_config;
  out->current_config = pigeon_shadow_wire.current_config;
  out->updated_at = pigeon_shadow_wire.updated_at;

  return 0;
}

int pigeon_shadow_get(struct pigeon_shadow_doc *out) {
  if (!out) {
    return -EINVAL;
  }

  (void)pigeon_transport_lock(K_FOREVER);

  int err = pigeon_shadow_get_locked(out);

  pigeon_transport_unlock();

  /* The lock covers the request and the decode, but out's config pointers
   * alias pigeon_shadow_wire and escape it -- they stay valid only until
   * the next call into this module, exactly as pigeon.h documents. A caller
   * that shares them with another thread must copy them out first. */
  return err;
}

/* Retry-After capture.
 *
 * Zephyr's http_client exposes no way to read an arbitrary response header,
 * but it does forward every header field/value fragment to an
 * application-supplied http_parser_settings (struct http_request::http_cb)
 * before consuming it, which is how this reads the one header it cares
 * about without patching the vendored client.
 *
 * One module-static capture slot is enough for every caller: each of them
 * runs entirely inside the shared transport lock, so no two requests can be
 * parsing headers at the same time. Each resets the slot before issuing its
 * own request rather than trusting the previous caller to have left it
 * clean.
 */
#define PIGEON_HTTPS_RETRY_AFTER_MAX 32

static struct {
  char value[PIGEON_HTTPS_RETRY_AFTER_MAX];
  uint8_t len;
  bool capturing;
} pigeon_https_retry_after;

static int pigeon_https_on_header_field(
    struct http_parser *parser, const char *at, size_t length
) {
  ARG_UNUSED(parser);
  static const char retry_after[] = "Retry-After";

  /* Exact length, not a prefix match, so a longer header that merely starts
   * the same way (Retry-After-Policy and friends) can't be mistaken for
   * this one. A field name split across two socket reads is missed rather
   * than mismatched -- the same limitation the vendored client's own
   * Content-Length detection carries, and the safe direction: a missed
   * header means the caller uses its own backoff. */
  pigeon_https_retry_after.capturing =
      (length == sizeof(retry_after) - 1) &&
      (strncasecmp(at, retry_after, sizeof(retry_after) - 1) == 0);

  return 0;
}

static int pigeon_https_on_header_value(
    struct http_parser *parser, const char *at, size_t length
) {
  ARG_UNUSED(parser);

  if (!pigeon_https_retry_after.capturing) {
    return 0;
  }

  /* Accumulate instead of overwrite: the parser hands over however many
   * fragments the value happened to be split into. Anything past the
   * buffer is dropped, which can only ever shrink an implausibly long
   * value that the cap would have clamped anyway. */
  size_t room = sizeof(pigeon_https_retry_after.value) - pigeon_https_retry_after.len;
  size_t n = MIN(length, room);

  memcpy(pigeon_https_retry_after.value + pigeon_https_retry_after.len, at, n);
  pigeon_https_retry_after.len += (uint8_t)n;

  return 0;
}

static const struct http_parser_settings pigeon_https_header_cb = {
    .on_header_field = pigeon_https_on_header_field,
    .on_header_value = pigeon_https_on_header_value,
};

/* Outer bound on a Retry-After this path will believe, before the flush
 * policy clamps it again to its own CONFIG_PIGEON_TELEMETRY_BATCH_BACKOFF_MAX_SEC.
 * An hour is generous rather than tuned: the number that governs how long a
 * device actually waits belongs to the caller, and the only job of a cap
 * here is to keep a hostile or broken field from being accumulated into
 * something absurd on its way out of the parser. */
#define PIGEON_HTTPS_TELEMETRY_RETRY_AFTER_MAX_SEC 3600

static int pigeon_transport_report_telemetry_locked(
    const char *body, size_t body_len, struct pigeon_http_result *res
) {
  int err = pigeon_https_parse_endpoint();

  if (err) {
    return err;
  }

  int sock = pigeon_https_connect();

  if (sock < 0) {
    return sock;
  }

  char url[PIGEON_HTTPS_PATH_MAX + sizeof("/telemetry")];

  snprintk(url, sizeof(url), "%s/telemetry", pigeon_https_path);

  char auth_header[PIGEON_HTTPS_AUTH_HEADER_MAX];

  snprintk(auth_header, sizeof(auth_header), "Authorization: Bearer %s\r\n", CONFIG_PIGEON_TOKEN);
  const char *headers[] = {auth_header, NULL};

  pigeon_https_body_len = 0;
  pigeon_https_body[0] = '\0';
  pigeon_https_retry_after.len = 0;
  pigeon_https_retry_after.capturing = false;

  /* body arrives pre-escaped and pre-framed (one flat JSON object of every
   * pending key, or -- under CONFIG_PIGEON_TELEMETRY_BATCH -- the batched
   * {"reports":[...]} form) from pigeon_core.c's pigeon_telemetry_flush().
   * This transport just moves the bytes, same as
   * pigeon_transport_upload_logs() below. pigeon_json_escape() and the body
   * building live in pigeon_core.c, not here. */
  struct http_request req = {
      .method = HTTP_POST,
      .url = url,
      .host = pigeon_https_host,
      .protocol = "HTTP/1.1",
      .header_fields = headers,
      .content_type_value = "application/json",
      .payload = body,
      .payload_len = body_len,
      .response = pigeon_https_response_cb,
      .recv_buf = pigeon_https_recv_buf,
      .recv_buf_len = sizeof(pigeon_https_recv_buf),
      .http_cb = &pigeon_https_header_cb,
  };

  err = http_client_req(sock, &req, 10000, NULL);
  zsock_close(sock);

  /* Recorded before the error check: a request that fails late may still
   * have parsed a status line, and that status is the most useful thing the
   * caller can be told about the failure. */
  res->status = req.internal.response.http_status_code;
  res->retry_after_sec = pigeon_http_parse_retry_after(
      pigeon_https_retry_after.value, pigeon_https_retry_after.len,
      PIGEON_HTTPS_TELEMETRY_RETRY_AFTER_MAX_SEC
  );

  if (err < 0) {
    LOG_ERR("Telemetry report POST request failed: %d", err);
    return err;
  }

  uint16_t status = res->status;

  /* A 429 here is the platform pacing this device, not refusing its data:
   * it is what a free-tier account gets for the rest of a billing period
   * once its pooled message allowance is spent, and what any per-pigeon
   * limiter answers. -EIO would make it indistinguishable from a broken
   * link, and a caller that cannot tell those apart either abandons data
   * that was never rejected or comes straight back into the limit. The
   * delay itself rides in res->retry_after_sec; the caller decides how long
   * to wait. */
  if (status == 429) {
    LOG_WRN("Telemetry report POST rate-limited (Retry-After: %us)", res->retry_after_sec);
    return -EAGAIN;
  }

  if (status < 200 || status >= 300) {
    LOG_ERR(
        "Telemetry report POST returned HTTP %u %s", status, req.internal.response.http_status
    );
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

  /* res is optional, and the helper below always has somewhere to write, so
   * it needs no NULL check of its own on any exit path. */
  struct pigeon_http_result scratch = {0};

  if (res) {
    res->status = 0;
    res->retry_after_sec = 0;
  } else {
    res = &scratch;
  }

  (void)pigeon_transport_lock(K_FOREVER);

  int err = pigeon_transport_report_telemetry_locked(body, body_len, res);

  pigeon_transport_unlock();

  return err;
}

static int pigeon_transport_upload_logs_locked(const uint8_t *data, size_t len) {
  int err = pigeon_https_parse_endpoint();

  if (err) {
    return err;
  }

  int sock = pigeon_https_connect();

  if (sock < 0) {
    return sock;
  }

  char url[PIGEON_HTTPS_PATH_MAX + sizeof("/logs")];

  snprintk(url, sizeof(url), "%s/logs", pigeon_https_path);

  char auth_header[PIGEON_HTTPS_AUTH_HEADER_MAX];

  snprintk(auth_header, sizeof(auth_header), "Authorization: Bearer %s\r\n", CONFIG_PIGEON_TOKEN);
  const char *headers[] = {auth_header, NULL};

  pigeon_https_body_len = 0;
  pigeon_https_body[0] = '\0';

  /* Raw dictionary-mode binary chunk, not JSON -- unlike the telemetry/shadow
   * POSTs above, the payload here is whatever pigeon_log_backend.c drained
   * from its ring buffer verbatim (source strings already stripped from the
   * firmware image at build time; nothing left to encode as JSON). */
  struct http_request req = {
      .method = HTTP_POST,
      .url = url,
      .host = pigeon_https_host,
      .protocol = "HTTP/1.1",
      .header_fields = headers,
      .content_type_value = "application/octet-stream",
      .payload = (const char *)data,
      .payload_len = len,
      .response = pigeon_https_response_cb,
      .recv_buf = pigeon_https_recv_buf,
      .recv_buf_len = sizeof(pigeon_https_recv_buf),
  };

  err = http_client_req(sock, &req, 10000, NULL);
  zsock_close(sock);

  if (err < 0) {
    LOG_ERR("Log upload POST request failed: %d", err);
    return err;
  }

  uint16_t status = req.internal.response.http_status_code;

  if (status < 200 || status >= 300) {
    LOG_ERR("Log upload POST returned HTTP %u %s", status, req.internal.response.http_status);
    return -EIO;
  }

  return 0;
}

int pigeon_transport_upload_logs(const uint8_t *data, size_t len) {
  if (!data || !len) {
    return -EINVAL;
  }

  /* The one caller that waits with a bound instead of K_FOREVER -- see
   * PIGEON_HTTPS_LOG_LOCK_TIMEOUT_MS. -EBUSY lands in the same
   * best-effort "this batch is lost" path the log backend already applies
   * to any other upload failure. */
  if (pigeon_transport_lock(K_MSEC(PIGEON_HTTPS_LOG_LOCK_TIMEOUT_MS)) != 0) {
    return -EBUSY;
  }

  int err = pigeon_transport_upload_logs_locked(data, len);

  pigeon_transport_unlock();

  return err;
}

static int pigeon_shadow_report_locked(int32_t current_version, const char *current_config) {
  int err = pigeon_https_parse_endpoint();

  if (err) {
    return err;
  }

  int sock = pigeon_https_connect();

  if (sock < 0) {
    return sock;
  }

  char url[PIGEON_HTTPS_PATH_MAX + sizeof("/shadow")];

  snprintk(url, sizeof(url), "%s/shadow", pigeon_https_path);

  char auth_header[PIGEON_HTTPS_AUTH_HEADER_MAX];

  snprintk(auth_header, sizeof(auth_header), "Authorization: Bearer %s\r\n", CONFIG_PIGEON_TOKEN);
  const char *headers[] = {auth_header, NULL};

  /* current_config is embedded verbatim as a raw JSON object -- not a
   * string value, so it must not be quote-escaped, only trusted to already be valid JSON
   * (the caller's responsibility, see pigeon_shadow_doc's docs). The margin
   * covers the fixed JSON framing plus an 11-char int32 (49 bytes). */
  char body[PIGEON_HTTPS_CONFIG_MAX + 64];

  snprintk(
      body, sizeof(body), "{\"current_config\":%s,\"current_version\":%d}", current_config,
      current_version
  );

  pigeon_https_body_len = 0;
  pigeon_https_body[0] = '\0';

  struct http_request req = {
      .method = HTTP_POST,
      .url = url,
      .host = pigeon_https_host,
      .protocol = "HTTP/1.1",
      .header_fields = headers,
      .content_type_value = "application/json",
      .payload = body,
      .payload_len = strlen(body),
      .response = pigeon_https_response_cb,
      .recv_buf = pigeon_https_recv_buf,
      .recv_buf_len = sizeof(pigeon_https_recv_buf),
  };

  err = http_client_req(sock, &req, 10000, NULL);
  zsock_close(sock);

  if (err < 0) {
    LOG_ERR("Shadow report POST request failed: %d", err);
    return err;
  }

  uint16_t status = req.internal.response.http_status_code;

  if (status < 200 || status >= 300) {
    LOG_ERR(
        "Shadow report POST returned HTTP %u %s", status, req.internal.response.http_status
    );
    return -EIO;
  }

  return 0;
}

int pigeon_shadow_report(int32_t current_version, const char *current_config) {
  (void)pigeon_transport_lock(K_FOREVER);

  int err = pigeon_shadow_report_locked(current_version, current_config);

  pigeon_transport_unlock();

  return err;
}

#if defined(CONFIG_PIGEON_FOTA)

/* Streaming window for the socket/HTTP-parser's own internal read buffer --
 * independent of CONFIG_PIGEON_FOTA_CHUNK_SIZE, since Zephyr's http_client
 * re-invokes the response callback (below) as many times as needed per
 * request rather than requiring recv_buf to hold a full chunk at once (see
 * struct http_response's doc comment in zephyr/net/http/client.h). */
#define PIGEON_HTTPS_FOTA_RECV_BUF_LEN 1024

static uint8_t pigeon_https_fota_recv_buf[PIGEON_HTTPS_FOTA_RECV_BUF_LEN];

/* Copies response body fragments straight into the caller's chunk buffer
 * (user_data), unlike pigeon_https_response_cb() above which accumulates
 * into the module-global pigeon_https_body -- that buffer is far too small
 * for a multi-KB firmware chunk, and reusing it here would race the
 * shadow/telemetry paths' use of the same static storage. */
struct pigeon_https_fota_ctx {
  uint8_t *dst;
  size_t dst_len;
  size_t written;
};

static int pigeon_https_fota_response_cb(
    struct http_response *rsp, enum http_final_call final_data, void *user_data
) {
  ARG_UNUSED(final_data);
  struct pigeon_https_fota_ctx *ctx = user_data;

  if (rsp->body_frag_start && rsp->body_frag_len && ctx->written < ctx->dst_len) {
    size_t copy_len = rsp->body_frag_len;
    size_t remaining = ctx->dst_len - ctx->written;

    if (copy_len > remaining) {
      copy_len = remaining;
    }

    memcpy(ctx->dst + ctx->written, rsp->body_frag_start, copy_len);
    ctx->written += copy_len;
  }

  return 0;
}

static int pigeon_transport_download_firmware_locked(
    size_t offset, uint8_t *buf, size_t buf_len, size_t *out_len, size_t *out_total,
    struct pigeon_http_result *res
) {
  int err = pigeon_https_parse_endpoint();

  if (err) {
    return err;
  }

  int sock = pigeon_https_connect();

  if (sock < 0) {
    return sock;
  }

  char url[PIGEON_HTTPS_PATH_MAX + sizeof("/firmware")];

  snprintk(url, sizeof(url), "%s/firmware", pigeon_https_path);

  char auth_header[PIGEON_HTTPS_AUTH_HEADER_MAX];

  snprintk(auth_header, sizeof(auth_header), "Authorization: Bearer %s\r\n", CONFIG_PIGEON_TOKEN);

  /* Inclusive end byte, per RFC 7233 -- buf_len is always > 0 here (the
   * public wrapper rejects zero), so offset + buf_len - 1 never underflows. */
  char range_header[64];

  snprintk(
      range_header, sizeof(range_header), "Range: bytes=%u-%u\r\n", (unsigned)offset,
      (unsigned)(offset + buf_len - 1)
  );

  const char *headers[] = {auth_header, range_header, NULL};

  struct pigeon_https_fota_ctx ctx = {.dst = buf, .dst_len = buf_len, .written = 0};

  pigeon_https_retry_after.len = 0;
  pigeon_https_retry_after.capturing = false;

  struct http_request req = {
      .method = HTTP_GET,
      .url = url,
      .host = pigeon_https_host,
      .protocol = "HTTP/1.1",
      .header_fields = headers,
      .response = pigeon_https_fota_response_cb,
      .recv_buf = pigeon_https_fota_recv_buf,
      .recv_buf_len = sizeof(pigeon_https_fota_recv_buf),
      .http_cb = &pigeon_https_header_cb,
  };

  /* Longer timeout than the control-plane requests above: this is a
   * multi-KB binary body over a cellular link, not a small JSON reply. */
  err = http_client_req(sock, &req, 30000, &ctx);
  zsock_close(sock);

  /* Recorded before the error check, not after: a request that fails late
   * may still have parsed a status line, and that status is the most
   * useful thing the caller can be told about the failure. */
  res->status = req.internal.response.http_status_code;
  res->retry_after_sec = pigeon_http_parse_retry_after(
      pigeon_https_retry_after.value, pigeon_https_retry_after.len,
      CONFIG_PIGEON_FOTA_RETRY_AFTER_MAX_SEC
  );

  if (err < 0) {
    LOG_ERR("Firmware chunk GET failed at offset %u: %d", (unsigned)offset, err);
    return err;
  }

  uint16_t status = res->status;

  /* Rate limiting is not a failure of this download, it is the server
   * pacing it, so it gets an errno the caller can tell apart from one --
   * -EIO here would make an operator-visible "attempt failed" out of an
   * expected part of a healthy transfer. The delay itself rides in
   * res->retry_after_sec; the caller decides how to wait. */
  if (status == 429) {
    LOG_WRN(
        "Firmware chunk GET rate-limited at offset %u (Retry-After: %us)", (unsigned)offset,
        res->retry_after_sec
    );
    return -EAGAIN;
  }

  /* Accept 200 too: a server that ignores Range and returns the whole
   * image on the very first (offset=0) request is still usable, just
   * inefficient -- pigeon_fota_apply()'s loop only advances by what
   * *out_len actually reports either way. */
  if (status != 206 && status != 200) {
    LOG_ERR(
        "Firmware chunk GET returned HTTP %u %s", status, req.internal.response.http_status
    );
    return -EIO;
  }

  if (ctx.written == 0) {
    LOG_ERR("Firmware chunk GET returned an empty body");
    return -ENODATA;
  }

  *out_len = ctx.written;
  /* content_range.total, not cr_present, is what says whether a total came
   * back: cr_present is a transient parser flag, set when the Content-Range
   * field name is seen and cleared again in the same header's value callback
   * once the range is copied out (zephyr/subsys/net/lib/http/http_client.c),
   * so it always reads false by the time the request returns. Reading it
   * here made *out_total unconditionally 0, which silently disarmed
   * pigeon_fota_apply()'s server-vs-shadow size cross-check. A total of 0 is
   * indistinguishable from absent either way, which is exactly the "server
   * didn't confirm a total" case callers are told to expect. */
  *out_total = (size_t)req.internal.response.content_range.total;

  return 0;
}

int pigeon_transport_download_firmware(
    size_t offset, uint8_t *buf, size_t buf_len, size_t *out_len, size_t *out_total,
    struct pigeon_http_result *res
) {
  if (!buf || !buf_len || !out_len || !out_total) {
    return -EINVAL;
  }

  /* res is optional for callers that only care whether the chunk arrived;
   * the helper below always has somewhere to write, so it needs no NULL
   * check of its own on any exit path. */
  struct pigeon_http_result scratch = {0};

  if (res) {
    res->status = 0;
    res->retry_after_sec = 0;
  } else {
    res = &scratch;
  }

  /* Per chunk, not per download: this path writes only the caller's buffer
   * and its own recv buffer, but it still needs the endpoint parse and the
   * device's single TLS handshake. Releasing between chunks lets shadow
   * polling and log uploads continue during a long transfer. */
  (void)pigeon_transport_lock(K_FOREVER);

  int err =
      pigeon_transport_download_firmware_locked(offset, buf, buf_len, out_len, out_total, res);

  pigeon_transport_unlock();

  return err;
}

#endif /* CONFIG_PIGEON_FOTA */
