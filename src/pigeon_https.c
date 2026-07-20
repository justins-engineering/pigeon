#include <errno.h>
#include <pigeon.h>
#include <string.h>
#include <zephyr/data/json.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/http/client.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>

#include "pigeon_internal.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

#define PIGEON_HTTPS_HOST_MAX 128
#define PIGEON_HTTPS_PATH_MAX 128
/* Bumped from 640/256 (both with headroom to spare) when the shadow's
 * target_config/current_config picked up the "firmware" key (see
 * CONFIG_PIGEON_FOTA, pigeon.h's pigeon_fota_info): a version string +
 * size + 64-char sha256 hex adds roughly 120-140 raw bytes per config on
 * top of whatever app-level keys (log/telemetry_interval/reboot) were
 * already there. */
#define PIGEON_HTTPS_RECV_BUF_LEN 768
#define PIGEON_HTTPS_CONFIG_MAX 320
#define PIGEON_HTTPS_AUTH_HEADER_MAX 384

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
 * JSON_TOK_STRING (as this used to) hands back a raw, still-escaped pointer
 * into pigeon_https_body: '{\"log\":true}' is not valid JSON, so the app's
 * own json_obj_parse() on target_config always failed downstream regardless
 * of which keys/values it held. JSON_TOK_STRING_BUF actually unescapes into
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
  struct zsock_addrinfo hints = {
      .ai_family = AF_INET,
      .ai_socktype = SOCK_STREAM,
  };
  struct zsock_addrinfo *res;

  int err = zsock_getaddrinfo(pigeon_https_host, "443", &hints, &res);

  if (err) {
    LOG_ERR("Failed to resolve %s: %d", pigeon_https_host, err);
    return -EHOSTUNREACH;
  }

  int sock = zsock_socket(res->ai_family, SOCK_STREAM, IPPROTO_TLS_1_2);

  if (sock < 0) {
    LOG_ERR("Failed to create TLS socket: %d", -errno);
    zsock_freeaddrinfo(res);
    return -errno;
  }

  sec_tag_t sec_tag_list[] = {CONFIG_PIGEON_HTTPS_SEC_TAG};

  err = zsock_setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_list, sizeof(sec_tag_list));
  if (err) {
    LOG_ERR("Failed to set TLS sec_tag %d: %d", CONFIG_PIGEON_HTTPS_SEC_TAG, -errno);
    goto cleanup;
  }

  err = zsock_setsockopt(
      sock, SOL_TLS, TLS_HOSTNAME, pigeon_https_host, strlen(pigeon_https_host)
  );
  if (err) {
    LOG_ERR("Failed to set TLS hostname: %d", -errno);
    goto cleanup;
  }

  err = zsock_connect(sock, res->ai_addr, res->ai_addrlen);
  zsock_freeaddrinfo(res);
  if (err) {
    LOG_ERR("Failed to connect to %s: %d", pigeon_https_host, -errno);
    zsock_close(sock);
    return -errno;
  }

  return sock;

cleanup:
  zsock_freeaddrinfo(res);
  zsock_close(sock);
  return -errno;
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

int pigeon_shadow_get(struct pigeon_shadow_doc *out) {
  if (!out) {
    return -EINVAL;
  }

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
   * bare token with no prefix produced a 401 here before this was added). */
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

int pigeon_transport_report_shadow(const char *key, const char *val) {
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

  /* Escaped forms can be up to ~6x the raw key/val in the worst case (every
   * byte a control character needing \u00XX -- pigeon_json_escape()'s only
   * unescaped-length guarantee is truncation, never overflow, but sizing
   * for the true worst case avoids silently losing most of an otherwise-
   * legitimate value). PIGEON_SHADOW_KEY_MAX=32/PIGEON_SHADOW_VAL_MAX=128
   * in pigeon_core.c -- 32*6+1=193, 128*6+1=769, rounded up. */
  char key_esc[200];
  char val_esc[800];

  pigeon_json_escape(key, key_esc, sizeof(key_esc));
  pigeon_json_escape(val, val_esc, sizeof(val_esc));

  char body[sizeof(key_esc) + sizeof(val_esc) + 8];

  snprintk(body, sizeof(body), "{\"%s\":\"%s\"}", key_esc, val_esc);

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
    LOG_ERR("Telemetry report POST request failed: %d", err);
    return err;
  }

  uint16_t status = req.internal.response.http_status_code;

  if (status < 200 || status >= 300) {
    LOG_ERR(
        "Telemetry report POST returned HTTP %u %s", status, req.internal.response.http_status
    );
    return -EIO;
  }

  return 0;
}

int pigeon_transport_upload_logs(const uint8_t *data, size_t len) {
  if (!data || !len) {
    return -EINVAL;
  }

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

int pigeon_shadow_report(int32_t current_version, const char *current_config) {
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

  /* current_config is embedded verbatim as a raw JSON object -- unlike
   * pigeon_transport_report_shadow()'s key/val, this is not a string value
   * so it must not be quote-escaped, only trusted to already be valid JSON
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

int pigeon_transport_download_firmware(
    size_t offset, uint8_t *buf, size_t buf_len, size_t *out_len, size_t *out_total
) {
  if (!buf || !buf_len || !out_len || !out_total) {
    return -EINVAL;
  }

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

  /* Inclusive end byte, per RFC 7233 -- buf_len is always > 0 here (see the
   * guard above), so offset + buf_len - 1 never underflows. */
  char range_header[64];

  snprintk(
      range_header, sizeof(range_header), "Range: bytes=%u-%u\r\n", (unsigned)offset,
      (unsigned)(offset + buf_len - 1)
  );

  const char *headers[] = {auth_header, range_header, NULL};

  struct pigeon_https_fota_ctx ctx = {.dst = buf, .dst_len = buf_len, .written = 0};

  struct http_request req = {
      .method = HTTP_GET,
      .url = url,
      .host = pigeon_https_host,
      .protocol = "HTTP/1.1",
      .header_fields = headers,
      .response = pigeon_https_fota_response_cb,
      .recv_buf = pigeon_https_fota_recv_buf,
      .recv_buf_len = sizeof(pigeon_https_fota_recv_buf),
  };

  /* Longer timeout than the control-plane requests above: this is a
   * multi-KB binary body over a cellular link, not a small JSON reply. */
  err = http_client_req(sock, &req, 30000, &ctx);
  zsock_close(sock);

  if (err < 0) {
    LOG_ERR("Firmware chunk GET failed at offset %u: %d", (unsigned)offset, err);
    return err;
  }

  uint16_t status = req.internal.response.http_status_code;

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
  *out_total = req.internal.response.cr_present
                   ? (size_t)req.internal.response.content_range.total
                   : 0;

  return 0;
}

#endif /* CONFIG_PIGEON_FOTA */
