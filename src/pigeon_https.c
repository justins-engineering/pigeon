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
#define PIGEON_HTTPS_RECV_BUF_LEN 640
#define PIGEON_HTTPS_CONFIG_MAX 256
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

/* Backing storage for pigeon_shadow_doc's target_config/current_config,
 * which pigeon.h documents as valid "until the next call." */
static char pigeon_shadow_target_config[PIGEON_HTTPS_CONFIG_MAX];
static char pigeon_shadow_current_config[PIGEON_HTTPS_CONFIG_MAX];

/* Wire shape of the JSON body GET <endpoint>/shadow returns (mirrors
 * capsules::PigeonShadow; see pigeon_shadow_doc in pigeon.h). */
struct pigeon_shadow_wire {
  int32_t target_version;
  int32_t current_version;
  const char *target_config;
  const char *current_config;
  int64_t updated_at;
};

static const struct json_obj_descr pigeon_shadow_wire_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct pigeon_shadow_wire, target_version, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct pigeon_shadow_wire, current_version, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct pigeon_shadow_wire, target_config, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct pigeon_shadow_wire, current_config, JSON_TOK_STRING),
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

  struct pigeon_shadow_wire wire = {0};
  int64_t decoded =
      json_obj_parse(
          pigeon_https_body, pigeon_https_body_len, pigeon_shadow_wire_descr,
          ARRAY_SIZE(pigeon_shadow_wire_descr), &wire
      );

  /* All 5 descriptor fields must decode: bits 0-4 set (0x1F). */
  if (decoded < 0 || (decoded & 0x1F) != 0x1F) {
    LOG_ERR("Failed to parse shadow response JSON (decoded=%lld)", decoded);
    return decoded < 0 ? (int)decoded : -EBADMSG;
  }

  strncpy(pigeon_shadow_target_config, wire.target_config, sizeof(pigeon_shadow_target_config) - 1);
  pigeon_shadow_target_config[sizeof(pigeon_shadow_target_config) - 1] = '\0';

  strncpy(
      pigeon_shadow_current_config, wire.current_config, sizeof(pigeon_shadow_current_config) - 1
  );
  pigeon_shadow_current_config[sizeof(pigeon_shadow_current_config) - 1] = '\0';

  out->target_version = wire.target_version;
  out->current_version = wire.current_version;
  out->target_config = pigeon_shadow_target_config;
  out->current_config = pigeon_shadow_current_config;
  out->updated_at = wire.updated_at;

  return 0;
}

/* Escapes '"' and '\' so key/val (arbitrary caller strings, see
 * pigeon_set_shadow_param()) can't break out of the JSON string they're
 * embedded in below. Truncates rather than overflows if out is too small. */
static size_t pigeon_https_json_escape(const char *in, char *out, size_t out_len) {
  size_t o = 0;

  for (size_t i = 0; in[i] != '\0' && o + 2 < out_len; i++) {
    if (in[i] == '"' || in[i] == '\\') {
      out[o++] = '\\';
    }
    out[o++] = in[i];
  }
  out[o] = '\0';

  return o;
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

  /* Escaped forms can be up to ~2x the raw key/val (PIGEON_SHADOW_KEY_MAX=32,
   * PIGEON_SHADOW_VAL_MAX=128 in pigeon_core.c). */
  char key_esc[64];
  char val_esc[256];

  pigeon_https_json_escape(key, key_esc, sizeof(key_esc));
  pigeon_https_json_escape(val, val_esc, sizeof(val_esc));

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
