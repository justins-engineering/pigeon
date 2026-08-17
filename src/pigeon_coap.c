#include <errno.h>
#include <pigeon.h>
#include <string.h>
#include <zephyr/data/json.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/sys/util.h>

#if defined(CONFIG_MODEM_KEY_MGMT)
#include <mbedtls/platform_util.h>
#include <modem/modem_key_mgmt.h>
#include <psa/crypto.h>
#endif

#include "pigeon_coap_internal.h"
#include "pigeon_internal.h"

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

char pigeon_coap_host[PIGEON_COAP_HOST_MAX];
char pigeon_coap_port[PIGEON_COAP_PORT_MAX];
char pigeon_coap_path[PIGEON_COAP_PATH_MAX];
static bool pigeon_coap_endpoint_parsed;

static bool pigeon_coap_psk_registered;

/* Wire shape of the JSON payload a shadow GET returns (mirrors
 * capsules::PigeonShadow; see pigeon_shadow_doc in pigeon.h and the matching
 * copy of this in pigeon_https.c). target_config/current_config are
 * themselves JSON objects serialized as a string on the wire (e.g.
 * "target_config":"{\"log\":true}") -- JSON_TOK_STRING would hand back a
 * raw, still-escaped pointer into the response buffer ('{\"log\":true}' is
 * not valid JSON, so the app's own json_obj_parse() on target_config would
 * fail downstream regardless of which keys/values it held).
 * JSON_TOK_STRING_BUF actually unescapes into a fixed-size buffer
 * instead, so these are plain arrays (not pointers) and
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

#if defined(CONFIG_MODEM_KEY_MGMT)
/* On nRF91-class boards TLS/DTLS runs inside the modem, which resolves
 * sec_tags against its OWN credential store (%CMNG) -- tls_credential_add()
 * into Zephyr's native store is invisible to it. modem_key_mgmt_write()
 * reaches the real store, but only while the modem is offline (CFUN=0/4),
 * so provisioning runs eagerly from pigeon_init() and the app must call
 * pigeon_init() BEFORE bringing LTE up. The modem's PSK slot (%CMNG type
 * 3) wants the secret as ASCII hex, not raw bytes. */

/* The modem never hands a stored PSK secret back out (%CMNG read on that
 * type is refused), so modem_key_mgmt_cmp() -- an AT read under the hood
 * -- returns -EACCES on the secret even when the stored value is
 * identical, and can never confirm a match. What the modem does expose
 * for every credential type is a SHA-256 digest of the stored data, so
 * compare by hashing the exact bytes a write would store and checking
 * digests instead; the identity slot gets the same treatment so both
 * slots go through one code path. */
static bool pigeon_coap_modem_cred_matches(
    enum modem_key_mgmt_cred_type type, const void *buf, size_t len
) {
  bool exists = false;
  int err = modem_key_mgmt_exists(CONFIG_PIGEON_COAP_SEC_TAG, type, &exists);

  if (err != 0 || !exists) {
    return false;
  }

  uint8_t stored[MODEM_KEY_MGMT_DIGEST_SIZE];

  err = modem_key_mgmt_digest(CONFIG_PIGEON_COAP_SEC_TAG, type, stored, sizeof(stored));
  if (err != 0) {
    return false;
  }

  uint8_t local[MODEM_KEY_MGMT_DIGEST_SIZE];
  size_t local_len = 0;

  if (psa_crypto_init() != PSA_SUCCESS ||
      psa_hash_compute(PSA_ALG_SHA_256, buf, len, local, sizeof(local), &local_len) !=
          PSA_SUCCESS ||
      local_len != sizeof(stored)) {
    /* Treated as a mismatch: falling through to the write is the same
     * outcome the pre-digest code had on every boot, so a hash backend
     * hiccup degrades to extra flash wear, never to lost provisioning. */
    return false;
  }

  return memcmp(stored, local, sizeof(stored)) == 0;
}

static int pigeon_coap_psk_write_modem(const struct pigeon_coap_config *cfg) {
  static const char hex_digits[] = "0123456789abcdef";
  char psk_hex[PIGEON_COAP_PSK_MAX * 2 + 1];
  size_t secret_len = strlen(cfg->tls_psk_secret);

  if (secret_len * 2 >= sizeof(psk_hex)) {
    LOG_ERR("CoAP PSK secret too long to hex-encode for the modem store");
    return -ENOSPC;
  }

  for (size_t i = 0; i < secret_len; i++) {
    uint8_t byte = (uint8_t)cfg->tls_psk_secret[i];

    psk_hex[2 * i] = hex_digits[byte >> 4];
    psk_hex[2 * i + 1] = hex_digits[byte & 0x0F];
  }
  psk_hex[secret_len * 2] = '\0';

  /* Compare-before-write: skips the (modem-offline-only, flash-wearing)
   * writes when the stored credentials already match, so a warm restart
   * that reaches pigeon_init() with credentials already in place doesn't
   * fail or rewrite for no reason. */
  int err = 0;

  if (pigeon_coap_modem_cred_matches(
          MODEM_KEY_MGMT_CRED_TYPE_IDENTITY, cfg->tls_psk_identity, strlen(cfg->tls_psk_identity)
      ) &&
      pigeon_coap_modem_cred_matches(MODEM_KEY_MGMT_CRED_TYPE_PSK, psk_hex, strlen(psk_hex))) {
    goto out;
  }

  err = modem_key_mgmt_write(
      CONFIG_PIGEON_COAP_SEC_TAG, MODEM_KEY_MGMT_CRED_TYPE_IDENTITY, cfg->tls_psk_identity,
      strlen(cfg->tls_psk_identity)
  );
  if (err) {
    LOG_ERR("Failed to write CoAP PSK identity to modem store: %d", err);
    goto out;
  }

  err = modem_key_mgmt_write(
      CONFIG_PIGEON_COAP_SEC_TAG, MODEM_KEY_MGMT_CRED_TYPE_PSK, psk_hex, strlen(psk_hex)
  );
  if (err) {
    LOG_ERR("Failed to write CoAP PSK secret to modem store: %d", err);
  }

out:
  /* psk_hex held the PSK secret in plaintext (ASCII-hex) for the modem
   * writes above; wipe it before this frame goes out of scope rather than
   * leaving it sitting readable on the stack for whatever this thread
   * calls next. Defense-in-depth only -- nothing here logs or otherwise
   * discloses psk_hex, and cfg->tls_psk_secret retains the raw secret for
   * the process lifetime regardless -- but the wipe is cheap and each
   * exit path (early match, either write failing, or full success) needs
   * it, hence the shared label instead of repeating the call at every
   * return. mbedtls_platform_zeroize rather than memset() so the store
   * can't be optimized away as dead: the compiler can see nothing reads
   * psk_hex again before it goes out of scope. */
  mbedtls_platform_zeroize(psk_hex, sizeof(psk_hex));
  return err;
}
#endif /* CONFIG_MODEM_KEY_MGMT */

int pigeon_coap_register_psk(void) {
  if (pigeon_coap_psk_registered) {
    return 0;
  }

  const struct pigeon_coap_config *cfg = pigeon_active_coap_config();

  if (!cfg->tls_psk_identity || !cfg->tls_psk_secret) {
    return 0;
  }

#if defined(CONFIG_MODEM_KEY_MGMT)
  int err = pigeon_coap_psk_write_modem(cfg);

  if (err) {
    return err;
  }

  pigeon_coap_psk_registered = true;

  return 0;
#else
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
#endif /* CONFIG_MODEM_KEY_MGMT */
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

  /* Block1 (27) goes on after Content-Format (12): options must be appended
   * in ascending option number, and a payload-less block would be
   * meaningless anyway. */
  if (opts && opts->block1) {
    return coap_append_block1_option(cpkt, opts->block1);
  }

  return 0;
}

static int pigeon_shadow_get_locked(struct pigeon_shadow_doc *out) {
  uint8_t rsp_code;
  const uint8_t *payload;
  size_t payload_len;
  int err = pigeon_coap_transport_exchange(
      COAP_METHOD_GET, "shadow", NULL, 0, NULL, &rsp_code, &payload, &payload_len
  );

  if (err) {
    return err;
  }

  if ((rsp_code >> 5) != 2) {
    LOG_ERR("Shadow GET returned CoAP %u.%02u", rsp_code >> 5, rsp_code & 0x1F);
    return -EIO;
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
   * pigeon_core.c's pigeon_telemetry_flush(). PIGEON_COAP_MSG_MAX is sized
   * off PIGEON_TELEMETRY_BODY_MAX (see pigeon_coap_internal.h) so a full
   * batch always fits the frame; coap_packet_append_payload()'s own bounds
   * check remains the safe failure path regardless. */
  uint8_t rsp_code;
  const uint8_t *payload;
  size_t payload_len;
  int err = pigeon_coap_transport_exchange(
      COAP_METHOD_POST, "telemetry", (const uint8_t *)body, body_len, NULL, &rsp_code, &payload,
      &payload_len
  );

  if (err) {
    return err;
  }

  if ((rsp_code >> 5) != 2) {
    LOG_ERR("Telemetry report POST returned CoAP %u.%02u", rsp_code >> 5, rsp_code & 0x1F);
    return -EIO;
  }

  return 0;
}

int pigeon_transport_report_telemetry(const char *body, size_t body_len) {
  if (!body || !body_len) {
    return -EINVAL;
  }

  (void)pigeon_transport_lock(K_FOREVER);

  int err = pigeon_transport_report_telemetry_locked(body, body_len);

  pigeon_transport_unlock();

  return err;
}

static int pigeon_shadow_report_locked(int32_t current_version, const char *current_config) {
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
  const uint8_t *payload;
  size_t payload_len;
  int err = pigeon_coap_transport_exchange(
      COAP_METHOD_POST, "shadow", (const uint8_t *)body, strlen(body), NULL, &rsp_code, &payload,
      &payload_len
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

int pigeon_shadow_report(int32_t current_version, const char *current_config) {
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
    uint8_t rsp_code;
    const uint8_t *payload;
    size_t payload_len;

    err = pigeon_coap_transport_exchange(
        COAP_METHOD_POST, "logs", data + ctx.current, this_block, &opts, &rsp_code, &payload,
        &payload_len
    );

    if (err) {
      return err;
    }

    if ((rsp_code >> 5) != 2) {
      LOG_ERR("Log upload POST returned CoAP %u.%02u", rsp_code >> 5, rsp_code & 0x1F);
      return -EIO;
    }

    /* 2.31 Continue is what acknowledges a non-final block; anything else
     * means the server stopped reassembling early, so every byte still
     * queued behind this one would be appended to nothing. */
    if (!last && rsp_code != COAP_RESPONSE_CODE_CONTINUE) {
      LOG_ERR(
          "Log upload block %u answered %u.%02u, expected 2.31 Continue",
          (unsigned)(ctx.current / block_bytes), rsp_code >> 5, rsp_code & 0x1F
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
