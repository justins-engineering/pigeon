#include <errno.h>
#include <string.h>
#include <zephyr/data/json.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#if defined(CONFIG_BOOTLOADER_MCUBOOT)
#include <zephyr/dfu/mcuboot.h>
#endif

#include "pigeon_internal.h"
#include "pigeon_token.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

/* Not a Kconfig dependency: that would drop the option silently from an image that claims it. */
BUILD_ASSERT(
    IS_ENABLED(CONFIG_SETTINGS) && !IS_ENABLED(CONFIG_SETTINGS_NONE),
    "CONFIG_PIGEON_TOKEN_ROTATION refuses to build without a settings backend: a rotated token "
    "would not survive a reboot"
);
BUILD_ASSERT(
    sizeof(struct pigeon_token_record) == 314,
    "the token record layout is frozen; a new field needs a new settings key"
);
BUILD_ASSERT(
    sizeof(CONFIG_PIGEON_ENDPOINT) <= sizeof(((struct pigeon_token_record *)0)->endpoint),
    "CONFIG_PIGEON_ENDPOINT is longer than the token record can bind to"
);
BUILD_ASSERT(
    sizeof(CONFIG_PIGEON_TOKEN) == PIGEON_TOKEN_LEN + 1,
    "CONFIG_PIGEON_TOKEN must be a 92-character device token: it is the first-boot value and "
    "the expiry every stored token is compared against"
);

/* Zephyr's HTTP client hexdumps each request, Authorization header included, at debug level,
 * and an uploaded log is readable by every member of the pigeon. */
#if defined(CONFIG_NET_HTTP_LOG_LEVEL)
BUILD_ASSERT(
    CONFIG_NET_HTTP_LOG_LEVEL < LOG_LEVEL_DBG,
    "CONFIG_PIGEON_TOKEN_ROTATION refuses HTTP client debug logging: it logs the token"
);
#endif

/* mbedTLS logs the master secret from level 3 and each record's plaintext at level 4, so a
 * captured session or the log alone carries the Authorization header and the new token. */
#if defined(CONFIG_MBEDTLS_DEBUG) && defined(CONFIG_MBEDTLS_DEBUG_LEVEL)
BUILD_ASSERT(
    CONFIG_MBEDTLS_DEBUG_LEVEL < 3,
    "CONFIG_PIGEON_TOKEN_ROTATION refuses mbedTLS debug at level 3 or above: it logs the TLS "
    "secrets and plaintext that carry the token"
);
#endif

/* The settings group reads any record over any MCUmgr transport, a network one included. */
BUILD_ASSERT(
    !IS_ENABLED(CONFIG_MCUMGR_GRP_SETTINGS),
    "CONFIG_PIGEON_TOKEN_ROTATION refuses CONFIG_MCUMGR_GRP_SETTINGS: MCUmgr could read the "
    "stored token"
);

/* Either shell can read or rewrite the record, and the allowlist matches by prefix. */
BUILD_ASSERT(
    !IS_ENABLED(CONFIG_PIGEON_SHELL_ALLOW_ALL),
    "CONFIG_PIGEON_TOKEN_ROTATION refuses CONFIG_PIGEON_SHELL_ALLOW_ALL: the remote shell could "
    "read the stored token"
);
BUILD_ASSERT(
    !(IS_ENABLED(CONFIG_PIGEON_SHELL) &&
      (IS_ENABLED(CONFIG_SETTINGS_SHELL) || IS_ENABLED(CONFIG_FLASH_SHELL))),
    "CONFIG_PIGEON_TOKEN_ROTATION refuses CONFIG_SETTINGS_SHELL and CONFIG_FLASH_SHELL beside "
    "CONFIG_PIGEON_SHELL: either reaches the stored token"
);

#if defined(CONFIG_BOOTLOADER_MCUBOOT)
BUILD_ASSERT(
    IS_ENABLED(CONFIG_MCUBOOT_IMG_MANAGER),
    "CONFIG_PIGEON_TOKEN_ROTATION under MCUboot needs CONFIG_MCUBOOT_IMG_MANAGER to tell "
    "whether the running image is confirmed"
);
#endif

#define PIGEON_TOKEN_CHECK_PERIOD_MS (24LL * 60 * 60 * MSEC_PER_SEC)

/* {"token":"<92>"} is 105 bytes; anything that does not fit is not a token. */
#define PIGEON_TOKEN_REPLY_MAX 160

static int pigeon_token_b64url(char c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  if (c == '-') {
    return 62;
  }
  if (c == '_') {
    return 63;
  }
  return -1;
}

/* Decodes the first 8 characters into the first 6 bytes: the version, the expiry and one more. */
static void pigeon_token_head(const char *token, uint8_t out[6]) {
  int v[8];

  for (int i = 0; i < 8; i++) {
    v[i] = pigeon_token_b64url(token[i]);
  }

  out[0] = (uint8_t)((v[0] << 2) | (v[1] >> 4));
  out[1] = (uint8_t)(((v[1] & 0xF) << 4) | (v[2] >> 2));
  out[2] = (uint8_t)(((v[2] & 0x3) << 6) | v[3]);
  out[3] = (uint8_t)((v[4] << 2) | (v[5] >> 4));
  out[4] = (uint8_t)(((v[5] & 0xF) << 4) | (v[6] >> 2));
  out[5] = (uint8_t)(((v[6] & 0x3) << 6) | v[7]);
}

bool pigeon_token_valid(const char *token) {
  if (!token) {
    return false;
  }

  /* The terminator fails the alphabet, so this also bounds the read. */
  for (size_t i = 0; i < PIGEON_TOKEN_LEN; i++) {
    if (pigeon_token_b64url(token[i]) < 0) {
      return false;
    }
  }
  if (token[PIGEON_TOKEN_LEN] != '\0') {
    return false;
  }

  uint8_t head[6];

  pigeon_token_head(token, head);

  return head[0] == PIGEON_TOKEN_VERSION;
}

uint32_t pigeon_token_expiry(const char *token) {
  if (!pigeon_token_valid(token)) {
    return 0;
  }

  uint8_t head[6];

  pigeon_token_head(token, head);

  return sys_get_le32(&head[1]);
}

struct pigeon_token_reply {
  /* One byte over a token, so an over-long value decodes long and fails validation. */
  char token[PIGEON_TOKEN_LEN + 2];
};

static const struct json_obj_descr pigeon_token_reply_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct pigeon_token_reply, token, JSON_TOK_STRING_BUF),
};

int pigeon_token_parse_reply(const char *body, char out[PIGEON_TOKEN_LEN + 1]) {
  /* json_obj_parse() takes a mutable buffer. */
  char copy[PIGEON_TOKEN_REPLY_MAX];
  size_t len = 0;

  while (len < sizeof(copy) && body[len] != '\0') {
    len++;
  }
  if (len == sizeof(copy)) {
    return -EMSGSIZE;
  }

  memcpy(copy, body, len + 1);

  struct pigeon_token_reply reply = {0};
  int64_t decoded = json_obj_parse(
      copy, len, pigeon_token_reply_descr, ARRAY_SIZE(pigeon_token_reply_descr), &reply
  );

  if (decoded < 0 || !(decoded & BIT(0))) {
    return -EBADMSG;
  }
  if (!pigeon_token_valid(reply.token)) {
    return -EINVAL;
  }

  memcpy(out, reply.token, PIGEON_TOKEN_LEN + 1);

  return 0;
}

/* The pigeon id: the endpoint's last path segment, trailing slashes aside. */
static size_t pigeon_token_id(const char *endpoint, const char **id) {
  size_t end = strlen(endpoint);

  while (end > 0 && endpoint[end - 1] == '/') {
    end--;
  }

  size_t start = end;

  while (start > 0 && endpoint[start - 1] != '/') {
    start--;
  }

  *id = endpoint + start;

  return end - start;
}

bool pigeon_token_same_pigeon(const char *a, const char *b) {
  const char *id_a;
  const char *id_b;
  size_t len_a = pigeon_token_id(a, &id_a);
  size_t len_b = pigeon_token_id(b, &id_b);

  return len_a > 0 && len_a == len_b && memcmp(id_a, id_b, len_a) == 0;
}

int pigeon_token_settings_key(const char *endpoint, char *out, size_t cap) {
  const char *id;
  size_t len = pigeon_token_id(endpoint, &id);

  /* '=' ends a settings name. */
  if (len == 0 || memchr(id, '=', len) != NULL) {
    return -EINVAL;
  }
  len = MIN(len, PIGEON_TOKEN_KEY_ID_LEN);

  size_t prefix = sizeof(PIGEON_TOKEN_SETTINGS_KEY "/") - 1;

  if (cap < prefix + len + 1) {
    return -ENOSPC;
  }

  memcpy(out, PIGEON_TOKEN_SETTINGS_KEY "/", prefix);
  memcpy(out + prefix, id, len);
  out[prefix + len] = '\0';

  return 0;
}

const char *pigeon_token_choose(
    const struct pigeon_token_record *rec, const char *endpoint, const char *baked
) {
  if (!pigeon_token_same_pigeon(rec->endpoint, endpoint) || !pigeon_token_valid(rec->active)) {
    return baked;
  }

  /* A keep-storage reflash after a refresh carries a newer token than anything stored. This
   * holds only while every mint expires later than the one before it, which is why dovecote's
   * DEVICE_TOKEN_LIFETIME_SECS must never shorten. */
  if (pigeon_token_valid(baked) && pigeon_token_expiry(rec->active) < pigeon_token_expiry(baked)) {
    return baked;
  }

  return rec->active;
}

#if defined(CONFIG_PIGEON_TOKEN_ROTATION)

/* The RAM copy and this boot's check bookkeeping. Changed only under the transport lock. */
static struct {
  struct pigeon_token_record rec;
  bool loaded;
  bool checked;
  int64_t last_check_ms;
  enum pigeon_token_gate logged_gate;
  int64_t logged_gate_ms;
} pigeon_token;

struct pigeon_token_read_ctx {
  struct pigeon_token_record *rec;
  bool found;
};

static int pigeon_token_read_cb(
    const char *key, size_t len, settings_read_cb read_cb, void *cb_arg, void *param
) {
  struct pigeon_token_read_ctx *ctx = param;

  if (settings_name_next(key, NULL) != 0) {
    return 0;
  }

  if (len != sizeof(*ctx->rec)) {
    LOG_WRN("Token: stored record has the wrong size (%zu); ignoring it", len);
    return 0;
  }

  if (read_cb(cb_arg, ctx->rec, sizeof(*ctx->rec)) == (ssize_t)sizeof(*ctx->rec)) {
    ctx->found = true;
  }

  return 0;
}

/* 0 with *rec filled or zeroed when absent; negative when settings failed. */
static int pigeon_token_read(struct pigeon_token_record *rec) {
  struct pigeon_token_read_ctx ctx = {.rec = rec, .found = false};

  memset(rec, 0, sizeof(*rec));

  char key[PIGEON_TOKEN_KEY_MAX];
  int err = pigeon_token_settings_key(CONFIG_PIGEON_ENDPOINT, key, sizeof(key));

  if (err == 0) {
    err = settings_subsys_init();
  }
  if (err == 0) {
    err = settings_load_subtree_direct(key, pigeon_token_read_cb, &ctx);
  }

  if (err || !ctx.found) {
    memset(rec, 0, sizeof(*rec));
  }

  return err;
}

static void pigeon_token_load(void) {
  struct pigeon_token_record *rec = &pigeon_token.rec;
  int err = pigeon_token_read(rec);

  if (err) {
    LOG_WRN("Token: record load failed: %d; using the built-in token", err);
    return;
  }

  rec->endpoint[sizeof(rec->endpoint) - 1] = '\0';

  /* A board moved to another pigeon by a new image must never present the old pigeon's token. */
  if (!pigeon_token_same_pigeon(rec->endpoint, CONFIG_PIGEON_ENDPOINT)) {
    memset(rec, 0, sizeof(*rec));
  }
  if (!pigeon_token_valid(rec->active)) {
    memset(rec->active, 0, sizeof(rec->active));
  }
  if (!pigeon_token_valid(rec->pending)) {
    memset(rec->pending, 0, sizeof(rec->pending));
  }

  pigeon_token.loaded = true;
}

static void pigeon_token_ensure_loaded(void) {
  if (!pigeon_token.loaded) {
    pigeon_token_load();
  }
}

/* D16: a write that reported success but did not land must not reach the server as a proof. */
static int pigeon_token_store(const struct pigeon_token_record *rec) {
  char key[PIGEON_TOKEN_KEY_MAX];
  int err = pigeon_token_settings_key(CONFIG_PIGEON_ENDPOINT, key, sizeof(key));

  if (err == 0) {
    err = settings_subsys_init();
  }
  if (err == 0) {
    err = settings_save_one(key, rec, sizeof(*rec));
  }
  if (err) {
    return err;
  }

  struct pigeon_token_record back;

  err = pigeon_token_read(&back);
  if (err) {
    return err;
  }

  return memcmp(&back, rec, sizeof(back)) == 0 ? 0 : -EIO;
}

/* A copy with a bound the compiler can see, so a field filled to capacity is not a truncation
 * warning. The field is zeroed first, which keeps it terminated. */
static void pigeon_token_field_set(char *field, size_t cap, const char *value) {
  size_t len = 0;

  while (len < cap - 1 && value[len] != '\0') {
    len++;
  }
  memcpy(field, value, len);
}

static void pigeon_token_record_set(
    struct pigeon_token_record *rec, const char *active, const char *pending
) {
  memset(rec, 0, sizeof(*rec));
  pigeon_token_field_set(rec->endpoint, sizeof(rec->endpoint), CONFIG_PIGEON_ENDPOINT);
  pigeon_token_field_set(rec->active, sizeof(rec->active), active);
  pigeon_token_field_set(rec->pending, sizeof(rec->pending), pending);
}

const char *pigeon_token_current(void) {
  pigeon_token_ensure_loaded();

  return pigeon_token_choose(&pigeon_token.rec, CONFIG_PIGEON_ENDPOINT, CONFIG_PIGEON_TOKEN);
}

bool pigeon_token_pending(void) {
  pigeon_token_ensure_loaded();

  return pigeon_token.rec.pending[0] != '\0';
}

void pigeon_token_prove(pigeon_token_send_fn send) {
  pigeon_token_ensure_loaded();

  struct pigeon_token_record *rec = &pigeon_token.rec;

  if (rec->pending[0] == '\0') {
    return;
  }

  char body[PIGEON_TOKEN_REPLY_MAX];
  uint16_t status = 0;
  int err = send(rec->pending, body, sizeof(body), &status);

  if (err) {
    LOG_WRN("Token: proof not delivered (%d); retrying before the next shadow GET", err);
    return;
  }

  struct pigeon_token_record next;

  if (status >= 200 && status < 300) {
    /* The server retired the old token at this request, so RAM moves on even if flash cannot:
     * the next boot then proves the same token again, which answers 2xx. */
    pigeon_token_record_set(&next, rec->pending, "");
    *rec = next;
    err = pigeon_token_store(&next);
    if (err) {
      LOG_WRN("Token: rotated, but the record did not save (%d); the next boot proves it again",
              err);
    } else {
      LOG_INF("Token: rotated");
    }
    return;
  }

  if (status == 401) {
    pigeon_token_record_set(&next, rec->active, "");
    *rec = next;
    LOG_WRN("Token: new token refused (HTTP 401); keeping the current one");
    err = pigeon_token_store(&next);
    if (err) {
      LOG_WRN("Token: dropping the refused token did not save (%d)", err);
    }
    return;
  }

  LOG_WRN("Token: proof answered HTTP %u; retrying before the next shadow GET", status);
}

static void pigeon_token_log_gate(enum pigeon_token_gate gate) {
  switch (gate) {
    case PIGEON_TOKEN_GATE_UNCONFIRMED:
      LOG_WRN("Token: check deferred: the running image is not confirmed");
      break;
    case PIGEON_TOKEN_GATE_DOWNLOADING:
      LOG_WRN("Token: check deferred: a firmware download is running");
      break;
    case PIGEON_TOKEN_GATE_SWAP_PENDING:
      LOG_WRN("Token: check deferred: an update is staged for the next boot");
      break;
    default:
      break;
  }
}

void pigeon_token_check(pigeon_token_send_fn send, pigeon_token_gate_fn gate, int64_t now_ms) {
  if (pigeon_token.checked && now_ms - pigeon_token.last_check_ms < PIGEON_TOKEN_CHECK_PERIOD_MS) {
    return;
  }

  /* A deferred check stays due, so it is retried on every poll; one warning per reason a day. */
  enum pigeon_token_gate verdict = gate();

  if (verdict != PIGEON_TOKEN_GATE_OPEN) {
    if (verdict != pigeon_token.logged_gate ||
        now_ms - pigeon_token.logged_gate_ms >= PIGEON_TOKEN_CHECK_PERIOD_MS) {
      pigeon_token_log_gate(verdict);
      pigeon_token.logged_gate = verdict;
      pigeon_token.logged_gate_ms = now_ms;
    }
    return;
  }

  pigeon_token.logged_gate = PIGEON_TOKEN_GATE_OPEN;
  pigeon_token.checked = true;
  pigeon_token.last_check_ms = now_ms;

  char sent[PIGEON_TOKEN_LEN + 1];

  strncpy(sent, pigeon_token_current(), sizeof(sent) - 1);
  sent[sizeof(sent) - 1] = '\0';

  char body[PIGEON_TOKEN_REPLY_MAX];
  uint16_t status = 0;
  int err = send(sent, body, sizeof(body), &status);

  if (err) {
    LOG_WRN("Token: check not delivered (%d); next one in 24 h", err);
    return;
  }

  if (status != 200) {
    if (status < 200 || status >= 300) {
      LOG_WRN("Token: check answered HTTP %u", status);
    }
    return;
  }

  char fresh[PIGEON_TOKEN_LEN + 1];

  err = pigeon_token_parse_reply(body, fresh);
  if (err) {
    LOG_WRN("Token: check reply is not a token (%d); ignored", err);
    return;
  }

  struct pigeon_token_record next;

  pigeon_token_record_set(&next, sent, fresh);
  err = pigeon_token_store(&next);
  if (err) {
    LOG_WRN("Token: new token not saved or not read back (%d); keeping the current one", err);
    return;
  }

  pigeon_token.rec = next;
  pigeon_token_prove(send);
}

enum pigeon_token_gate pigeon_token_gate_now(void) {
#if defined(CONFIG_BOOTLOADER_MCUBOOT)
  if (!boot_is_img_confirmed()) {
    return PIGEON_TOKEN_GATE_UNCONFIRMED;
  }
#if defined(CONFIG_PIGEON_FOTA)
  if (pigeon_fota_download_running()) {
    return PIGEON_TOKEN_GATE_DOWNLOADING;
  }
#endif
  /* An unreadable swap state is treated as staged: the check waits rather than guesses. */
  if (mcuboot_swap_type() != BOOT_SWAP_TYPE_NONE) {
    return PIGEON_TOKEN_GATE_SWAP_PENDING;
  }
#endif
  return PIGEON_TOKEN_GATE_OPEN;
}

void pigeon_token_reset(void) { memset(&pigeon_token, 0, sizeof(pigeon_token)); }

#endif /* CONFIG_PIGEON_TOKEN_ROTATION */
