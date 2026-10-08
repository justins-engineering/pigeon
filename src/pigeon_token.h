#ifndef PIDGEIOT_PIGEON_TOKEN_H_
#define PIDGEIOT_PIGEON_TOKEN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Remote token rotation (CONFIG_PIGEON_TOKEN_ROTATION): the device half of
 * dovecote's POST <endpoint>/token. pidgeiot's docs/design/token-rotation.md
 * is the authority; D-numbers below refer to it.
 *
 * One settings record, outside both image slots, holds the token this device
 * uses and the one it was handed but has not yet proven. CONFIG_PIGEON_TOKEN
 * stays the first-boot value. Every request takes one token from
 * pigeon_token_current(); there is no per-request fallback.
 */

/* 69 bytes, version | expires_at (u32 LE) | Ed25519 signature, base64url without padding. */
#define PIGEON_TOKEN_LEN     92
#define PIGEON_TOKEN_VERSION 1

/*
 * Each pigeon's record has its own key, "pigeon/token/<first 16 characters of the pigeon id>",
 * so an image built for another pigeon, run on this board by mistake, saves beside this
 * pigeon's record and never over it.
 */
#define PIGEON_TOKEN_SETTINGS_KEY "pigeon/token"
#define PIGEON_TOKEN_KEY_ID_LEN   16
#define PIGEON_TOKEN_KEY_MAX      (sizeof(PIGEON_TOKEN_SETTINGS_KEY "/") + PIGEON_TOKEN_KEY_ID_LEN)

/*
 * Compiled into every image built with this option. dovecote tags an uploaded image as able to
 * read a rotated token by finding this string in its bytes, so the tag cannot be declared by
 * mistake. A change to the record's key or layout gets a new marker.
 */
#define PIGEON_TOKEN_MARKER "pigeon-token-rotation/1"

/* Layout is frozen: a later field gets a new key, and a load refuses any other size. */
struct pigeon_token_record {
  /* CONFIG_PIGEON_ENDPOINT this record was written under. Only its last path segment, the
   * pigeon id, binds the record: a token belongs to its pigeon, whichever host serves it. */
  char endpoint[128];
  char active[PIGEON_TOKEN_LEN + 1];
  /* Received and saved, not yet proven; "" when no rotation is in flight. */
  char pending[PIGEON_TOKEN_LEN + 1];
};

/* Why a due check did not run. Each maps to one warning. */
enum pigeon_token_gate {
  PIGEON_TOKEN_GATE_OPEN,
  /* A revert could land on an image holding only a token rotation retired. */
  PIGEON_TOKEN_GATE_UNCONFIRMED,
  PIGEON_TOKEN_GATE_DOWNLOADING,
  /* The staged image carries only its baked token. */
  PIGEON_TOKEN_GATE_SWAP_PENDING,
  /* The shadow assigns another image, which may hold only its baked token. */
  PIGEON_TOKEN_GATE_FIRMWARE_ASSIGNED,
};

/*
 * One POST <endpoint>/token presenting token, with an empty body. Returns 0
 * once a status line arrived (*status set, body NUL-terminated and truncated
 * to body_cap - 1), negative when nothing usable came back. Implemented by
 * pigeon_https.c; tests supply their own.
 */
typedef int (*pigeon_token_send_fn)(
    const char *token, char *body, size_t body_cap, uint16_t *status
);

typedef enum pigeon_token_gate (*pigeon_token_gate_fn)(void);

#if defined(CONFIG_PIGEON_TOKEN_ROTATION)

/*
 * The token for the next request (D19 step 3): the record's active token, or
 * CONFIG_PIGEON_TOKEN when the record is empty, was written for another
 * pigeon, or its active token's signed expiry is earlier than the baked
 * one's (a keep-storage reflash after a refresh). The record changes only
 * under the transport lock, so call this under it and copy the result
 * before releasing it.
 */
const char *pigeon_token_current(void);

/* Whether a received token is still waiting for its proof. Under the transport lock. */
bool pigeon_token_pending(void);

/*
 * D19 step 2, run before every shadow GET while a token is pending: present
 * it, keep it on 2xx, drop it on 401, keep it pending on anything else.
 * Under the transport lock.
 */
void pigeon_token_prove(pigeon_token_send_fn send);

/*
 * D17, run after a successful shadow GET: once per boot and every 24 h of
 * uptime, unless gate says no, in which case the check stays due. On a
 * token in the reply it saves, reads back and proves it. Under the
 * transport lock.
 */
void pigeon_token_check(pigeon_token_send_fn send, pigeon_token_gate_fn gate, int64_t now_ms);

/* D18 as built: always open without MCUboot, where nothing can revert or be staged. */
enum pigeon_token_gate pigeon_token_gate_now(void);

/* Forgets what is in RAM, as a reboot does; the next call reloads the record. */
void pigeon_token_reset(void);

#else

static inline const char *pigeon_token_current(void) { return CONFIG_PIGEON_TOKEN; }

static inline bool pigeon_token_pending(void) { return false; }

#endif /* CONFIG_PIGEON_TOKEN_ROTATION */

/* Pure helpers, exercised by tests/token. */

/* D15: exactly PIGEON_TOKEN_LEN base64url characters whose first byte is the known version. */
bool pigeon_token_valid(const char *token);

/* The signed expiry (bytes 1 to 4), readable without a key. 0 for a token that is not valid. */
uint32_t pigeon_token_expiry(const char *token);

/*
 * Extracts and validates the token from a 200 body {"token":"..."}. Decoded
 * into out, never into anything a caller of pigeon_shadow_get() still reads.
 */
int pigeon_token_parse_reply(const char *body, char out[PIGEON_TOKEN_LEN + 1]);

/* Whether two endpoints name the same pigeon: the same non-empty last path segment. */
bool pigeon_token_same_pigeon(const char *a, const char *b);

/*
 * Writes the record's settings key for endpoint into out. -EINVAL when the endpoint has no
 * last path segment, or one a settings name cannot carry; -ENOSPC when out is too small.
 */
int pigeon_token_settings_key(const char *endpoint, char *out, size_t cap);

/*
 * Whether a shadow target_config assigns firmware whose version is not running: a "firmware"
 * object with a non-empty "version" other than running. Parses config in place, consuming it.
 * A config that does not parse assigns nothing, since the application cannot read it either.
 */
bool pigeon_token_firmware_assigned(char *config, size_t len, const char *running);

/* D19 step 3 as a pure choice over a loaded record. */
const char *pigeon_token_choose(
    const struct pigeon_token_record *rec, const char *endpoint, const char *baked
);

#endif /* PIDGEIOT_PIGEON_TOKEN_H_ */
