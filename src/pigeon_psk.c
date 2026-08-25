#include <errno.h>
#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/tls_credentials.h>

#if defined(CONFIG_MODEM_KEY_MGMT)
#include <mbedtls/platform_util.h>
#include <modem/modem_key_mgmt.h>
#include <psa/crypto.h>
#endif

#include "pigeon_internal.h"
#include "pigeon_psk.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

#if defined(CONFIG_MODEM_KEY_MGMT)
/* On nRF91-class boards TLS/DTLS runs inside the modem, which resolves
 * sec_tags against its OWN credential store (%CMNG) -- tls_credential_add()
 * into Zephyr's native store is invisible to it. modem_key_mgmt_write()
 * reaches the real store, but only while the modem is offline (CFUN=0/4),
 * so provisioning runs eagerly from pigeon_init() and the app must call
 * pigeon_init() BEFORE bringing the link up. The modem's PSK slot (%CMNG
 * type 3) wants the secret as ASCII hex, not raw bytes. */

/* The modem never hands a stored PSK secret back out (%CMNG read on that
 * type is refused), so modem_key_mgmt_cmp() -- an AT read under the hood
 * -- returns -EACCES on the secret even when the stored value is
 * identical, and can never confirm a match. What the modem does expose
 * for every credential type is a SHA-256 digest of the stored data, so
 * compare by hashing the exact bytes a write would store and checking
 * digests instead; the identity slot gets the same treatment so both
 * slots go through one code path. */
static bool pigeon_psk_modem_cred_matches(
    int sec_tag, enum modem_key_mgmt_cred_type type, const void *buf, size_t len
) {
  bool exists = false;
  int err = modem_key_mgmt_exists(sec_tag, type, &exists);

  if (err != 0 || !exists) {
    return false;
  }

  uint8_t stored[MODEM_KEY_MGMT_DIGEST_SIZE];

  err = modem_key_mgmt_digest(sec_tag, type, stored, sizeof(stored));
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

static int pigeon_psk_write_modem(int sec_tag, const char *identity, const char *secret) {
  static const char hex_digits[] = "0123456789abcdef";
  char psk_hex[PIGEON_PSK_MAX * 2 + 1];
  size_t secret_len = strlen(secret);

  if (secret_len * 2 >= sizeof(psk_hex)) {
    LOG_ERR("PSK secret too long to hex-encode for the modem store");
    return -ENOSPC;
  }

  for (size_t i = 0; i < secret_len; i++) {
    uint8_t byte = (uint8_t)secret[i];

    psk_hex[2 * i] = hex_digits[byte >> 4];
    psk_hex[2 * i + 1] = hex_digits[byte & 0x0F];
  }
  psk_hex[secret_len * 2] = '\0';

  /* Compare-before-write: skips the (modem-offline-only, flash-wearing)
   * writes when the stored credentials already match, so a warm restart
   * that reaches pigeon_init() with credentials already in place doesn't
   * fail or rewrite for no reason. */
  int err = 0;

  if (pigeon_psk_modem_cred_matches(
          sec_tag, MODEM_KEY_MGMT_CRED_TYPE_IDENTITY, identity, strlen(identity)
      ) &&
      pigeon_psk_modem_cred_matches(
          sec_tag, MODEM_KEY_MGMT_CRED_TYPE_PSK, psk_hex, strlen(psk_hex)
      )) {
    goto out;
  }

  err = modem_key_mgmt_write(
      sec_tag, MODEM_KEY_MGMT_CRED_TYPE_IDENTITY, identity, strlen(identity)
  );
  if (err) {
    LOG_ERR("Failed to write PSK identity to modem store: %d", err);
    goto out;
  }

  err = modem_key_mgmt_write(sec_tag, MODEM_KEY_MGMT_CRED_TYPE_PSK, psk_hex, strlen(psk_hex));
  if (err) {
    LOG_ERR("Failed to write PSK secret to modem store: %d", err);
  }

out:
  /* psk_hex held the PSK secret in plaintext (ASCII-hex) for the modem
   * writes above; wipe it before this frame goes out of scope rather than
   * leaving it sitting readable on the stack for whatever this thread
   * calls next. Defense-in-depth only -- nothing here logs or otherwise
   * discloses psk_hex, and the caller's config retains the raw secret for
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

int pigeon_psk_register(int sec_tag, const char *identity, const char *secret) {
  if (!identity || !secret) {
    return 0;
  }

#if defined(CONFIG_MODEM_KEY_MGMT)
  return pigeon_psk_write_modem(sec_tag, identity, secret);
#else
  int err =
      tls_credential_add(sec_tag, TLS_CREDENTIAL_PSK_ID, identity, strlen(identity));

  if (err) {
    LOG_ERR("Failed to register PSK identity under sec_tag %d: %d", sec_tag, err);
    return err;
  }

  err = tls_credential_add(sec_tag, TLS_CREDENTIAL_PSK, secret, strlen(secret));

  if (err) {
    LOG_ERR("Failed to register PSK secret under sec_tag %d: %d", sec_tag, err);
    return err;
  }

  return 0;
#endif /* CONFIG_MODEM_KEY_MGMT */
}
