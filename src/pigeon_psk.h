#ifndef PIDGEIOT_PIGEON_PSK_H_
#define PIDGEIOT_PIGEON_PSK_H_

#include <stddef.h>

/*
 * TLS-PSK credential registration, shared by every connector that
 * authenticates with a pre-shared key: the CoAP connector's DTLS/UDP and
 * TLS/TCP transports, and the MQTT connector's PSK sessions. It lives here
 * rather than inside one connector because the second one needed it
 * verbatim, modem branch included, and a copy would have been a copy of the
 * part that is hardest to get right.
 *
 * RFC 4279 sec 5.3 only obliges TLS stacks to support PSKs up to 64 bytes;
 * the platform mints 32-hex-char secrets, well inside that.
 */
#define PIGEON_PSK_MAX 64

/*
 * Registers identity/secret under sec_tag so a TLS or DTLS socket naming
 * that tag can complete a PSK handshake with them.
 *
 * Two stores, picked at build time rather than by preference: on
 * CONFIG_MODEM_KEY_MGMT boards the handshake runs inside the modem, which
 * resolves sec_tags against its OWN credential store, so the credentials
 * are written there (%CMNG, secret ASCII-hex encoded) -- and only while the
 * modem is offline, which is why such builds must register from
 * pigeon_init() before bringing the link up rather than lazily at first
 * connect. Everywhere else the credentials go into Zephyr's native store
 * via tls_credential_add().
 *
 * Idempotent in the sense that matters on the modem: it compares digests
 * before writing, so a warm restart that reaches this with the same
 * credentials already stored neither fails nor wears flash. Callers keep
 * their own "already done this boot" latch; this function does not, so one
 * build could register two different tags if it ever needed to.
 *
 * Returns 0 on success (including "nothing supplied", when either string is
 * NULL), or a negative errno.
 */
int pigeon_psk_register(int sec_tag, const char *identity, const char *secret);

#endif /* PIDGEIOT_PIGEON_PSK_H_ */
