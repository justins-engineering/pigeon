#include <pigeon.h>
#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/ztest.h>

/* A made-up identity and key: nothing ever completes a handshake with them. */
#define TEST_PSK_IDENTITY "pigeon-coap-dtls-test"
#define TEST_PSK_SECRET "0123456789abcdef"

#define SILENT_PORT 56841

static int silent_peer = -1;

static void *setup(void) {
  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(SILENT_PORT),
  };

  zassert_equal(zsock_inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr), 1);
  silent_peer = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  zassert_true(silent_peer >= 0, "socket: %d", errno);
  zassert_ok(zsock_bind(silent_peer, (struct sockaddr *)&addr, sizeof(addr)), "bind: %d", errno);

  struct pigeon_config config = {
      .device_id = "test",
      .connector =
          {
              .type = PIGEON_CONNECTOR_COAP,
              .coap =
                  {
                      .tls_psk_identity = TEST_PSK_IDENTITY,
                      .tls_psk_secret = TEST_PSK_SECRET,
                  },
          },
  };

  zassert_ok(pigeon_init(&config));

  return NULL;
}

static void teardown(void *fixture) {
  ARG_UNUSED(fixture);
  zsock_close(silent_peer);
}

ZTEST_SUITE(coap_dtls, NULL, setup, NULL, NULL, teardown);

/* The ClientHello goes unanswered. Without a bound of the library's own, mbedTLS retransmits on
 * its defaults for about two minutes, and the modem for ever. */
ZTEST(coap_dtls, test_handshake_gives_up_within_its_bound) {
  struct pigeon_shadow_doc doc;
  int64_t start = k_uptime_get();
  int err = pigeon_shadow_get(&doc);
  int64_t took = k_uptime_get() - start;

  zassert_true(err < 0, "a handshake nobody answers cannot succeed");
  zassert_true(
      took >= (CONFIG_PIGEON_COAP_DTLS_HANDSHAKE_TIMEOUT_SEC - 1) * MSEC_PER_SEC,
      "gave up after %lld ms, before the bound", took
  );
  zassert_true(
      took < (CONFIG_PIGEON_COAP_DTLS_HANDSHAKE_TIMEOUT_SEC + 2) * MSEC_PER_SEC,
      "gave up after %lld ms", took
  );
}
