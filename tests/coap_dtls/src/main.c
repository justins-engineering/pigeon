#include <errno.h>
#include <pigeon.h>
#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/ztest.h>

/* A made-up identity and key: nothing ever completes a handshake with them. */
#define TEST_PSK_IDENTITY "pigeon-coap-dtls-test"
#define TEST_PSK_SECRET "0123456789abcdef"

/* A port on the host's own loopback, through NSOS: two runs of this suite at once fail each
 * other's bind. */
#define PEER_PORT 56841

/* The other end of CONFIG_PIGEON_ENDPOINT: a plain UDP socket that counts what arrives and
 * either stays silent or refuses each ClientHello with a fatal alert, as a terminator does for
 * an identity it does not know. */
static int peer = -1;
static atomic_t peer_refuses;
static atomic_t peer_datagrams;
static atomic_t peer_stop;

/* A DTLS 1.2 plaintext record, epoch 0, sequence 0: alert, fatal, unknown_psk_identity. */
static const uint8_t refusal[] = {21, 254, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 115};

static void peer_run(void *p1, void *p2, void *p3) {
  ARG_UNUSED(p1);
  ARG_UNUSED(p2);
  ARG_UNUSED(p3);

  while (!atomic_get(&peer_stop)) {
    struct zsock_pollfd pfd = {.fd = peer, .events = ZSOCK_POLLIN};

    if (zsock_poll(&pfd, 1, 100) <= 0) {
      continue;
    }

    uint8_t buf[1500];
    struct sockaddr from;
    socklen_t from_len = sizeof(from);

    if (zsock_recvfrom(peer, buf, sizeof(buf), 0, &from, &from_len) <= 0) {
      continue;
    }
    atomic_inc(&peer_datagrams);
    if (atomic_get(&peer_refuses)) {
      (void)zsock_sendto(peer, refusal, sizeof(refusal), 0, &from, from_len);
    }
  }
}

K_THREAD_STACK_DEFINE(peer_stack, 8192);
static struct k_thread peer_thread;

static void *setup(void) {
  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(PEER_PORT),
  };

  zassert_equal(zsock_inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr), 1);
  peer = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  zassert_true(peer >= 0, "socket: %d", errno);
  zassert_ok(zsock_bind(peer, (struct sockaddr *)&addr, sizeof(addr)), "bind: %d", errno);
  k_thread_create(
      &peer_thread, peer_stack, K_THREAD_STACK_SIZEOF(peer_stack), peer_run, NULL, NULL, NULL,
      K_PRIO_PREEMPT(1), 0, K_NO_WAIT
  );

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

static void before(void *fixture) {
  ARG_UNUSED(fixture);
  atomic_clear(&peer_refuses);
  atomic_clear(&peer_datagrams);
#if defined(CONFIG_PIGEON_COAP_AUTH_BACKOFF_SEC)
  /* Outlasts any hold an earlier test left; native_sim's clock skips ahead while idle. */
  k_sleep(K_SECONDS(CONFIG_PIGEON_COAP_AUTH_BACKOFF_SEC + 1));
#endif
}

static void teardown(void *fixture) {
  ARG_UNUSED(fixture);
  atomic_set(&peer_stop, 1);
  k_thread_join(&peer_thread, K_FOREVER);
  zsock_close(peer);
}

ZTEST_SUITE(coap_dtls, NULL, setup, before, NULL, teardown);

/* check-refusals.sh also builds this suite for the TCP transport, which runs none of these. */
#if defined(CONFIG_PIGEON_COAP_TRANSPORT_UDP)
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

/* The refusal reaches the application as -EACCES, and the next request stays off the air. */
ZTEST(coap_dtls, test_refused_handshake_holds_requests_off) {
  struct pigeon_shadow_doc doc;

  atomic_set(&peer_refuses, 1);
  int64_t start = k_uptime_get();

  zassert_equal(pigeon_shadow_get(&doc), -EACCES);
  zassert_true(k_uptime_get() - start < MSEC_PER_SEC, "a refusal is no timeout");

  atomic_val_t sent = atomic_get(&peer_datagrams);

  zassert_true(sent > 0);
  zassert_equal(pigeon_shadow_get(&doc), -EACCES);
  zassert_equal(pigeon_shadow_report(1, "{}"), -EACCES);
  k_sleep(K_MSEC(300));
  zassert_equal(atomic_get(&peer_datagrams), sent, "a held request must not reach the peer");
}
#endif
