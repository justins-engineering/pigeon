#include <errno.h>
#include <pigeon.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/ztest.h>

/* Made up. Both ends hold the same pair, each under its own tag. */
#define TEST_PSK_IDENTITY "pigeon-coap-session-test"
#define TEST_PSK_SECRET "0123456789abcdef"
#define SERVER_TAG 46

/* What the server answers a shadow GET with. */
enum serve {
  /* loft's json_response at a 512-byte ceiling: the block asked for, Size2 on block 0. */
  SERVE_BLOCKS,
  /* One datagram larger than the block asked for, Block2 or not. */
  SERVE_OVERSIZED,
};

static atomic_t serve_mode;
static atomic_t requests;
static atomic_t server_stop;
static int server = -1;

/* The departure board's config with a firmware target, as in ../coap_block2. */
static const char board_config[] =
    "{\"stop_id\":\"414\",\"displays\":[{\"r\":\"B7\",\"d\":\"N\",\"p\":0},"
    "{\"r\":\"B7\",\"d\":\"S\",\"p\":1},{\"r\":\"P21\",\"d\":\"N\",\"p\":0},"
    "{\"r\":\"P21\",\"d\":\"S\",\"p\":1},{\"r\":\"X90\",\"d\":\"N\",\"p\":0},"
    "{\"r\":\"R29\",\"d\":\"S\",\"p\":1}],\"update_stop_interval\":300,"
    "\"telemetry_interval\":300,\"http_retry_count\":3,\"firmware\":{\"version\":\"0.15.0\","
    "\"size\":486123,\"sha256\":"
    "\"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f\"},"
    "\"firmware_repush\":1}";

static char doc[2048];
static size_t doc_len;

/* Past one 512-byte block and its options, and inside the 1024-byte record a native DTLS client
 * negotiates (CONFIG_NET_SOCKETS_DTLS_MAX_FRAGMENT_LENGTH). */
static char oversized[1000];

static void make_doc(void) {
  static char esc[2 * sizeof(board_config)];
  size_t n = 0;

  for (const char *p = board_config; *p; p++) {
    if (*p == '"' || *p == '\\') {
      esc[n++] = '\\';
    }
    esc[n++] = *p;
  }
  esc[n] = '\0';

  doc_len = (size_t)snprintk(
      doc, sizeof(doc),
      "{\"target_version\":12,\"current_version\":12,\"target_config\":\"%s\","
      "\"current_config\":\"%s\",\"updated_at\":1760000000}",
      esc, esc
  );
}

static void answer(
    const struct coap_packet *req, const struct sockaddr *from, socklen_t from_len
) {
  static uint8_t out[sizeof(oversized) + 64];
  struct coap_packet rsp;

  if (coap_ack_init(&rsp, req, out, sizeof(out), COAP_RESPONSE_CODE_CONTENT) ||
      coap_append_option_int(&rsp, COAP_OPTION_CONTENT_FORMAT, COAP_CONTENT_FORMAT_APP_JSON)) {
    return;
  }

  const char *payload = oversized;
  size_t len = sizeof(oversized);

  if (atomic_get(&serve_mode) == SERVE_BLOCKS) {
    int asked = coap_get_option_int(req, COAP_OPTION_BLOCK2);
    uint32_t num = asked < 0 ? 0 : (uint32_t)asked >> 4;
    uint32_t szx = asked < 0 ? 5 : MIN((uint32_t)asked & 0x07, 5U);
    size_t size = 16U << szx;
    size_t start = MIN(num * size, doc_len);
    size_t end = MIN(start + size, doc_len);

    if (coap_append_option_int(
            &rsp, COAP_OPTION_BLOCK2, (num << 4) | (end < doc_len ? 0x08 : 0) | szx
        ) ||
        (num == 0 && coap_append_option_int(&rsp, COAP_OPTION_SIZE2, doc_len))) {
      return;
    }
    payload = doc + start;
    len = end - start;
  }

  if (len && (coap_packet_append_payload_marker(&rsp) ||
              coap_packet_append_payload(&rsp, (const uint8_t *)payload, len))) {
    return;
  }

  (void)zsock_sendto(server, rsp.data, rsp.offset, 0, from, from_len);
}

static void server_run(void *p1, void *p2, void *p3) {
  ARG_UNUSED(p1);
  ARG_UNUSED(p2);
  ARG_UNUSED(p3);

  while (!atomic_get(&server_stop)) {
    struct zsock_pollfd pfd = {.fd = server, .events = ZSOCK_POLLIN};

    if (zsock_poll(&pfd, 1, 100) <= 0) {
      continue;
    }

    static uint8_t buf[1500];
    struct sockaddr from;
    socklen_t from_len = sizeof(from);
    ssize_t n = zsock_recvfrom(server, buf, sizeof(buf), ZSOCK_MSG_DONTWAIT, &from, &from_len);
    struct coap_packet req;

    if (n <= 0 || coap_packet_parse(&req, buf, (uint16_t)n, NULL, 0) < 0 ||
        coap_header_get_type(&req) != COAP_TYPE_CON) {
      continue;
    }
    atomic_inc(&requests);
    answer(&req, &from, from_len);
  }
}

K_THREAD_STACK_DEFINE(server_stack, 16384);
static struct k_thread server_thread;

static void *setup(void) {
  make_doc();
  zassert_equal(doc_len, 1075, "the board's 1.07 KB shadow");
  memset(oversized, ' ', sizeof(oversized));
  memcpy(oversized, "{\"pad\":", 7);

  zassert_ok(tls_credential_add(
      SERVER_TAG, TLS_CREDENTIAL_PSK, TEST_PSK_SECRET, strlen(TEST_PSK_SECRET)
  ));
  zassert_ok(tls_credential_add(
      SERVER_TAG, TLS_CREDENTIAL_PSK_ID, TEST_PSK_IDENTITY, strlen(TEST_PSK_IDENTITY)
  ));

  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(5684),
  };
  sec_tag_t tags[] = {SERVER_TAG};
  int role = TLS_DTLS_ROLE_SERVER;

  zassert_equal(zsock_inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr), 1);
  server = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_DTLS_1_2);
  zassert_true(server >= 0, "socket: %d", errno);
  zassert_ok(zsock_setsockopt(server, SOL_TLS, TLS_SEC_TAG_LIST, tags, sizeof(tags)));
  zassert_ok(zsock_setsockopt(server, SOL_TLS, TLS_DTLS_ROLE, &role, sizeof(role)));
  zassert_ok(zsock_bind(server, (struct sockaddr *)&addr, sizeof(addr)), "bind: %d", errno);
  k_thread_create(
      &server_thread, server_stack, K_THREAD_STACK_SIZEOF(server_stack), server_run, NULL, NULL,
      NULL, K_PRIO_PREEMPT(1), 0, K_NO_WAIT
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
  atomic_set(&serve_mode, SERVE_BLOCKS);
  atomic_clear(&requests);
}

static void teardown(void *fixture) {
  ARG_UNUSED(fixture);
  atomic_set(&server_stop, 1);
  k_thread_join(&server_thread, K_FOREVER);
  zsock_close(server);
}

ZTEST_SUITE(coap_session, NULL, setup, before, NULL, teardown);

/* The board's shadow is past the nRF9160's datagram; asked for in 512-byte blocks, every
 * answer fits the connector's one-block response buffer. */
ZTEST(coap_session, test_board_shadow_arrives_over_dtls_in_blocks) {
  struct pigeon_shadow_doc out;

  zassert_ok(pigeon_shadow_get(&out));
  zassert_equal(atomic_get(&requests), 3);
  zassert_equal(out.target_version, 12);
  zassert_str_equal(out.target_config, board_config);
  zassert_str_equal(out.current_config, board_config);
}

/* A receive cuts a datagram to the buffer without saying so; the connector must notice rather
 * than read what is left as the whole answer. */
ZTEST(coap_session, test_an_answer_over_the_buffer_is_refused_not_cut) {
  struct pigeon_shadow_doc out;

  atomic_set(&serve_mode, SERVE_OVERSIZED);
  zassert_equal(pigeon_shadow_get(&out), -EMSGSIZE);
  zassert_equal(atomic_get(&requests), 1);

  atomic_set(&serve_mode, SERVE_BLOCKS);
  zassert_ok(pigeon_shadow_get(&out), "the next call starts a session of its own");
  zassert_str_equal(out.target_config, board_config);
}

/* The report builds its body where the GET reassembled its blocks; the shadow that GET handed out
 * lives elsewhere and must survive it. */
ZTEST(coap_session, test_a_report_leaves_the_last_shadow_intact) {
  struct pigeon_shadow_doc out;

  zassert_ok(pigeon_shadow_get(&out));
  zassert_ok(pigeon_shadow_report(12, "{\"stop_id\":\"415\"}"));
  zassert_equal(atomic_get(&requests), 4);
  zassert_str_equal(out.target_config, board_config);
  zassert_str_equal(out.current_config, board_config);
}
