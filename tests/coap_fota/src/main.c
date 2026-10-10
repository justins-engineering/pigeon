#include <errno.h>
#include <pigeon.h>
#include <psa/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/ztest.h>

/* Made up. The firmware host here is TLS-PSK so the suite needs no certificate; the CoAP
 * connector's own PSK sits at another tag, as it must on a device. */
#define TEST_PSK_IDENTITY "pigeon-coap-fota-test"
#define TEST_PSK_SECRET "fedcba9876543210"
#define TEST_COAP_PSK_IDENTITY "pigeon-coap-fota-coap"
#define TEST_COAP_PSK_SECRET "0123456789abcdef"

#define CHUNK CONFIG_PIGEON_FOTA_CHUNK_SIZE
#define IMAGE_SIZE (3 * CHUNK + 700)
#define MAX_SEEN 16

static uint8_t image[IMAGE_SIZE];
static char image_sha256[PIGEON_FOTA_SHA256_HEX_LEN + 1];

/* What the firmware host was asked since the last reset_seen(). */
static struct {
  struct k_mutex lock;
  int requests;
  long starts[MAX_SEEN];
  char path[96];
  char auth[96];
} seen;

/* How many more chunks the host serves before it answers 503; negative for no limit. */
static atomic_t serve_left;
static atomic_t server_stop;
static int listener = -1;

static void reset_seen(atomic_val_t limit) {
  k_mutex_lock(&seen.lock, K_FOREVER);
  seen.requests = 0;
  seen.path[0] = '\0';
  seen.auth[0] = '\0';
  k_mutex_unlock(&seen.lock);
  atomic_set(&serve_left, limit);
}

static int send_all(int sock, const void *buf, size_t len) {
  const uint8_t *p = buf;

  while (len > 0) {
    ssize_t n = zsock_send(sock, p, len, 0);

    if (n <= 0) {
      return -1;
    }
    p += n;
    len -= (size_t)n;
  }

  return 0;
}

/* Copies the value of header name from req into out, or leaves out empty. */
static void header_value(const char *req, const char *name, char *out, size_t out_len) {
  out[0] = '\0';

  const char *at = strstr(req, name);

  if (!at) {
    return;
  }
  at += strlen(name);

  const char *end = strstr(at, "\r\n");
  size_t len = end ? (size_t)(end - at) : strlen(at);

  if (len >= out_len) {
    len = out_len - 1;
  }
  memcpy(out, at, len);
  out[len] = '\0';
}

/* One request per connection, as the client closes after each chunk. */
static void serve(int sock) {
  char req[1024];
  size_t got = 0;

  while (got < sizeof(req) - 1) {
    ssize_t n = zsock_recv(sock, req + got, sizeof(req) - 1 - got, 0);

    if (n <= 0) {
      return;
    }
    got += (size_t)n;
    req[got] = '\0';
    if (strstr(req, "\r\n\r\n")) {
      break;
    }
  }

  char path[96] = "";
  char auth[96];
  char range[48];
  const char *sp = strchr(req, ' ');

  if (sp) {
    const char *sp2 = strchr(sp + 1, ' ');
    size_t len = sp2 ? (size_t)(sp2 - sp - 1) : 0;

    if (len < sizeof(path)) {
      memcpy(path, sp + 1, len);
      path[len] = '\0';
    }
  }
  header_value(req, "Authorization: ", auth, sizeof(auth));
  header_value(req, "Range: bytes=", range, sizeof(range));

  char *dash;
  long start = strtol(range, &dash, 10);
  long end = (*dash == '-') ? strtol(dash + 1, NULL, 10) : -1;

  k_mutex_lock(&seen.lock, K_FOREVER);
  if (seen.requests < MAX_SEEN) {
    seen.starts[seen.requests] = start;
  }
  seen.requests++;
  strcpy(seen.path, path);
  strcpy(seen.auth, auth);
  k_mutex_unlock(&seen.lock);

  static const char refused[] = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
                                "Connection: close\r\n\r\n";
  static const char unauthorized[] = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
                                     "Connection: close\r\n\r\n";

  if (strcmp(auth, "Bearer " CONFIG_PIGEON_TOKEN) != 0) {
    (void)send_all(sock, unauthorized, sizeof(unauthorized) - 1);
    return;
  }
  if (start < 0 || start >= IMAGE_SIZE || end < start) {
    (void)send_all(sock, refused, sizeof(refused) - 1);
    return;
  }
  if (atomic_get(&serve_left) == 0) {
    (void)send_all(sock, refused, sizeof(refused) - 1);
    return;
  }
  if (atomic_get(&serve_left) > 0) {
    atomic_dec(&serve_left);
  }
  if (end >= IMAGE_SIZE) {
    end = IMAGE_SIZE - 1;
  }

  char head[160];
  int head_len = snprintf(
      head, sizeof(head),
      "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes %ld-%ld/%d\r\n"
      "Content-Length: %ld\r\nConnection: close\r\n\r\n",
      start, end, IMAGE_SIZE, end - start + 1
  );

  if (send_all(sock, head, (size_t)head_len) == 0) {
    (void)send_all(sock, image + start, (size_t)(end - start + 1));
  }
}

static void server_run(void *p1, void *p2, void *p3) {
  ARG_UNUSED(p1);
  ARG_UNUSED(p2);
  ARG_UNUSED(p3);

  while (!atomic_get(&server_stop)) {
    struct zsock_pollfd pfd = {.fd = listener, .events = ZSOCK_POLLIN};

    if (zsock_poll(&pfd, 1, 100) <= 0) {
      continue;
    }

    int sock = zsock_accept(listener, NULL, NULL);

    if (sock < 0) {
      continue;
    }
    serve(sock);
    zsock_close(sock);
  }
}

K_THREAD_STACK_DEFINE(server_stack, 16384);
static struct k_thread server_thread;

static void add_psk(sec_tag_t tag, const char *identity, const char *secret) {
  zassert_ok(tls_credential_add(tag, TLS_CREDENTIAL_PSK, secret, strlen(secret)));
  zassert_ok(tls_credential_add(tag, TLS_CREDENTIAL_PSK_ID, identity, strlen(identity)));
}

static void *setup(void) {
  k_mutex_init(&seen.lock);

  for (size_t i = 0; i < sizeof(image); i++) {
    image[i] = (uint8_t)(i * 7 + (i >> 8));
  }

  uint8_t digest[32];
  size_t digest_len;

  zassert_equal(psa_crypto_init(), PSA_SUCCESS);
  zassert_equal(
      psa_hash_compute(PSA_ALG_SHA_256, image, sizeof(image), digest, sizeof(digest), &digest_len),
      PSA_SUCCESS
  );
  for (size_t i = 0; i < sizeof(digest); i++) {
    static const char hex[] = "0123456789abcdef";

    image_sha256[2 * i] = hex[digest[i] >> 4];
    image_sha256[2 * i + 1] = hex[digest[i] & 0xf];
  }
  image_sha256[PIGEON_FOTA_SHA256_HEX_LEN] = '\0';

  /* The client and the server share the HTTPS tag: one PSK, both ends. */
  add_psk(CONFIG_PIGEON_HTTPS_SEC_TAG, TEST_PSK_IDENTITY, TEST_PSK_SECRET);

  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(443),
  };

  zassert_equal(zsock_inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr), 1);
  listener = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
  zassert_true(listener >= 0, "socket: %d", errno);

  sec_tag_t tags[] = {CONFIG_PIGEON_HTTPS_SEC_TAG};

  zassert_ok(zsock_setsockopt(listener, SOL_TLS, TLS_SEC_TAG_LIST, tags, sizeof(tags)));
  zassert_ok(zsock_bind(listener, (struct sockaddr *)&addr, sizeof(addr)), "bind: %d", errno);
  zassert_ok(zsock_listen(listener, 2), "listen: %d", errno);
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
                      .tls_psk_identity = TEST_COAP_PSK_IDENTITY,
                      .tls_psk_secret = TEST_COAP_PSK_SECRET,
                  },
          },
  };

  zassert_ok(pigeon_init(&config));

  return NULL;
}

static void teardown(void *fixture) {
  ARG_UNUSED(fixture);
  atomic_set(&server_stop, 1);
  k_thread_join(&server_thread, K_FOREVER);
  zsock_close(listener);
}

ZTEST_SUITE(coap_fota, NULL, setup, NULL, NULL, teardown);

static struct pigeon_fota_info target(const char *version) {
  struct pigeon_fota_info info = {.size = IMAGE_SIZE};

  strncpy(info.version, version, sizeof(info.version) - 1);
  memcpy(info.sha256, image_sha256, sizeof(info.sha256));

  return info;
}

static void assert_slot_holds_image(void) {
  const struct flash_area *fa;
  static uint8_t back[CHUNK];

  zassert_ok(flash_area_open(PARTITION_ID(slot1_partition), &fa));
  for (size_t off = 0; off < IMAGE_SIZE; off += CHUNK) {
    size_t n = MIN(CHUNK, IMAGE_SIZE - off);

    zassert_ok(flash_area_read(fa, off, back, n));
    zassert_mem_equal(back, image + off, n, "slot differs from the image at %zu", off);
  }
  flash_area_close(fa);
}

/* The shadow names the image over CoAP; the image itself comes from the HTTPS host, chunk by
 * chunk, with the pigeon's bearer token. */
ZTEST(coap_fota, test_image_comes_over_https_with_the_token) {
  struct pigeon_fota_info info = target("1.1.0");

  reset_seen(-1);
  zassert_ok(pigeon_fota_apply(&info));

  k_mutex_lock(&seen.lock, K_FOREVER);
  zassert_equal(seen.requests, 4, "%d requests for a four-chunk image", seen.requests);
  for (int i = 0; i < 4; i++) {
    zassert_equal(seen.starts[i], (long)i * CHUNK, "chunk %d asked from %ld", i, seen.starts[i]);
  }
  zassert_str_equal(seen.path, "/device/pigeons/test/firmware");
  zassert_str_equal(seen.auth, "Bearer " CONFIG_PIGEON_TOKEN);
  k_mutex_unlock(&seen.lock);
  assert_slot_holds_image();
}

/* A transfer cut off mid-image continues from what reached flash, not from byte 0. */
ZTEST(coap_fota, test_interrupted_image_resumes_where_flash_stopped) {
  struct pigeon_fota_info info = target("1.2.0");

  reset_seen(2);
  zassert_true(pigeon_fota_apply(&info) < 0, "the host refused the third chunk");

  reset_seen(-1);
  zassert_ok(pigeon_fota_apply(&info));

  k_mutex_lock(&seen.lock, K_FOREVER);
  zassert_equal(seen.starts[0], 2 * CHUNK, "resumed from %ld", seen.starts[0]);
  zassert_equal(seen.requests, 2);
  k_mutex_unlock(&seen.lock);
  assert_slot_holds_image();
}

/* A start from byte 0 spends an attempt, a continuation that advances spends none, one that
 * stands still spends one, and a new shadow write reopens the budget. */
ZTEST(coap_fota, test_budget_charges_fresh_and_stalled_attempts) {
  struct pigeon_fota_info info = target("1.3.0");

  zassert_true(pigeon_fota_attempt_allowed(&info, 7));

  reset_seen(1);
  zassert_true(pigeon_fota_apply(&info) < 0);
  zassert_true(pigeon_fota_attempt_allowed(&info, 7), "one of two spent");

  reset_seen(1);
  zassert_true(pigeon_fota_apply(&info) < 0);
  zassert_equal(seen.starts[0], CHUNK, "a continuation, not a restart");
  zassert_true(pigeon_fota_attempt_allowed(&info, 7), "progress spends nothing");

  reset_seen(0);
  zassert_true(pigeon_fota_apply(&info) < 0);
  zassert_false(pigeon_fota_attempt_allowed(&info, 7), "a stalled continuation spends one");
  zassert_true(pigeon_fota_attempt_allowed(&info, 8), "a new shadow write reopens it");
}
