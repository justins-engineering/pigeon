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

#include "pigeon_coap_internal.h"
#include "pigeon_shadow_wire.h"

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

/* What the host was asked since the last reset_seen(): firmware chunks, and apart from them
 * the shadow requests with the last one's method and body. */
static struct {
  struct k_mutex lock;
  int requests;
  long starts[MAX_SEEN];
  char path[96];
  char auth[96];
  int shadow_requests;
  char method[8];
  char body[512];
} seen;

/* How many more chunks the host serves before it answers 503; negative for no limit. */
static atomic_t serve_left;
static atomic_t server_stop;
static int listener = -1;

/* What /shadow answers: shadow_status, and with a 200 the body shadow_body, sent in two writes
 * a pause apart when shadow_split is set. */
static atomic_t shadow_status;
static const char *shadow_body;
static atomic_t shadow_split;

static void reset_seen(atomic_val_t limit) {
  k_mutex_lock(&seen.lock, K_FOREVER);
  seen.requests = 0;
  seen.path[0] = '\0';
  seen.auth[0] = '\0';
  seen.shadow_requests = 0;
  seen.method[0] = '\0';
  seen.body[0] = '\0';
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

/* The shadow route: records the request, then answers shadow_status. */
static void serve_shadow(
    int sock, const char *method, const char *path, const char *auth, const char *body
) {
  k_mutex_lock(&seen.lock, K_FOREVER);
  seen.shadow_requests++;
  strcpy(seen.method, method);
  strcpy(seen.path, path);
  strcpy(seen.auth, auth);
  strncpy(seen.body, body, sizeof(seen.body) - 1);
  k_mutex_unlock(&seen.lock);

  int status = (int)atomic_get(&shadow_status);
  const char *payload = status == 200 ? shadow_body : "";
  char head[128];
  int head_len = snprintf(
      head, sizeof(head), "HTTP/1.1 %d Test\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
      status, strlen(payload)
  );

  if (send_all(sock, head, (size_t)head_len) != 0) {
    return;
  }

  size_t len = strlen(payload);
  size_t first = atomic_get(&shadow_split) ? len / 2 : len;

  /* Each write is its own TLS record, and the pause lets the client read the first alone. */
  if (send_all(sock, payload, first) == 0 && first < len) {
    k_msleep(50);
    (void)send_all(sock, payload + first, len - first);
  }
}

/* One request per connection, as the client closes after each one. */
static void serve(int sock) {
  static char req[2048];
  size_t got = 0;
  char *head_end = NULL;

  while (!head_end && got < sizeof(req) - 1) {
    ssize_t n = zsock_recv(sock, req + got, sizeof(req) - 1 - got, 0);

    if (n <= 0) {
      return;
    }
    got += (size_t)n;
    req[got] = '\0';
    head_end = strstr(req, "\r\n\r\n");
  }
  if (!head_end) {
    return;
  }

  char method[8] = "";
  char path[96] = "";
  char auth[96];
  char range[48];
  char length[16];
  const char *sp = strchr(req, ' ');

  if (sp && (size_t)(sp - req) < sizeof(method)) {
    memcpy(method, req, (size_t)(sp - req));
    method[sp - req] = '\0';

    const char *sp2 = strchr(sp + 1, ' ');
    size_t len = sp2 ? (size_t)(sp2 - sp - 1) : 0;

    if (len < sizeof(path)) {
      memcpy(path, sp + 1, len);
      path[len] = '\0';
    }
  }
  header_value(req, "Authorization: ", auth, sizeof(auth));
  header_value(req, "Range: bytes=", range, sizeof(range));
  header_value(req, "Content-Length: ", length, sizeof(length));

  /* The body may follow the headers in later reads. */
  char *body = head_end + 4;
  size_t want = (size_t)(body - req) + strtoul(length, NULL, 10);

  while (got < want && got < sizeof(req) - 1) {
    ssize_t n = zsock_recv(sock, req + got, sizeof(req) - 1 - got, 0);

    if (n <= 0) {
      return;
    }
    got += (size_t)n;
    req[got] = '\0';
  }

  size_t path_len = strlen(path);

  if (path_len >= sizeof("/shadow") - 1 &&
      strcmp(path + path_len - (sizeof("/shadow") - 1), "/shadow") == 0) {
    serve_shadow(sock, method, path, auth, body);
    return;
  }

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

/* A shadow as dovecote sends it: both configs JSON text inside JSON strings, so escaped. */
static const char shadow_json[] =
    "{\"target_version\":7,\"current_version\":6,"
    "\"target_config\":\"{\\\"log\\\":\\\"inf\\\",\\\"telemetry_interval\\\":900}\","
    "\"current_config\":\"{\\\"log\\\":\\\"wrn\\\"}\",\"updated_at\":1786639870}";

/* Also waits out the TIME_WAIT the last request's connection left (prj.conf), which a run of
 * quick requests would otherwise exhaust the contexts with. */
static void serve_shadow_json(int status, const char *body) {
  k_msleep(2 * CONFIG_NET_TCP_TIME_WAIT_DELAY);
  atomic_set(&shadow_status, status);
  atomic_set(&shadow_split, 0);
  shadow_body = body;
  reset_seen(-1);
}

/* The fallback GET presents the token, decodes with the CoAP GET's decode and hands out configs
 * from the CoAP GET's own wire struct. The CoAP GET itself is not driven here, so a body only its
 * reassembly would treat differently goes unseen. */
ZTEST(coap_fota, test_https_shadow_decodes_as_the_coap_get_does) {
  struct pigeon_shadow_doc doc;

  serve_shadow_json(200, shadow_json);
  zassert_ok(pigeon_https_shadow_get(&doc));

  k_mutex_lock(&seen.lock, K_FOREVER);
  zassert_equal(seen.shadow_requests, 1);
  zassert_str_equal(seen.method, "GET");
  zassert_str_equal(seen.path, "/device/pigeons/test/shadow");
  zassert_str_equal(seen.auth, "Bearer " CONFIG_PIGEON_TOKEN);
  k_mutex_unlock(&seen.lock);

  static char copy[sizeof(shadow_json)];
  static struct pigeon_shadow_wire wire;
  struct pigeon_shadow_doc coap;

  memcpy(copy, shadow_json, sizeof(copy));
  zassert_ok(pigeon_shadow_wire_decode(copy, sizeof(copy) - 1, &wire, &coap));

  zassert_equal(doc.target_version, coap.target_version);
  zassert_equal(doc.current_version, coap.current_version);
  zassert_str_equal(doc.target_config, coap.target_config);
  zassert_str_equal(doc.current_config, coap.current_config);
  zassert_equal(doc.updated_at, coap.updated_at);
  zassert_str_equal(doc.target_config, "{\"log\":\"inf\",\"telemetry_interval\":900}");
  zassert_equal_ptr(doc.target_config, pigeon_coap_shadow_wire.target_config);
  zassert_equal_ptr(doc.current_config, pigeon_coap_shadow_wire.current_config);
}

/* The ack is the HTTPS connector's report, with the token. */
ZTEST(coap_fota, test_https_shadow_report_sends_the_body_with_the_token) {
  serve_shadow_json(200, shadow_json);
  zassert_ok(pigeon_https_shadow_report(7, "{\"log\":\"inf\"}"));

  k_mutex_lock(&seen.lock, K_FOREVER);
  zassert_equal(seen.shadow_requests, 1);
  zassert_str_equal(seen.method, "POST");
  zassert_str_equal(seen.path, "/device/pigeons/test/shadow");
  zassert_str_equal(seen.auth, "Bearer " CONFIG_PIGEON_TOKEN);
  zassert_str_equal(seen.body, "{\"current_config\":{\"log\":\"inf\"},\"current_version\":7}");
  k_mutex_unlock(&seen.lock);
}

/* A body that arrives in two reads is decoded whole, not as its last fragment. */
ZTEST(coap_fota, test_https_shadow_in_two_reads_decodes_whole) {
  struct pigeon_shadow_doc doc;

  serve_shadow_json(200, shadow_json);
  atomic_set(&shadow_split, 1);
  zassert_ok(pigeon_https_shadow_get(&doc));
  zassert_equal(doc.target_version, 7);
  zassert_equal(doc.updated_at, 1786639870);
  zassert_str_equal(doc.target_config, "{\"log\":\"inf\",\"telemetry_interval\":900}");
  zassert_str_equal(doc.current_config, "{\"log\":\"wrn\"}");
}

/* A body past the buffer is refused, even one whose cut prefix would decode. */
ZTEST(coap_fota, test_https_shadow_over_the_buffer_is_refused_not_cut) {
  static char padded[PIGEON_SHADOW_DOC_MAX + 64];
  struct pigeon_shadow_doc doc;

  memset(padded, ' ', sizeof(padded) - 1);
  memcpy(padded, shadow_json, sizeof(shadow_json) - 1);
  padded[sizeof(padded) - 1] = '\0';

  static char cut[PIGEON_SHADOW_DOC_MAX];
  static struct pigeon_shadow_wire wire;

  memcpy(cut, padded, sizeof(cut) - 1);
  zassert_ok(pigeon_shadow_wire_decode(cut, sizeof(cut) - 1, &wire, &doc), "the prefix decodes");

  serve_shadow_json(200, padded);
  zassert_equal(pigeon_https_shadow_get(&doc), -EMSGSIZE);
}

/* A body that fills the buffer exactly is the whole document, which the CoAP GET decodes too. */
ZTEST(coap_fota, test_https_shadow_filling_the_buffer_decodes) {
  static char padded[PIGEON_SHADOW_DOC_MAX + 1];
  struct pigeon_shadow_doc doc;

  memset(padded, ' ', sizeof(padded) - 1);
  memcpy(padded, shadow_json, sizeof(shadow_json) - 1);
  padded[sizeof(padded) - 1] = '\0';

  serve_shadow_json(200, padded);
  zassert_ok(pigeon_https_shadow_get(&doc));
  zassert_equal(doc.target_version, 7);
  zassert_str_equal(doc.target_config, "{\"log\":\"inf\",\"telemetry_interval\":900}");
}

static int get_answered(int status) {
  struct pigeon_shadow_doc doc;

  serve_shadow_json(status, NULL);

  return pigeon_https_shadow_get(&doc);
}

static int report_answered(int status) {
  serve_shadow_json(status, NULL);

  return pigeon_https_shadow_report(7, "{}");
}

/* A refused token reads as the CoAP connector's refusal; any other status is -EIO. */
ZTEST(coap_fota, test_https_shadow_refusals_map_to_eacces) {
  zassert_equal(get_answered(401), -EACCES);
  zassert_equal(report_answered(401), -EACCES);
  zassert_equal(get_answered(403), -EACCES);
  zassert_equal(report_answered(403), -EACCES);
  zassert_equal(get_answered(500), -EIO);
  zassert_equal(report_answered(500), -EIO);
}

/* A report no later GET could decode is refused before it is sent. */
ZTEST(coap_fota, test_https_shadow_report_over_the_cap_sends_nothing) {
  static char config[CONFIG_PIGEON_SHADOW_CONFIG_MAX + 8];

  memset(config, 'a', sizeof(config) - 1);
  memcpy(config, "{\"k\":\"", 6);
  memcpy(config + sizeof(config) - 3, "\"}", 2);
  config[sizeof(config) - 1] = '\0';

  serve_shadow_json(200, shadow_json);
  zassert_equal(pigeon_https_shadow_report(7, config), -EMSGSIZE);

  k_mutex_lock(&seen.lock, K_FOREVER);
  zassert_equal(seen.shadow_requests, 0);
  k_mutex_unlock(&seen.lock);
}
