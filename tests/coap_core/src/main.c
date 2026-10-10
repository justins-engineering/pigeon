#include <errno.h>
#include <pigeon.h>
#include <string.h>
#include <zephyr/net/coap.h>
#include <zephyr/ztest.h>

#include "pigeon_coap_internal.h"
#include "pigeon_psk.h"

#define CONFIG_MAX CONFIG_PIGEON_SHADOW_CONFIG_MAX

/* What the scripted transport saw, and what it answers. */
static struct {
  int calls;
  uint8_t code;
  char leaf[16];
  char body[2048];
  size_t body_len;
} seen;

static struct {
  int err;
  uint8_t code;
  char payload[2048];
  size_t payload_len;
} answer;

int pigeon_coap_transport_exchange(
    uint8_t code, const char *leaf, const uint8_t *payload, size_t payload_len,
    const struct pigeon_coap_req_opts *opts, uint8_t *rsp_code, const uint8_t **rsp_payload,
    size_t *rsp_payload_len
) {
  ARG_UNUSED(opts);

  seen.calls++;
  seen.code = code;
  strncpy(seen.leaf, leaf, sizeof(seen.leaf) - 1);
  zassert_true(payload_len < sizeof(seen.body));
  memcpy(seen.body, payload, payload_len);
  seen.body[payload_len] = '\0';
  seen.body_len = payload_len;

  if (answer.err) {
    return answer.err;
  }

  *rsp_code = answer.code;
  *rsp_payload = answer.payload_len ? (const uint8_t *)answer.payload : NULL;
  *rsp_payload_len = answer.payload_len;

  return 0;
}

int pigeon_psk_register(int sec_tag, const char *identity, const char *secret) {
  ARG_UNUSED(sec_tag);
  ARG_UNUSED(identity);
  ARG_UNUSED(secret);

  return 0;
}

static void answer_with(uint8_t code, const char *payload) {
  answer.err = 0;
  answer.code = code;
  answer.payload_len = payload ? strlen(payload) : 0;
  if (payload) {
    memcpy(answer.payload, payload, answer.payload_len);
  }
}

/* A valid JSON object of exactly len bytes: {"k":"aaaa...."}. */
static void make_config(char *out, size_t len) {
  zassert_true(len >= 9);
  strcpy(out, "{\"k\":\"");
  memset(out + 6, 'a', len - 8);
  strcpy(out + len - 2, "\"}");
}

static void reset(void *fixture) {
  ARG_UNUSED(fixture);
  memset(&seen, 0, sizeof(seen));
  memset(&answer, 0, sizeof(answer));
}

ZTEST_SUITE(coap_core, NULL, NULL, reset, NULL, NULL);

ZTEST(coap_core, test_report_carries_the_largest_config_whole) {
  static char config[CONFIG_MAX];
  static char expect[CONFIG_MAX + 64];

  make_config(config, CONFIG_MAX - 1);
  snprintk(expect, sizeof(expect), "{\"current_config\":%s,\"current_version\":7}", config);
  answer_with(COAP_RESPONSE_CODE_CHANGED, NULL);

  zassert_ok(pigeon_shadow_report(7, config));
  zassert_equal(seen.calls, 1);
  zassert_equal(seen.code, COAP_METHOD_POST);
  zassert_str_equal(seen.leaf, "shadow");
  zassert_str_equal(seen.body, expect, "the report must leave whole");
}

ZTEST(coap_core, test_report_carries_the_largest_version_whole) {
  static char config[CONFIG_MAX];
  static char expect[CONFIG_MAX + 64];

  make_config(config, CONFIG_MAX - 1);
  snprintk(
      expect, sizeof(expect), "{\"current_config\":%s,\"current_version\":-2147483648}", config
  );
  answer_with(COAP_RESPONSE_CODE_CHANGED, NULL);

  zassert_ok(pigeon_shadow_report(INT32_MIN, config));
  zassert_str_equal(seen.body, expect);
}

ZTEST(coap_core, test_oversized_report_is_refused_and_not_sent) {
  static char config[CONFIG_MAX + 1];

  make_config(config, CONFIG_MAX);
  answer_with(COAP_RESPONSE_CODE_CHANGED, NULL);

  zassert_equal(pigeon_shadow_report(7, config), -EMSGSIZE);
  zassert_equal(seen.calls, 0, "a cut report must not reach the platform");
}
