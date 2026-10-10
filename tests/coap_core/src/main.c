#include <errno.h>
#include <pigeon.h>
#include <string.h>
#include <zephyr/net/coap.h>
#include <zephyr/ztest.h>

#include "pigeon_coap_internal.h"
#include "pigeon_psk.h"
#include "pigeon_shadow_wire.h"

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

/* JSON-string escaping as the platform's serializer applies it to a config: a JSON text holds
 * no raw control character, so only quotes and backslashes grow. */
static size_t escape(const char *in, char *out) {
  size_t n = 0;

  for (; *in; in++) {
    if (*in == '"' || *in == '\\') {
      out[n++] = '\\';
    }
    out[n++] = *in;
  }
  out[n] = '\0';

  return n;
}

/* A config of exactly len bytes in which exactly escapes bytes need escaping on the wire: the
 * four quotes of {"k":"..."} plus escaped quotes inside the value, two bytes each (\"). */
static void make_escaped_config(char *out, size_t len, size_t escapes) {
  size_t inner = (escapes - 4) / 2;

  zassert_true(escapes >= 4 && escapes % 2 == 0);
  zassert_true(len >= 8 + 2 * inner);
  strcpy(out, "{\"k\":\"");
  size_t n = 6;

  for (size_t i = 0; i < inner; i++) {
    out[n++] = '\\';
    out[n++] = '"';
  }
  while (n < len - 2) {
    out[n++] = 'a';
  }
  strcpy(out + n, "\"}");
}

static char doc[2 * PIGEON_SHADOW_CONFIG_WIRE_MAX + 256];

static void answer_shadow(const char *target, const char *current) {
  static char target_esc[2 * CONFIG_MAX * 2];
  static char current_esc[2 * CONFIG_MAX * 2];

  escape(target, target_esc);
  escape(current, current_esc);
  snprintk(
      doc, sizeof(doc),
      "{\"pigeon_id\":\"test\",\"target_version\":5,\"current_version\":4,"
      "\"target_config\":\"%s\",\"current_config\":\"%s\",\"updated_at\":1760000000}",
      target_esc, current_esc
  );
  answer_with(COAP_RESPONSE_CODE_CONTENT, doc);
}

/* The shape of the departure board's shadow: a stop, three tunables, six display rows and a
 * firmware target, 235 bytes decoded and 295 escaped, past the 256 the CoAP connector decoded
 * into before it shared the other connectors' buffers. */
static const char board_config[] =
    "{\"stop_id\":\"414\",\"poll_s\":300,\"retries\":3,\"stale_s\":600,\"displays\":["
    "{\"r\":\"B7\",\"d\":0},{\"r\":\"B7\",\"d\":1},{\"r\":\"P21\",\"d\":0},"
    "{\"r\":\"P21\",\"d\":1},{\"r\":\"X90\",\"d\":0},{\"r\":\"R29\",\"d\":1}],"
    "\"firmware\":{\"version\":\"0.15.0\",\"size\":486123,\"sha256\":\"0f\"}}";

ZTEST(coap_core, test_shadow_get_decodes_a_board_sized_config) {
  static char esc[2 * sizeof(board_config)];
  struct pigeon_shadow_doc out;

  zassert_true(strlen(board_config) < CONFIG_MAX);
  zassert_true(escape(board_config, esc) > 256, "the fixture must exceed the old CoAP cap");
  answer_shadow(board_config, "{}");

  zassert_ok(pigeon_shadow_get(&out));
  zassert_equal(seen.code, COAP_METHOD_GET);
  zassert_str_equal(seen.leaf, "shadow");
  zassert_equal(out.target_version, 5);
  zassert_equal(out.current_version, 4);
  zassert_equal(out.updated_at, 1760000000);
  zassert_str_equal(out.target_config, board_config);
  zassert_str_equal(out.current_config, "{}");
}

/* The headroom's edge: the largest config, with as many escapes as the wire buffer still holds. */
ZTEST(coap_core, test_shadow_get_decodes_the_largest_config_at_the_escape_limit) {
  static char config[CONFIG_MAX];
  static char esc[2 * CONFIG_MAX];
  size_t escapes = PIGEON_SHADOW_CONFIG_WIRE_MAX - CONFIG_MAX;
  struct pigeon_shadow_doc out;

  escapes -= escapes % 2;
  make_escaped_config(config, CONFIG_MAX - 1, escapes);
  zassert_equal(escape(config, esc), CONFIG_MAX - 1 + escapes);
  zassert_true(CONFIG_MAX - 1 + escapes < PIGEON_SHADOW_CONFIG_WIRE_MAX);
  answer_shadow(config, config);

  zassert_ok(pigeon_shadow_get(&out));
  zassert_str_equal(out.target_config, config);
  zassert_str_equal(out.current_config, config);
}

ZTEST(coap_core, test_shadow_get_refuses_a_config_past_the_escape_limit) {
  static char config[CONFIG_MAX];
  size_t escapes = PIGEON_SHADOW_CONFIG_WIRE_MAX - CONFIG_MAX + 2;
  struct pigeon_shadow_doc out;

  escapes -= escapes % 2;
  make_escaped_config(config, CONFIG_MAX - 1, escapes);
  answer_shadow(config, "{}");

  zassert_true(pigeon_shadow_get(&out) < 0);
}

ZTEST(coap_core, test_shadow_get_refuses_a_config_over_the_cap) {
  static char config[CONFIG_MAX + 1];
  struct pigeon_shadow_doc out;

  make_config(config, CONFIG_MAX);
  answer_shadow("{}", config);

  zassert_equal(pigeon_shadow_get(&out), -EMSGSIZE);
}

ZTEST(coap_core, test_shadow_get_refuses_a_partial_document) {
  struct pigeon_shadow_doc out;

  answer_with(
      COAP_RESPONSE_CODE_CONTENT,
      "{\"target_version\":5,\"current_version\":4,\"target_config\":\"{}\","
      "\"current_config\":\"{}\"}"
  );

  zassert_equal(pigeon_shadow_get(&out), -EBADMSG);
}

/* The check WS applies to a shadow_update, whose nested decode reports no missing field. */
ZTEST(coap_core, test_wire_doc_holds_a_nested_decode_to_the_cap) {
  static struct pigeon_shadow_wire wire;
  struct pigeon_shadow_doc out;

  memset(&wire, 0, sizeof(wire));
  make_config(wire.target_config, CONFIG_MAX - 1);
  zassert_ok(pigeon_shadow_wire_doc(&wire, &out));
  zassert_equal(out.target_config, wire.target_config);

  make_config(wire.current_config, CONFIG_MAX);
  zassert_equal(pigeon_shadow_wire_doc(&wire, &out), -EMSGSIZE);
}
