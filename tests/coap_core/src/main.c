#include <errno.h>
#include <pigeon.h>
#include <string.h>
#include <zephyr/net/coap.h>
#include <zephyr/sys/byteorder.h>
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
  bool has_opts;
  struct pigeon_coap_req_opts opts;
} seen;

static struct {
  int err;
  uint8_t code;
  char payload[2048];
  size_t payload_len;
} answer;

int pigeon_coap_transport_exchange(
    uint8_t code, const char *leaf, const uint8_t *payload, size_t payload_len,
    const struct pigeon_coap_req_opts *opts, struct pigeon_coap_rsp *rsp
) {
  seen.calls++;
  seen.has_opts = opts != NULL;
  if (opts) {
    seen.opts = *opts;
  }
  seen.code = code;
  strncpy(seen.leaf, leaf, sizeof(seen.leaf) - 1);
  zassert_true(payload_len < sizeof(seen.body));
  memcpy(seen.body, payload, payload_len);
  seen.body[payload_len] = '\0';
  seen.body_len = payload_len;

  if (answer.err) {
    return answer.err;
  }

  memset(rsp, 0, sizeof(*rsp));
  rsp->code = answer.code;
  rsp->payload = answer.payload_len ? (const uint8_t *)answer.payload : NULL;
  rsp->payload_len = answer.payload_len;

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
  /* Outlasts any hold an earlier test left (native_sim's clock skips ahead while idle), and an
   * answer clears the refusal count, so each test starts at the first hold. */
  k_sleep(K_SECONDS(CONFIG_PIGEON_COAP_AUTH_BACKOFF_SEC + 1));
  answer_with(COAP_RESPONSE_CODE_CHANGED, NULL);
  zassert_ok(pigeon_shadow_report(1, "{}"));
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

/* The answer is the whole shadow again, past the nRF9160's datagram at loft's default ceiling. */
ZTEST(coap_core, test_report_asks_for_the_smallest_block_of_its_answer) {
  answer_with(COAP_RESPONSE_CODE_CHANGED, NULL);

  zassert_ok(pigeon_shadow_report(7, "{}"));
  zassert_true(seen.has_opts);
  zassert_true(seen.opts.has_block2);
  zassert_equal(seen.opts.block2, 0, "block 0 of 16 bytes");
  zassert_equal(seen.opts.content_format, COAP_CONTENT_FORMAT_APP_JSON);
  zassert_is_null(seen.opts.block1);
}

/* The options go on in ascending number, Block2 (23) after Content-Format (12). */
ZTEST(coap_core, test_report_options_frame_as_zephyr_parses_them) {
  static const uint8_t token[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  struct pigeon_coap_req_opts opts = {
      .content_format = COAP_CONTENT_FORMAT_APP_JSON,
      .has_block2 = true,
      .block2 = 0,
  };
  uint8_t buf[256];
  struct coap_packet pkt;
  struct coap_packet parsed;

  zassert_ok(pigeon_coap_parse_endpoint());
  zassert_ok(coap_packet_init(
      &pkt, buf, sizeof(buf), COAP_VERSION_1, COAP_TYPE_CON, 8, token, COAP_METHOD_POST, 1
  ));
  zassert_ok(pigeon_coap_append_request_options(&pkt, "shadow", true, &opts));
  zassert_ok(coap_packet_append_payload_marker(&pkt));
  zassert_ok(coap_packet_append_payload(&pkt, (const uint8_t *)"{}", 2));
  zassert_ok(coap_packet_parse(&parsed, buf, pkt.offset, NULL, 0));
  zassert_equal(coap_get_option_int(&parsed, COAP_OPTION_CONTENT_FORMAT), 50);
  zassert_equal(coap_get_option_int(&parsed, COAP_OPTION_BLOCK2), 0);
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

/* Under the cap, and as escaped as a GET's buffer still holds: the report goes out. */
ZTEST(coap_core, test_report_at_the_escape_limit_goes_out) {
  static char config[CONFIG_MAX];
  size_t escapes = PIGEON_SHADOW_CONFIG_WIRE_MAX - CONFIG_MAX;

  escapes -= escapes % 2;
  make_escaped_config(config, CONFIG_MAX - 1, escapes);
  answer_with(COAP_RESPONSE_CODE_CHANGED, NULL);

  zassert_ok(pigeon_shadow_report(7, config));
  zassert_equal(seen.calls, 1);
}

/* Under the cap, but quote-dense: the platform would store it and send it back escaped past
 * what every later GET can decode, so the device would never see another target. */
ZTEST(coap_core, test_report_that_could_not_come_back_is_refused_and_not_sent) {
  static char config[CONFIG_MAX];
  size_t escapes = PIGEON_SHADOW_CONFIG_WIRE_MAX - CONFIG_MAX + 2;

  escapes -= escapes % 2;
  make_escaped_config(config, CONFIG_MAX - 1, escapes);
  answer_with(COAP_RESPONSE_CODE_CHANGED, NULL);

  zassert_equal(pigeon_shadow_report(7, config), -EMSGSIZE);
  zassert_equal(seen.calls, 0, "a report the GET cannot decode must not reach the platform");
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

static int get(void) {
  struct pigeon_shadow_doc out;

  return pigeon_shadow_get(&out);
}

ZTEST(coap_core, test_unauthorized_holds_every_request_off_the_air) {
  answer_with(COAP_RESPONSE_CODE_UNAUTHORIZED, NULL);
  zassert_equal(get(), -EACCES);
  zassert_equal(seen.calls, 1);

  /* Whatever the request, and however the platform would answer it now. */
  answer_with(COAP_RESPONSE_CODE_CHANGED, NULL);
  zassert_equal(get(), -EACCES);
  zassert_equal(pigeon_shadow_report(1, "{}"), -EACCES);
  zassert_equal(pigeon_transport_report_telemetry("{\"k\":\"v\"}", 9, NULL), -EACCES);
  k_sleep(K_SECONDS(CONFIG_PIGEON_COAP_AUTH_BACKOFF_FIRST_SEC - 1));
  zassert_equal(get(), -EACCES);
  zassert_equal(seen.calls, 1, "a held request must not reach the transport");
}

ZTEST(coap_core, test_forbidden_holds_like_unauthorized) {
  answer_with(COAP_RESPONSE_CODE_FORBIDDEN, NULL);
  zassert_equal(pigeon_shadow_report(1, "{}"), -EACCES);
  zassert_equal(get(), -EACCES);
  zassert_equal(seen.calls, 1);
}

ZTEST(coap_core, test_refused_handshake_holds_like_unauthorized) {
  answer.err = PIGEON_COAP_HANDSHAKE_REFUSED;
  zassert_equal(get(), -EACCES);
  answer_with(COAP_RESPONSE_CODE_CONTENT, NULL);
  zassert_equal(get(), -EACCES);
  zassert_equal(seen.calls, 1);
}

/* The modem's credential store answers -EACCES when it will not take a write: a fault on the
 * device, not the platform refusing it. */
ZTEST(coap_core, test_a_local_eacces_does_not_hold) {
  answer.err = -EACCES;
  zassert_equal(get(), -EACCES);
  answer_with(COAP_RESPONSE_CODE_CHANGED, NULL);
  zassert_ok(pigeon_shadow_report(1, "{}"));
  zassert_equal(seen.calls, 2, "the next request must go out");
}

/* One refusal can be an outage that has already passed: the first hold is the short one. */
ZTEST(coap_core, test_first_hold_ends_after_the_first_backoff) {
  answer.err = PIGEON_COAP_HANDSHAKE_REFUSED;
  zassert_equal(get(), -EACCES);
  k_sleep(K_SECONDS(CONFIG_PIGEON_COAP_AUTH_BACKOFF_FIRST_SEC));

  answer_with(COAP_RESPONSE_CODE_CHANGED, NULL);
  zassert_ok(pigeon_shadow_report(1, "{}"));
  zassert_equal(seen.calls, 2, "the first request after the hold must go out");
}

/* With the transport refusing, the time from the last refused request to the next one that
 * reaches the transport: the hold that refusal started, in whole seconds. */
static int64_t next_hold(void) {
  int calls = seen.calls;
  int64_t start = k_uptime_get();

  do {
    k_sleep(K_SECONDS(1));
    (void)get();
  } while (seen.calls == calls);

  return (k_uptime_get() - start) / MSEC_PER_SEC;
}

/* Refused again and again, the device is refused: the hold doubles until the ceiling. */
ZTEST(coap_core, test_repeated_refusals_lengthen_the_hold_to_the_ceiling) {
  int64_t expect = CONFIG_PIGEON_COAP_AUTH_BACKOFF_FIRST_SEC;

  answer.err = PIGEON_COAP_HANDSHAKE_REFUSED;
  zassert_equal(get(), -EACCES);
  for (int i = 0; i < 7; i++) {
    int64_t took = next_hold();

    zassert_equal(took, expect, "refusal %d held %lld s, not %lld s", i + 1, took, expect);
    expect = MIN(2 * expect, CONFIG_PIGEON_COAP_AUTH_BACKOFF_SEC);
  }
  zassert_equal(expect, CONFIG_PIGEON_COAP_AUTH_BACKOFF_SEC, "the ceiling was reached");
}

/* Any other answer means the credentials got through, so the next refusal starts short. */
ZTEST(coap_core, test_an_answer_starts_the_count_again) {
  answer_with(COAP_RESPONSE_CODE_UNAUTHORIZED, NULL);
  zassert_equal(get(), -EACCES);
  k_sleep(K_SECONDS(CONFIG_PIGEON_COAP_AUTH_BACKOFF_FIRST_SEC));
  answer_with(COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, NULL);
  zassert_equal(get(), -EIO);

  answer.err = PIGEON_COAP_HANDSHAKE_REFUSED;
  zassert_equal(get(), -EACCES);
  zassert_equal(next_hold(), CONFIG_PIGEON_COAP_AUTH_BACKOFF_FIRST_SEC);
}

/* A link or a terminator in trouble may be fine next time: no hold. */
ZTEST(coap_core, test_other_failures_do_not_hold) {
  answer.err = -ETIMEDOUT;
  zassert_equal(get(), -ETIMEDOUT);
  answer.err = -ECONNREFUSED;
  zassert_equal(get(), -ECONNREFUSED);
  answer_with(COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, NULL);
  zassert_equal(get(), -EIO);
  answer_with(COAP_RESPONSE_CODE_NOT_FOUND, NULL);
  zassert_equal(get(), -EIO);
  answer_with(COAP_RESPONSE_CODE_CHANGED, NULL);
  zassert_ok(pigeon_shadow_report(1, "{}"));
  zassert_equal(seen.calls, 5);
}

/* A response as the UDP transport receives it: framed and parsed by Zephyr, then read through
 * the same call the transport makes. */
ZTEST(coap_core, test_read_packet_keeps_block2_size2_etag_and_payload) {
  static const uint8_t token[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  static const uint8_t etag[4] = {0xde, 0xad, 0xbe, 0xef};
  uint8_t buf[128];
  struct coap_packet pkt;
  struct pigeon_coap_rsp rsp;

  zassert_ok(coap_packet_init(
      &pkt, buf, sizeof(buf), COAP_VERSION_1, COAP_TYPE_ACK, 8, token,
      COAP_RESPONSE_CODE_CONTENT, 0x1234
  ));
  zassert_ok(coap_packet_append_option(&pkt, COAP_OPTION_ETAG, etag, sizeof(etag)));
  zassert_ok(coap_append_option_int(&pkt, COAP_OPTION_CONTENT_FORMAT, 50));
  zassert_ok(coap_append_option_int(&pkt, COAP_OPTION_BLOCK2, (1 << 4) | 0x08 | 5));
  zassert_ok(coap_append_option_int(&pkt, COAP_OPTION_SIZE2, 1075));
  zassert_ok(coap_packet_append_payload_marker(&pkt));
  zassert_ok(coap_packet_append_payload(&pkt, (const uint8_t *)"{}", 2));

  struct coap_packet parsed;

  zassert_ok(coap_packet_parse(&parsed, buf, pkt.offset, NULL, 0));
  zassert_ok(pigeon_coap_read_packet(&parsed, &rsp));
  zassert_equal(rsp.code, COAP_RESPONSE_CODE_CONTENT);
  zassert_true(rsp.has_block2);
  zassert_equal(rsp.block2, (1 << 4) | 0x08 | 5);
  zassert_true(rsp.has_size2);
  zassert_equal(rsp.size2, 1075);
  zassert_equal(rsp.etag_len, sizeof(etag));
  zassert_mem_equal(rsp.etag, etag, sizeof(etag));
  zassert_equal(rsp.payload_len, 2);
  zassert_mem_equal(rsp.payload, "{}", 2);
}

/* Options with one- and two-byte extended deltas and lengths, as an RFC 8323 frame body. */
ZTEST(coap_core, test_read_body_walks_extended_deltas_and_lengths) {
  static uint8_t body[2 + 20 + 5 + 300 + 3 + 2];
  size_t n = 0;
  struct pigeon_coap_rsp rsp;

  /* Location-Path (8): delta 8, length 13 + 7. */
  body[n++] = (8 << 4) | 13;
  body[n++] = 7;
  memset(&body[n], 'p', 20);
  n += 20;
  /* Option 300, elective so skipped: delta 269 + 23, length 269 + 31. */
  body[n++] = (14 << 4) | 14;
  sys_put_be16(300 - 8 - 269, &body[n]);
  n += 2;
  sys_put_be16(300 - 269, &body[n]);
  n += 2;
  memset(&body[n], 'x', 300);
  n += 300;
  body[n++] = 0xFF;
  body[n++] = '{';
  body[n++] = '}';

  zassert_ok(pigeon_coap_read_body(COAP_RESPONSE_CODE_CONTENT, body, n, &rsp));
  zassert_false(rsp.has_block2);
  zassert_false(rsp.has_size2);
  zassert_equal(rsp.etag_len, 0);
  zassert_equal(rsp.payload_len, 2);
  zassert_mem_equal(rsp.payload, "{}", 2);
}

ZTEST(coap_core, test_read_body_without_payload) {
  /* Block2 (23): delta 13 + 10, one byte, num 0 m 0 szx 6. */
  static const uint8_t body[] = {(13 << 4) | 1, 10, 0x06};
  struct pigeon_coap_rsp rsp;

  zassert_ok(pigeon_coap_read_body(COAP_RESPONSE_CODE_CONTENT, body, sizeof(body), &rsp));
  zassert_true(rsp.has_block2);
  zassert_equal(rsp.block2, 0x06);
  zassert_is_null(rsp.payload);
  zassert_equal(rsp.payload_len, 0);
  zassert_ok(pigeon_coap_read_body(COAP_RESPONSE_CODE_CHANGED, NULL, 0, &rsp));
  zassert_is_null(rsp.payload);
}

ZTEST(coap_core, test_read_body_refuses_malformed_options) {
  struct pigeon_coap_rsp rsp;
  /* A value running past the body. */
  static const uint8_t past[] = {(4 << 4) | 4, 0xaa, 0xbb};
  /* A reserved delta nibble. */
  static const uint8_t delta15[] = {(15 << 4) | 0};
  /* An extended length cut short. */
  static const uint8_t cut[] = {(4 << 4) | 14, 0x00};
  /* An empty ETag, and a nine-byte one. */
  static const uint8_t etag0[] = {(4 << 4) | 0};
  static const uint8_t etag9[] = {(4 << 4) | 9, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  /* A five-byte Size2 (28): delta 13 + 15. */
  static const uint8_t size5[] = {(13 << 4) | 5, 15, 0, 0, 0, 1, 0};
  /* A payload marker with nothing after it (RFC 7252 sec 3). */
  static const uint8_t marker_only[] = {0xFF};
  /* A four-byte Block2 (23): delta 13 + 10 (RFC 7959 sec 2.2 allows three). */
  static const uint8_t block4[] = {(13 << 4) | 4, 10, 0, 0, 0, 0x06};
  /* Proxy-Uri (35), critical and unknown here: delta 13 + 22, one byte. */
  static const uint8_t critical[] = {(13 << 4) | 1, 22, 'x'};

  zassert_equal(pigeon_coap_read_body(0x45, past, sizeof(past), &rsp), -EBADMSG);
  zassert_equal(pigeon_coap_read_body(0x45, delta15, sizeof(delta15), &rsp), -EBADMSG);
  zassert_equal(pigeon_coap_read_body(0x45, cut, sizeof(cut), &rsp), -EBADMSG);
  zassert_equal(pigeon_coap_read_body(0x45, etag0, sizeof(etag0), &rsp), -EBADMSG);
  zassert_equal(pigeon_coap_read_body(0x45, etag9, sizeof(etag9), &rsp), -EBADMSG);
  zassert_equal(pigeon_coap_read_body(0x45, size5, sizeof(size5), &rsp), -EBADMSG);
  zassert_equal(pigeon_coap_read_body(0x45, marker_only, sizeof(marker_only), &rsp), -EBADMSG);
  zassert_equal(pigeon_coap_read_body(0x45, block4, sizeof(block4), &rsp), -EBADMSG);
  zassert_equal(pigeon_coap_read_body(0x45, critical, sizeof(critical), &rsp), -EBADMSG);
}

/* Block1 (27) is critical, and loft echoes it on the log upload's answers. */
ZTEST(coap_core, test_read_body_accepts_an_echoed_block1) {
  /* Block1: delta 13 + 14, one byte, num 0 m 1 szx 5. */
  static const uint8_t body[] = {(13 << 4) | 1, 14, 0x0D};
  struct pigeon_coap_rsp rsp;

  zassert_ok(pigeon_coap_read_body(COAP_RESPONSE_CODE_CONTINUE, body, sizeof(body), &rsp));
}
