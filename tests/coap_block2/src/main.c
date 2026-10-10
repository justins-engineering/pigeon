#include <errno.h>
#include <pigeon.h>
#include <string.h>
#include <zephyr/net/coap.h>
#include <zephyr/ztest.h>

#include "pigeon_coap_internal.h"
#include "pigeon_psk.h"
#include "pigeon_shadow_wire.h"

/* RFC 7959 Block option values: num << 4 | m << 3 | szx; szx 4, 5, 6 are 256, 512, 1024. */
#define BLOCK(num, more, szx) (((uint32_t)(num) << 4) | ((more) ? 0x08U : 0U) | (szx))

#define MAX_CALLS 16

/* The document behind the shadow route, and the terminator in front of it. */
static struct {
  const char *doc;
  size_t len;
  /* LOFT_UDP_MAX_BLOCK_BYTES as a block-size exponent. */
  uint32_t max_szx;
  /* An ETag on every block when etag_len is not 0, as loft sends on a firmware image. */
  uint8_t etag[PIGEON_COAP_ETAG_MAX];
  uint8_t etag_len;
  /* Applied to each response after it is built; a non-zero return is the exchange's error. */
  int (*tamper)(int call, struct pigeon_coap_rsp *rsp);
} server;

/* The Block2 option each request carried, or -1 for none. */
static struct {
  int calls;
  int64_t block2[MAX_CALLS];
} seen;

/* loft's json_response (~/loft loft/src/handler.rs) for a 2.05 on UDP: a requested Block2 is
 * served at no more than the ceiling, the offset kept; no request option and a body over the
 * ceiling gets block 0 anyway; Size2 rides block 0 only; no ETag on a JSON body. */
static void loft_json_response(
    const struct pigeon_coap_req_opts *opts, struct pigeon_coap_rsp *rsp
) {
  uint32_t num = 0;
  uint32_t szx = server.max_szx;
  bool block = server.len > (16U << server.max_szx);

  memset(rsp, 0, sizeof(*rsp));
  rsp->code = COAP_RESPONSE_CODE_CONTENT;

  if (opts && opts->has_block2) {
    num = opts->block2 >> 4;
    szx = MIN(opts->block2 & 0x07, 6U);
    if (szx > server.max_szx) {
      num <<= szx - server.max_szx;
      szx = server.max_szx;
    }
    block = true;
  }

  if (!block) {
    rsp->payload = (const uint8_t *)server.doc;
    rsp->payload_len = server.len;
    return;
  }

  size_t size = 16U << szx;
  size_t start = num * size;

  if (start >= server.len && num > 0) {
    rsp->code = COAP_RESPONSE_CODE_BAD_REQUEST;
    return;
  }

  size_t end = MIN(start + size, server.len);

  rsp->has_block2 = true;
  rsp->block2 = BLOCK(num, end < server.len, szx);
  if (num == 0) {
    rsp->has_size2 = true;
    rsp->size2 = server.len;
  }
  rsp->payload = end > start ? (const uint8_t *)server.doc + start : NULL;
  rsp->payload_len = end - start;
  rsp->etag_len = server.etag_len;
  memcpy(rsp->etag, server.etag, server.etag_len);
}

int pigeon_coap_transport_exchange(
    uint8_t code, const char *leaf, const uint8_t *payload, size_t payload_len,
    const struct pigeon_coap_req_opts *opts, struct pigeon_coap_rsp *rsp
) {
  ARG_UNUSED(payload);
  ARG_UNUSED(payload_len);

  int call = seen.calls++;

  zassert_true(call < MAX_CALLS, "the client must stop asking");
  zassert_equal(code, COAP_METHOD_GET);
  zassert_str_equal(leaf, "shadow");
  seen.block2[call] = (opts && opts->has_block2) ? (int64_t)opts->block2 : -1;

  loft_json_response(opts, rsp);

  return server.tamper ? server.tamper(call, rsp) : 0;
}

int pigeon_psk_register(int sec_tag, const char *identity, const char *secret) {
  ARG_UNUSED(sec_tag);
  ARG_UNUSED(identity);
  ARG_UNUSED(secret);

  return 0;
}

/* JSON-string escaping as the platform applies it to a config. */
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

/* capsules::PigeonShadow as dovecote serializes it for the device. */
static size_t make_doc(char *out, size_t size, int32_t version, const char *config) {
  static char esc[2 * CONFIG_PIGEON_SHADOW_CONFIG_MAX];

  escape(config, esc);
  return (size_t)snprintk(
      out, size,
      "{\"target_version\":%d,\"current_version\":%d,\"target_config\":\"%s\","
      "\"current_config\":\"%s\",\"updated_at\":1760000000}",
      version, version, esc, esc
  );
}

/* The departure board's shadow once a firmware target is assigned: the sign's own keys in the
 * shape of its provisioning copy (a 257-byte config against 258 measured for sign 414), then the
 * firmware object with a full sha256 and the re-push counter. Synthetic values, real shape. */
static const char board_config[] =
    "{\"stop_id\":\"414\",\"displays\":[{\"r\":\"B7\",\"d\":\"N\",\"p\":0},"
    "{\"r\":\"B7\",\"d\":\"S\",\"p\":1},{\"r\":\"P21\",\"d\":\"N\",\"p\":0},"
    "{\"r\":\"P21\",\"d\":\"S\",\"p\":1},{\"r\":\"X90\",\"d\":\"N\",\"p\":0},"
    "{\"r\":\"R29\",\"d\":\"S\",\"p\":1}],\"update_stop_interval\":300,"
    "\"telemetry_interval\":300,\"http_retry_count\":3,\"firmware\":{\"version\":\"0.15.0\","
    "\"size\":486123,\"sha256\":"
    "\"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f\"},"
    "\"firmware_repush\":1}";

static char doc[PIGEON_SHADOW_DOC_MAX + 1024];

static void serve_board(uint32_t max_szx) {
  server.doc = doc;
  server.len = make_doc(doc, sizeof(doc), 12, board_config);
  server.max_szx = max_szx;
}

static void reset(void *fixture) {
  ARG_UNUSED(fixture);
  memset(&server, 0, sizeof(server));
  memset(&seen, 0, sizeof(seen));
  /* Outlasts any hold an earlier test left; native_sim's clock skips ahead while idle. */
  k_sleep(K_SECONDS(CONFIG_PIGEON_COAP_AUTH_BACKOFF_SEC + 1));
}

ZTEST_SUITE(coap_block2, NULL, NULL, reset, NULL, NULL);

static void assert_board(const struct pigeon_shadow_doc *out) {
  zassert_equal(out->target_version, 12);
  zassert_equal(out->current_version, 12);
  zassert_equal(out->updated_at, 1760000000);
  zassert_str_equal(out->target_config, board_config);
  zassert_str_equal(out->current_config, board_config);
}

ZTEST(coap_block2, test_board_shadow_arrives_in_three_blocks) {
  struct pigeon_shadow_doc out;

  serve_board(5);
  zassert_equal(server.len, 1075, "the fixture is the board's 1.07 KB shadow");

  zassert_ok(pigeon_shadow_get(&out));
  assert_board(&out);
  zassert_equal(seen.calls, 3);
  zassert_equal(seen.block2[0], BLOCK(0, 0, 5));
  zassert_equal(seen.block2[1], BLOCK(1, 0, 5));
  zassert_equal(seen.block2[2], BLOCK(2, 0, 5));
}

/* loft's default ceiling is 1024; the device's smaller ask still sets the size. */
ZTEST(coap_block2, test_board_shadow_under_lofts_default_ceiling) {
  struct pigeon_shadow_doc out;

  serve_board(6);
  zassert_ok(pigeon_shadow_get(&out));
  assert_board(&out);
  zassert_equal(seen.calls, 3);
  zassert_equal(seen.block2[2], BLOCK(2, 0, 5));
}

ZTEST(coap_block2, test_smaller_blocks_from_the_terminator_are_followed) {
  struct pigeon_shadow_doc out;

  serve_board(4);
  zassert_ok(pigeon_shadow_get(&out));
  assert_board(&out);
  zassert_equal(seen.calls, 5);
  zassert_equal(seen.block2[0], BLOCK(0, 0, 5));
  for (int i = 1; i < 5; i++) {
    zassert_equal(seen.block2[i], BLOCK(i, 0, 4));
  }
}

ZTEST(coap_block2, test_a_small_shadow_is_one_exchange) {
  static char small[256];
  struct pigeon_shadow_doc out;

  server.doc = small;
  server.len = make_doc(small, sizeof(small), 3, "{\"stop_id\":\"1670\"}");
  server.max_szx = 5;

  zassert_ok(pigeon_shadow_get(&out));
  zassert_str_equal(out.target_config, "{\"stop_id\":\"1670\"}");
  zassert_equal(seen.calls, 1);
  zassert_equal(seen.block2[0], BLOCK(0, 0, 5));
}

static int ignore_block2(int call, struct pigeon_coap_rsp *rsp) {
  ARG_UNUSED(call);
  rsp->has_block2 = false;
  rsp->has_size2 = false;
  rsp->payload = (const uint8_t *)server.doc;
  rsp->payload_len = server.len;
  return 0;
}

/* A server that does not speak Block2 answers whole, as before this client asked. */
ZTEST(coap_block2, test_a_server_ignoring_block2_still_serves_the_whole_shadow) {
  struct pigeon_shadow_doc out;

  serve_board(5);
  server.tamper = ignore_block2;
  zassert_ok(pigeon_shadow_get(&out));
  assert_board(&out);
  zassert_equal(seen.calls, 1);
}

static void serve_oversized(void) {
  memset(doc, 'x', sizeof(doc));
  server.doc = doc;
  server.len = sizeof(doc);
  server.max_szx = 5;
}

ZTEST(coap_block2, test_size2_past_the_cap_is_refused_at_block_0) {
  struct pigeon_shadow_doc out;

  serve_oversized();
  zassert_equal(pigeon_shadow_get(&out), -EMSGSIZE);
  zassert_equal(seen.calls, 1, "no block past the first may be fetched");
}

static int drop_size2(int call, struct pigeon_coap_rsp *rsp) {
  ARG_UNUSED(call);
  rsp->has_size2 = false;
  return 0;
}

ZTEST(coap_block2, test_a_document_past_the_cap_without_size2_is_refused) {
  struct pigeon_shadow_doc out;

  serve_oversized();
  server.tamper = drop_size2;
  zassert_equal(pigeon_shadow_get(&out), -EMSGSIZE);
  zassert_equal(seen.calls, PIGEON_SHADOW_DOC_MAX / 512 + 1);
}

static int skip_block_1(int call, struct pigeon_coap_rsp *rsp) {
  if (call == 1) {
    rsp->block2 = BLOCK(2, 0, 5);
    rsp->payload = (const uint8_t *)server.doc + 1024;
    rsp->payload_len = server.len - 1024;
  }
  return 0;
}

ZTEST(coap_block2, test_a_gap_fails) {
  struct pigeon_shadow_doc out;

  serve_board(5);
  server.tamper = skip_block_1;
  zassert_equal(pigeon_shadow_get(&out), -EBADMSG);
  zassert_equal(seen.calls, 2);
}

static int short_block_0(int call, struct pigeon_coap_rsp *rsp) {
  if (call == 0) {
    rsp->payload_len -= 1;
  }
  return 0;
}

ZTEST(coap_block2, test_a_short_block_before_the_last_fails) {
  struct pigeon_shadow_doc out;

  serve_board(5);
  server.tamper = short_block_0;
  zassert_equal(pigeon_shadow_get(&out), -EBADMSG);
  zassert_equal(seen.calls, 1);
}

static int whole_block_1(int call, struct pigeon_coap_rsp *rsp) {
  if (call == 1) {
    rsp->has_block2 = false;
  }
  return 0;
}

ZTEST(coap_block2, test_a_later_block_without_block2_fails) {
  struct pigeon_shadow_doc out;

  serve_board(5);
  server.tamper = whole_block_1;
  zassert_equal(pigeon_shadow_get(&out), -EBADMSG);
}

static int larger_than_asked(int call, struct pigeon_coap_rsp *rsp) {
  if (call == 0) {
    rsp->block2 = BLOCK(0, 1, 6);
    rsp->payload_len = 1024;
  }
  return 0;
}

ZTEST(coap_block2, test_a_block_larger_than_asked_fails) {
  struct pigeon_shadow_doc out;

  serve_board(5);
  server.tamper = larger_than_asked;
  zassert_equal(pigeon_shadow_get(&out), -EBADMSG);
}

/* An ETag on every block, as loft sends with a firmware image, that stays put. */
ZTEST(coap_block2, test_a_steady_etag_is_accepted) {
  static const uint8_t tag[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  struct pigeon_shadow_doc out;

  serve_board(5);
  memcpy(server.etag, tag, sizeof(tag));
  server.etag_len = sizeof(tag);
  zassert_ok(pigeon_shadow_get(&out));
  assert_board(&out);
}

static int etag_changes_at_2(int call, struct pigeon_coap_rsp *rsp) {
  if (call == 2) {
    rsp->etag[0] ^= 0xFF;
  }
  return 0;
}

static int etag_vanishes_at_1(int call, struct pigeon_coap_rsp *rsp) {
  if (call == 1) {
    rsp->etag_len = 0;
  }
  return 0;
}

ZTEST(coap_block2, test_a_changed_etag_fails) {
  static const uint8_t tag[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  struct pigeon_shadow_doc out;

  serve_board(5);
  memcpy(server.etag, tag, sizeof(tag));
  server.etag_len = sizeof(tag);
  server.tamper = etag_changes_at_2;
  zassert_equal(pigeon_shadow_get(&out), -EAGAIN);
  zassert_equal(seen.calls, 3);

  memset(&seen, 0, sizeof(seen));
  server.tamper = etag_vanishes_at_1;
  zassert_equal(pigeon_shadow_get(&out), -EAGAIN);
  zassert_equal(seen.calls, 2);
}

/* loft fetches the shadow again for every block and sends no ETag on it, so a dashboard write
 * between two blocks reaches the device as blocks of two documents. A new length is caught by
 * Size2 against what arrived; a document that shrank past the block asked for is loft's 4.00. */
static char edited[PIGEON_SHADOW_DOC_MAX];
static char edited_config[sizeof(board_config)];

static int edit_after_block_0(int call, struct pigeon_coap_rsp *rsp) {
  ARG_UNUSED(rsp);
  if (call == 0) {
    server.doc = edited;
    server.len = make_doc(edited, sizeof(edited), 13, edited_config);
  }
  return 0;
}

ZTEST(coap_block2, test_a_shadow_that_changes_length_between_blocks_fails) {
  struct pigeon_shadow_doc out;
  char *stop = edited_config + strlen("{\"stop_id\":\"");

  /* Stop 73 in place of 414: two bytes shorter, still three blocks. */
  strcpy(edited_config, "{\"stop_id\":\"73");
  strcat(edited_config, board_config + strlen("{\"stop_id\":\"414"));
  zassert_equal(strncmp(stop, "73\"", 3), 0);

  serve_board(5);
  server.tamper = edit_after_block_0;
  zassert_equal(pigeon_shadow_get(&out), -EAGAIN);
  zassert_equal(seen.calls, 3);

  /* The next call reads the new document from block 0. */
  server.tamper = NULL;
  memset(&seen, 0, sizeof(seen));
  zassert_ok(pigeon_shadow_get(&out));
  zassert_equal(out.target_version, 13);
  zassert_str_equal(out.target_config, edited_config);
  zassert_equal(seen.calls, 3);
  zassert_equal(seen.block2[0], BLOCK(0, 0, 5));
}

static int shrink_after_block_0(int call, struct pigeon_coap_rsp *rsp) {
  ARG_UNUSED(rsp);
  if (call == 0) {
    server.doc = edited;
    server.len = make_doc(edited, sizeof(edited), 13, "{\"stop_id\":\"73\"}");
  }
  return 0;
}

ZTEST(coap_block2, test_a_shadow_that_shrinks_between_blocks_fails) {
  struct pigeon_shadow_doc out;

  serve_board(5);
  server.tamper = shrink_after_block_0;
  zassert_equal(pigeon_shadow_get(&out), -EIO);
  zassert_equal(seen.calls, 2);
}

static int time_out_block_1(int call, struct pigeon_coap_rsp *rsp) {
  ARG_UNUSED(rsp);
  return call == 1 ? -ETIMEDOUT : 0;
}

ZTEST(coap_block2, test_a_failed_exchange_ends_the_transfer_and_the_next_starts_over) {
  struct pigeon_shadow_doc out;

  serve_board(5);
  server.tamper = time_out_block_1;
  zassert_equal(pigeon_shadow_get(&out), -ETIMEDOUT);
  zassert_equal(seen.calls, 2);

  server.tamper = NULL;
  memset(&seen, 0, sizeof(seen));
  zassert_ok(pigeon_shadow_get(&out));
  assert_board(&out);
  zassert_equal(seen.block2[0], BLOCK(0, 0, 5));
}

static int refuse_block_1(int call, struct pigeon_coap_rsp *rsp) {
  if (call == 1) {
    memset(rsp, 0, sizeof(*rsp));
    rsp->code = COAP_RESPONSE_CODE_UNAUTHORIZED;
  }
  return 0;
}

ZTEST(coap_block2, test_a_refusal_mid_transfer_holds_like_any_other) {
  struct pigeon_shadow_doc out;

  serve_board(5);
  server.tamper = refuse_block_1;
  zassert_equal(pigeon_shadow_get(&out), -EACCES);
  zassert_equal(pigeon_shadow_get(&out), -EACCES);
  zassert_equal(seen.calls, 2, "a held request must not reach the transport");
}
