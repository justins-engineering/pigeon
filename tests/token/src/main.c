/*
 * Token rotation on native_sim, against a fake of dovecote's POST <endpoint>/token that keeps
 * a current and a pending token as the Durable Object does, and against the real settings/NVS
 * stack. A power cut is a lost request or reply, an optionally dropped settings write, and
 * pigeon_token_reset(), which leaves only what reached flash.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/ztest.h>

#include "pigeon_token.h"

#define BAKED_EXPIRY 1800000000U
#define DAY_MS       (24LL * 60 * 60 * 1000)
#define OTHER_ENDPOINT "https://api.example.invalid/device/pigeons/other"

/* This pigeon's record key, and another pigeon's. */
static char key[PIGEON_TOKEN_KEY_MAX];
static char other_key[PIGEON_TOKEN_KEY_MAX];

/* Private to the settings subsystem, but defined with external linkage. */
extern struct settings_store *settings_save_dst;

static void mint(
    char out[PIGEON_TOKEN_LEN + 1], uint8_t version, uint32_t expiry, uint32_t serial
) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  uint8_t raw[69];

  raw[0] = version;
  sys_put_le32(expiry, &raw[1]);
  for (size_t i = 5; i < sizeof(raw); i++) {
    raw[i] = (uint8_t)(serial * 31U + i);
  }

  size_t o = 0;

  for (size_t i = 0; i < sizeof(raw); i += 3) {
    uint32_t v = ((uint32_t)raw[i] << 16) | ((uint32_t)raw[i + 1] << 8) | raw[i + 2];

    out[o++] = alphabet[(v >> 18) & 0x3F];
    out[o++] = alphabet[(v >> 12) & 0x3F];
    out[o++] = alphabet[(v >> 6) & 0x3F];
    out[o++] = alphabet[v & 0x3F];
  }
  out[o] = '\0';
}

/* The fake server. */

enum fate {
  DELIVER,
  /* The request never reached the server. */
  LOSE_REQUEST,
  /* The server acted, and its reply never reached the device. */
  LOSE_REPLY,
};

static struct {
  char current[PIGEON_TOKEN_LEN + 1];
  char pending[PIGEON_TOKEN_LEN + 1];
  bool due;
  bool garbage_reply;
  uint32_t serial;
  int calls;
  int promotions;
  enum fate script[8];
  int script_len;
  int script_pos;
  bool random_faults;
} srv;

static uint32_t rng_state;

static uint32_t rng(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 17;
  rng_state ^= rng_state << 5;
  return rng_state;
}

static enum fate next_fate(void) {
  if (srv.random_faults) {
    uint32_t r = rng() % 10;

    return r < 6 ? DELIVER : (r < 8 ? LOSE_REQUEST : LOSE_REPLY);
  }
  if (srv.script_pos < srv.script_len) {
    return srv.script[srv.script_pos++];
  }
  return DELIVER;
}

static int fake_send(const char *token, char *body, size_t body_cap, uint16_t *status) {
  enum fate fate = next_fate();

  srv.calls++;
  if (fate == LOSE_REQUEST) {
    return -ECONNRESET;
  }

  body[0] = '\0';
  if (strcmp(token, srv.current) == 0) {
    if (srv.due) {
      mint(srv.pending, PIGEON_TOKEN_VERSION, BAKED_EXPIRY + 1000U + srv.serial, srv.serial + 100U);
      srv.serial++;
      *status = 200;
      snprintf(body, body_cap, "{\"token\":\"%s\"}", srv.garbage_reply ? "x\\r\\ny" : srv.pending);
    } else {
      *status = 204;
    }
  } else if (srv.pending[0] != '\0' && strcmp(token, srv.pending) == 0) {
    strcpy(srv.current, srv.pending);
    srv.pending[0] = '\0';
    srv.due = false;
    srv.promotions++;
    *status = 204;
  } else {
    *status = 401;
  }

  return fate == LOSE_REPLY ? -ECONNRESET : 0;
}

static bool server_accepts(const char *token) { return strcmp(token, srv.current) == 0; }

static void script(int n, const enum fate *fates) {
  memcpy(srv.script, fates, n * sizeof(*fates));
  srv.script_len = n;
  srv.script_pos = 0;
}

/* The gate. */

static enum pigeon_token_gate gate_value;
static int gate_calls;

static enum pigeon_token_gate fake_gate(void) {
  gate_calls++;
  return gate_value;
}

/* A settings destination that can drop or fail the next writes of the token record. */

static struct settings_store *real_dst;
/* Counted from 1 per test; a dropped write reports success and stores nothing. */
static int token_writes;
static int drop_write;
static int fail_write;
static uint32_t drop_per_ten;

static int lying_save(struct settings_store *cs, const char *name, const char *value, size_t len) {
  ARG_UNUSED(cs);
  if (strcmp(name, key) == 0 && value != NULL) {
    token_writes++;
    if (token_writes == fail_write) {
      return -EIO;
    }
    if (token_writes == drop_write || (drop_per_ten > 0 && rng() % 10 < drop_per_ten)) {
      return 0;
    }
  }
  return real_dst->cs_itf->csi_save(real_dst, name, value, len);
}

static const struct settings_store_itf lying_itf = {.csi_save = lying_save};
static struct settings_store lying_store = {.cs_itf = &lying_itf};

static int read_record(struct pigeon_token_record *rec) {
  memset(rec, 0, sizeof(*rec));
  ssize_t n = settings_load_one(key, rec, sizeof(*rec));

  return n == sizeof(*rec) ? 0 : -ENOENT;
}

/* One pigeon_shadow_get(): the proof, the GET, and on success the check. */
static bool cycle(int64_t now_ms) {
  pigeon_token_prove(fake_send);
  bool ok = server_accepts(pigeon_token_current());

  if (ok) {
    pigeon_token_check(fake_send, fake_gate, now_ms);
  }
  return ok;
}

static void reboot(void) { pigeon_token_reset(); }

static void *suite_setup(void) {
  zassert_ok(pigeon_token_settings_key(CONFIG_PIGEON_ENDPOINT, key, sizeof(key)));
  zassert_ok(pigeon_token_settings_key(OTHER_ENDPOINT, other_key, sizeof(other_key)));
  zassert_ok(settings_subsys_init());
  real_dst = settings_save_dst;
  settings_dst_register(&lying_store);
  return NULL;
}

static void before_each(void *fixture) {
  ARG_UNUSED(fixture);
  zassert_ok(settings_delete(key));
  zassert_ok(settings_delete(other_key));
  memset(&srv, 0, sizeof(srv));
  strcpy(srv.current, CONFIG_PIGEON_TOKEN);
  gate_value = PIGEON_TOKEN_GATE_OPEN;
  gate_calls = 0;
  token_writes = 0;
  drop_write = 0;
  fail_write = 0;
  drop_per_ten = 0;
  rng_state = 0x2545F491U;
  reboot();
}

ZTEST_SUITE(token, NULL, suite_setup, before_each, NULL, NULL);

/* Validation (D15) and the signed expiry. */

ZTEST(token, test_valid_accepts_a_minted_token) {
  char t[PIGEON_TOKEN_LEN + 1];

  mint(t, PIGEON_TOKEN_VERSION, 123456789U, 7);
  zassert_true(pigeon_token_valid(t));
  zassert_true(pigeon_token_valid(CONFIG_PIGEON_TOKEN));
  zassert_equal(pigeon_token_expiry(t), 123456789U);
  zassert_equal(pigeon_token_expiry(CONFIG_PIGEON_TOKEN), BAKED_EXPIRY);
}

ZTEST(token, test_valid_refuses_malformed_tokens) {
  char t[PIGEON_TOKEN_LEN + 2];

  mint(t, PIGEON_TOKEN_VERSION, 1U, 1);
  t[PIGEON_TOKEN_LEN - 1] = '\0';
  zassert_false(pigeon_token_valid(t), "91 characters");

  mint(t, PIGEON_TOKEN_VERSION, 1U, 1);
  t[PIGEON_TOKEN_LEN] = 'A';
  t[PIGEON_TOKEN_LEN + 1] = '\0';
  zassert_false(pigeon_token_valid(t), "93 characters");

  static const char bad[] = {'\r', '\n', '+', '/', '=', ' ', '"', '\\'};

  for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
    mint(t, PIGEON_TOKEN_VERSION, 1U, 1);
    t[40] = bad[i];
    zassert_false(pigeon_token_valid(t), "byte 0x%02x", bad[i]);
  }

  mint(t, 2, 1U, 1);
  zassert_false(pigeon_token_valid(t), "unknown version");
  zassert_false(pigeon_token_valid(""));
  zassert_false(pigeon_token_valid(NULL));
  zassert_equal(pigeon_token_expiry("short"), 0);
}

ZTEST(token, test_parse_reply_takes_only_a_valid_token) {
  char t[PIGEON_TOKEN_LEN + 1];
  char body[200];
  char out[PIGEON_TOKEN_LEN + 1];

  mint(t, PIGEON_TOKEN_VERSION, 5U, 3);
  snprintf(body, sizeof(body), "{\"token\":\"%s\"}", t);
  zassert_ok(pigeon_token_parse_reply(body, out));
  zassert_str_equal(out, t);

  zassert_not_ok(pigeon_token_parse_reply("{}", out));
  zassert_not_ok(pigeon_token_parse_reply("not json", out));
  zassert_not_ok(pigeon_token_parse_reply("", out));

  /* An escaped CR LF would decode into a header injection. */
  snprintf(body, sizeof(body), "{\"token\":\"%.40s\\r\\n%.50s\"}", t, t + 42);
  zassert_not_ok(pigeon_token_parse_reply(body, out));

  snprintf(body, sizeof(body), "{\"token\":\"%sA\"}", t);
  zassert_not_ok(pigeon_token_parse_reply(body, out), "93 characters");

  char big[400];

  memset(big, ' ', sizeof(big) - 1);
  big[sizeof(big) - 1] = '\0';
  zassert_not_ok(pigeon_token_parse_reply(big, out), "over-long body");
}

/* Token choice (D19 step 3). */

ZTEST(token, test_choose_prefers_the_record_unless_it_cannot_serve) {
  struct pigeon_token_record rec = {0};

  zassert_equal(pigeon_token_choose(&rec, CONFIG_PIGEON_ENDPOINT, CONFIG_PIGEON_TOKEN),
                CONFIG_PIGEON_TOKEN, "empty record");

  strcpy(rec.endpoint, CONFIG_PIGEON_ENDPOINT);
  mint(rec.active, PIGEON_TOKEN_VERSION, BAKED_EXPIRY + 1U, 9);
  zassert_equal(pigeon_token_choose(&rec, CONFIG_PIGEON_ENDPOINT, CONFIG_PIGEON_TOKEN),
                rec.active, "later expiry");

  mint(rec.active, PIGEON_TOKEN_VERSION, BAKED_EXPIRY, 9);
  zassert_equal(pigeon_token_choose(&rec, CONFIG_PIGEON_ENDPOINT, CONFIG_PIGEON_TOKEN),
                rec.active, "same expiry");

  mint(rec.active, PIGEON_TOKEN_VERSION, BAKED_EXPIRY - 1U, 9);
  zassert_equal(pigeon_token_choose(&rec, CONFIG_PIGEON_ENDPOINT, CONFIG_PIGEON_TOKEN),
                CONFIG_PIGEON_TOKEN, "a keep-storage reflash after a refresh bakes a newer one");

  mint(rec.active, PIGEON_TOKEN_VERSION, BAKED_EXPIRY + 1U, 9);
  zassert_equal(pigeon_token_choose(&rec, OTHER_ENDPOINT, CONFIG_PIGEON_TOKEN),
                CONFIG_PIGEON_TOKEN, "another endpoint");

  zassert_equal(pigeon_token_choose(&rec, "http://moved.example.invalid/x/test/",
                                    CONFIG_PIGEON_TOKEN),
                rec.active, "the same pigeon behind another host");

  rec.active[10] = '\n';
  zassert_equal(pigeon_token_choose(&rec, CONFIG_PIGEON_ENDPOINT, CONFIG_PIGEON_TOKEN),
                CONFIG_PIGEON_TOKEN, "corrupt record");
}

ZTEST(token, test_the_settings_key_names_the_pigeon) {
  char out[PIGEON_TOKEN_KEY_MAX];

  zassert_str_equal(key, "pigeon/token/test");
  zassert_ok(pigeon_token_settings_key("https://h/device/pigeons/0123456789abcdef0123/", out,
                                       sizeof(out)));
  zassert_str_equal(out, "pigeon/token/0123456789abcdef", "the id is cut to 16 characters");
  zassert_equal(pigeon_token_settings_key("https://h/device/pigeons/a=b", out, sizeof(out)),
                -EINVAL);
  zassert_equal(pigeon_token_settings_key("///", out, sizeof(out)), -EINVAL);
  zassert_equal(pigeon_token_settings_key(CONFIG_PIGEON_ENDPOINT, out, 8), -ENOSPC);
  zassert_true(pigeon_token_same_pigeon("https://a/p/x", "http://b/q/x/"));
  zassert_false(pigeon_token_same_pigeon("https://a/p/x", "https://a/p/xy"));
  zassert_false(pigeon_token_same_pigeon("/", "/"));
}

/* The record (D14). */

ZTEST(token, test_load_refuses_a_size_mismatch) {
  uint8_t short_rec[10] = {0};

  zassert_ok(settings_save_one(key, short_rec, sizeof(short_rec)));
  reboot();
  zassert_equal(pigeon_token_current(), CONFIG_PIGEON_TOKEN);
  zassert_false(pigeon_token_pending());
}

ZTEST(token, test_record_for_another_endpoint_reads_empty) {
  struct pigeon_token_record rec = {0};

  strcpy(rec.endpoint, OTHER_ENDPOINT);
  mint(rec.active, PIGEON_TOKEN_VERSION, BAKED_EXPIRY + 50U, 11);
  mint(rec.pending, PIGEON_TOKEN_VERSION, BAKED_EXPIRY + 60U, 12);
  zassert_ok(settings_save_one(key, &rec, sizeof(rec)));
  reboot();

  zassert_equal(pigeon_token_current(), CONFIG_PIGEON_TOKEN);
  zassert_false(pigeon_token_pending(), "another pigeon's pending token must not be proven");
  pigeon_token_prove(fake_send);
  zassert_equal(srv.calls, 0);
}

/* Another pigeon's image on this board, rotating that pigeon, saves under that pigeon's key. */
ZTEST(token, test_another_pigeons_record_leaves_this_one_alone) {
  struct pigeon_token_record theirs = {0};
  struct pigeon_token_record rec;

  srv.due = true;
  zassert_true(cycle(0));
  zassert_equal(srv.promotions, 1);

  strcpy(theirs.endpoint, OTHER_ENDPOINT);
  mint(theirs.active, PIGEON_TOKEN_VERSION, BAKED_EXPIRY + 70U, 13);
  zassert_ok(settings_save_one(other_key, &theirs, sizeof(theirs)));
  reboot();

  zassert_ok(read_record(&rec));
  zassert_str_equal(rec.active, srv.current);
  zassert_true(server_accepts(pigeon_token_current()), "this pigeon's rotated token survives");
}

/* The check and the proof (D17, D19). */

ZTEST(token, test_not_due_answers_204_and_writes_nothing) {
  struct pigeon_token_record rec;

  zassert_true(cycle(0));
  zassert_equal(srv.calls, 1);
  zassert_equal(read_record(&rec), -ENOENT);
  zassert_equal(pigeon_token_current(), CONFIG_PIGEON_TOKEN);
}

ZTEST(token, test_rotation_end_to_end) {
  char baked[PIGEON_TOKEN_LEN + 1];
  struct pigeon_token_record rec;

  strcpy(baked, CONFIG_PIGEON_TOKEN);
  srv.due = true;
  zassert_true(cycle(0));

  zassert_equal(srv.calls, 2, "one ask, one proof");
  zassert_equal(srv.promotions, 1);
  zassert_true(server_accepts(pigeon_token_current()));
  zassert_false(server_accepts(baked), "the old token is retired");
  zassert_false(pigeon_token_pending());

  zassert_ok(read_record(&rec));
  zassert_str_equal(rec.endpoint, CONFIG_PIGEON_ENDPOINT);
  zassert_str_equal(rec.active, srv.current);
  zassert_equal(rec.pending[0], '\0');

  reboot();
  zassert_true(server_accepts(pigeon_token_current()), "the rotated token survives a reboot");
}

ZTEST(token, test_check_runs_once_per_boot_and_daily) {
  zassert_true(cycle(0));
  zassert_true(cycle(DAY_MS / 2));
  zassert_equal(srv.calls, 1);

  zassert_true(cycle(DAY_MS));
  zassert_equal(srv.calls, 2);

  reboot();
  zassert_true(cycle(DAY_MS + 1000));
  zassert_equal(srv.calls, 3, "a reboot owes a check even inside the day");
}

ZTEST(token, test_gates_hold_the_check_without_using_it_up) {
  static const enum pigeon_token_gate gates[] = {
      PIGEON_TOKEN_GATE_UNCONFIRMED,
      PIGEON_TOKEN_GATE_DOWNLOADING,
      PIGEON_TOKEN_GATE_SWAP_PENDING,
      PIGEON_TOKEN_GATE_FIRMWARE_ASSIGNED,
  };

  srv.due = true;
  for (size_t i = 0; i < ARRAY_SIZE(gates); i++) {
    gate_value = gates[i];
    zassert_true(cycle(1000 * (int64_t)i));
    zassert_equal(srv.calls, 0, "gate %d sent a request", gates[i]);
  }

  gate_value = PIGEON_TOKEN_GATE_OPEN;
  zassert_true(cycle(5000));
  zassert_equal(srv.calls, 2, "the next poll runs the deferred check");
  zassert_equal(srv.promotions, 1);
}

static bool assigned(const char *config) {
  char buf[256];
  size_t len = strlen(config);

  memcpy(buf, config, len + 1);
  return pigeon_token_firmware_assigned(buf, len, "1.2.0");
}

ZTEST(token, test_a_firmware_target_not_yet_running_holds_the_check) {
  zassert_true(assigned("{\"log\":true,\"firmware\":{\"version\":\"1.3.0\",\"size\":4096,"
                        "\"sha256\":\"ab\"},\"firmware_repush\":2}"));
  zassert_false(assigned("{\"firmware\":{\"version\":\"1.2.0\",\"size\":4096}}"),
                "the target is what runs");
  zassert_false(assigned("{\"log\":true,\"telemetry_interval\":60}"), "no firmware key");
  zassert_false(assigned("{\"firmware\":{\"version\":\"\"}}"), "an empty version");
  zassert_false(assigned("{}"));
  zassert_false(assigned("not json"), "the application cannot read it either");
}

ZTEST(token, test_gates_are_open_without_mcuboot) {
  zassert_equal(pigeon_token_gate_now(), PIGEON_TOKEN_GATE_OPEN);
}

ZTEST(token, test_lost_reply_to_the_ask_keeps_the_old_token) {
  static const enum fate fates[] = {LOSE_REPLY};
  char first[PIGEON_TOKEN_LEN + 1];

  srv.due = true;
  script(ARRAY_SIZE(fates), fates);
  zassert_true(cycle(0));
  strcpy(first, srv.pending);

  zassert_false(pigeon_token_pending());
  zassert_true(server_accepts(pigeon_token_current()), "T0 still serves");

  zassert_true(cycle(DAY_MS));
  zassert_equal(srv.promotions, 1, "the next check mints afresh and rotates");
  zassert_false(server_accepts(first));
}

ZTEST(token, test_proof_not_delivered_is_retried_before_the_next_get) {
  static const enum fate fates[] = {DELIVER, LOSE_REQUEST};

  srv.due = true;
  script(ARRAY_SIZE(fates), fates);
  zassert_true(cycle(0));
  zassert_true(pigeon_token_pending(), "FOTA stays held off");
  zassert_equal(srv.promotions, 0);
  zassert_true(server_accepts(pigeon_token_current()), "T0 serves until the proof");

  zassert_true(cycle(1000));
  zassert_equal(srv.promotions, 1);
  zassert_false(pigeon_token_pending());
  zassert_true(server_accepts(pigeon_token_current()));
}

ZTEST(token, test_lost_reply_to_the_proof_costs_one_cycle) {
  static const enum fate fates[] = {DELIVER, LOSE_REPLY};

  srv.due = true;
  script(ARRAY_SIZE(fates), fates);
  zassert_true(cycle(0));
  zassert_equal(srv.promotions, 1);
  zassert_true(pigeon_token_pending());

  /* Without the proof the GET would present the retired token; the proof runs first. */
  zassert_false(server_accepts(pigeon_token_current()));
  zassert_true(cycle(1000));
  zassert_false(pigeon_token_pending());
}

ZTEST(token, test_a_superseded_token_is_dropped_and_the_old_one_serves) {
  static const enum fate fates[] = {DELIVER, LOSE_REQUEST};
  char t0[PIGEON_TOKEN_LEN + 1];
  char body[200];
  uint16_t status;

  srv.due = true;
  script(ARRAY_SIZE(fates), fates);
  zassert_true(cycle(0));
  zassert_true(pigeon_token_pending());

  /* A holder of a copy of T0 asks too, replacing the device's pending key on the server. */
  strcpy(t0, CONFIG_PIGEON_TOKEN);
  zassert_ok(fake_send(t0, body, sizeof(body), &status));
  zassert_equal(status, 200);

  zassert_true(cycle(1000));
  zassert_false(pigeon_token_pending(), "a 401 proof drops the new token");
  zassert_str_equal(pigeon_token_current(), CONFIG_PIGEON_TOKEN);
  zassert_true(server_accepts(pigeon_token_current()));
}

ZTEST(token, test_failed_read_back_never_reaches_the_server) {
  drop_write = 1;
  srv.due = true;
  zassert_true(cycle(0));

  zassert_equal(srv.calls, 1, "no proof after a write that did not land");
  zassert_false(pigeon_token_pending());
  zassert_true(server_accepts(pigeon_token_current()));

  reboot();
  zassert_true(server_accepts(pigeon_token_current()));
}

ZTEST(token, test_refused_save_keeps_the_old_token) {
  fail_write = 1;
  srv.due = true;
  zassert_true(cycle(0));

  zassert_equal(srv.calls, 1);
  zassert_true(server_accepts(pigeon_token_current()));
}

ZTEST(token, test_a_reply_that_is_not_a_token_is_ignored) {
  struct pigeon_token_record rec;

  srv.due = true;
  srv.garbage_reply = true;
  zassert_true(cycle(0));

  zassert_equal(srv.calls, 1);
  zassert_equal(read_record(&rec), -ENOENT);
  zassert_true(server_accepts(pigeon_token_current()));
}

/* A power cut at each step: whatever reached flash must authenticate after a reboot. */
ZTEST(token, test_power_cut_at_each_step) {
  enum step {
    CUT_ASK_REPLY,
    CUT_PENDING_WRITE,
    CUT_BEFORE_PROOF,
    CUT_PROOF_REPLY,
    CUT_FINAL_WRITE,
    CUT_AFTER_ALL,
    STEPS,
  };

  for (int step = 0; step < STEPS; step++) {
    before_each(NULL);
    srv.due = true;

    switch (step) {
      case CUT_ASK_REPLY:
        script(1, (const enum fate[]){LOSE_REPLY});
        break;
      case CUT_PENDING_WRITE:
        drop_write = 1;
        break;
      case CUT_BEFORE_PROOF:
        script(2, (const enum fate[]){DELIVER, LOSE_REQUEST});
        break;
      case CUT_PROOF_REPLY:
        script(2, (const enum fate[]){DELIVER, LOSE_REPLY});
        break;
      case CUT_FINAL_WRITE:
        drop_write = 2;
        break;
      default:
        break;
    }

    zassert_true(cycle(0), "step %d", step);
    reboot();

    /* The first poll after boot: the proof, then a GET that must succeed. */
    zassert_true(cycle(DAY_MS), "step %d: no working token after the reboot", step);

    /* And the rotation completes once nothing else fails. */
    for (int i = 0; i < 3 && (srv.promotions == 0 || pigeon_token_pending()); i++) {
      srv.due = srv.promotions == 0;
      zassert_true(cycle((2 + i) * DAY_MS), "step %d", step);
    }
    zassert_equal(srv.promotions, 1, "step %d", step);
    zassert_false(pigeon_token_pending(), "step %d", step);
    zassert_true(server_accepts(pigeon_token_current()), "step %d", step);

    reboot();
    zassert_true(server_accepts(pigeon_token_current()), "step %d: record not repaired", step);
  }
}

/* Repeated rotations under random request loss, dropped writes and reboots. */
ZTEST(token, test_randomized_cuts_always_leave_a_working_token) {
  int64_t now = 0;

  srv.random_faults = true;
  drop_per_ten = 1;

  for (int i = 0; i < 400; i++) {
    if (rng() % 3 == 0) {
      srv.due = true;
    }
    (void)cycle(now);
    now += DAY_MS + 1;

    if (rng() % 3 == 0) {
      reboot();
    }

    /* A fault-free first step must leave a token the server takes for the GET. */
    srv.random_faults = false;
    drop_per_ten = 0;
    pigeon_token_prove(fake_send);
    zassert_true(server_accepts(pigeon_token_current()), "iteration %d", i);
    srv.random_faults = true;
    drop_per_ten = 1;
  }

  srv.random_faults = false;
  drop_per_ten = 0;
  srv.due = true;
  zassert_true(cycle(now));
  zassert_false(pigeon_token_pending());
  zassert_true(server_accepts(pigeon_token_current()));
  zassert_true(srv.promotions > 50, "only %d rotations completed", srv.promotions);
}
