#include <errno.h>
#include <string.h>
#include <zephyr/ztest.h>

#include "pigeon_mqtt_policy.h"

/* The MQTT connector's decision layer (pigeon_mqtt_policy.c): the topic
 * map both ends of the wire have to agree on, how a refusal or a dropped
 * session turns into a retry schedule, and the in-flight table that makes
 * redelivery this connector's own. The session state machine itself is not
 * re-tested here -- these are exactly the decisions that can be made wrong
 * without a broker present to notice. */

#define SLOTS 2

static struct pigeon_mqtt_pending slots[SLOTS];
static struct pigeon_mqtt_pending_table table;

static void fresh_table(void *fixture) {
  ARG_UNUSED(fixture);
  pigeon_mqtt_pending_init(&table, slots, SLOTS);
}

ZTEST_SUITE(mqtt_policy, NULL, NULL, fresh_table, NULL, NULL);

/* Topics: these strings are the contract with pigeonhole-wire, so a typo
 * here is a connection the broker closes rather than a report it drops. */

ZTEST(mqtt_policy, test_publish_topics_are_the_session_scoped_leaves) {
  zassert_str_equal(pigeon_mqtt_publish_topic(PIGEON_MQTT_LEAF_TELEMETRY), "pigeon/telemetry");
  zassert_str_equal(
      pigeon_mqtt_publish_topic(PIGEON_MQTT_LEAF_SHADOW_REPORT), "pigeon/shadow/report"
  );
  zassert_str_equal(pigeon_mqtt_publish_topic(PIGEON_MQTT_LEAF_LOGS), "pigeon/logs");
}

ZTEST(mqtt_policy, test_unknown_leaf_has_no_topic) {
  zassert_is_null(pigeon_mqtt_publish_topic((enum pigeon_mqtt_leaf)99));
}

ZTEST(mqtt_policy, test_shadow_target_matches_exactly) {
  const char *topic = "pigeon/shadow/target";

  zassert_true(pigeon_mqtt_is_shadow_target(topic, strlen(topic)));
}

ZTEST(mqtt_policy, test_shadow_target_rejects_near_misses) {
  const char *prefix = "pigeon/shadow/targ";
  const char *longer = "pigeon/shadow/target/extra";
  const char *other = "pigeon/shadow/report";

  zassert_false(pigeon_mqtt_is_shadow_target(prefix, strlen(prefix)));
  zassert_false(pigeon_mqtt_is_shadow_target(longer, strlen(longer)));
  zassert_false(pigeon_mqtt_is_shadow_target(other, strlen(other)));
  zassert_false(pigeon_mqtt_is_shadow_target(NULL, 0));
}

ZTEST(mqtt_policy, test_shadow_target_is_not_nul_terminated_on_the_wire) {
  /* An MQTT topic arrives as a length-prefixed span inside the receive
   * buffer, so the match has to respect the length rather than reading to
   * the next NUL. */
  const char wire[] = "pigeon/shadow/targetpigeon/telemetry";

  zassert_true(pigeon_mqtt_is_shadow_target(wire, strlen("pigeon/shadow/target")));
}

/* CONNACK classification: the point of the split is not to hammer a broker
 * that has already said the credentials are wrong, while still reconnecting
 * briskly from anything that lifts on its own. */

ZTEST(mqtt_policy, test_credential_refusals_wait) {
  /* MQTT 3.1.1 */
  zassert_equal(pigeon_mqtt_connack_retry(0x04), PIGEON_MQTT_RETRY_LATER);
  zassert_equal(pigeon_mqtt_connack_retry(0x05), PIGEON_MQTT_RETRY_LATER);
  /* MQTT 5: bad credentials, and the revoked-token/deleted-pigeon case */
  zassert_equal(pigeon_mqtt_connack_retry(0x86), PIGEON_MQTT_RETRY_LATER);
  zassert_equal(pigeon_mqtt_connack_retry(0x87), PIGEON_MQTT_RETRY_LATER);
}

ZTEST(mqtt_policy, test_identity_disagreement_waits) {
  /* The id, the username and the PSK identity must agree; when they do not,
   * every retry with the same build answers the same way. */
  zassert_equal(pigeon_mqtt_connack_retry(0x02), PIGEON_MQTT_RETRY_LATER);
  zassert_equal(pigeon_mqtt_connack_retry(0x85), PIGEON_MQTT_RETRY_LATER);
}

ZTEST(mqtt_policy, test_platform_trouble_retries_soon) {
  zassert_equal(pigeon_mqtt_connack_retry(0x00), PIGEON_MQTT_RETRY_SOON);
  /* 3.1.1 "server unavailable": the broker's answer for a failing platform,
   * an edge-mitigated request, AND a paused free-tier account. */
  zassert_equal(pigeon_mqtt_connack_retry(0x03), PIGEON_MQTT_RETRY_SOON);
  /* MQTT 5 equivalents plus the deploy/certificate-renewal case. */
  zassert_equal(pigeon_mqtt_connack_retry(0x88), PIGEON_MQTT_RETRY_SOON);
  zassert_equal(pigeon_mqtt_connack_retry(0x89), PIGEON_MQTT_RETRY_SOON);
  zassert_equal(pigeon_mqtt_connack_retry(0x8B), PIGEON_MQTT_RETRY_SOON);
  /* Quota exceeded is explicitly "valid credentials, come back later". */
  zassert_equal(pigeon_mqtt_connack_retry(0x97), PIGEON_MQTT_RETRY_SOON);
}

ZTEST(mqtt_policy, test_unknown_refusal_retries_soon) {
  /* An unrecognised code is likelier a broker this build has not met than a
   * permanent verdict, so it must not park the device for a quarter hour. */
  zassert_equal(pigeon_mqtt_connack_retry(0x7F), PIGEON_MQTT_RETRY_SOON);
  zassert_equal(pigeon_mqtt_connack_retry(0xFF), PIGEON_MQTT_RETRY_SOON);
}

/* Close policy: the free-tier fuse's only signal to a 3.1.1 client. */

ZTEST(mqtt_policy, test_isolated_closes_are_not_persistent) {
  zassert_false(pigeon_mqtt_close_is_persistent(0));
  zassert_false(pigeon_mqtt_close_is_persistent(1));
  zassert_false(pigeon_mqtt_close_is_persistent(PIGEON_MQTT_UNACKED_CLOSES_PERSISTENT - 1));
}

ZTEST(mqtt_policy, test_repeated_close_after_publish_is_persistent) {
  zassert_true(pigeon_mqtt_close_is_persistent(PIGEON_MQTT_UNACKED_CLOSES_PERSISTENT));
  zassert_true(pigeon_mqtt_close_is_persistent(PIGEON_MQTT_UNACKED_CLOSES_PERSISTENT + 10));
}

/* Backoff. */

ZTEST(mqtt_policy, test_backoff_doubles_then_caps) {
  zassert_equal(pigeon_mqtt_backoff_next(1, 300), 2);
  zassert_equal(pigeon_mqtt_backoff_next(2, 300), 4);
  zassert_equal(pigeon_mqtt_backoff_next(128, 300), 256);
  zassert_equal(pigeon_mqtt_backoff_next(256, 300), 300);
  zassert_equal(pigeon_mqtt_backoff_next(300, 300), 300);
}

ZTEST(mqtt_policy, test_backoff_from_zero_starts_at_the_base) {
  zassert_equal(
      pigeon_mqtt_backoff_next(0, 300), PIGEON_MQTT_BACKOFF_BASE_SEC * 2,
      "a zero base must not stall the schedule at zero"
  );
}

ZTEST(mqtt_policy, test_jitter_stays_within_a_quarter_and_is_never_zero) {
  for (int i = 0; i < 200; i++) {
    uint32_t jittered = pigeon_mqtt_backoff_jitter(60);

    zassert_between_inclusive(jittered, 45, 75);
    zassert_not_equal(jittered, 0);
  }

  /* A one-second base has no room to jitter and must still be a real
   * delay rather than a busy loop. */
  zassert_equal(pigeon_mqtt_backoff_jitter(1), 1);
}

/* The in-flight table, i.e. redelivery. */

ZTEST(mqtt_policy, test_claim_hands_out_every_slot_then_refuses) {
  zassert_equal(pigeon_mqtt_pending_claim(&table), 0);
  zassert_equal(pigeon_mqtt_pending_claim(&table), 1);
  zassert_equal(
      pigeon_mqtt_pending_claim(&table), -EBUSY,
      "an oversubscribed store must refuse rather than queue"
  );
}

ZTEST(mqtt_policy, test_release_returns_a_slot_to_the_free_set) {
  int slot = pigeon_mqtt_pending_claim(&table);

  zassert_equal(pigeon_mqtt_pending_claim(&table), 1);
  pigeon_mqtt_pending_release(&table, slot);
  zassert_equal(pigeon_mqtt_pending_claim(&table), slot);
}

ZTEST(mqtt_policy, test_arm_assigns_distinct_identifiers) {
  int a = pigeon_mqtt_pending_claim(&table);
  int b = pigeon_mqtt_pending_claim(&table);
  uint16_t id_a = pigeon_mqtt_pending_arm(&table, a);
  uint16_t id_b = pigeon_mqtt_pending_arm(&table, b);

  zassert_not_equal(id_a, 0, "0 is not a legal MQTT packet identifier");
  zassert_not_equal(id_b, 0);
  zassert_not_equal(id_a, id_b);
  zassert_true(pigeon_mqtt_pending_any_awaiting(&table));
}

ZTEST(mqtt_policy, test_identifier_wrap_skips_zero_and_whatever_is_in_flight) {
  int a = pigeon_mqtt_pending_claim(&table);

  table.next_message_id = UINT16_MAX;
  uint16_t id_a = pigeon_mqtt_pending_arm(&table, a);

  zassert_equal(id_a, UINT16_MAX);

  int b = pigeon_mqtt_pending_claim(&table);
  uint16_t id_b = pigeon_mqtt_pending_arm(&table, b);

  zassert_equal(id_b, 1, "the counter wraps to 1, never to 0");

  /* Slot a is still awaiting its acknowledgement, so the counter coming
   * back around must step over its identifier rather than let one PUBACK
   * credit two publishes. */
  pigeon_mqtt_pending_release(&table, b);
  table.next_message_id = UINT16_MAX;

  int c = pigeon_mqtt_pending_claim(&table);
  uint16_t id_c = pigeon_mqtt_pending_arm(&table, c);

  zassert_not_equal(id_c, id_a);
}

ZTEST(mqtt_policy, test_puback_credits_exactly_its_own_publish) {
  int a = pigeon_mqtt_pending_claim(&table);
  int b = pigeon_mqtt_pending_claim(&table);
  uint16_t id_a = pigeon_mqtt_pending_arm(&table, a);

  pigeon_mqtt_pending_arm(&table, b);

  zassert_equal(pigeon_mqtt_pending_ack(&table, id_a), a);
  zassert_true(table.slots[a].acked);
  zassert_false(table.slots[a].awaiting_ack);
  zassert_false(table.slots[b].acked, "the other publish is still in flight");
}

ZTEST(mqtt_policy, test_stray_puback_is_ignored) {
  int a = pigeon_mqtt_pending_claim(&table);
  uint16_t id_a = pigeon_mqtt_pending_arm(&table, a);

  zassert_equal(pigeon_mqtt_pending_ack(&table, (uint16_t)(id_a + 7)), -ENOENT);
  /* A duplicate acknowledgement for a publish already credited is just as
   * harmless, and just as much a no-op. */
  zassert_equal(pigeon_mqtt_pending_ack(&table, id_a), a);
  zassert_equal(pigeon_mqtt_pending_ack(&table, id_a), -ENOENT);
}

ZTEST(mqtt_policy, test_session_loss_marks_in_flight_publishes_for_redelivery) {
  int a = pigeon_mqtt_pending_claim(&table);
  int b = pigeon_mqtt_pending_claim(&table);
  uint16_t id_a = pigeon_mqtt_pending_arm(&table, a);

  pigeon_mqtt_pending_arm(&table, b);
  zassert_equal(pigeon_mqtt_pending_ack(&table, id_a), a);

  zassert_true(pigeon_mqtt_pending_any_awaiting(&table), "b is still unacknowledged");
  pigeon_mqtt_pending_session_lost(&table);

  zassert_true(table.slots[b].lost);
  zassert_true(table.slots[b].dup, "the republish must carry the duplicate flag");
  zassert_false(table.slots[b].awaiting_ack);

  /* The one that was already acknowledged is finished, not redelivered. */
  zassert_false(table.slots[a].lost);
  zassert_false(table.slots[a].dup);
  zassert_false(pigeon_mqtt_pending_any_awaiting(&table));
}

ZTEST(mqtt_policy, test_a_quiet_session_loss_marks_nothing) {
  int a = pigeon_mqtt_pending_claim(&table);

  /* Claimed but never published -- waiting for a session, which is the
   * state a publish sits in while the worker reconnects. Nothing was sent,
   * so nothing is a duplicate. */
  zassert_false(pigeon_mqtt_pending_any_awaiting(&table));
  pigeon_mqtt_pending_session_lost(&table);
  zassert_false(table.slots[a].dup);
}

ZTEST(mqtt_policy, test_redelivery_survives_a_second_interruption) {
  int a = pigeon_mqtt_pending_claim(&table);

  pigeon_mqtt_pending_arm(&table, a);
  pigeon_mqtt_pending_session_lost(&table);
  zassert_true(table.slots[a].dup);

  /* Re-armed for the redelivery, interrupted again: still a duplicate, and
   * still owed an acknowledgement. */
  pigeon_mqtt_pending_arm(&table, a);
  zassert_true(table.slots[a].dup, "arming an attempt must not clear the duplicate flag");
  zassert_false(table.slots[a].lost, "each attempt starts without the previous one's verdict");

  pigeon_mqtt_pending_session_lost(&table);
  zassert_true(table.slots[a].lost);
  zassert_true(table.slots[a].dup);
}
