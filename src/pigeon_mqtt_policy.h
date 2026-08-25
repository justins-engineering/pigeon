#ifndef PIDGEIOT_PIGEON_MQTT_POLICY_H_
#define PIDGEIOT_PIGEON_MQTT_POLICY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * The decisions the MQTT connector makes that are neither network IO nor
 * Zephyr state: which topic a report goes to, whether a refusal is worth
 * retrying soon, how the reconnect schedule advances, and which QoS 1
 * publishes still owe an acknowledgement. Deliberately free of sockets,
 * Kconfig and the MQTT library (hence the caller-owned slot array below),
 * so tests/mqtt_policy can drive every one of them on native_sim without a
 * broker -- the same split pigeon_coap_udp_match.c uses for the CoAP
 * message layer.
 */

/*
 * Session-scoped topics (pigeonhole's ADR C). The pigeon is fixed by the
 * handshake, so no id appears in a topic; the platform's own
 * pigeonhole-wire crate is the paired definition and these strings must
 * match it byte for byte -- an unknown topic closes the connection rather
 * than being ignored.
 */
#define PIGEON_MQTT_TOPIC_TELEMETRY     "pigeon/telemetry"
#define PIGEON_MQTT_TOPIC_SHADOW_REPORT "pigeon/shadow/report"
#define PIGEON_MQTT_TOPIC_LOGS          "pigeon/logs"
#define PIGEON_MQTT_TOPIC_SHADOW_TARGET "pigeon/shadow/target"

enum pigeon_mqtt_leaf {
  PIGEON_MQTT_LEAF_TELEMETRY,
  PIGEON_MQTT_LEAF_SHADOW_REPORT,
  PIGEON_MQTT_LEAF_LOGS,
};

/* The topic one report publishes to, or NULL for a leaf that does not
 * exist -- there is no default, because guessing a topic here would earn a
 * connection close from the broker. */
const char *pigeon_mqtt_publish_topic(enum pigeon_mqtt_leaf leaf);

/* Whether an inbound topic is the retained target shadow. Exact match: the
 * broker publishes it under its full name whichever filter was subscribed,
 * and a near miss is something this connector did not ask for. */
bool pigeon_mqtt_is_shadow_target(const char *topic, size_t topic_len);

/*
 * How soon a refused or dropped session is worth trying again.
 *
 * The distinction is whether anything can change on this side. A broker
 * that is busy, paused or unreachable will take the same credentials
 * happily once it recovers, so the ordinary exponential schedule applies.
 * A refusal that names the credentials or the identity cannot resolve
 * without something happening off-device -- a rotated token, a
 * re-provisioned PSK, an operator undeleting a pigeon -- so retrying every
 * few seconds only burns radio and fills the broker's refusal brake.
 */
enum pigeon_mqtt_retry {
  PIGEON_MQTT_RETRY_SOON,
  PIGEON_MQTT_RETRY_LATER,
};

/*
 * Classifies a CONNACK return code. Both protocol versions arrive here:
 * MQTT 3.1.1's return codes are 0x01-0x05 and MQTT 5's reason codes are
 * 0x80 and up, so the two ranges cannot collide and one function reads
 * both. Anything unrecognised retries soon, because an unknown refusal is
 * more likely a broker this build has not met than a permanent verdict.
 */
enum pigeon_mqtt_retry pigeon_mqtt_connack_retry(uint8_t return_code);

/*
 * How many consecutive sessions may die with an unacknowledged publish in
 * flight before the connector treats it as a standing condition rather
 * than bad luck.
 *
 * This is the free-tier fuse's only signal to an MQTT 3.1.1 client. A
 * paused account earns PUBACK 0x97 ("quota exceeded", come back later) on
 * MQTT 5, but 3.1.1 has no reason code to carry that, so the broker closes
 * the connection instead -- indistinguishable, packet for packet, from an
 * outage. Reconnecting instantly into a fuse that will not lift for the
 * rest of the billing period is the failure mode worth avoiding, and
 * waiting out three of them costs a healthy device nothing.
 */
#define PIGEON_MQTT_UNACKED_CLOSES_PERSISTENT 3

bool pigeon_mqtt_close_is_persistent(uint32_t consecutive_unacked_closes);

/* First delay of the reconnect schedule. */
#define PIGEON_MQTT_BACKOFF_BASE_SEC 1u

/*
 * Next backoff base: doubles, capped at max_sec. Kept separate from the
 * jitter below so the schedule itself is exactly assertable in a test while
 * the value actually slept on stays randomized.
 */
uint32_t pigeon_mqtt_backoff_next(uint32_t base_sec, uint32_t max_sec);

/*
 * `base_sec` +-25%, never 0. A fleet sharing an outage -- or a broker
 * restarting for a certificate renewal, which drops every session it
 * holds -- otherwise reconnects in lockstep and rebuilds the spike it is
 * backing off from.
 */
uint32_t pigeon_mqtt_backoff_jitter(uint32_t base_sec);

/*
 * One QoS 1 publish that has not been acknowledged yet.
 *
 * Redelivery is this connector's own: Zephyr's MQTT client never
 * retransmits, and the broker holds no session state to resume into
 * (it answers session_present = 0 by design), so a publish interrupted by
 * a dropped connection is republished from here -- with the duplicate flag
 * set, which is the whole reason `dup` outlives the attempt that earned
 * it.
 */
struct pigeon_mqtt_pending {
  /** A publishing thread owns this slot. */
  bool in_use;
  /** Published; the PUBACK has not arrived. */
  bool awaiting_ack;
  /** The acknowledgement arrived. */
  bool acked;
  /** The session dropped while this publish was in flight, so the next
   * attempt is a redelivery. */
  bool lost;
  /** Set on every attempt after the first. */
  bool dup;
  /** Packet identifier of the attempt in flight. */
  uint16_t message_id;
};

/*
 * The in-flight set. `slots` is caller-owned (the connector sizes it from
 * CONFIG_PIGEON_MQTT_MAX_INFLIGHT) so this file stays free of Kconfig and a
 * test can hand it any size it likes.
 */
struct pigeon_mqtt_pending_table {
  struct pigeon_mqtt_pending *slots;
  uint8_t count;
  /** Rolls over 1..65535; 0 is not a legal MQTT packet identifier. */
  uint16_t next_message_id;
};

void pigeon_mqtt_pending_init(
    struct pigeon_mqtt_pending_table *table, struct pigeon_mqtt_pending *slots, uint8_t count
);

/*
 * Takes a free slot for a publish that is about to be attempted, or -EBUSY
 * when every slot is owned. Refusing is deliberate: queueing here would
 * hide a device publishing faster than the link can carry, and the callers
 * (a telemetry flush, a log batch) each already know how to keep their data
 * and try again.
 */
int pigeon_mqtt_pending_claim(struct pigeon_mqtt_pending_table *table);

/*
 * Assigns the next packet identifier to a claimed slot and marks it
 * awaiting acknowledgement. Identifiers already in flight are skipped, so a
 * PUBACK can never be credited to the wrong publish, however far the
 * counter has wrapped.
 */
uint16_t pigeon_mqtt_pending_arm(struct pigeon_mqtt_pending_table *table, int slot);

/*
 * Credits a PUBACK. Returns the slot it matched, or -ENOENT for an
 * identifier nothing is waiting on (a duplicate acknowledgement, or one for
 * a publish already given up on -- both harmless, neither worth acting on).
 */
int pigeon_mqtt_pending_ack(struct pigeon_mqtt_pending_table *table, uint16_t message_id);

/*
 * Marks every in-flight publish as interrupted, so each waiting thread
 * republishes with the duplicate flag once the session is back. Called on
 * every disconnect, however the session ended.
 */
void pigeon_mqtt_pending_session_lost(struct pigeon_mqtt_pending_table *table);

/* Whether any slot was still awaiting an acknowledgement -- the input to
 * pigeon_mqtt_close_is_persistent() above, and the reason a close is worth
 * counting at all. */
bool pigeon_mqtt_pending_any_awaiting(const struct pigeon_mqtt_pending_table *table);

/* Returns a slot to the free set. */
void pigeon_mqtt_pending_release(struct pigeon_mqtt_pending_table *table, int slot);

#endif /* PIDGEIOT_PIGEON_MQTT_POLICY_H_ */
