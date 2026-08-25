#include <errno.h>
#include <string.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/util.h>

#include "pigeon_mqtt_policy.h"

const char *pigeon_mqtt_publish_topic(enum pigeon_mqtt_leaf leaf) {
  switch (leaf) {
    case PIGEON_MQTT_LEAF_TELEMETRY:
      return PIGEON_MQTT_TOPIC_TELEMETRY;
    case PIGEON_MQTT_LEAF_SHADOW_REPORT:
      return PIGEON_MQTT_TOPIC_SHADOW_REPORT;
    case PIGEON_MQTT_LEAF_LOGS:
      return PIGEON_MQTT_TOPIC_LOGS;
    default:
      return NULL;
  }
}

bool pigeon_mqtt_is_shadow_target(const char *topic, size_t topic_len) {
  if (!topic) {
    return false;
  }

  return topic_len == strlen(PIGEON_MQTT_TOPIC_SHADOW_TARGET) &&
         memcmp(topic, PIGEON_MQTT_TOPIC_SHADOW_TARGET, topic_len) == 0;
}

enum pigeon_mqtt_retry pigeon_mqtt_connack_retry(uint8_t return_code) {
  switch (return_code) {
    /* MQTT 3.1.1 (2.2.2). 0x03 is "server unavailable", which the broker
     * sends for an edge-mitigated or failing platform AND for a paused
     * free-tier account -- all three lift on their own. */
    case 0x01: /* unacceptable protocol version */
    case 0x02: /* identifier rejected: the id disagrees with the identity */
    case 0x04: /* bad user name or password */
    case 0x05: /* not authorized */
      return PIGEON_MQTT_RETRY_LATER;

    /* MQTT 5 (3.2.2.2). The reasons a retry cannot fix. */
    case 0x84: /* unsupported protocol version */
    case 0x85: /* client identifier not valid */
    case 0x86: /* bad user name or password */
    case 0x87: /* not authorized: a revoked token, or a deleted pigeon */
    case 0x8A: /* banned */
    case 0x8C: /* bad authentication method */
    case 0x9A: /* retain not supported */
    case 0x9B: /* QoS not supported */
      return PIGEON_MQTT_RETRY_LATER;

    default:
      /* 0x00 accepted, 0x03/0x88 unavailable, 0x89 busy, 0x97 quota
       * exceeded, 0x8B server shutting down (a deploy or a certificate
       * renewal), and anything this build has not met. */
      return PIGEON_MQTT_RETRY_SOON;
  }
}

bool pigeon_mqtt_close_is_persistent(uint32_t consecutive_unacked_closes) {
  return consecutive_unacked_closes >= PIGEON_MQTT_UNACKED_CLOSES_PERSISTENT;
}

uint32_t pigeon_mqtt_backoff_next(uint32_t base_sec, uint32_t max_sec) {
  if (base_sec == 0) {
    base_sec = PIGEON_MQTT_BACKOFF_BASE_SEC;
  }

  return MIN(base_sec * 2, max_sec ? max_sec : base_sec);
}

uint32_t pigeon_mqtt_backoff_jitter(uint32_t base_sec) {
  uint32_t span = base_sec / 2; /* 50% span, i.e. +-25% of base_sec */
  uint32_t jitter = span ? (sys_rand32_get() % span) : 0;
  uint32_t jittered = (base_sec - span / 2) + jitter;

  return jittered ? jittered : 1;
}

void pigeon_mqtt_pending_init(
    struct pigeon_mqtt_pending_table *table, struct pigeon_mqtt_pending *slots, uint8_t count
) {
  memset(slots, 0, sizeof(*slots) * count);
  table->slots = slots;
  table->count = count;
  table->next_message_id = 1;
}

int pigeon_mqtt_pending_claim(struct pigeon_mqtt_pending_table *table) {
  for (uint8_t i = 0; i < table->count; i++) {
    if (!table->slots[i].in_use) {
      table->slots[i] = (struct pigeon_mqtt_pending){.in_use = true};
      return i;
    }
  }

  return -EBUSY;
}

uint16_t pigeon_mqtt_pending_arm(struct pigeon_mqtt_pending_table *table, int slot) {
  uint16_t id;
  bool taken;

  /* Bounded by the slot count plus one wrap: with at most
   * CONFIG_PIGEON_MQTT_MAX_INFLIGHT identifiers ever in flight, a free one
   * is always within that many steps. */
  do {
    id = table->next_message_id;
    table->next_message_id = (id == UINT16_MAX) ? 1 : (uint16_t)(id + 1);

    taken = false;
    for (uint8_t i = 0; i < table->count; i++) {
      if (i != (uint8_t)slot && table->slots[i].awaiting_ack &&
          table->slots[i].message_id == id) {
        taken = true;
        break;
      }
    }
  } while (taken);

  table->slots[slot].message_id = id;
  table->slots[slot].awaiting_ack = true;
  table->slots[slot].acked = false;
  table->slots[slot].lost = false;

  return id;
}

int pigeon_mqtt_pending_ack(struct pigeon_mqtt_pending_table *table, uint16_t message_id) {
  for (uint8_t i = 0; i < table->count; i++) {
    struct pigeon_mqtt_pending *slot = &table->slots[i];

    if (slot->awaiting_ack && slot->message_id == message_id) {
      slot->awaiting_ack = false;
      slot->acked = true;
      return i;
    }
  }

  return -ENOENT;
}

void pigeon_mqtt_pending_session_lost(struct pigeon_mqtt_pending_table *table) {
  for (uint8_t i = 0; i < table->count; i++) {
    struct pigeon_mqtt_pending *slot = &table->slots[i];

    if (slot->awaiting_ack) {
      slot->awaiting_ack = false;
      slot->lost = true;
      /* The republish is a redelivery of the same application message,
       * whether or not the broker ever saw the first attempt -- which is
       * exactly what the duplicate flag tells it. */
      slot->dup = true;
    }
  }
}

bool pigeon_mqtt_pending_any_awaiting(const struct pigeon_mqtt_pending_table *table) {
  for (uint8_t i = 0; i < table->count; i++) {
    if (table->slots[i].awaiting_ack) {
      return true;
    }
  }

  return false;
}

void pigeon_mqtt_pending_release(struct pigeon_mqtt_pending_table *table, int slot) {
  table->slots[slot] = (struct pigeon_mqtt_pending){0};
}
