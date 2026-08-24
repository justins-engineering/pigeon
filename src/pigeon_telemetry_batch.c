/*
 * Bounded accumulation buffer + flush policy for CONFIG_PIGEON_TELEMETRY_BATCH.
 * See pigeon_telemetry_batch.h for what each entry point promises and why
 * the module is transport-free and clock-free.
 *
 * Storage shape: one flat byte arena holding the readings' already-escaped
 * metrics fragments back to back, plus a small descriptor array carrying
 * each reading's uptime stamp and its slice of that arena. Two knobs bound
 * it -- CONFIG_PIGEON_TELEMETRY_BATCH_BUF_SIZE for the bytes,
 * CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH for the readings -- and both are
 * compile-time, so the whole feature's RAM cost is visible in the map file
 * rather than in a device's high-water mark.
 *
 * Fragments are stored pre-escaped because escaping is the expensive part
 * and the value can no longer change once a reading is closed: doing it at
 * record time means a retry of a refused batch re-frames but never
 * re-escapes, and it lets the arena hold exactly the bytes that will go on
 * the wire rather than a worst-case allowance for what they might become.
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include "pigeon_telemetry_batch.h"

BUILD_ASSERT(
    PIGEON_TELEMETRY_BATCH_BODY_MAX <= PIGEON_TELEMETRY_BATCH_SERVER_BYTES_MAX,
    "CONFIG_PIGEON_TELEMETRY_BATCH_BUF_SIZE and _DEPTH together can emit a body over the "
    "platform's 16 KiB batch cap, which refuses the whole batch with 413 -- shrink either knob"
);

BUILD_ASSERT(
    CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH <= PIGEON_TELEMETRY_BATCH_SERVER_READINGS_MAX,
    "CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH exceeds the platform's 64-readings-per-batch cap"
);

/* Fraction of the arena that, once held, makes a delivery due -- see
 * pigeon_telemetry_batch_due()'s docs for why a high-water trigger is what
 * keeps an undersized arena spending its capacity on deliveries instead of
 * on drops. Three quarters leaves room for one more typical reading to land
 * before the flush that this trigger asks for actually happens. */
#define PIGEON_TELEMETRY_BATCH_HIGH_WATER \
  ((size_t)CONFIG_PIGEON_TELEMETRY_BATCH_BUF_SIZE - (CONFIG_PIGEON_TELEMETRY_BATCH_BUF_SIZE / 4))

struct pigeon_telemetry_batch_entry {
  int64_t taken_ms;
  uint16_t off;
  uint16_t len;
};

static struct {
  struct pigeon_telemetry_batch_entry entries[CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH];
  char arena[CONFIG_PIGEON_TELEMETRY_BATCH_BUF_SIZE];
  int count;
  size_t used;
  uint32_t dropped;
} batch;

void pigeon_telemetry_batch_reset(void) {
  batch.count = 0;
  batch.used = 0;
  batch.dropped = 0;
}

/* Drops the oldest reading, compacting the arena so entry 0 always starts at
 * offset 0. A memmove per drop is O(arena), but a drop only ever happens
 * while deliveries are failing and the buffer is already full -- the steady
 * state never reaches this path, and paying a copy there buys a flat arena
 * with no wrap handling anywhere else in the module. */
static void pigeon_telemetry_batch_drop_oldest(void) {
  if (batch.count == 0) {
    return;
  }

  size_t drop_len = batch.entries[0].len;

  memmove(batch.arena, batch.arena + drop_len, batch.used - drop_len);
  batch.used -= drop_len;

  for (int i = 1; i < batch.count; i++) {
    batch.entries[i - 1] = batch.entries[i];
    batch.entries[i - 1].off -= (uint16_t)drop_len;
  }

  batch.count--;
  batch.dropped++;
}

int pigeon_telemetry_batch_record(const char *metrics, size_t metrics_len, int64_t now_ms) {
  if (!metrics || metrics_len == 0) {
    return -EINVAL;
  }

  if (metrics_len > sizeof(batch.arena)) {
    /* Nothing that can be dropped would make room, so say so rather than
     * evicting the whole buffer for a reading that still would not fit. */
    return -EMSGSIZE;
  }

  while (batch.count >= CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH ||
         batch.used + metrics_len > sizeof(batch.arena)) {
    pigeon_telemetry_batch_drop_oldest();
  }

  struct pigeon_telemetry_batch_entry *entry = &batch.entries[batch.count];

  entry->taken_ms = now_ms;
  entry->off = (uint16_t)batch.used;
  entry->len = (uint16_t)metrics_len;

  memcpy(batch.arena + batch.used, metrics, metrics_len);
  batch.used += metrics_len;
  batch.count++;

  return 0;
}

int pigeon_telemetry_batch_count(void) { return batch.count; }

size_t pigeon_telemetry_batch_used(void) { return batch.used; }

uint32_t pigeon_telemetry_batch_take_dropped(void) {
  uint32_t dropped = batch.dropped;

  batch.dropped = 0;

  return dropped;
}

uint32_t pigeon_telemetry_batch_age_secs(int64_t taken_ms, int64_t now_ms) {
  int64_t delta_ms = now_ms - taken_ms;

  if (delta_ms <= 0) {
    return 0;
  }

  int64_t secs = (delta_ms + (MSEC_PER_SEC / 2)) / MSEC_PER_SEC;

  if (secs > (int64_t)PIGEON_TELEMETRY_BATCH_MAX_AGE_SECS) {
    return PIGEON_TELEMETRY_BATCH_MAX_AGE_SECS;
  }

  return (uint32_t)secs;
}

bool pigeon_telemetry_batch_due(int64_t now_ms) {
  if (batch.count == 0) {
    return false;
  }

  if (batch.count >= CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH) {
    return true;
  }

  if (batch.used >= PIGEON_TELEMETRY_BATCH_HIGH_WATER) {
    return true;
  }

  /* The oldest reading is entry 0 by construction (appended in order, and
   * drops only ever come off the front), so one age check covers the
   * buffer. */
  return pigeon_telemetry_batch_age_secs(batch.entries[0].taken_ms, now_ms) >=
         (uint32_t)CONFIG_PIGEON_TELEMETRY_BATCH_MAX_AGE_SEC;
}

size_t pigeon_telemetry_batch_build(
    char *out, size_t out_len, int64_t now_ms, int *out_readings
) {
  if (out_readings) {
    *out_readings = 0;
  }

  if (!out || out_len == 0 || batch.count == 0) {
    return 0;
  }

  static const char prefix[] = "{\"reports\":[";
  size_t len = sizeof(prefix) - 1;

  /* Every append below is bounds-checked against out_len rather than
   * trusting the build assertions above: this writes a network body, and a
   * sizing mistake must fail visibly (0, which the caller reports and
   * treats as a batch it cannot deliver) instead of emitting a truncated
   * object that the platform would answer with a 400. */
  if (len + 2 > out_len) {
    return 0;
  }

  memcpy(out, prefix, len);

  for (int i = 0; i < batch.count; i++) {
    const struct pigeon_telemetry_batch_entry *entry = &batch.entries[i];
    char head[PIGEON_TELEMETRY_BATCH_ENTRY_MAX];
    int head_len = snprintk(
        head, sizeof(head), "%s{\"age_secs\":%u,\"metrics\":", i ? "," : "",
        pigeon_telemetry_batch_age_secs(entry->taken_ms, now_ms)
    );

    if (head_len < 0 || (size_t)head_len >= sizeof(head)) {
      return 0;
    }

    /* +3: this reading's closing brace, plus the "]}" the envelope still
     * owes after the last one. */
    if (len + (size_t)head_len + entry->len + 3 > out_len) {
      return 0;
    }

    memcpy(out + len, head, (size_t)head_len);
    len += (size_t)head_len;
    memcpy(out + len, batch.arena + entry->off, entry->len);
    len += entry->len;
    out[len++] = '}';
  }

  out[len++] = ']';
  out[len++] = '}';
  out[len] = '\0';

  if (out_readings) {
    *out_readings = batch.count;
  }

  return len;
}

uint32_t pigeon_telemetry_batch_backoff_next(uint32_t base_sec) {
  uint32_t cap = (uint32_t)CONFIG_PIGEON_TELEMETRY_BATCH_BACKOFF_MAX_SEC;

  if (base_sec == 0) {
    return 1;
  }

  if (base_sec >= cap) {
    return cap;
  }

  return MIN(base_sec * 2, cap);
}

uint32_t pigeon_telemetry_batch_backoff_jitter(uint32_t base_sec) {
  /* Same shape as pigeon_ws.c's reconnect jitter: a 50%-wide window centered
   * on base_sec, i.e. +-25%, floored at 1s so a jittered value can never
   * collapse into an immediate retry. */
  uint32_t span = base_sec / 2;
  uint32_t jitter = span ? (sys_rand32_get() % span) : 0;
  uint32_t jittered = (base_sec - span / 2) + jitter;

  return jittered ? jittered : 1;
}

bool pigeon_telemetry_batch_status_is_fatal(uint16_t status) {
  return status == 400 || status == 413;
}
