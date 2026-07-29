#include <errno.h>
#include <pigeon.h>
#include <stdbool.h>
#include <string.h>
#include <zephyr/logging/log.h>

#include "pigeon_internal.h"

LOG_MODULE_REGISTER(pigeon, CONFIG_PIGEON_LOG_LEVEL);

/* Batched pending-telemetry store: CONFIG_PIGEON_TELEMETRY_MAX_KEYS
 * latest-value-per-key slots (mirroring the backend's own upsert
 * semantics), drained by pigeon_telemetry_flush() as ONE flat JSON report
 * over the active transport. Deliberately lock-free: set/flush are
 * single-app-thread by contract (see pigeon.h), same assumption the old
 * single-slot version already relied on. */
struct pigeon_telemetry_slot {
  bool pending;
  char key[PIGEON_TELEMETRY_KEY_MAX];
  char val[PIGEON_TELEMETRY_VAL_MAX];
};

static struct {
  bool initialized;
  struct pigeon_telemetry_slot slots[CONFIG_PIGEON_TELEMETRY_MAX_KEYS];
} pigeon_state;

/* Shared flush body ({"k1":"v1","k2":"v2",...}). Static, not stack:
 * PIGEON_TELEMETRY_BODY_MAX scales with CONFIG_PIGEON_TELEMETRY_MAX_KEYS
 * (~1.3KB at the default 8), too big to drop on an arbitrary caller's
 * stack -- and flush is single-caller by contract anyway (see
 * pigeon_telemetry_flush() in pigeon.h). */
static char pigeon_telemetry_body[PIGEON_TELEMETRY_BODY_MAX];

/* Runtime CoAP config from pigeon_init()'s config->connector.coap, exposed to
 * pigeon_coap.c via pigeon_active_coap_config(). Zero-valued (NULL fields)
 * unless the active connector is PIGEON_CONNECTOR_COAP. */
static struct pigeon_coap_config pigeon_coap_cfg;

const struct pigeon_coap_config *pigeon_active_coap_config(void) {
  return &pigeon_coap_cfg;
}

/* Escapes '"' and '\', plus every RFC 8259 sec 7 control character
 * (0x00-0x1F) -- \n/\r/\t via their shorthand, everything else via \u00XX --
 * so an arbitrary caller string (a shadow telemetry key/val, see
 * pigeon_set_shadow_param()) can't break out of the JSON string it's
 * embedded in, or otherwise produce invalid JSON. Truncates rather than
 * overflows if out is too small. */
size_t pigeon_json_escape(const char *in, char *out, size_t out_len) {
  static const char hex_digits[] = "0123456789abcdef";
  size_t o = 0;

  for (size_t i = 0; in[i] != '\0'; i++) {
    unsigned char c = (unsigned char)in[i];

    if (c == '"' || c == '\\') {
      if (o + 2 >= out_len) {
        break;
      }
      out[o++] = '\\';
      out[o++] = (char)c;
    } else if (c == '\n' || c == '\r' || c == '\t') {
      /* RFC 8259 sec 7 shorthand escapes. */
      if (o + 2 >= out_len) {
        break;
      }
      out[o++] = '\\';
      out[o++] = (c == '\n') ? 'n' : (c == '\r') ? 'r' : 't';
    } else if (c < 0x20) {
      /* Every other control character (0x00-0x1F) is illegal unescaped in
       * a JSON string per RFC 8259 sec 7, and has no shorthand -- \u00XX
       * is the only option. Caught by real-world use: an arbitrary
       * caller-supplied telemetry value (e.g. a sensor error string) with
       * an embedded raw control byte used to produce invalid JSON here;
       * over HTTPS/CoAP that failed one isolated report, but over
       * pigeon_ws.c's shared persistent socket it got the whole connection
       * closed by dovecote's strict serde_json parse (code 4003), tearing
       * down shadow_update push delivery along with the one bad report. */
      if (o + 6 >= out_len) {
        break;
      }
      out[o++] = '\\';
      out[o++] = 'u';
      out[o++] = '0';
      out[o++] = '0';
      out[o++] = hex_digits[(c >> 4) & 0xF];
      out[o++] = hex_digits[c & 0xF];
    } else {
      if (o + 1 >= out_len) {
        break;
      }
      out[o++] = (char)c;
    }
  }
  out[o] = '\0';

  return o;
}

int pigeon_init(const struct pigeon_config* config) {
  if (!config || !config->device_id) {
    LOG_ERR("Invalid configuration parameters supplied");
    return -EINVAL;
  }

#if defined(CONFIG_PIGEON_CONNECTOR_HTTPS) || defined(CONFIG_PIGEON_CONNECTOR_COAP)
  /* CONFIG_PIGEON_ENDPOINT/_TOKEN live outside "if PIGEON" in Kconfig (see
   * its comment) so pigeon_core.c -- compiled unconditionally regardless of
   * CONFIG_PIGEON -- always has a value to read. That means this guard must
   * itself be gated on a connector actually being selected: a sample that
   * leaves CONFIG_PIGEON off entirely (e.g. shadow_model, which only wants
   * pigeon_init()'s bookkeeping and the shadow structs, no transport) gets
   * empty-string defaults for both, and used to hard-fail here even though
   * it never asked for a transport at all. */
  if (!*CONFIG_PIGEON_ENDPOINT || !*CONFIG_PIGEON_TOKEN) {
    LOG_ERR("CONFIG_PIGEON_ENDPOINT and CONFIG_PIGEON_TOKEN must be set");
    return -EINVAL;
  }
#endif

  LOG_INF("Initializing Pigeon tracking instance: %s", config->device_id);

  switch (config->connector.type) {
    case PIGEON_CONNECTOR_HTTPS:
      LOG_INF("Transport mapped to secure HTTPS edge pipeline: %s", CONFIG_PIGEON_ENDPOINT);
      break;
    case PIGEON_CONNECTOR_COAP:
      LOG_INF("Transport mapped to low-overhead CoAP edge pipeline: %s", CONFIG_PIGEON_ENDPOINT);
      pigeon_coap_cfg = config->connector.coap;
      break;
    default:
      LOG_ERR("Unknown connector type: %d", config->connector.type);
      return -EINVAL;
  }

  pigeon_state.initialized = true;
  LOG_INF("Pigeon tracking instance ready: %s", config->device_id);

#if defined(CONFIG_PIGEON_WATCHDOG)
  pigeon_watchdog_start();
#endif

  return 0;
}

int pigeon_telemetry_set(const char *key, const char *val) {
  if (!key || !val) {
    LOG_ERR("Telemetry key/val must not be NULL");
    return -EINVAL;
  }

  if (!pigeon_state.initialized) {
    LOG_ERR("pigeon_telemetry_set called before pigeon_init");
    return -ENODEV;
  }

  if (strlen(key) >= PIGEON_TELEMETRY_KEY_MAX || strlen(val) >= PIGEON_TELEMETRY_VAL_MAX) {
    LOG_ERR(
        "Telemetry param '%s' exceeds buffer limits (key<%d, val<%d)", key,
        PIGEON_TELEMETRY_KEY_MAX, PIGEON_TELEMETRY_VAL_MAX
    );
    return -ENOSPC;
  }

  struct pigeon_telemetry_slot *free_slot = NULL;

  for (int i = 0; i < CONFIG_PIGEON_TELEMETRY_MAX_KEYS; i++) {
    struct pigeon_telemetry_slot *slot = &pigeon_state.slots[i];

    if (slot->pending && strcmp(slot->key, key) == 0) {
      /* Latest-value-per-key: refreshing a still-pending key's value is the
       * expected steady state (it mirrors the backend's own upsert), not
       * the data-loss hazard the old single-slot store used to warn about. */
      strcpy(slot->val, val);
      LOG_INF("Updated pending telemetry: %s=%s", key, val);
      return 0;
    }

    if (!slot->pending && !free_slot) {
      free_slot = slot;
    }
  }

  if (!free_slot) {
    LOG_ERR(
        "Telemetry store full (%d distinct keys pending, see "
        "CONFIG_PIGEON_TELEMETRY_MAX_KEYS); flush before setting '%s'",
        CONFIG_PIGEON_TELEMETRY_MAX_KEYS, key
    );
    return -ENOMEM;
  }

  strcpy(free_slot->key, key);
  strcpy(free_slot->val, val);
  free_slot->pending = true;

  LOG_INF("Queued telemetry: %s=%s", key, val);

  return 0;
}

int pigeon_set_shadow_param(const char *key, const char *val) {
  return pigeon_telemetry_set(key, val);
}

/* Builds one flat JSON object from the pending slots into
 * pigeon_telemetry_body, packing slots (in slot order, skipping any that
 * don't fit) until the buffer budget is spent. included[] marks which slots
 * made it into THIS body -- normally all of them, since the buffer is sized
 * so a full batch of escape-free max-length values always fits (see
 * PIGEON_TELEMETRY_BODY_MAX in pigeon_internal.h); escape-heavy values
 * spill into a further body on the flush loop's next pass. Returns the body
 * length (excluding the NUL). */
static size_t pigeon_telemetry_build_body(bool *included, int *included_count) {
  /* Worst-case escaped forms (6x growth: every byte a control character
   * needing \u00XX) of one key/value -- the same sizing arithmetic the
   * transports' per-key encode used before body-building moved here. */
  char key_esc[6 * (PIGEON_TELEMETRY_KEY_MAX - 1) + 1];
  char val_esc[6 * (PIGEON_TELEMETRY_VAL_MAX - 1) + 1];
  size_t len = 0;

  *included_count = 0;
  pigeon_telemetry_body[len++] = '{';

  for (int i = 0; i < CONFIG_PIGEON_TELEMETRY_MAX_KEYS; i++) {
    struct pigeon_telemetry_slot *slot = &pigeon_state.slots[i];

    included[i] = false;

    if (!slot->pending) {
      continue;
    }

    pigeon_json_escape(slot->key, key_esc, sizeof(key_esc));
    pigeon_json_escape(slot->val, val_esc, sizeof(val_esc));

    /* Entry syntax: [,]"key":"val" -- plus the closing brace and NUL (2)
     * that still have to fit after the last entry. */
    size_t needed = strlen(key_esc) + strlen(val_esc) + 6 + (*included_count ? 1 : 0);

    if (len + needed + 2 > sizeof(pigeon_telemetry_body)) {
      continue;
    }

    len += snprintk(
        pigeon_telemetry_body + len, sizeof(pigeon_telemetry_body) - len, "%s\"%s\":\"%s\"",
        *included_count ? "," : "", key_esc, val_esc
    );
    included[i] = true;
    (*included_count)++;
  }

  pigeon_telemetry_body[len++] = '}';
  pigeon_telemetry_body[len] = '\0';

  return len;
}

int pigeon_telemetry_flush(void) {
  if (!pigeon_state.initialized) {
    LOG_ERR("pigeon_telemetry_flush called before pigeon_init");
    return -ENODEV;
  }

  int remaining = 0;

  for (int i = 0; i < CONFIG_PIGEON_TELEMETRY_MAX_KEYS; i++) {
    remaining += pigeon_state.slots[i].pending ? 1 : 0;
  }

  if (!remaining) {
    return -ENODATA;
  }

  while (remaining > 0) {
    bool included[CONFIG_PIGEON_TELEMETRY_MAX_KEYS];
    int chunk_keys;
    size_t body_len = pigeon_telemetry_build_body(included, &chunk_keys);

    if (chunk_keys == 0) {
      /* Unreachable by construction (PIGEON_TELEMETRY_BODY_MAX's floor
       * guarantees even a single fully-escaped worst-case slot fits an
       * empty body) -- defensive so a sizing regression can't spin this
       * loop forever. */
      LOG_ERR("Pending telemetry cannot fit the flush body buffer");
      return -EMSGSIZE;
    }

    int err;

#if defined(CONFIG_PIGEON_WS)
    /* Saves a full TLS connect/request/teardown cycle per report when the WS
     * socket is up; falls back to HTTPS (below) when it isn't, or on any
     * other WS send failure -- see pigeon_ws_report_telemetry()'s docs on
     * why this is safe only for telemetry, never for shadow_report. */
    err = pigeon_ws_report_telemetry(pigeon_telemetry_body, body_len);
    if (err == -ENOTCONN)
#endif
    err = pigeon_transport_report_telemetry(pigeon_telemetry_body, body_len);

    if (err) {
      /* Clear-on-success, per report: nothing from THIS report (nor any
       * not-yet-attempted slot) is cleared, so every unsent key stays
       * queued -- while keys already cleared by a previous loop pass rode
       * a report that succeeded, so nothing gets double-sent either. */
      LOG_WRN("Telemetry flush failed: %d (%d key(s) still queued, will retry)", err, remaining);
      return err;
    }

    for (int i = 0; i < CONFIG_PIGEON_TELEMETRY_MAX_KEYS; i++) {
      if (included[i]) {
        pigeon_state.slots[i].pending = false;
      }
    }
    remaining -= chunk_keys;

    LOG_INF("Flushed %d telemetry key(s) in one report (%u bytes)", chunk_keys, (unsigned)body_len);

#if defined(CONFIG_PIGEON_WATCHDOG)
    /* A successful report over WHICHEVER transport (WS telemetry or the
     * HTTPS/CoAP fallback above) is confirmed round-trip liveness -- see
     * zephyr/Kconfig's CONFIG_PIGEON_WATCHDOG help. Fed per report, not
     * per full flush: even a flush that later fails on a follow-up
     * escape-spill report has just proven the round trip works. */
    pigeon_watchdog_feed();
#endif
  }

  return 0;
}

int pigeon_shadow_flush(void) {
  return pigeon_telemetry_flush();
}
