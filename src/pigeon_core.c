#include <errno.h>
#include <pigeon.h>
#include <stdbool.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
/* snprintk: must be included explicitly -- logging/log.h only provides it
 * transitively when CONFIG_LOG=y, and this module also builds into log-free
 * images (e.g. a release MCUboot config under sysbuild). */
#include <zephyr/sys/printk.h>

#include "pigeon_internal.h"

#if defined(CONFIG_PIGEON_TELEMETRY_BATCH)
#include "pigeon_telemetry_batch.h"
#endif

#if defined(CONFIG_PIGEON_CONNECTOR_COAP) && defined(CONFIG_MODEM_KEY_MGMT)
#include "pigeon_coap_internal.h"
#endif

#if defined(CONFIG_PIGEON_RESET_CAUSE_TELEMETRY)
#include <zephyr/drivers/hwinfo.h>
#endif

LOG_MODULE_REGISTER(pigeon, CONFIG_PIGEON_LOG_LEVEL);

/* Serializes TLS handshakes across every transport module, which is why it
 * lives here rather than inside one of them: on an offloaded-TLS modem the
 * handshake runs in the modem, and that modem permits several concurrent
 * TLS *sessions* but only one handshake in flight, reporting a violation as
 * a spurious "sec_tag not found" on a tag that is demonstrably present.
 *
 * pigeon_https.c also depends on it to guard its module-global request
 * state, so it holds the lock across a whole connect/request/close.
 * pigeon_ws.c shares no state with it and takes the lock only around its
 * own connect -- the one point where both modules can be handshaking at
 * once. Nothing holds it across an established session's traffic:
 * concurrent sessions are permitted, and doing so would stall polling
 * behind a long transfer for no gain.
 *
 * Defining it in core keeps it independent of which transports a given
 * build selects, rather than making one module's presence a prerequisite
 * for another's correctness. */
K_MUTEX_DEFINE(pigeon_transport_mutex);

int pigeon_transport_lock(k_timeout_t timeout) {
  return k_mutex_lock(&pigeon_transport_mutex, timeout);
}

void pigeon_transport_unlock(void) { k_mutex_unlock(&pigeon_transport_mutex); }

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

#if defined(CONFIG_PIGEON_TELEMETRY_BATCH)
/* Assembled batched body ({"reports":[...]}), handed to the transport. Static
 * for the same reason the flat body above is: it scales with the batch knobs
 * (~2.3KB at the defaults) and flush is single-caller by contract. */
static char pigeon_telemetry_batch_body[PIGEON_TELEMETRY_BATCH_BODY_MAX];

/* Retry pacing for a batch the platform did not take. Only the deadline is
 * consulted on the hot path; the base is the exponential schedule's position,
 * advanced on every failure and reset by a delivery. */
static struct {
  uint32_t backoff_base_sec;
  int64_t retry_after_uptime_ms;
} pigeon_batch_retry = {
    .backoff_base_sec = PIGEON_TELEMETRY_BATCH_BACKOFF_BASE_SEC,
};

#if defined(CONFIG_PIGEON_WATCHDOG) && !defined(CONFIG_PIGEON_WS)
/* Without CONFIG_PIGEON_WS there is no pong feeding the watchdog, so a
 * delivered batch is the only liveness evidence the library produces -- and
 * batching is precisely what lengthens the gap between deliveries. A max-age
 * at or past the wedge timeout would reboot a perfectly healthy device that
 * was merely holding a partial batch, so the ordering is a build error rather
 * than a reboot loop found in the field. */
BUILD_ASSERT(
    CONFIG_PIGEON_WATCHDOG_TIMEOUT_SEC > CONFIG_PIGEON_TELEMETRY_BATCH_MAX_AGE_SEC,
    "CONFIG_PIGEON_TELEMETRY_BATCH_MAX_AGE_SEC must stay well under "
    "CONFIG_PIGEON_WATCHDOG_TIMEOUT_SEC: a delivered batch is what feeds the watchdog on a "
    "build without CONFIG_PIGEON_WS"
);
#endif
#endif /* CONFIG_PIGEON_TELEMETRY_BATCH */

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
       * is the only option. An unescaped control byte in a caller-supplied
       * telemetry value (e.g. a sensor error string) produces invalid
       * JSON: over HTTPS/CoAP that fails one isolated report, but over
       * pigeon_ws.c's shared persistent socket it closes the whole
       * connection under dovecote's strict serde_json parse (code 4003),
       * tearing down shadow_update push delivery along with the one bad
       * report. */
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
   * itself be gated on a connector actually being selected: a build that
   * leaves CONFIG_PIGEON off entirely (wanting only pigeon_init()'s
   * bookkeeping and the shadow structs, no transport) gets empty-string
   * defaults and must not hard-fail here. */
  if (!*CONFIG_PIGEON_ENDPOINT) {
    LOG_ERR("CONFIG_PIGEON_ENDPOINT must be set");
    return -EINVAL;
  }
#endif

#if defined(CONFIG_PIGEON_CONNECTOR_HTTPS)
  /* The bearer token only rides HTTPS requests; the CoAP connector
   * authenticates through its PSK handshake instead and never reads it. */
  if (!*CONFIG_PIGEON_TOKEN) {
    LOG_ERR("CONFIG_PIGEON_TOKEN must be set");
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
#if defined(CONFIG_PIGEON_CONNECTOR_COAP) && defined(CONFIG_MODEM_KEY_MGMT)
      /* Modem-offloaded boards keep TLS/DTLS credentials in the modem's
       * own store, writable only while the modem is offline -- so PSK
       * provisioning can't stay lazy inside the transport's first
       * connect() (LTE is up by then). It happens here instead, which
       * obligates the app to call pigeon_init() BEFORE bringing LTE up on
       * these builds -- see pigeon_coap_psk_write_modem() in
       * pigeon_coap.c and coap_dtls_init's main.c in pigeon-examples. */
      {
        int cred_err = pigeon_coap_register_psk();

        if (cred_err) {
          return cred_err;
        }
      }
#endif
      break;
    default:
      LOG_ERR("Unknown connector type: %d", config->connector.type);
      return -EINVAL;
  }

  pigeon_state.initialized = true;
  LOG_INF("Pigeon tracking instance ready: %s", config->device_id);

#if defined(CONFIG_PIGEON_RESET_CAUSE_TELEMETRY)
  /* One-shot: queued here so it rides this boot's first telemetry flush
   * over whichever transport is active, same as any other key. Read-only
   * on purpose -- see CONFIG_PIGEON_RESET_CAUSE_TELEMETRY's Kconfig help
   * for why this must never call hwinfo_clear_reset_cause(). */
  {
    uint32_t reset_cause;
    int reset_cause_err = hwinfo_get_reset_cause(&reset_cause);

    if (reset_cause_err) {
      LOG_WRN(
          "hwinfo_get_reset_cause failed: %d -- no reset_cause telemetry this boot",
          reset_cause_err
      );
    } else {
      /* Widest uint32_t as decimal ("4294967295") plus NUL. */
      char reset_cause_str[11];

      snprintk(reset_cause_str, sizeof(reset_cause_str), "%u", reset_cause);
      pigeon_telemetry_set("reset_cause", reset_cause_str);
    }
  }
#endif

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
       * expected steady state, mirroring the backend's own upsert
       * semantics. */
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

/* Pending keys awaiting a report (flat mode) or a reading (batch mode). */
static int pigeon_telemetry_pending_keys(void) {
  int pending = 0;

  for (int i = 0; i < CONFIG_PIGEON_TELEMETRY_MAX_KEYS; i++) {
    pending += pigeon_state.slots[i].pending ? 1 : 0;
  }

  return pending;
}

static void pigeon_telemetry_clear_included(const bool *included) {
  for (int i = 0; i < CONFIG_PIGEON_TELEMETRY_MAX_KEYS; i++) {
    if (included[i]) {
      pigeon_state.slots[i].pending = false;
    }
  }
}

#if !defined(CONFIG_PIGEON_TELEMETRY_BATCH)
/* The unbatched path, unchanged: one report per flush, carrying every pending
 * key, cleared per report on success. Compiled out entirely under
 * CONFIG_PIGEON_TELEMETRY_BATCH -- a build is one shape or the other, never
 * switching at runtime, so neither carries the other's code. */
static int pigeon_telemetry_flush_flat(void) {
  int remaining = pigeon_telemetry_pending_keys();

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
    /* No result out-param: an unbatched report has nothing to pace. Its keys
     * stay queued on any failure and ride the app's next flush, which is the
     * same thing a Retry-After would have asked for. */
    err = pigeon_transport_report_telemetry(pigeon_telemetry_body, body_len, NULL);

    if (err) {
      /* Clear-on-success, per report: nothing from THIS report (nor any
       * not-yet-attempted slot) is cleared, so every unsent key stays
       * queued -- while keys already cleared by a previous loop pass rode
       * a report that succeeded, so nothing gets double-sent either. */
      LOG_WRN("Telemetry flush failed: %d (%d key(s) still queued, will retry)", err, remaining);
      return err;
    }

    pigeon_telemetry_clear_included(included);
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
#endif /* !CONFIG_PIGEON_TELEMETRY_BATCH */

#if defined(CONFIG_PIGEON_TELEMETRY_BATCH)

/* Closes the pending keys into buffered reading(s) stamped at now_ms. Almost
 * always exactly one: the split loop only runs for a store of pathologically
 * escape-heavy values that cannot fit one body, and the resulting readings
 * share a timestamp, which the platform resolves by keeping the order they
 * were sent in. */
static int pigeon_telemetry_record_pending(int64_t now_ms) {
  int remaining = pigeon_telemetry_pending_keys();

  if (!remaining) {
    return -ENODATA;
  }

  while (remaining > 0) {
    bool included[CONFIG_PIGEON_TELEMETRY_MAX_KEYS];
    int chunk_keys;
    size_t body_len = pigeon_telemetry_build_body(included, &chunk_keys);

    if (chunk_keys == 0) {
      LOG_ERR("Pending telemetry cannot fit the flush body buffer");
      return -EMSGSIZE;
    }

    int err = pigeon_telemetry_batch_record(pigeon_telemetry_body, body_len, now_ms);

    if (err) {
      /* The keys stay pending: a reading that could not be buffered is
       * retried on the next record rather than lost, and the buffer only
       * refuses a fragment no eviction could make room for. */
      LOG_ERR("Telemetry reading could not be buffered: %d", err);
      return err;
    }

    pigeon_telemetry_clear_included(included);
    remaining -= chunk_keys;
  }

  return 0;
}

static void pigeon_telemetry_batch_delivered(void) {
  pigeon_telemetry_batch_reset();
  pigeon_batch_retry.retry_after_uptime_ms = 0;
  pigeon_batch_retry.backoff_base_sec = PIGEON_TELEMETRY_BATCH_BACKOFF_BASE_SEC;
}

/* Sends one already-framed batched body, WS first when that socket is up --
 * same preference and same -ENOTCONN fallback the flat path uses, for the
 * same reason: it saves a full TLS connect/request/teardown per delivery. */
static int pigeon_telemetry_batch_send(
    const char *body, size_t body_len, struct pigeon_http_result *res
) {
  int err;

#if defined(CONFIG_PIGEON_WS)
  err = pigeon_ws_report_telemetry_batch(body, body_len);
  if (err == -ENOTCONN)
#endif
  err = pigeon_transport_report_telemetry(body, body_len, res);

  return err;
}

static int pigeon_telemetry_flush_batched(bool force) {
  int64_t now_ms = k_uptime_get();

  /* -ENODATA here just means the app flushed without setting anything since
   * the last one, which is normal and not a reason to skip delivering what is
   * already buffered. */
  (void)pigeon_telemetry_record_pending(now_ms);

  uint32_t dropped = pigeon_telemetry_batch_take_dropped();

  if (dropped) {
    LOG_WRN(
        "Telemetry batch buffer full: dropped %u oldest reading(s) (see "
        "CONFIG_PIGEON_TELEMETRY_BATCH_BUF_SIZE/_DEPTH)",
        dropped
    );
  }

  if (pigeon_telemetry_batch_count() == 0) {
    return -ENODATA;
  }

  if (!force) {
    if (pigeon_batch_retry.retry_after_uptime_ms &&
        now_ms < pigeon_batch_retry.retry_after_uptime_ms) {
      /* Backing off from a failed delivery. Reported as success because
       * nothing was lost or even attempted -- the readings are buffered and
       * the wait is deliberate. */
      return 0;
    }

    if (!pigeon_telemetry_batch_due(now_ms)) {
      return 0;
    }
  }

  int readings = 0;
  size_t body_len = pigeon_telemetry_batch_build(
      pigeon_telemetry_batch_body, sizeof(pigeon_telemetry_batch_body), now_ms, &readings
  );

  if (body_len == 0) {
    /* Unreachable while the body buffer is sized off the same two knobs the
     * buffer is (PIGEON_TELEMETRY_BATCH_BODY_MAX) -- defensive against a
     * sizing regression, and dropped rather than kept so an unframeable batch
     * cannot wedge every later reading behind it. */
    LOG_ERR("Telemetry batch of %d reading(s) could not be framed -- dropped", readings);
    pigeon_telemetry_batch_delivered();
    return -EMSGSIZE;
  }

  struct pigeon_http_result res = {0};
  int err = pigeon_telemetry_batch_send(pigeon_telemetry_batch_body, body_len, &res);

  if (!err) {
    pigeon_telemetry_batch_delivered();
    LOG_INF(
        "Flushed %d telemetry reading(s) in one batch (%u bytes)", readings, (unsigned)body_len
    );
#if defined(CONFIG_PIGEON_WATCHDOG)
    /* Fed only by a delivery that actually completed a round trip -- a
     * buffered reading proves nothing about the link, which is the one thing
     * this watchdog exists to notice. */
    pigeon_watchdog_feed();
#endif
    return 0;
  }

  /* -EMSGSIZE is the same class of failure as a 413 arriving from the far
   * end: the bytes do not fit, here because a transport could not frame
   * them (a WS frame buffer, say) rather than because the platform said so.
   * Either way retrying identical bytes cannot succeed, and a WS send has no
   * status to report at all -- so the errno has to carry it. */
  if (err == -EMSGSIZE || pigeon_telemetry_batch_status_is_fatal(res.status)) {
    /* The batch was refused on its own merits, not the moment's, so the same
     * bytes will be refused identically forever. Dropped loudly: keeping them
     * would stall every later reading behind a batch that can never leave. */
    LOG_ERR(
        "Telemetry batch refused (HTTP %u, err %d) -- dropping %d reading(s); the batch breaks "
        "a size or count cap, check CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH and the key count per "
        "reading",
        res.status, err, readings
    );
    pigeon_telemetry_batch_delivered();
    return err;
  }

  uint32_t delay_sec;

  if (err == -EAGAIN && res.retry_after_sec) {
    /* The server named a delay; honor it rather than this side's schedule,
     * clamped so a hostile or mistaken value cannot park the device. */
    delay_sec = MIN(res.retry_after_sec, (uint32_t)CONFIG_PIGEON_TELEMETRY_BATCH_BACKOFF_MAX_SEC);
  } else {
    delay_sec = pigeon_telemetry_batch_backoff_jitter(pigeon_batch_retry.backoff_base_sec);
  }

  pigeon_batch_retry.backoff_base_sec =
      pigeon_telemetry_batch_backoff_next(pigeon_batch_retry.backoff_base_sec);
  pigeon_batch_retry.retry_after_uptime_ms = now_ms + ((int64_t)delay_sec * MSEC_PER_SEC);

  LOG_WRN(
      "Telemetry batch delivery failed: %d (%d reading(s) kept, retrying in %us)", err, readings,
      delay_sec
  );

  return err;
}

int pigeon_telemetry_record(void) {
  if (!pigeon_state.initialized) {
    LOG_ERR("pigeon_telemetry_record called before pigeon_init");
    return -ENODEV;
  }

  return pigeon_telemetry_record_pending(k_uptime_get());
}

int pigeon_telemetry_flush_now(void) {
  if (!pigeon_state.initialized) {
    LOG_ERR("pigeon_telemetry_flush_now called before pigeon_init");
    return -ENODEV;
  }

  return pigeon_telemetry_flush_batched(true);
}

int pigeon_telemetry_batch_pending(void) {
  return pigeon_telemetry_batch_count();
}

#endif /* CONFIG_PIGEON_TELEMETRY_BATCH */

int pigeon_telemetry_flush(void) {
  if (!pigeon_state.initialized) {
    LOG_ERR("pigeon_telemetry_flush called before pigeon_init");
    return -ENODEV;
  }

#if defined(CONFIG_PIGEON_TELEMETRY_BATCH)
  return pigeon_telemetry_flush_batched(false);
#else
  return pigeon_telemetry_flush_flat();
#endif
}

int pigeon_shadow_flush(void) {
  return pigeon_telemetry_flush();
}
