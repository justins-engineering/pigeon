/*
 * MQTT connector: one persistent session to the pigeonhole broker, which
 * bridges every publish onto the same /device/pigeons/:id/... routes the
 * HTTPS connector calls directly, carrying this pigeon's own bearer token.
 *
 * It is a transport module (it defines pigeon_shadow_get/
 * pigeon_shadow_report/pigeon_transport_report_telemetry/
 * pigeon_transport_upload_logs, like pigeon_https.c and pigeon_coap.c) AND
 * it owns a persistent connection with a worker thread, like pigeon_ws.c --
 * the first module here to be both, because on this transport the session
 * is what carries the requests and the pushes alike. That shapes two things
 * a reader of the other connectors will not expect:
 *
 *   - pigeon_shadow_get() fetches nothing. The broker publishes the
 *     pigeon's target shadow as a RETAINED message on pigeon/shadow/target
 *     and re-publishes it whenever the dashboard changes it, so this
 *     connector serves the value that arrived last. A polling app keeps
 *     working unchanged and stops paying for the poll.
 *   - a publish is acknowledged end to end. The broker answers a QoS 1
 *     PUBACK only once the platform has taken the report, so a flush that
 *     returns 0 means the same thing it does over HTTPS. Redelivery of an
 *     interrupted publish is ours: Zephyr's client never retransmits and
 *     the broker holds no session to resume into (it answers
 *     session_present = 0 by design), so pigeon_mqtt_policy.c's pending
 *     table tracks what is in flight and this module republishes it with
 *     the duplicate flag once the session is back.
 *
 * Topics are session-scoped and carry no pigeon id: the handshake already
 * bound the connection to exactly one pigeon. That is also why
 * pigeon_config.device_id is load-bearing here and log-only elsewhere -- it
 * is the CONNECT client id and username, and the broker refuses anything
 * that is not this pigeon's own 64-hex id.
 */
#include <errno.h>
#include <pigeon.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/data/json.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include "pigeon_internal.h"
#include "pigeon_mqtt_policy.h"
#include "pigeon_psk.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

/* TLS only, always: the broker has no cleartext listener in any deployment
 * shape, and on a certificate session the CONNECT password is this device's
 * bearer token. An mqtt:// endpoint is refused at parse time rather than
 * attempted and failed, so the mistake reads as the configuration error it
 * is instead of as a broker that will not answer. */
#define PIGEON_MQTT_SCHEME       "mqtts"
#define PIGEON_MQTT_DEFAULT_PORT 8883

#define PIGEON_MQTT_HOST_MAX 128

/* Upper bound on one poll() in the worker's inner loop, so stop_requested
 * is observed promptly rather than at the next keepalive -- pigeon_ws.c's
 * PIGEON_WS_POLL_MAX_MS, for the same reason (no wakeup primitive backs
 * these flags). */
#define PIGEON_MQTT_POLL_MAX_MS 1000

/* How long the CONNACK and SUBACK are waited for after their packets go
 * out. Generous because it covers a cellular round trip, and bounded
 * because a broker that never answers must not hold the worker forever. */
#define PIGEON_MQTT_ACK_TIMEOUT_MS 15000

/* Bounds every blocking send on the session socket, including Zephyr's own
 * internal writes -- see pigeon_ws.c's identically-reasoned setsockopt for
 * why SO_SNDTIMEO is the only thing standing between a half-dead TCP path
 * and an unbounded block, and why CONFIG_NET_CONTEXT_SNDTIMEO is selected. */
#define PIGEON_MQTT_SEND_TIMEOUT_MS 10000

/* A retained shadow carries the full PigeonShadow with two JSON-in-a-string
 * configs, each capped at PIGEON_HTTPS_CONFIG_MAX once decoded; the escaped
 * wire form plus framing fits in twice that plus headroom. */
#define PIGEON_MQTT_PAYLOAD_MAX (2 * PIGEON_HTTPS_CONFIG_MAX + 512)

/* capsules::MAX_LOG_CHUNK_BYTES, which is also the broker's inbound payload
 * cap. A log batch larger than this is split across consecutive publishes
 * rather than refused: the platform stores each chunk opaquely into a ring
 * buffer, so two chunks and one chunk of the same bytes decode identically
 * host-side. */
#define PIGEON_MQTT_LOG_CHUNK_MAX 16384

/* Below the app's own work, same reasoning as PIGEON_WS_THREAD_PRIORITY:
 * this worker should never starve application logic to service a socket. */
#define PIGEON_MQTT_THREAD_PRIORITY 10

K_THREAD_STACK_DEFINE(pigeon_mqtt_stack, CONFIG_PIGEON_MQTT_THREAD_STACK_SIZE);
static struct k_thread pigeon_mqtt_thread_data;

/*
 * Guards the state below. Held only for brief, non-blocking reads and
 * writes -- never across a network call, which is what pigeon_mqtt_tx_lock
 * is for (see its own comment).
 */
K_MUTEX_DEFINE(pigeon_mqtt_lock);

/*
 * Serializes use of the MQTT client object against its own destruction.
 * Zephyr's client has an internal mutex, so a publish from an application
 * thread and mqtt_input() on the worker are already safe against each
 * other; what that mutex does NOT cover is mqtt_client_init() memsetting
 * the whole client, or a teardown closing the socket, while a publisher is
 * inside it. The worker holds this across connect and teardown, publishers
 * hold it across their own mqtt_publish(), and nothing holds it across the
 * inner loop's mqtt_input()/mqtt_live(), which would stall every publisher
 * behind a poll cycle for no gain.
 */
K_MUTEX_DEFINE(pigeon_mqtt_tx_lock);

static struct mqtt_client pigeon_mqtt_client;

/* Every address the broker's name resolved to, not just the first. A host
 * with both an A and a AAAA record hands back a ranked list (RFC 6724) and
 * the top entry is not necessarily reachable from here -- a v4-only network
 * offered ::1 first, or an IPv6-only cellular PDN offered nothing else. The
 * connect below walks the list, exactly as pigeon_ws.c's own resolve loop
 * does, rather than making one attempt and calling the broker down. Four is
 * more candidates than any of these hosts publishes. */
#define PIGEON_MQTT_MAX_ADDRS 4

static struct net_sockaddr_storage pigeon_mqtt_addrs[PIGEON_MQTT_MAX_ADDRS];
static uint8_t pigeon_mqtt_addr_count;
static uint8_t pigeon_mqtt_rx_buf[CONFIG_PIGEON_MQTT_RX_BUF_SIZE];
static uint8_t pigeon_mqtt_tx_buf[CONFIG_PIGEON_MQTT_TX_BUF_SIZE];
static uint8_t pigeon_mqtt_payload[PIGEON_MQTT_PAYLOAD_MAX];

static char pigeon_mqtt_host[PIGEON_MQTT_HOST_MAX];
static uint16_t pigeon_mqtt_port;
static bool pigeon_mqtt_endpoint_parsed;
static bool pigeon_mqtt_psk_registered;

static struct pigeon_mqtt_pending pigeon_mqtt_slots[CONFIG_PIGEON_MQTT_MAX_INFLIGHT];
static struct pigeon_mqtt_pending_table pigeon_mqtt_pending;

/* One per slot: given by the worker whenever something a waiting publisher
 * cares about happened -- its PUBACK, a session coming up, a session going
 * down, or a stop. The publisher re-reads the table rather than trusting
 * the wakeup to mean any particular thing. */
static struct k_sem pigeon_mqtt_slot_sem[CONFIG_PIGEON_MQTT_MAX_INFLIGHT];

/* Given when a retained target shadow lands, so the first
 * pigeon_shadow_get() after a connect can wait for one. */
static K_SEM_DEFINE(pigeon_mqtt_shadow_sem, 0, 1);

static struct {
  bool running;        /* worker spawned, not yet joined */
  bool stop_requested; /* pigeon_mqtt_stop() asked the worker to exit */
  bool session_up;     /* CONNACK accepted, subscription in place */
  pigeon_event_cb_t cb;
  uint32_t backoff_base_sec;
  /* Consecutive sessions that died with a publish unacknowledged: the
   * free-tier fuse's only signal to a 3.1.1 client (see
   * pigeon_mqtt_close_is_persistent()). */
  uint32_t unacked_closes;
  bool have_shadow;
  /* CONNACK bookkeeping for the connect handshake, read by the worker
   * once its wait ends. */
  bool connack_seen;
  uint8_t connack_code;
  bool suback_seen;
  bool suback_failed;
} pigeon_mqtt = {
    .backoff_base_sec = PIGEON_MQTT_BACKOFF_BASE_SEC,
};

/*
 * Wire shape of the retained pigeon/shadow/target payload: capsules::
 * PigeonShadow exactly as the device shadow GET returns it, which is why
 * this is the same struct and the same JSON_TOK_STRING_BUF reasoning as
 * pigeon_https.c's and pigeon_ws.c's copies -- the two configs are
 * JSON-in-a-JSON-string on the wire and must be unescaped in place. Static
 * so pigeon_shadow_doc's pointers can alias straight into it.
 */
struct pigeon_mqtt_shadow_wire {
  int32_t target_version;
  int32_t current_version;
  char target_config[PIGEON_HTTPS_CONFIG_MAX];
  char current_config[PIGEON_HTTPS_CONFIG_MAX];
  int64_t updated_at;
};

static struct pigeon_mqtt_shadow_wire pigeon_mqtt_shadow;

static const struct json_obj_descr pigeon_mqtt_shadow_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct pigeon_mqtt_shadow_wire, target_version, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct pigeon_mqtt_shadow_wire, current_version, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct pigeon_mqtt_shadow_wire, target_config, JSON_TOK_STRING_BUF),
    JSON_OBJ_DESCR_PRIM(struct pigeon_mqtt_shadow_wire, current_config, JSON_TOK_STRING_BUF),
    JSON_OBJ_DESCR_PRIM(struct pigeon_mqtt_shadow_wire, updated_at, JSON_TOK_INT64),
};

int pigeon_mqtt_register_psk(void) {
  if (pigeon_mqtt_psk_registered) {
    return 0;
  }

  const struct pigeon_mqtt_config *cfg = pigeon_active_mqtt_config();

  if (!cfg->tls_psk_identity || !cfg->tls_psk_secret) {
    return 0;
  }

  int err = pigeon_psk_register(
      CONFIG_PIGEON_MQTT_SEC_TAG, cfg->tls_psk_identity, cfg->tls_psk_secret
  );

  if (err) {
    return err;
  }

  pigeon_mqtt_psk_registered = true;

  return 0;
}

/* Splits CONFIG_PIGEON_ENDPOINT ("mqtts://host[:port]") once. Unlike the
 * other connectors' endpoints this one carries no path: the session names
 * the pigeon, not a URL. A trailing path is refused rather than ignored,
 * since an endpoint minted for another connector is the likeliest way one
 * arrives here. */
static int pigeon_mqtt_parse_endpoint(void) {
  if (pigeon_mqtt_endpoint_parsed) {
    return 0;
  }

  const char *endpoint = CONFIG_PIGEON_ENDPOINT;
  const char *scheme_end = strstr(endpoint, "://");

  if (!scheme_end) {
    LOG_ERR("CONFIG_PIGEON_ENDPOINT missing scheme: %s", endpoint);
    return -EINVAL;
  }

  size_t scheme_len = (size_t)(scheme_end - endpoint);

  if (scheme_len != strlen(PIGEON_MQTT_SCHEME) ||
      strncmp(endpoint, PIGEON_MQTT_SCHEME, scheme_len) != 0) {
    LOG_ERR(
        "CONFIG_PIGEON_ENDPOINT scheme mismatch: the MQTT connector speaks " PIGEON_MQTT_SCHEME
        ":// only (no cleartext listener exists), got %s",
        endpoint
    );
    return -EINVAL;
  }

  const char *host_start = scheme_end + 3;
  const char *path_start = strchr(host_start, '/');

  if (path_start && *(path_start + 1) != '\0') {
    LOG_ERR("CONFIG_PIGEON_ENDPOINT carries a path: an MQTT endpoint names the broker only");
    return -EINVAL;
  }

  size_t host_port_len = path_start ? (size_t)(path_start - host_start) : strlen(host_start);
  const char *colon = memchr(host_start, ':', host_port_len);
  size_t host_len = colon ? (size_t)(colon - host_start) : host_port_len;

  if (host_len == 0 || host_len >= sizeof(pigeon_mqtt_host)) {
    LOG_ERR("CONFIG_PIGEON_ENDPOINT host empty or too long");
    return -EINVAL;
  }

  memcpy(pigeon_mqtt_host, host_start, host_len);
  pigeon_mqtt_host[host_len] = '\0';

  pigeon_mqtt_port = PIGEON_MQTT_DEFAULT_PORT;

  if (colon) {
    unsigned long port = strtoul(colon + 1, NULL, 10);

    if (port == 0 || port > UINT16_MAX) {
      LOG_ERR("CONFIG_PIGEON_ENDPOINT port out of range");
      return -EINVAL;
    }

    pigeon_mqtt_port = (uint16_t)port;
  }

  pigeon_mqtt_endpoint_parsed = true;

  return 0;
}

static void pigeon_mqtt_wake_waiters(void) {
  for (int i = 0; i < CONFIG_PIGEON_MQTT_MAX_INFLIGHT; i++) {
    k_sem_give(&pigeon_mqtt_slot_sem[i]);
  }
}

/* Reads an inbound PUBLISH payload out of the socket. Always drains it,
 * even when it is too big to keep or lands on a topic this connector did
 * not ask for: an unread payload leaves the stream mid-packet and every
 * later read is garbage. Returns the number of bytes kept. */
static int pigeon_mqtt_read_payload(struct mqtt_client *client, size_t len) {
  if (len <= sizeof(pigeon_mqtt_payload)) {
    int err = mqtt_readall_publish_payload(client, pigeon_mqtt_payload, len);

    return err ? err : (int)len;
  }

  LOG_WRN(
      "Inbound publish of %u bytes exceeds the %u-byte buffer -- draining", (unsigned)len,
      (unsigned)sizeof(pigeon_mqtt_payload)
  );

  size_t remaining = len;

  while (remaining) {
    size_t chunk = MIN(remaining, sizeof(pigeon_mqtt_payload));
    int err = mqtt_readall_publish_payload(client, pigeon_mqtt_payload, chunk);

    if (err) {
      return err;
    }

    remaining -= chunk;
  }

  return -EMSGSIZE;
}

/* Decodes a retained target shadow and hands it to the app. */
static void pigeon_mqtt_apply_shadow(size_t len) {
  int ret = json_obj_parse(
      (char *)pigeon_mqtt_payload, len, pigeon_mqtt_shadow_descr,
      ARRAY_SIZE(pigeon_mqtt_shadow_descr), &pigeon_mqtt_shadow
  );

  if (ret < 0) {
    LOG_ERR("Retained shadow failed to decode: %d", ret);
    return;
  }

  struct pigeon_shadow_doc doc = {
      .target_version = pigeon_mqtt_shadow.target_version,
      .current_version = pigeon_mqtt_shadow.current_version,
      .target_config = pigeon_mqtt_shadow.target_config,
      .current_config = pigeon_mqtt_shadow.current_config,
      .updated_at = pigeon_mqtt_shadow.updated_at,
  };

  pigeon_event_cb_t cb;

  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
  pigeon_mqtt.have_shadow = true;
  cb = pigeon_mqtt.cb;
  k_mutex_unlock(&pigeon_mqtt_lock);

  k_sem_give(&pigeon_mqtt_shadow_sem);

  LOG_INF("Target shadow received: target_version %d", doc.target_version);

  if (cb) {
    cb(PIGEON_EVENT_SHADOW_UPDATE, &doc);
  }
}

static void pigeon_mqtt_handle_publish(
    struct mqtt_client *client, const struct mqtt_publish_param *param
) {
  const struct mqtt_topic *topic = &param->message.topic;
  bool wanted =
      pigeon_mqtt_is_shadow_target((const char *)topic->topic.utf8, topic->topic.size);
  int kept = pigeon_mqtt_read_payload(client, param->message.payload.len);

  if (topic->qos == MQTT_QOS_1_AT_LEAST_ONCE) {
    /* Acknowledged whatever the payload turned out to be: the broker
     * redelivers an unacknowledged publish, and redelivering a shadow this
     * device could not decode would only repeat the failure. */
    struct mqtt_puback_param ack = {.message_id = param->message_id};

    (void)mqtt_publish_qos1_ack(client, &ack);
  }

  if (!wanted) {
    LOG_WRN("Ignoring publish on an unexpected topic (%u bytes)", (unsigned)topic->topic.size);
    return;
  }

  if (kept < 0) {
    LOG_ERR("Retained shadow could not be read: %d", kept);
    return;
  }

  pigeon_mqtt_apply_shadow((size_t)kept);
}

static void pigeon_mqtt_evt_handler(struct mqtt_client *client, const struct mqtt_evt *evt) {
  switch (evt->type) {
    case MQTT_EVT_CONNACK:
      k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
      pigeon_mqtt.connack_seen = true;
      /* evt->result is the return/reason code on a refusal and 0 on
       * acceptance; param.connack.return_code carries it either way. */
      pigeon_mqtt.connack_code = evt->param.connack.return_code;
      k_mutex_unlock(&pigeon_mqtt_lock);
      break;

    case MQTT_EVT_DISCONNECT:
      LOG_WRN("MQTT session closed by the broker or the link: %d", evt->result);
      k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
      pigeon_mqtt.session_up = false;
      k_mutex_unlock(&pigeon_mqtt_lock);
      break;

    case MQTT_EVT_PUBLISH:
      pigeon_mqtt_handle_publish(client, &evt->param.publish);
      break;

    case MQTT_EVT_PUBACK: {
      k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
      int slot = pigeon_mqtt_pending_ack(&pigeon_mqtt_pending, evt->param.puback.message_id);
      k_mutex_unlock(&pigeon_mqtt_lock);

      if (slot >= 0) {
        k_sem_give(&pigeon_mqtt_slot_sem[slot]);
      }
      break;
    }

    case MQTT_EVT_SUBACK:
      k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
      pigeon_mqtt.suback_seen = true;
      /* A refused filter is not a transient failure: it means this build's
       * topic constants and the broker's disagree, which no reconnect
       * fixes. Recorded so the worker can say so and back off properly. */
      pigeon_mqtt.suback_failed = evt->result < 0;
      k_mutex_unlock(&pigeon_mqtt_lock);
      break;

    case MQTT_EVT_PINGRESP:
#if defined(CONFIG_PIGEON_WATCHDOG)
      /* A PINGRESP is a completed round trip over the live session, which
       * is exactly the liveness evidence pigeon_ws.c feeds on a pong --
       * and the only such evidence on a QoS 0 telemetry build, where a
       * report is a socket write and nothing answers it. */
      pigeon_watchdog_feed();
#endif
      break;

    default:
      break;
  }
}

/* One poll/input/live turn of the session. Returns 0 while the session is
 * healthy, negative when it is over. */
static int pigeon_mqtt_service(int32_t timeout_ms) {
  struct zsock_pollfd fds[1] = {
      {.fd = pigeon_mqtt_client.transport.tls.sock, .events = ZSOCK_POLLIN},
  };
  int ret = zsock_poll(fds, 1, timeout_ms);

  if (ret < 0) {
    LOG_WRN("MQTT poll failed: %d", -errno);
    return -errno;
  }

  if (ret > 0) {
    if (fds[0].revents & (ZSOCK_POLLERR | ZSOCK_POLLHUP | ZSOCK_POLLNVAL)) {
      return -ENOTCONN;
    }

    int err = mqtt_input(&pigeon_mqtt_client);

    if (err) {
      return err;
    }
  }

  /* Sends a PINGREQ when the keepalive is due; -EAGAIN just means it was
   * not. */
  int err = mqtt_live(&pigeon_mqtt_client);

  return (err == -EAGAIN) ? 0 : err;
}

/* Drives the session until one of the acks the connect handshake waits for
 * arrives, or the deadline passes. */
static int pigeon_mqtt_wait_for(bool *flag, int64_t deadline_ms) {
  while (true) {
    bool seen;

    k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
    seen = *flag;
    k_mutex_unlock(&pigeon_mqtt_lock);

    if (seen) {
      return 0;
    }

    int64_t remaining = deadline_ms - k_uptime_get();

    if (remaining <= 0) {
      return -ETIMEDOUT;
    }

    int err = pigeon_mqtt_service((int32_t)MIN(remaining, PIGEON_MQTT_POLL_MAX_MS));

    if (err) {
      return err;
    }
  }
}

static int pigeon_mqtt_resolve_broker(void) {
  struct zsock_addrinfo hints = {
      /* AF_UNSPEC, not a v4 hint: an IPv6-only cellular PDN hands back only
       * AAAA records, and a hard-coded family fails the resolve outright. */
      .ai_family = AF_UNSPEC,
      .ai_socktype = SOCK_STREAM,
  };
  struct zsock_addrinfo *addr_list;
  char port_str[6];

  snprintk(port_str, sizeof(port_str), "%u", pigeon_mqtt_port);

  int err = zsock_getaddrinfo(pigeon_mqtt_host, port_str, &hints, &addr_list);

  if (err) {
    LOG_ERR("MQTT: failed to resolve %s: %d", pigeon_mqtt_host, err);
    return -EHOSTUNREACH;
  }

  pigeon_mqtt_addr_count = 0;

  for (struct zsock_addrinfo *res = addr_list;
       res && pigeon_mqtt_addr_count < PIGEON_MQTT_MAX_ADDRS; res = res->ai_next) {
    if (res->ai_addrlen <= sizeof(pigeon_mqtt_addrs[0])) {
      memcpy(&pigeon_mqtt_addrs[pigeon_mqtt_addr_count], res->ai_addr, res->ai_addrlen);
      pigeon_mqtt_addr_count++;
    }
  }

  zsock_freeaddrinfo(addr_list);

  return pigeon_mqtt_addr_count ? 0 : -EHOSTUNREACH;
}

/* Builds the client and completes the handshake: TLS, CONNECT, CONNACK,
 * SUBSCRIBE, SUBACK. On return 0 the session is live and the retained
 * target shadow is on its way. */
static int pigeon_mqtt_connect_once(void) {
  int err = pigeon_mqtt_parse_endpoint();

  if (err) {
    return err;
  }

  err = pigeon_mqtt_register_psk();
  if (err) {
    return err;
  }

  err = pigeon_mqtt_resolve_broker();
  if (err) {
    return err;
  }

  const char *device_id = pigeon_active_device_id();

  if (!device_id || !*device_id) {
    LOG_ERR("pigeon_config.device_id is the MQTT client id and username, and must be the pigeon id"
    );
    return -EINVAL;
  }

  k_mutex_lock(&pigeon_mqtt_tx_lock, K_FOREVER);

  mqtt_client_init(&pigeon_mqtt_client);

  static struct mqtt_utf8 user_name;
  static struct mqtt_utf8 password;

  user_name.utf8 = (const uint8_t *)device_id;
  user_name.size = strlen(device_id);

  pigeon_mqtt_client.broker = &pigeon_mqtt_addrs[0];
  pigeon_mqtt_client.evt_cb = pigeon_mqtt_evt_handler;
  pigeon_mqtt_client.client_id.utf8 = (const uint8_t *)device_id;
  pigeon_mqtt_client.client_id.size = strlen(device_id);
  pigeon_mqtt_client.user_name = &user_name;
  pigeon_mqtt_client.rx_buf = pigeon_mqtt_rx_buf;
  pigeon_mqtt_client.rx_buf_size = sizeof(pigeon_mqtt_rx_buf);
  pigeon_mqtt_client.tx_buf = pigeon_mqtt_tx_buf;
  pigeon_mqtt_client.tx_buf_size = sizeof(pigeon_mqtt_tx_buf);
  pigeon_mqtt_client.transport.type = MQTT_TRANSPORT_SECURE;

#if defined(CONFIG_PIGEON_MQTT_AUTH_CERT)
  /* The bearer token is the CONNECT password. On a PSK session it is not
   * sent at all: the broker resolves this pigeon's token server-side from
   * the handshake identity, so there is nothing to put here. */
  password.utf8 = (const uint8_t *)CONFIG_PIGEON_TOKEN;
  password.size = strlen(CONFIG_PIGEON_TOKEN);
  pigeon_mqtt_client.password = &password;
#else
  (void)password;
#endif

  static sec_tag_t sec_tag_list[] = {CONFIG_PIGEON_MQTT_SEC_TAG};
  struct mqtt_sec_config *tls = &pigeon_mqtt_client.transport.tls.config;

  tls->sec_tag_list = sec_tag_list;
  tls->sec_tag_count = ARRAY_SIZE(sec_tag_list);
#if defined(CONFIG_PIGEON_MQTT_AUTH_CERT)
  /* Required, and the hostname with it: a broker reached by a name its
   * certificate does not carry is refused rather than trusted, which is
   * the property worth keeping in a development loop too. */
  tls->peer_verify = TLS_PEER_VERIFY_REQUIRED;
  tls->hostname = pigeon_mqtt_host;
#else
  /* A PSK session authenticates both ends by the key itself; there is no
   * certificate to verify and no name to check it against. */
  tls->peer_verify = TLS_PEER_VERIFY_NONE;
#endif

  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
  pigeon_mqtt.connack_seen = false;
  pigeon_mqtt.connack_code = 0;
  pigeon_mqtt.suback_seen = false;
  pigeon_mqtt.suback_failed = false;
  k_mutex_unlock(&pigeon_mqtt_lock);

  /* The TLS handshake inside mqtt_connect() is the one point this module
   * competes with another transport for a modem's single in-flight
   * handshake, so the shared transport lock covers exactly it. Bounded
   * rather than K_FOREVER: this worker owns a backoff schedule, so failing
   * to acquire is best reported as a failed connect. */
  err = pigeon_transport_lock(K_MSEC(PIGEON_MQTT_ACK_TIMEOUT_MS));

  if (err) {
    k_mutex_unlock(&pigeon_mqtt_tx_lock);
    return err;
  }

  for (uint8_t i = 0; i < pigeon_mqtt_addr_count; i++) {
    pigeon_mqtt_client.broker = &pigeon_mqtt_addrs[i];
    err = mqtt_connect(&pigeon_mqtt_client);

    if (!err) {
      break;
    }

    LOG_WRN(
        "MQTT connect to %s:%u failed on candidate address %u/%u: %d", pigeon_mqtt_host,
        pigeon_mqtt_port, i + 1, pigeon_mqtt_addr_count, err
    );
  }

  pigeon_transport_unlock();

  if (err) {
    LOG_ERR(
        "MQTT connect to %s:%u failed on every resolved address: %d", pigeon_mqtt_host,
        pigeon_mqtt_port, err
    );
    k_mutex_unlock(&pigeon_mqtt_tx_lock);
    return err;
  }

  struct zsock_timeval sndtimeo = {
      .tv_sec = PIGEON_MQTT_SEND_TIMEOUT_MS / 1000,
      .tv_usec = (PIGEON_MQTT_SEND_TIMEOUT_MS % 1000) * 1000,
  };

  if (zsock_setsockopt(
          pigeon_mqtt_client.transport.tls.sock, SOL_SOCKET, SO_SNDTIMEO, &sndtimeo,
          sizeof(sndtimeo)
      ) < 0) {
    LOG_WRN("MQTT: failed to set SO_SNDTIMEO: %d (sends may block unbounded)", -errno);
  }

  k_mutex_unlock(&pigeon_mqtt_tx_lock);

  int64_t deadline = k_uptime_get() + PIGEON_MQTT_ACK_TIMEOUT_MS;

  err = pigeon_mqtt_wait_for(&pigeon_mqtt.connack_seen, deadline);
  if (err) {
    LOG_ERR("MQTT CONNACK never arrived: %d", err);
    return err;
  }

  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
  uint8_t code = pigeon_mqtt.connack_code;
  k_mutex_unlock(&pigeon_mqtt_lock);

  if (code != 0) {
    /* The broker's refusals are specific on purpose (bad credentials
     * apart from a busy platform apart from a paused account), so name the
     * code rather than only that something failed. */
    LOG_ERR("MQTT CONNECT refused: reason 0x%02x", code);
    return -EACCES;
  }

  struct mqtt_topic filter = {
      .topic = {
          .utf8 = (const uint8_t *)PIGEON_MQTT_TOPIC_SHADOW_TARGET,
          .size = strlen(PIGEON_MQTT_TOPIC_SHADOW_TARGET),
      },
      /* QoS 1 so a config push cannot be lost to a dropped packet the way
       * QoS 0 allows; the broker grants at most this. */
      .qos = MQTT_QOS_1_AT_LEAST_ONCE,
  };
  struct mqtt_subscription_list sub = {
      .list = &filter,
      .list_count = 1,
      .message_id = 1,
  };

  err = mqtt_subscribe(&pigeon_mqtt_client, &sub);
  if (err) {
    LOG_ERR("MQTT subscribe failed: %d", err);
    return err;
  }

  err = pigeon_mqtt_wait_for(&pigeon_mqtt.suback_seen, k_uptime_get() + PIGEON_MQTT_ACK_TIMEOUT_MS);
  if (err) {
    LOG_ERR("MQTT SUBACK never arrived: %d", err);
    return err;
  }

  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
  bool refused = pigeon_mqtt.suback_failed;
  k_mutex_unlock(&pigeon_mqtt_lock);

  if (refused) {
    LOG_ERR(
        "MQTT: the broker refused the " PIGEON_MQTT_TOPIC_SHADOW_TARGET
        " subscription -- this build's topics and the broker's disagree"
    );
    return -EPROTO;
  }

  return 0;
}

static void pigeon_mqtt_teardown(bool graceful) {
  k_mutex_lock(&pigeon_mqtt_tx_lock, K_FOREVER);

  if (graceful) {
    /* A real DISCONNECT: an ungraceful drop is what tells the broker to
     * publish this session's will, and this device is leaving on purpose. */
    (void)mqtt_disconnect(&pigeon_mqtt_client, NULL);
  } else {
    (void)mqtt_abort(&pigeon_mqtt_client);
  }

  k_mutex_unlock(&pigeon_mqtt_tx_lock);

  pigeon_event_cb_t cb;
  bool was_up;

  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
  was_up = pigeon_mqtt.session_up;
  pigeon_mqtt.session_up = false;
  cb = pigeon_mqtt.cb;

  /* Whether anything was still owed a PUBACK is what separates an ordinary
   * reconnect from the fuse's 3.1.1 signature (see
   * pigeon_mqtt_close_is_persistent()). */
  if (pigeon_mqtt_pending_any_awaiting(&pigeon_mqtt_pending)) {
    pigeon_mqtt.unacked_closes++;
  } else {
    pigeon_mqtt.unacked_closes = 0;
  }

  pigeon_mqtt_pending_session_lost(&pigeon_mqtt_pending);
  k_mutex_unlock(&pigeon_mqtt_lock);

  pigeon_mqtt_wake_waiters();

  if (was_up && cb) {
    cb(PIGEON_EVENT_DISCONNECTED, NULL);
  }
}

/* Slept in <=1s slices so a stop is honored promptly rather than after the
 * full backoff. */
static void pigeon_mqtt_sleep_backoff(uint32_t delay_sec) {
  int64_t deadline = k_uptime_get() + (int64_t)delay_sec * MSEC_PER_SEC;

  while (k_uptime_get() < deadline) {
    k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
    bool stop = pigeon_mqtt.stop_requested;
    k_mutex_unlock(&pigeon_mqtt_lock);

    if (stop) {
      return;
    }

    k_sleep(K_MSEC(MIN(1000, deadline - k_uptime_get())));
  }
}

/* Turns a failed or ended session into the delay before the next attempt.
 * Two schedules, not one: the ordinary exponential one, and the long wait
 * for a refusal nothing on this device can fix. */
static uint32_t pigeon_mqtt_backoff_after(enum pigeon_mqtt_retry retry) {
  uint32_t base;

  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
  if (retry == PIGEON_MQTT_RETRY_LATER ||
      pigeon_mqtt_close_is_persistent(pigeon_mqtt.unacked_closes)) {
    base = CONFIG_PIGEON_MQTT_AUTH_BACKOFF_SEC;
  } else {
    base = pigeon_mqtt.backoff_base_sec;
    pigeon_mqtt.backoff_base_sec = pigeon_mqtt_backoff_next(
        base, (uint32_t)CONFIG_PIGEON_MQTT_RECONNECT_MAX_DELAY_SEC
    );
  }
  k_mutex_unlock(&pigeon_mqtt_lock);

  return pigeon_mqtt_backoff_jitter(base);
}

static void pigeon_mqtt_thread_fn(void *p1, void *p2, void *p3) {
  ARG_UNUSED(p1);
  ARG_UNUSED(p2);
  ARG_UNUSED(p3);

  while (true) {
    k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
    bool stop = pigeon_mqtt.stop_requested;
    k_mutex_unlock(&pigeon_mqtt_lock);

    if (stop) {
      break;
    }

    int err = pigeon_mqtt_connect_once();

    if (err) {
      /* An -EACCES here is the broker naming the credentials; anything
       * else is a link or a broker that may well be fine next time. */
      enum pigeon_mqtt_retry retry = PIGEON_MQTT_RETRY_SOON;

      if (err == -EACCES) {
        k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
        retry = pigeon_mqtt_connack_retry(pigeon_mqtt.connack_code);
        k_mutex_unlock(&pigeon_mqtt_lock);
      } else if (err == -EPROTO || err == -EINVAL) {
        retry = PIGEON_MQTT_RETRY_LATER;
      }

      pigeon_mqtt_teardown(false);

      uint32_t delay = pigeon_mqtt_backoff_after(retry);

      LOG_WRN("MQTT connect failed (%d), retrying in %us", err, delay);
      pigeon_mqtt_sleep_backoff(delay);
      continue;
    }

    pigeon_event_cb_t cb;

    k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
    pigeon_mqtt.session_up = true;
    pigeon_mqtt.backoff_base_sec = PIGEON_MQTT_BACKOFF_BASE_SEC;
    cb = pigeon_mqtt.cb;
    k_mutex_unlock(&pigeon_mqtt_lock);

    LOG_INF("MQTT session up: %s:%u", pigeon_mqtt_host, pigeon_mqtt_port);

    /* Publishers waiting for a session -- including any redelivery held
     * over from the connection that just died -- go now. */
    pigeon_mqtt_wake_waiters();

    if (cb) {
      cb(PIGEON_EVENT_CONNECTED, NULL);
    }

    while (true) {
      k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
      bool stop_now = pigeon_mqtt.stop_requested;
      bool up = pigeon_mqtt.session_up;
      k_mutex_unlock(&pigeon_mqtt_lock);

      if (stop_now || !up) {
        break;
      }

      int32_t keepalive_ms = mqtt_keepalive_time_left(&pigeon_mqtt_client);
      int32_t timeout = (int32_t)MIN((int64_t)keepalive_ms, (int64_t)PIGEON_MQTT_POLL_MAX_MS);

      err = pigeon_mqtt_service(MAX(timeout, 0));
      if (err) {
        LOG_WRN("MQTT session ended: %d", err);
        break;
      }
    }

    k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
    bool stopping = pigeon_mqtt.stop_requested;
    k_mutex_unlock(&pigeon_mqtt_lock);

    pigeon_mqtt_teardown(stopping);

    if (stopping) {
      break;
    }

    uint32_t delay = pigeon_mqtt_backoff_after(PIGEON_MQTT_RETRY_SOON);

    pigeon_mqtt_sleep_backoff(delay);
  }

  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
  pigeon_mqtt.running = false;
  k_mutex_unlock(&pigeon_mqtt_lock);
}

/*
 * Publishes one report and, for QoS 1, waits for the acknowledgement that
 * says the platform took it -- republishing with the duplicate flag if the
 * session dies first, until CONFIG_PIGEON_MQTT_PUBLISH_TIMEOUT_SEC. The
 * whole call is bounded by that deadline, not each attempt, so a caller's
 * error handling sees one outcome rather than a retry loop of its own.
 */
static int pigeon_mqtt_publish_report(
    enum pigeon_mqtt_leaf leaf, const uint8_t *payload, size_t len, enum mqtt_qos qos
) {
  const char *topic = pigeon_mqtt_publish_topic(leaf);

  if (!topic) {
    return -EINVAL;
  }

  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
  bool running = pigeon_mqtt.running;
  int slot = running ? pigeon_mqtt_pending_claim(&pigeon_mqtt_pending) : -ENOTCONN;
  k_mutex_unlock(&pigeon_mqtt_lock);

  if (!running) {
    LOG_ERR("MQTT session not started -- call pigeon_mqtt_start() after the link is up");
    return -ENOTCONN;
  }

  if (slot < 0) {
    /* Every slot owned: the device is publishing faster than the link
     * carries. Callers keep their data and try again rather than queueing
     * here, so nothing is lost by refusing. */
    return -EBUSY;
  }

  k_sem_reset(&pigeon_mqtt_slot_sem[slot]);

  int64_t deadline = k_uptime_get() + (int64_t)CONFIG_PIGEON_MQTT_PUBLISH_TIMEOUT_SEC * MSEC_PER_SEC;
  int err = -ETIMEDOUT;

  while (k_uptime_get() < deadline) {
    bool up;
    bool dup;

    k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
    up = pigeon_mqtt.session_up;
    dup = pigeon_mqtt_pending.slots[slot].dup;
    k_mutex_unlock(&pigeon_mqtt_lock);

    if (!up) {
      /* Waiting for the worker to bring a session back. */
      int64_t remaining = deadline - k_uptime_get();

      if (remaining <= 0) {
        break;
      }

      k_sem_take(&pigeon_mqtt_slot_sem[slot], K_MSEC(MIN(remaining, PIGEON_MQTT_POLL_MAX_MS)));
      continue;
    }

    struct mqtt_publish_param param = {
        .message =
            {
                .topic =
                    {
                        .topic = {.utf8 = (const uint8_t *)topic, .size = strlen(topic)},
                        .qos = qos,
                    },
                .payload = {.data = (uint8_t *)payload, .len = len},
            },
        .dup_flag = dup ? 1 : 0,
        .retain_flag = 0,
    };

    if (qos == MQTT_QOS_1_AT_LEAST_ONCE) {
      k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
      param.message_id = pigeon_mqtt_pending_arm(&pigeon_mqtt_pending, slot);
      k_mutex_unlock(&pigeon_mqtt_lock);
      k_sem_reset(&pigeon_mqtt_slot_sem[slot]);
    }

    k_mutex_lock(&pigeon_mqtt_tx_lock, K_FOREVER);
    err = mqtt_publish(&pigeon_mqtt_client, &param);
    k_mutex_unlock(&pigeon_mqtt_tx_lock);

    if (err) {
      LOG_WRN("MQTT publish to %s failed: %d", topic, err);

      k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
      pigeon_mqtt_pending.slots[slot].awaiting_ack = false;
      pigeon_mqtt_pending.slots[slot].dup = true;
      k_mutex_unlock(&pigeon_mqtt_lock);

      /* A send that failed on a live session is this attempt's problem;
       * one that failed because the session went away is the worker's, and
       * waiting for the reconnect is the redelivery. */
      k_sem_take(&pigeon_mqtt_slot_sem[slot], K_MSEC(PIGEON_MQTT_POLL_MAX_MS));
      continue;
    }

    if (qos == MQTT_QOS_0_AT_MOST_ONCE) {
      /* Fire and forget, by the caller's own choice: the report rode the
       * broker's held device socket and nothing answers it. */
      err = 0;
      break;
    }

    bool acked = false;
    bool lost = false;

    while (k_uptime_get() < deadline) {
      int64_t remaining = deadline - k_uptime_get();

      k_sem_take(&pigeon_mqtt_slot_sem[slot], K_MSEC(MIN(remaining, PIGEON_MQTT_POLL_MAX_MS)));

      k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
      acked = pigeon_mqtt_pending.slots[slot].acked;
      lost = pigeon_mqtt_pending.slots[slot].lost;
      k_mutex_unlock(&pigeon_mqtt_lock);

      if (acked || lost) {
        break;
      }
    }

    if (acked) {
      err = 0;
      break;
    }

    if (lost) {
      /* The session died with this publish in flight. The next pass
       * republishes it with the duplicate flag the table just set. */
      LOG_WRN("MQTT publish to %s interrupted -- redelivering", topic);
      err = -ECONNRESET;
      continue;
    }

    err = -ETIMEDOUT;
    break;
  }

  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
  pigeon_mqtt_pending_release(&pigeon_mqtt_pending, slot);
  k_mutex_unlock(&pigeon_mqtt_lock);

  if (err) {
    LOG_ERR("MQTT publish to %s gave up after %ds: %d", topic, CONFIG_PIGEON_MQTT_PUBLISH_TIMEOUT_SEC, err);
  }

  return err;
}

int pigeon_shadow_get(struct pigeon_shadow_doc *out) {
  if (!out) {
    return -EINVAL;
  }

  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
  bool have = pigeon_mqtt.have_shadow;
  bool running = pigeon_mqtt.running;
  k_mutex_unlock(&pigeon_mqtt_lock);

  if (!running) {
    LOG_ERR("MQTT session not started -- call pigeon_mqtt_start() after the link is up");
    return -ENOTCONN;
  }

  if (!have) {
    /* Nothing has been pushed yet: this is the first call after a connect,
     * so wait for the retained target rather than answering with an empty
     * shadow the app would apply. */
    if (k_sem_take(&pigeon_mqtt_shadow_sem, K_SECONDS(CONFIG_PIGEON_MQTT_SHADOW_WAIT_SEC))) {
      LOG_WRN("No retained target shadow within %ds", CONFIG_PIGEON_MQTT_SHADOW_WAIT_SEC);
      return -EAGAIN;
    }
  }

  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
  out->target_version = pigeon_mqtt_shadow.target_version;
  out->current_version = pigeon_mqtt_shadow.current_version;
  out->target_config = pigeon_mqtt_shadow.target_config;
  out->current_config = pigeon_mqtt_shadow.current_config;
  out->updated_at = pigeon_mqtt_shadow.updated_at;
  k_mutex_unlock(&pigeon_mqtt_lock);

  return 0;
}

int pigeon_shadow_report(int32_t current_version, const char *current_config) {
  if (!current_config) {
    return -EINVAL;
  }

  /* current_config is embedded verbatim as a raw JSON object -- not a
   * string value, so it must not be quote-escaped, only trusted to already
   * be valid JSON (the caller's responsibility, see pigeon_shadow_doc's
   * docs). The margin covers the fixed framing plus an 11-char int32, the
   * same arithmetic pigeon_https.c uses. */
  static char body[PIGEON_HTTPS_CONFIG_MAX + 64];

  int len = snprintk(
      body, sizeof(body), "{\"current_config\":%s,\"current_version\":%d}", current_config,
      current_version
  );

  if (len < 0 || (size_t)len >= sizeof(body)) {
    LOG_ERR("Shadow report body does not fit (see CONFIG_PIGEON_SHADOW_CONFIG_MAX)");
    return -EMSGSIZE;
  }

  /* Always QoS 1: the acknowledgement is the only evidence the platform
   * recorded the convergence, which is the whole point of reporting it. */
  int err = pigeon_mqtt_publish_report(
      PIGEON_MQTT_LEAF_SHADOW_REPORT, (const uint8_t *)body, (size_t)len,
      MQTT_QOS_1_AT_LEAST_ONCE
  );

  if (err) {
    return err;
  }

  /*
   * Fold the acknowledged report into the cached shadow, which the other
   * connectors get for free and this one does not: there, the next
   * pigeon_shadow_get() re-fetches and sees its own report reflected back.
   * Here the cached value only refreshes when the broker re-publishes the
   * retained target, and the broker deliberately re-publishes ONLY when
   * target_version changes -- a device's own report-back must not read as a
   * fresh config to it. Without this, an application comparing
   * target_version against current_version would re-apply and re-report the
   * same target on every pass until something else moved.
   *
   * Safe to treat as authoritative precisely because the publish was
   * acknowledged: the platform has taken exactly these bytes.
   */
  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
  pigeon_mqtt_shadow.current_version = current_version;
  strncpy(
      pigeon_mqtt_shadow.current_config, current_config,
      sizeof(pigeon_mqtt_shadow.current_config) - 1
  );
  pigeon_mqtt_shadow.current_config[sizeof(pigeon_mqtt_shadow.current_config) - 1] = '\0';
  k_mutex_unlock(&pigeon_mqtt_lock);

  return 0;
}

int pigeon_transport_report_telemetry(
    const char *body, size_t body_len, struct pigeon_http_result *res
) {
  if (res) {
    /* MQTT reason codes are not HTTP statuses, and nothing on this
     * transport consumes them yet -- zeroed for the same reason the CoAP
     * connector zeroes it. */
    *res = (struct pigeon_http_result){0};
  }

  enum mqtt_qos qos = IS_ENABLED(CONFIG_PIGEON_MQTT_TELEMETRY_QOS1)
                          ? MQTT_QOS_1_AT_LEAST_ONCE
                          : MQTT_QOS_0_AT_MOST_ONCE;

  return pigeon_mqtt_publish_report(
      PIGEON_MQTT_LEAF_TELEMETRY, (const uint8_t *)body, body_len, qos
  );
}

int pigeon_transport_upload_logs(const uint8_t *data, size_t len) {
  while (len) {
    size_t chunk = MIN(len, (size_t)PIGEON_MQTT_LOG_CHUNK_MAX);
    int err = pigeon_mqtt_publish_report(
        PIGEON_MQTT_LEAF_LOGS, data, chunk, MQTT_QOS_1_AT_LEAST_ONCE
    );

    if (err) {
      return err;
    }

    data += chunk;
    len -= chunk;
  }

  return 0;
}

int pigeon_mqtt_start(pigeon_event_cb_t cb) {
  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);

  if (pigeon_mqtt.running) {
    k_mutex_unlock(&pigeon_mqtt_lock);
    return -EALREADY;
  }

  for (int i = 0; i < CONFIG_PIGEON_MQTT_MAX_INFLIGHT; i++) {
    k_sem_init(&pigeon_mqtt_slot_sem[i], 0, 1);
  }

  pigeon_mqtt_pending_init(
      &pigeon_mqtt_pending, pigeon_mqtt_slots, CONFIG_PIGEON_MQTT_MAX_INFLIGHT
  );

  pigeon_mqtt.cb = cb;
  pigeon_mqtt.stop_requested = false;
  pigeon_mqtt.session_up = false;
  pigeon_mqtt.have_shadow = false;
  pigeon_mqtt.unacked_closes = 0;
  pigeon_mqtt.backoff_base_sec = PIGEON_MQTT_BACKOFF_BASE_SEC;
  pigeon_mqtt.running = true;
  k_mutex_unlock(&pigeon_mqtt_lock);

  k_tid_t tid = k_thread_create(
      &pigeon_mqtt_thread_data, pigeon_mqtt_stack, K_THREAD_STACK_SIZEOF(pigeon_mqtt_stack),
      pigeon_mqtt_thread_fn, NULL, NULL, NULL, PIGEON_MQTT_THREAD_PRIORITY, 0, K_NO_WAIT
  );

  if (!tid) {
    k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
    pigeon_mqtt.running = false;
    k_mutex_unlock(&pigeon_mqtt_lock);
    return -EAGAIN;
  }

  k_thread_name_set(tid, "pigeon_mqtt");

  return 0;
}

int pigeon_mqtt_stop(void) {
  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
  bool running = pigeon_mqtt.running;

  pigeon_mqtt.stop_requested = true;
  k_mutex_unlock(&pigeon_mqtt_lock);

  if (!running) {
    return 0;
  }

  /* Publishers blocked on a deadline get to give up now rather than
   * holding the join for their full timeout. */
  pigeon_mqtt_wake_waiters();

  int err = k_thread_join(&pigeon_mqtt_thread_data, K_SECONDS(30));

  if (err) {
    LOG_WRN("MQTT worker did not exit within 30s: %d", err);
  }

  return err;
}

bool pigeon_mqtt_connected(void) {
  k_mutex_lock(&pigeon_mqtt_lock, K_FOREVER);
  bool up = pigeon_mqtt.session_up;
  k_mutex_unlock(&pigeon_mqtt_lock);

  return up;
}
