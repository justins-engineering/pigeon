/*
 * Persistent WebSocket push channel: GET <CONFIG_PIGEON_ENDPOINT>/ws (dovecote
 * task #32). Deliberately NOT a transport module like pigeon_https.c/
 * pigeon_coap.c -- it defines none of pigeon_shadow_get/pigeon_shadow_report/
 * pigeon_transport_*. It owns a persistent connection (the transports open
 * one socket per request and close it), a dedicated worker thread (the
 * transports run entirely on the caller's thread), and pushes events into
 * the app (the transport API is strictly pull). See pigeon.h for the public
 * pigeon_ws_start()/pigeon_ws_stop()/pigeon_ws_connected() contract and
 * pigeon_internal.h for pigeon_ws_report_telemetry() (pigeon_core.c's
 * pigeon_shadow_flush() fallback wiring).
 *
 * Frame budget vs. the server's 50-frames/10s fixed-window limit
 * (dovecote's objects/ws.rs): one ping every CONFIG_PIGEON_WS_PING_INTERVAL_SEC
 * (default 60s) + one telemetry report per shadow flush (app-driven, default
 * also ~60s) + occasional protocol pongs is on the order of 2-3 frames/min --
 * three orders of magnitude under the limit, no client-side throttle needed.
 */
#include <errno.h>
#include <pigeon.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <zephyr/data/json.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/net/websocket.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/printk.h>

#include "pigeon_internal.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

#define PIGEON_WS_HOST_MAX 128
#define PIGEON_WS_PATH_MAX 128
#define PIGEON_WS_AUTH_HEADER_MAX 384
#define PIGEON_WS_TYPE_MAX 16
#define PIGEON_WS_SEND_TIMEOUT_MS 10000
#define PIGEON_WS_CONNECT_TIMEOUT_MS 10000

/*
 * Upper bound on each zsock_poll() call in the worker's inner loop, even
 * when the next ping is much further away than this. pigeon_ws.stop_requested/
 * force_reconnect are only re-checked at the top of that loop, i.e. once
 * per poll call -- an in-progress poll cannot itself be woken by a flag
 * set from another thread (no k_event/self-pipe backing it), so without
 * this cap, a flag set moments after the loop entered a fresh ~60s
 * (CONFIG_PIGEON_WS_PING_INTERVAL_SEC) poll would sit unobserved for
 * nearly that whole window. A 1s cap bounds that staleness cheaply on a
 * WiFi/mains-powered target (this Kconfig's use case) at negligible extra
 * CPU cost, without the complexity of a real wakeup primitive.
 */
#define PIGEON_WS_POLL_MAX_MS 1000

/* Reconnect backoff: exponential from this base, doubling, capped at
 * CONFIG_PIGEON_WS_RECONNECT_MAX_DELAY_SEC, +-25% jitter. Reset to this base
 * once a connection survives its first app-level pong (see pigeon_ws_thread_fn).
 * No close-code-specific policy (e.g. a slow start on a 4009 "replaced by
 * another connection" close) -- see pigeon_ws_next_backoff_sec()'s docs on
 * why that turned out not to be safely recoverable from the vendored
 * websocket_recv_msg() API and was dropped in favor of uniform backoff. */
#define PIGEON_WS_BACKOFF_BASE_SEC 1

/* Two consecutive missed app-level pongs mark the connection half-open. */
#define PIGEON_WS_MAX_MISSED_PONGS 2

enum pigeon_ws_state {
  PIGEON_WS_STATE_DISCONNECTED,
  PIGEON_WS_STATE_CONNECTING,
  PIGEON_WS_STATE_UP,
};

/*
 * Single instance: this library supports exactly one pigeon/one WS
 * connection per device (matches pigeon_core.c's single-instance model
 * elsewhere). Guarded by pigeon_ws_lock -- brief, non-blocking struct
 * reads/writes only. The actual network write (websocket_send_msg(),
 * reachable from both the worker thread's pings and the app thread's
 * pigeon_ws_report_telemetry() via pigeon_shadow_flush()) is serialized by
 * a separate lock, pigeon_ws_tx_lock, defined just below -- see its own
 * comment for why the two are split rather than one lock covering both.
 */
static struct {
  bool running;         /* worker thread spawned, not yet joined */
  bool stop_requested;  /* pigeon_ws_stop() asked the worker to exit */
  bool force_reconnect;  /* a TX-path send failure wants the worker to
                          * reconnect sooner than its next poll timeout */
  enum pigeon_ws_state state;
  int real_sock; /* underlying TLS socket, -1 when not connected */
  int ws_sock;   /* websocket_connect()'s virtual fd, -1 when not connected */
  pigeon_ws_event_cb_t cb;
  uint32_t reconnect_delay_sec;
  int64_t next_ping_uptime_ms;
  int missed_pongs;
  bool pong_seen_this_connection;
} pigeon_ws = {
    .real_sock = -1,
    .ws_sock = -1,
};

K_MUTEX_DEFINE(pigeon_ws_lock);

/*
 * Dedicated lock for the actual network write (websocket_send_msg()) --
 * deliberately separate from pigeon_ws_lock above. An earlier revision of
 * this file held pigeon_ws_lock itself across the blocking send, which
 * meant every state read (pigeon_ws_connected(), pigeon_ws_stop(), the
 * worker's own loop) queued up behind a single slow network write (up to
 * PIGEON_WS_SEND_TIMEOUT_MS). Splitting the locks means pigeon_ws_lock is
 * now only ever held for brief, non-blocking struct reads/writes, and
 * pigeon_ws_tx_lock serializes concurrent senders (the worker's pings and
 * protocol-level pong-echoes vs. the app thread's pigeon_ws_report_telemetry())
 * without blocking anything else.
 *
 * This reopens a narrower hazard the two-lock split would otherwise cause:
 * with the send no longer covered by pigeon_ws_lock, a concurrent
 * pigeon_ws_stop()/pigeon_ws_teardown() could zsock_close() a live fd out
 * from under an in-progress websocket_send_msg() on that same fd. Fixed by
 * having pigeon_ws_stop()/pigeon_ws_teardown() also take pigeon_ws_tx_lock
 * around their actual close calls (never nested with pigeon_ws_lock --
 * each function always fully releases one lock before acquiring the
 * other, so there is no lock-ordering/deadlock hazard), so a close always
 * waits for any in-flight send to finish first. That wait is now bounded
 * (see pigeon_ws_open_tls_socket()'s SO_SNDTIMEO) rather than the
 * previously-unbounded K_FOREVER default.
 */
K_MUTEX_DEFINE(pigeon_ws_tx_lock);

K_THREAD_STACK_DEFINE(pigeon_ws_stack, CONFIG_PIGEON_WS_THREAD_STACK_SIZE);
static struct k_thread pigeon_ws_thread_data;

/* Priority is a plain preemptible priority below (numerically above) the
 * app's own main-thread work (shadow_loop() etc.) -- this worker should
 * never starve application logic just to ping/poll a socket. */
#define PIGEON_WS_THREAD_PRIORITY 10

/* Parsed once (lazily) from CONFIG_PIGEON_ENDPOINT, same split as
 * pigeon_https.c's pigeon_https_parse_endpoint() -- duplicated locally
 * rather than shared, since pigeon_ws.c is deliberately not a transport
 * module and pigeon_https.c doesn't export its statics (see file header). */
static char pigeon_ws_host[PIGEON_WS_HOST_MAX];
static char pigeon_ws_path[PIGEON_WS_PATH_MAX];
static bool pigeon_ws_endpoint_parsed;

/* websocket_request.tmp_buf: HTTP upgrade response + frame parse scratch,
 * must stay valid for the whole connection (Zephyr reuses it as ctx->recv_buf
 * internally -- confirmed in zephyr/subsys/net/lib/websocket/websocket.c,
 * not just inferred from the header doc), hence static, never stack. */
static uint8_t pigeon_ws_scratch[CONFIG_PIGEON_WS_RX_BUF_SIZE];

/* Buffer we read decoded message payloads into via websocket_recv_msg().
 * Distinct from pigeon_ws_scratch above (that one is the library's own
 * internal parse buffer; this one is ours). */
static uint8_t pigeon_ws_rx_buf[CONFIG_PIGEON_WS_RX_BUF_SIZE];

/*
 * Wire shape of an inbound shadow_update frame's "shadow" object (mirrors
 * capsules::PigeonShadow, same fields/order as pigeon_https.c's
 * pigeon_shadow_wire -- see PIGEON_HTTPS_CONFIG_MAX in pigeon_internal.h for
 * why the config caps are shared). JSON_TOK_STRING_BUF (not JSON_TOK_STRING)
 * for the two configs: they're JSON-in-a-JSON-string on the wire and must be
 * unescaped in place, same lesson as pigeon_https.c's commit f076a7e.
 */
struct pigeon_ws_shadow_wire {
  int32_t target_version;
  int32_t current_version;
  char target_config[PIGEON_HTTPS_CONFIG_MAX];
  char current_config[PIGEON_HTTPS_CONFIG_MAX];
  int64_t updated_at;
};

/*
 * Wire shape of any inbound frame (dovecote/src/objects/ws.rs: only "pong"
 * and "shadow_update" are ever sent; "shadow" is present only on the latter,
 * see pigeon_ws_dispatch_frame()'s note on why the outer decode bitmask
 * alone can't guarantee every "shadow" sub-field decoded).
 */
struct pigeon_ws_frame_wire {
  char type[PIGEON_WS_TYPE_MAX];
  struct pigeon_ws_shadow_wire shadow;
};

static struct pigeon_ws_frame_wire pigeon_ws_frame;

static const struct json_obj_descr pigeon_ws_shadow_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct pigeon_ws_shadow_wire, target_version, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct pigeon_ws_shadow_wire, current_version, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct pigeon_ws_shadow_wire, target_config, JSON_TOK_STRING_BUF),
    JSON_OBJ_DESCR_PRIM(struct pigeon_ws_shadow_wire, current_config, JSON_TOK_STRING_BUF),
    JSON_OBJ_DESCR_PRIM(struct pigeon_ws_shadow_wire, updated_at, JSON_TOK_INT64),
};

static const struct json_obj_descr pigeon_ws_frame_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct pigeon_ws_frame_wire, type, JSON_TOK_STRING_BUF),
    JSON_OBJ_DESCR_OBJECT(struct pigeon_ws_frame_wire, shadow, pigeon_ws_shadow_descr),
};

/* Bit position of each pigeon_ws_frame_descr entry in json_obj_parse()'s
 * returned bitmask (see pigeon_ws_dispatch_frame()). */
#define PIGEON_WS_FIELD_TYPE   BIT(0)
#define PIGEON_WS_FIELD_SHADOW BIT(1)

#if defined(CONFIG_PIGEON_SHELL)
#define PIGEON_WS_SHELL_REQUEST_ID_MAX 64
#define PIGEON_WS_SHELL_CMD_MAX        128

/*
 * Wire shape of an inbound shell_cmd frame's request_id/cmd (task #34).
 * Deliberately a separate struct/descriptor from pigeon_ws_frame_wire/
 * pigeon_ws_frame_descr above rather than folding these two fields into
 * that generic struct -- that one stays "type + whichever domain object
 * the type implies" (shadow_update's "shadow"), decoded with its own
 * second, targeted json_obj_parse() pass once pigeon_ws_dispatch_frame()
 * already knows type == "shell_cmd" from the first pass. Two passes over
 * the same buf/len is safe: JSON_TOK_STRING_BUF unescapes in place, but a
 * shell_cmd frame has no "shadow" object for the first pass to have
 * touched, and re-tokenizing "type" itself a second time is idempotent
 * (a bare constant like "shell_cmd" has nothing left to unescape).
 */
struct pigeon_ws_shell_cmd_wire {
  char request_id[PIGEON_WS_SHELL_REQUEST_ID_MAX];
  char cmd[PIGEON_WS_SHELL_CMD_MAX];
};

static struct pigeon_ws_shell_cmd_wire pigeon_ws_shell_cmd;

static const struct json_obj_descr pigeon_ws_shell_cmd_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct pigeon_ws_shell_cmd_wire, request_id, JSON_TOK_STRING_BUF),
    JSON_OBJ_DESCR_PRIM(struct pigeon_ws_shell_cmd_wire, cmd, JSON_TOK_STRING_BUF),
};

#define PIGEON_WS_SHELL_FIELD_REQUEST_ID BIT(0)
#define PIGEON_WS_SHELL_FIELD_CMD        BIT(1)
#endif /* CONFIG_PIGEON_SHELL */

/* Splits CONFIG_PIGEON_ENDPOINT ("https://host[:port]/path...") into
 * pigeon_ws_host / pigeon_ws_path once -- byte-for-byte the same algorithm
 * as pigeon_https_parse_endpoint(), see this file's header comment for why
 * it isn't shared directly. */
static int pigeon_ws_parse_endpoint(void) {
  if (pigeon_ws_endpoint_parsed) {
    return 0;
  }

  const char *endpoint = CONFIG_PIGEON_ENDPOINT;
  const char *scheme_end = strstr(endpoint, "://");

  if (!scheme_end) {
    LOG_ERR("CONFIG_PIGEON_ENDPOINT missing scheme: %s", endpoint);
    return -EINVAL;
  }

  const char *host_start = scheme_end + 3;
  const char *path_start = strchr(host_start, '/');
  size_t host_len = path_start ? (size_t)(path_start - host_start) : strlen(host_start);

  if (host_len == 0 || host_len >= sizeof(pigeon_ws_host)) {
    LOG_ERR("CONFIG_PIGEON_ENDPOINT host empty or too long");
    return -EINVAL;
  }

  memcpy(pigeon_ws_host, host_start, host_len);
  pigeon_ws_host[host_len] = '\0';

  if (path_start) {
    if (strlen(path_start) >= sizeof(pigeon_ws_path)) {
      LOG_ERR("CONFIG_PIGEON_ENDPOINT path too long");
      return -EINVAL;
    }
    strcpy(pigeon_ws_path, path_start);
  } else {
    pigeon_ws_path[0] = '\0';
  }

  pigeon_ws_endpoint_parsed = true;

  return 0;
}

/* Opens the TLS transport socket. Byte-for-byte the pattern in
 * pigeon_https.c's pigeon_https_connect(): same sec_tag, same SNI, same
 * IPPROTO_TLS_1_2. Returns the socket fd (>=0) or a negative errno. */
static int pigeon_ws_open_tls_socket(void) {
  struct zsock_addrinfo hints = {
      .ai_family = AF_INET,
      .ai_socktype = SOCK_STREAM,
  };
  struct zsock_addrinfo *res;

  int err = zsock_getaddrinfo(pigeon_ws_host, "443", &hints, &res);

  if (err) {
    LOG_ERR("WS: failed to resolve %s: %d", pigeon_ws_host, err);
    return -EHOSTUNREACH;
  }

  int sock = zsock_socket(res->ai_family, SOCK_STREAM, IPPROTO_TLS_1_2);

  if (sock < 0) {
    LOG_ERR("WS: failed to create TLS socket: %d", -errno);
    zsock_freeaddrinfo(res);
    return -errno;
  }

  sec_tag_t sec_tag_list[] = {CONFIG_PIGEON_HTTPS_SEC_TAG};

  err = zsock_setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_list, sizeof(sec_tag_list));
  if (err) {
    LOG_ERR("WS: failed to set TLS sec_tag %d: %d", CONFIG_PIGEON_HTTPS_SEC_TAG, -errno);
    goto cleanup;
  }

  err = zsock_setsockopt(sock, SOL_TLS, TLS_HOSTNAME, pigeon_ws_host, strlen(pigeon_ws_host));
  if (err) {
    LOG_ERR("WS: failed to set TLS hostname: %d", -errno);
    goto cleanup;
  }

  err = zsock_connect(sock, res->ai_addr, res->ai_addrlen);
  zsock_freeaddrinfo(res);
  if (err) {
    LOG_ERR("WS: failed to connect to %s: %d", pigeon_ws_host, -errno);
    zsock_close(sock);
    return -errno;
  }

  /*
   * Bounds every future blocking send on this socket -- not just our own
   * websocket_send_msg() calls, but Zephyr's *internal* CLOSE-frame echo
   * inside websocket_internal_disconnect() (zephyr/subsys/net/lib/websocket/
   * websocket.c), which unconditionally requests SYS_FOREVER_MS and has no
   * way for a caller to override that per-call. Traced the actual socket
   * layer (zephyr/subsys/net/lib/sockets/sockets_inet.c:zsock_sendmsg_ctx()):
   * the first send attempt inside websocket.c's sendmsg_all() is a plain
   * blocking zsock_sendmsg() with no DONTWAIT flag, and that path ignores
   * whatever k_timeout the *caller* wanted entirely -- it pulls its actual
   * timeout from this socket's own SO_SNDTIMEO option (defaulting to
   * K_FOREVER, i.e. genuinely unbounded, if never set). Only the secondary
   * EAGAIN-retry loop honors a caller-supplied deadline. So this
   * setsockopt is the *only* thing standing between a stalled/half-dead
   * TCP path and an indefinite block in pigeon_ws_stop() (called
   * synchronously from the app thread right before sys_reboot() on the
   * shadow "reboot" path) or in pigeon_ws_send_text()'s own sends.
   * CONFIG_NET_CONTEXT_SNDTIMEO must be enabled for this option to have
   * any effect at all (see zephyr/Kconfig: CONFIG_PIGEON_WS selects it) --
   * silently a no-op otherwise, so failure here is logged but not fatal
   * to the connection (falls back to the pre-existing, less-safe default).
   */
  struct zsock_timeval sndtimeo = {
      .tv_sec = PIGEON_WS_SEND_TIMEOUT_MS / 1000,
      .tv_usec = (PIGEON_WS_SEND_TIMEOUT_MS % 1000) * 1000,
  };

  if (zsock_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &sndtimeo, sizeof(sndtimeo)) < 0) {
    LOG_WRN("WS: failed to set SO_SNDTIMEO: %d (sends may block unbounded)", -errno);
  }

  return sock;

cleanup:
  zsock_freeaddrinfo(res);
  zsock_close(sock);
  return -errno;
}

/* Performs the TLS connect + HTTP Upgrade handshake, storing the resulting
 * fds into pigeon_ws under lock on success. */
static int pigeon_ws_connect_once(void) {
  int err = pigeon_ws_parse_endpoint();

  if (err) {
    return err;
  }

  int sock = pigeon_ws_open_tls_socket();

  if (sock < 0) {
    return sock;
  }

  char url[PIGEON_WS_PATH_MAX + sizeof("/ws")];

  snprintk(url, sizeof(url), "%s/ws", pigeon_ws_path);

  static char auth_header[PIGEON_WS_AUTH_HEADER_MAX];

  snprintk(auth_header, sizeof(auth_header), "Authorization: Bearer %s\r\n", CONFIG_PIGEON_TOKEN);
  const char *headers[] = {auth_header, NULL};

  struct websocket_request req = {0};

  req.host = pigeon_ws_host;
  req.url = url;
  req.optional_headers = headers;
  req.tmp_buf = pigeon_ws_scratch;
  req.tmp_buf_len = sizeof(pigeon_ws_scratch);

  int ws_sock = websocket_connect(sock, &req, PIGEON_WS_CONNECT_TIMEOUT_MS, NULL);

  if (ws_sock < 0) {
    /* websocket_connect() has no way to distinguish a 401 (bad/rotated
     * token) from any other HTTP-level upgrade failure at this API level
     * (see pigeon.h's pigeon_ws_start() docs) -- treated the same as any
     * other connect failure, normal backoff applies either way. */
    LOG_ERR("WS: upgrade handshake failed: %d", ws_sock);
    zsock_close(sock);
    return ws_sock;
  }

  k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
  pigeon_ws.real_sock = sock;
  pigeon_ws.ws_sock = ws_sock;
  pigeon_ws.state = PIGEON_WS_STATE_UP;
  pigeon_ws.missed_pongs = 0;
  pigeon_ws.pong_seen_this_connection = false;
  pigeon_ws.next_ping_uptime_ms =
      k_uptime_get() + (int64_t)CONFIG_PIGEON_WS_PING_INTERVAL_SEC * MSEC_PER_SEC;
  k_mutex_unlock(&pigeon_ws_lock);

  LOG_INF("WS: connected to %s%s", pigeon_ws_host, url);

  return 0;
}

/*
 * Tears down whichever of the two fds are still open and resets connection
 * state to DISCONNECTED. Safe to call more than once (e.g. once from the
 * path that noticed the drop and once from a racing pigeon_ws_stop()) --
 * fds are captured and cleared under lock before being closed, so a second
 * caller sees -1 and does nothing.
 *
 * Always calls websocket_disconnect(ws_sock) itself, unconditionally, when
 * ws_sock is still live -- an earlier revision skipped this on the
 * server-initiated-CLOSE path, trusting that Zephyr's own
 * websocket_recv_msg() had already called websocket_internal_disconnect()
 * (and therefore websocket_context_unref()) internally for us. That trust
 * was misplaced: read the vendored source
 * (zephyr/subsys/net/lib/websocket/websocket.c, the check right before its
 * internal disconnect call) --
 *
 *   if (ctx->message_type == WEBSOCKET_FLAG_CLOSE) {
 *           return websocket_internal_disconnect(ctx);
 *   }
 *
 * -- this is an EXACT-equality check, not a bitwise `&`. RFC 6455 sec
 * 5.5.1 forbids fragmenting control frames, so any real CLOSE frame from a
 * compliant peer always also carries WEBSOCKET_FLAG_FINAL, making
 * ctx->message_type WEBSOCKET_FLAG_CLOSE|WEBSOCKET_FLAG_FINAL (0x09), which
 * this check can never match (0x09 != 0x08) -- confirmed empirically
 * against a real close from dovecote (a native_sim harness with temporary
 * ref/unref tracing showed exactly one ref() and zero unref() calls across
 * a full connect -> server-close -> reconnect-attempts cycle). In
 * practice, the library's own internal-disconnect path on this branch is
 * dead code for every real peer, and previously trusting it here silently
 * leaked the sole CONFIG_WEBSOCKET_MAX_CONTEXTS context slot on every
 * server-initiated close -- reproduced as a permanent post-churn
 * "upgrade handshake failed: -17" (EEXIST, websocket_find() matching the
 * leaked context's stale real_sock against a reused fd number) wedging
 * every subsequent reconnect attempt.
 *
 * websocket_disconnect() is exactly zsock_close(ws_sock): sends a CLOSE
 * frame over real_sock, then unconditionally unrefs the library's own
 * context via the *outer* close_vmeth path (unaffected by the buggy
 * equality check above, which only guards the recv-side internal-disconnect
 * shortcut) -- this is what actually frees the slot. It does not touch
 * real_sock, which the library never closes in any path (confirmed against
 * the vendored source and its own websocket_client sample, which always
 * closes both fds itself on every exit path), so that's still always
 * closed here separately.
 *
 * Calling websocket_disconnect() here even when the library's own recv-path
 * disconnect DID somehow run (a non-compliant peer sending an unfragmented
 * close with FIN unset -- self-contradictory per spec, but hypothetically
 * possible) would double-unref an already-0 refcount. Not guarded against:
 * no real-world WS server does this, dovecote's frame close codes are all
 * ordinary FIN-set control frames, and the alternative (silently leaking
 * the single context slot on every real close, as the previous revision
 * did) is a strictly worse, already-proven failure mode.
 */
static void pigeon_ws_teardown(void) {
  k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
  int ws_sock = pigeon_ws.ws_sock;
  int real_sock = pigeon_ws.real_sock;

  pigeon_ws.ws_sock = -1;
  pigeon_ws.real_sock = -1;
  pigeon_ws.state = PIGEON_WS_STATE_DISCONNECTED;
  k_mutex_unlock(&pigeon_ws_lock);

  /* Wait for any in-flight send on these fds (pigeon_ws_send_locked(), from
   * either this worker thread's own ping or a concurrent app-thread
   * pigeon_ws_report_telemetry() call) to finish before closing out from
   * under it -- pigeon_ws_tx_lock is a different lock from pigeon_ws_lock
   * above (see this file's header comment on the two-lock split), so this
   * is a separate, sequential acquisition, never nested with it. Bounded
   * by SO_SNDTIMEO (pigeon_ws_open_tls_socket()), not indefinite. */
  k_mutex_lock(&pigeon_ws_tx_lock, K_FOREVER);

  if (ws_sock >= 0) {
    websocket_disconnect(ws_sock);
  }

  if (real_sock >= 0) {
    zsock_close(real_sock);
  }

  k_mutex_unlock(&pigeon_ws_tx_lock);
}

/* Sends one frame, serialized against every other sender on this socket
 * (the worker's pings, its RFC 6455 protocol-ping echoes, and the app
 * thread's pigeon_ws_report_telemetry()) via pigeon_ws_tx_lock -- a
 * dedicated lock, deliberately not pigeon_ws_lock (see this file's header
 * comment). Returns whatever websocket_send_msg() returned. */
static int pigeon_ws_send_locked(
    int ws_sock, const uint8_t *payload, size_t len, enum websocket_opcode opcode
) {
  k_mutex_lock(&pigeon_ws_tx_lock, K_FOREVER);
  int ret = websocket_send_msg(ws_sock, payload, len, opcode, true, true, PIGEON_WS_SEND_TIMEOUT_MS);
  k_mutex_unlock(&pigeon_ws_tx_lock);

  return ret;
}

/* Returns 0 on send success, -ENOTCONN when not currently UP (checked
 * before attempting anything) or when the send itself fails -- from the
 * caller's perspective a failed send and a socket that was already down are
 * the same outcome (see pigeon_ws_report_telemetry()'s doc in pigeon.h,
 * and pigeon_core.c's pigeon_shadow_flush(), which relies on exactly this
 * -ENOTCONN mapping to fall back to the HTTPS transport). */
static int pigeon_ws_send_text(const char *payload, size_t len, bool is_from_worker) {
  k_mutex_lock(&pigeon_ws_lock, K_FOREVER);

  if (pigeon_ws.state != PIGEON_WS_STATE_UP || pigeon_ws.ws_sock < 0) {
    k_mutex_unlock(&pigeon_ws_lock);
    return -ENOTCONN;
  }

  int ws_sock = pigeon_ws.ws_sock;

  /* Released before the blocking send below -- state reads
   * (pigeon_ws_connected(), pigeon_ws_stop(), the worker's own loop) must
   * never queue up behind a slow network write (see this file's header
   * comment on the two-lock split). */
  k_mutex_unlock(&pigeon_ws_lock);

  int ret = pigeon_ws_send_locked(ws_sock, (const uint8_t *)payload, len, WEBSOCKET_OPCODE_DATA_TEXT);

  if (ret < 0 && !is_from_worker) {
    /* Let the worker thread notice and reconnect on its own -- it owns all
     * fd teardown/state transitions (see pigeon_ws_teardown()'s docs). */
    k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
    pigeon_ws.force_reconnect = true;
    k_mutex_unlock(&pigeon_ws_lock);
  }

  return ret < 0 ? -ENOTCONN : 0;
}

int pigeon_ws_report_telemetry(const char *key, const char *val) {
  if (!key || !val) {
    return -EINVAL;
  }

  /* Escaped forms can be up to ~6x the raw key/val in the worst case (every
   * byte a control character needing \u00XX) -- same sizing as the HTTPS/
   * CoAP transports' telemetry encode, see their comments for the
   * PIGEON_SHADOW_KEY_MAX/VAL_MAX arithmetic. The resulting body stays
   * comfortably under the server's 16 KiB per-frame cap either way. */
  char key_esc[200];
  char val_esc[800];

  pigeon_json_escape(key, key_esc, sizeof(key_esc));
  pigeon_json_escape(val, val_esc, sizeof(val_esc));

  char body[sizeof(key_esc) + sizeof(val_esc) + 48];

  snprintk(
      body, sizeof(body), "{\"type\":\"telemetry\",\"metrics\":{\"%s\":\"%s\"}}", key_esc, val_esc
  );

  return pigeon_ws_send_text(body, strlen(body), false);
}

#if defined(CONFIG_PIGEON_SHELL)
/*
 * Sized off CONFIG_SHELL_BACKEND_DUMMY_BUF_SIZE (Zephyr's own shell_dummy
 * output-capture buffer, selected by CONFIG_PIGEON_SHELL -- this file
 * doesn't own that Kconfig symbol, it just reads it) rather than a
 * separate CONFIG_PIGEON_SHELL_-prefixed size: shell_dummy's buffer is the
 * actual upstream limit on how much raw output pigeon_shell.c can ever
 * hand us, so sizing off anything else would either waste static RAM
 * (bigger than shell_dummy could ever fill) or truncate before shell_dummy
 * itself would have. 2x, not the 6x "every byte a control character"
 * worst case pigeon_ws_report_telemetry() above uses for arbitrary
 * caller-supplied telemetry values -- real shell command output is
 * overwhelmingly plain text with at most occasional newlines (2 chars
 * each), and true 6x sizing here would push a single shell_output frame
 * uncomfortably close to the server's 16 KiB MAX_WS_FRAME_BYTES cap once
 * CONFIG_SHELL_BACKEND_DUMMY_BUF_SIZE is bumped past its tiny (300 byte)
 * upstream default for real use. A command whose output is pathologically
 * escape-heavy still can't overflow this buffer (pigeon_json_escape()
 * only ever truncates) -- it just trips the escape_truncated check below
 * instead, same honest signal as shell_dummy's own overflow. */
#define PIGEON_WS_SHELL_BODY_MAX (2 * CONFIG_SHELL_BACKEND_DUMMY_BUF_SIZE + 160)

static char pigeon_ws_shell_body[PIGEON_WS_SHELL_BODY_MAX];

/* Only ever called from pigeon_shell.c's single dedicated shell thread
 * (v1 is one command in flight per device, see zephyr/Kconfig), so the
 * module-static scratch buffer above is safe without its own lock --
 * same reasoning pigeon_ws_scratch/pigeon_ws_rx_buf already rely on for
 * their own single-owner-thread buffers elsewhere in this file. */
int pigeon_ws_send_shell_output(
    const char *request_id, const char *output, int exit_code, bool truncated
) {
  if (!request_id) {
    return -EINVAL;
  }

  char request_id_esc[PIGEON_WS_SHELL_REQUEST_ID_MAX * 2];

  pigeon_json_escape(request_id, request_id_esc, sizeof(request_id_esc));

  int prefix_len = snprintk(
      pigeon_ws_shell_body, sizeof(pigeon_ws_shell_body),
      "{\"type\":\"shell_output\",\"request_id\":\"%s\",\"output\":\"", request_id_esc
  );

  if (prefix_len < 0 || (size_t)prefix_len >= sizeof(pigeon_ws_shell_body)) {
    LOG_ERR("WS: shell_output prefix build failed/overflowed (prefix_len=%d)", prefix_len);
    return -ENOMEM;
  }

  size_t remaining = sizeof(pigeon_ws_shell_body) - (size_t)prefix_len;
  size_t escaped_len = 0;

  if (output) {
    escaped_len = pigeon_json_escape(output, pigeon_ws_shell_body + prefix_len, remaining);
  } else {
    pigeon_ws_shell_body[prefix_len] = '\0';
  }

  /* Mirrors pigeon_json_escape()'s own "\u00XX needs 6 bytes" bail-out
   * margin (pigeon_core.c) -- if the escaped output landed within that
   * margin of remaining, it plausibly hit its own truncation point on the
   * last byte it could fit, same heuristic spirit as shell_dummy's own
   * "len == buffer size - 1" truncation signal pigeon_shell.c checks. */
  bool escape_truncated = output && remaining > 7 && escaped_len >= remaining - 7;

  size_t suffix_offset = (size_t)prefix_len + escaped_len;
  int suffix_len = snprintk(
      pigeon_ws_shell_body + suffix_offset, sizeof(pigeon_ws_shell_body) - suffix_offset,
      "\",\"exit_code\":%d,\"truncated\":%s}", exit_code,
      (truncated || escape_truncated) ? "true" : "false"
  );

  if (suffix_len < 0 || suffix_offset + (size_t)suffix_len >= sizeof(pigeon_ws_shell_body)) {
    LOG_ERR("WS: shell_output suffix build failed/overflowed (suffix_len=%d)", suffix_len);
    return -ENOMEM;
  }

  return pigeon_ws_send_text(pigeon_ws_shell_body, suffix_offset + (size_t)suffix_len, false);
}
#endif /* CONFIG_PIGEON_SHELL */

/* Handles one already-received frame: rx_buf[0..len) is the message
 * payload (text opcode assumed by the caller). */
static void pigeon_ws_dispatch_frame(uint8_t *buf, size_t len) {
  memset(&pigeon_ws_frame, 0, sizeof(pigeon_ws_frame));

  int64_t decoded = json_obj_parse(
      (char *)buf, len, pigeon_ws_frame_descr, ARRAY_SIZE(pigeon_ws_frame_descr), &pigeon_ws_frame
  );

  if (decoded < 0) {
    LOG_WRN("WS: dropping malformed frame (decoded=%lld)", decoded);
    return;
  }

  if (!(decoded & PIGEON_WS_FIELD_TYPE)) {
    LOG_WRN("WS: dropping frame with no \"type\" field");
    return;
  }

  if (strcmp(pigeon_ws_frame.type, "pong") == 0) {
    k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
    pigeon_ws.missed_pongs = 0;
    if (!pigeon_ws.pong_seen_this_connection) {
      /* First pong of this connection survived -- the connection is good,
       * so reset backoff to the base rather than leaving it wherever the
       * exponential ramp had climbed to from prior failed attempts. */
      pigeon_ws.pong_seen_this_connection = true;
      pigeon_ws.reconnect_delay_sec = PIGEON_WS_BACKOFF_BASE_SEC;
    }
    k_mutex_unlock(&pigeon_ws_lock);
    return;
  }

  if (strcmp(pigeon_ws_frame.type, "shadow_update") == 0) {
    if (!(decoded & PIGEON_WS_FIELD_SHADOW)) {
      LOG_WRN("WS: shadow_update frame missing \"shadow\" object");
      return;
    }

    /*
     * Gotcha (not obvious from json.h's docs, confirmed by reading
     * zephyr/lib/utils/json.c's decode_value()/obj_parse()): the outer
     * PIGEON_WS_FIELD_SHADOW bit only means the nested object parsed
     * without a syntax error -- it does NOT mean all 5 of
     * pigeon_ws_shadow_descr's own sub-fields were present, the way a
     * top-level json_obj_parse() call's return value would. The nested
     * obj_parse()'s own field-completeness bitmask is discarded by
     * decode_value() and never surfaces here. In practice this is safe
     * because dovecote always serializes a complete capsules::PigeonShadow
     * (see ws.rs), and pigeon_ws_frame was memset to 0 above, so any
     * hypothetically-missing sub-field would decode as a zeroed/empty
     * value rather than garbage -- but a partial "shadow" object from a
     * misbehaving peer would NOT be caught here the way pigeon_https.c's
     * top-level shadow decode catches a partial GET /shadow response.
     */
    struct pigeon_shadow_doc doc = {
        .target_version = pigeon_ws_frame.shadow.target_version,
        .current_version = pigeon_ws_frame.shadow.current_version,
        .target_config = pigeon_ws_frame.shadow.target_config,
        .current_config = pigeon_ws_frame.shadow.current_config,
        .updated_at = pigeon_ws_frame.shadow.updated_at,
    };

    LOG_INF(
        "WS: shadow_update pushed (target_version=%d current_version=%d)", doc.target_version,
        doc.current_version
    );

    pigeon_ws_event_cb_t cb;

    k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
    cb = pigeon_ws.cb;
    k_mutex_unlock(&pigeon_ws_lock);

    if (cb) {
      cb(PIGEON_WS_EVENT_SHADOW_UPDATE, &doc);
    }
    return;
  }

#if defined(CONFIG_PIGEON_SHELL)
  if (strcmp(pigeon_ws_frame.type, "shell_cmd") == 0) {
    memset(&pigeon_ws_shell_cmd, 0, sizeof(pigeon_ws_shell_cmd));

    int64_t shell_decoded = json_obj_parse(
        (char *)buf, len, pigeon_ws_shell_cmd_descr, ARRAY_SIZE(pigeon_ws_shell_cmd_descr),
        &pigeon_ws_shell_cmd
    );

    if (shell_decoded < 0 ||
        (shell_decoded & (PIGEON_WS_SHELL_FIELD_REQUEST_ID | PIGEON_WS_SHELL_FIELD_CMD)) !=
            (PIGEON_WS_SHELL_FIELD_REQUEST_ID | PIGEON_WS_SHELL_FIELD_CMD)) {
      LOG_WRN("WS: dropping malformed shell_cmd frame (decoded=%lld)", shell_decoded);
      return;
    }

    pigeon_shell_handle_cmd(pigeon_ws_shell_cmd.request_id, pigeon_ws_shell_cmd.cmd);
    return;
  }
#endif /* CONFIG_PIGEON_SHELL */

  /* Forward-compat: dovecote's frame dispatch may grow new types (e.g.
   * task #34's remote shell, when CONFIG_PIGEON_SHELL is off) without
   * breaking already-deployed devices -- ignore anything we don't
   * recognize rather than treating it as an error. */
  LOG_DBG("WS: ignoring frame of unhandled type '%s'", pigeon_ws_frame.type);
}

/*
 * Computes the next jittered backoff delay (seconds): plain exponential
 * doubling from pigeon_ws.reconnect_delay_sec, capped at
 * CONFIG_PIGEON_WS_RECONNECT_MAX_DELAY_SEC, +-25% jitter.
 *
 * The design this file implements called for a close-code-aware policy
 * table (4008 rate-limit -> wait out one window; 4009 replaced-by-another-
 * connection -> slow start; everything else -> this same normal backoff --
 * an earlier revision had PIGEON_WS_RATE_LIMIT_WINDOW_SEC/
 * PIGEON_WS_REPLACED_MIN_DELAY_SEC constants for this, since removed along
 * with the dead code that used them). That turned out not to be safely implementable
 * against the vendored zephyr/subsys/net/lib/websocket/websocket.c: on a
 * server-initiated CLOSE, websocket_recv_msg() runs its own
 * websocket_internal_disconnect() (echoes the CLOSE, unrefs its context)
 * and returns *that* call's result -- not the number of close-payload
 * bytes it copied into our buffer. payload.count (the actual length) is
 * computed internally but never surfaced to the caller on this path, so
 * there is no reliable way via the public API to know whether buf[0:2)
 * is a real close code or stale bytes left over from a previous message.
 * Per this design's own explicitly pre-approved fallback for exactly this
 * risk ("if close-code extraction from Zephyr's recv path proves
 * impractical, collapse all close codes to normal backoff -- only the
 * 4009 slow-start distinction is lost, and jittered exponential backoff
 * still bounds flapping"), every server-initiated close is therefore
 * treated identically to a network-loss/-ENOTCONN/pong-timeout drop.
 */
static uint32_t pigeon_ws_next_backoff_sec(void) {
  uint32_t delay_sec;

  k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
  delay_sec = pigeon_ws.reconnect_delay_sec;
  pigeon_ws.reconnect_delay_sec =
      MIN(delay_sec * 2, (uint32_t)CONFIG_PIGEON_WS_RECONNECT_MAX_DELAY_SEC);
  k_mutex_unlock(&pigeon_ws_lock);

  /* +-25% jitter. */
  uint32_t jitter_range = delay_sec / 2; /* 50% span, i.e. +-25% of delay_sec */
  uint32_t jitter = jitter_range ? (sys_rand32_get() % jitter_range) : 0;
  uint32_t jittered = (delay_sec - jitter_range / 2) + jitter;

  return jittered ? jittered : 1;
}

static void pigeon_ws_sleep_backoff(uint32_t delay_sec) {
  int64_t deadline = k_uptime_get() + (int64_t)delay_sec * MSEC_PER_SEC;

  /* Slept in <=1s slices so pigeon_ws_stop() (which only force-closes fds,
   * there's nothing to close while we're between connections) is honored
   * promptly instead of after the full backoff. */
  while (k_uptime_get() < deadline) {
    k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
    bool stop = pigeon_ws.stop_requested;
    k_mutex_unlock(&pigeon_ws_lock);

    if (stop) {
      return;
    }

    k_sleep(K_MSEC(MIN(1000, deadline - k_uptime_get())));
  }
}

static void pigeon_ws_thread_fn(void *p1, void *p2, void *p3) {
  ARG_UNUSED(p1);
  ARG_UNUSED(p2);
  ARG_UNUSED(p3);

  while (true) {
    k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
    bool stop = pigeon_ws.stop_requested;
    k_mutex_unlock(&pigeon_ws_lock);

    if (stop) {
      break;
    }

    int err = pigeon_ws_connect_once();

    if (err) {
      uint32_t delay = pigeon_ws_next_backoff_sec();

      LOG_WRN("WS: connect failed (%d), retrying in %us", err, delay);
      pigeon_ws_sleep_backoff(delay);
      continue;
    }

    pigeon_ws_event_cb_t connected_cb;

    k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
    connected_cb = pigeon_ws.cb;
    k_mutex_unlock(&pigeon_ws_lock);

    if (connected_cb) {
      /* Server sends no state snapshot on accept -- CONNECTED is the
       * app's cue to pigeon_shadow_get() over HTTPS to pick up anything
       * pushed while disconnected (see pigeon.h's docs). */
      connected_cb(PIGEON_WS_EVENT_CONNECTED, NULL);
    }

    while (true) {
      k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
      bool stop_now = pigeon_ws.stop_requested;
      bool force_reconnect = pigeon_ws.force_reconnect;

      pigeon_ws.force_reconnect = false;

      int ws_sock = pigeon_ws.ws_sock;
      int64_t next_ping = pigeon_ws.next_ping_uptime_ms;

      k_mutex_unlock(&pigeon_ws_lock);

      if (stop_now || force_reconnect) {
        break;
      }

      int64_t now = k_uptime_get();
      int32_t poll_timeout_ms =
          (int32_t)MAX(0, MIN(next_ping - now, (int64_t)PIGEON_WS_POLL_MAX_MS));

      struct zsock_pollfd fds[1] = {{.fd = ws_sock, .events = ZSOCK_POLLIN}};
      int poll_ret = zsock_poll(fds, 1, poll_timeout_ms);

      if (poll_ret < 0) {
        LOG_WRN("WS: poll failed: %d", -errno);
        break;
      }

      if (poll_ret == 0) {
        /* Timed out: nothing readable, time to consider a ping. */
        if (k_uptime_get() < next_ping) {
          continue;
        }

        k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
        int missed = pigeon_ws.missed_pongs;
        k_mutex_unlock(&pigeon_ws_lock);

        if (missed >= PIGEON_WS_MAX_MISSED_PONGS) {
          LOG_WRN("WS: %d consecutive missed pongs, treating as half-open", missed);
          break;
        }

        static const char ping_frame[] = "{\"type\":\"ping\"}";
        int send_err = pigeon_ws_send_text(ping_frame, sizeof(ping_frame) - 1, true);

        k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
        if (send_err == 0) {
          pigeon_ws.missed_pongs++;
        }
        pigeon_ws.next_ping_uptime_ms =
            k_uptime_get() + (int64_t)CONFIG_PIGEON_WS_PING_INTERVAL_SEC * MSEC_PER_SEC;
        k_mutex_unlock(&pigeon_ws_lock);

        if (send_err) {
          LOG_WRN("WS: ping send failed: %d", send_err);
          break;
        }

        continue;
      }

      /* Readable: receive one message. */
      uint32_t msg_type = 0;
      uint64_t remaining = 0;

      int ret = websocket_recv_msg(
          ws_sock, pigeon_ws_rx_buf, sizeof(pigeon_ws_rx_buf), &msg_type, &remaining, 0
      );

      if (msg_type & WEBSOCKET_FLAG_CLOSE) {
        /*
         * Server-initiated close. message_type is the only trustworthy
         * signal of this -- websocket_recv_msg()'s return value here is
         * NOT reliably -ENOTCONN (an earlier revision assumed it was; see
         * git history), and the library's own attempt to auto-tear-down
         * its context on this path is itself unreliable (an exact-equality
         * bug in its CLOSE check makes that internal call unreachable for
         * any real, FIN-set CLOSE frame -- see pigeon_ws_teardown()'s docs
         * for the full trace). pigeon_ws_teardown() below always calls
         * websocket_disconnect() itself now, regardless of what the
         * library may or may not have already done internally, so this
         * path no longer needs to track or assume anything about that.
         *
         * The close *code* is deliberately not read out of
         * pigeon_ws_rx_buf here: the actual close-payload length
         * (payload.count internally) is never surfaced to the caller on
         * this path, so there is no reliable way to tell a real 2-byte
         * code apart from stale bytes left over from a previous message.
         * See pigeon_ws_next_backoff_sec()'s docs for why every close is
         * therefore treated identically (the design's own pre-approved
         * fallback for this exact risk).
         */
        LOG_WRN("WS: server closed the connection");
        break;
      }

      if (ret < 0) {
        if (ret == -EAGAIN) {
          continue;
        }

        /* Hard failure: network loss, or a bare TCP close with no WS-level
         * CLOSE frame at all (message_type left unset/0 in this path --
         * websocket_recv_msg() returns -ENOTCONN directly from its
         * zsock_recv()==0 branch before ever touching message_type). */
        LOG_WRN("WS: recv failed: %d", ret);
        break;
      }

      if (msg_type & WEBSOCKET_FLAG_PING) {
        /* Protocol-level RFC 6455 ping -- Zephyr's library does NOT
         * auto-pong these (confirmed: no code path in websocket.c sends
         * WEBSOCKET_OPCODE_PONG except in direct response to our own
         * explicit send), so echo it back ourselves. The Cloudflare edge
         * may emit these even though dovecote's app layer never does.
         * Routed through pigeon_ws_send_locked() (same TX lock as every
         * other sender on this socket) rather than a bare
         * websocket_send_msg() call -- this used to be the one unguarded
         * sender, a latent race with pigeon_ws_send_text() on the same fd. */
        k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
        int echo_sock = pigeon_ws.ws_sock;
        k_mutex_unlock(&pigeon_ws_lock);

        if (echo_sock >= 0) {
          pigeon_ws_send_locked(echo_sock, pigeon_ws_rx_buf, (size_t)ret, WEBSOCKET_OPCODE_PONG);
        }
        continue;
      }

      if (msg_type & WEBSOCKET_FLAG_PONG) {
        /* Unsolicited protocol-level pong -- irrelevant to our app-level
         * keepalive bookkeeping (only a JSON {"type":"pong"} frame resets
         * missed_pongs, see pigeon_ws_dispatch_frame()). */
        continue;
      }

      if (msg_type & WEBSOCKET_FLAG_BINARY) {
        LOG_WRN("WS: dropping unexpected binary frame (%d bytes)", ret);
        continue;
      }

      if (!(msg_type & WEBSOCKET_FLAG_TEXT)) {
        /* Continuation frame with no type flag set, or a 0-byte frame we
         * don't otherwise recognize -- nothing to dispatch. */
        continue;
      }

      if (remaining != 0) {
        /* Message bigger than our buffer -- drain and drop, don't attempt
         * to parse a truncated JSON document (server hard-caps frames at
         * 16 KiB; CONFIG_PIGEON_WS_RX_BUF_SIZE is deliberately smaller). */
        LOG_WRN("WS: dropping oversized frame (%llu bytes remaining after first read)", remaining);

        while (remaining != 0) {
          uint32_t drain_type;
          int drain_ret = websocket_recv_msg(
              ws_sock, pigeon_ws_rx_buf, sizeof(pigeon_ws_rx_buf), &drain_type, &remaining, 0
          );

          if (drain_ret < 0) {
            break;
          }
        }
        continue;
      }

      pigeon_ws_dispatch_frame(pigeon_ws_rx_buf, (size_t)ret);
    }

    pigeon_ws_teardown();

    pigeon_ws_event_cb_t disconnected_cb;

    k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
    disconnected_cb = pigeon_ws.cb;
    stop = pigeon_ws.stop_requested;
    k_mutex_unlock(&pigeon_ws_lock);

    if (disconnected_cb) {
      disconnected_cb(PIGEON_WS_EVENT_DISCONNECTED, NULL);
    }

    if (stop) {
      break;
    }

    uint32_t delay = pigeon_ws_next_backoff_sec();

    LOG_INF("WS: reconnecting in %us", delay);
    pigeon_ws_sleep_backoff(delay);
  }
}

int pigeon_ws_start(pigeon_ws_event_cb_t cb) {
  k_mutex_lock(&pigeon_ws_lock, K_FOREVER);

  if (pigeon_ws.running) {
    k_mutex_unlock(&pigeon_ws_lock);
    LOG_WRN("pigeon_ws_start() called while already running");
    return -EALREADY;
  }

  pigeon_ws.running = true;
  pigeon_ws.stop_requested = false;
  pigeon_ws.force_reconnect = false;
  pigeon_ws.state = PIGEON_WS_STATE_DISCONNECTED;
  pigeon_ws.real_sock = -1;
  pigeon_ws.ws_sock = -1;
  pigeon_ws.cb = cb;
  pigeon_ws.reconnect_delay_sec = PIGEON_WS_BACKOFF_BASE_SEC;
  pigeon_ws.missed_pongs = 0;
  pigeon_ws.pong_seen_this_connection = false;

  k_mutex_unlock(&pigeon_ws_lock);

  k_tid_t tid = k_thread_create(
      &pigeon_ws_thread_data, pigeon_ws_stack, K_THREAD_STACK_SIZEOF(pigeon_ws_stack),
      pigeon_ws_thread_fn, NULL, NULL, NULL, PIGEON_WS_THREAD_PRIORITY, 0, K_NO_WAIT
  );

  k_thread_name_set(tid, "pigeon_ws");

  LOG_INF("WS: worker thread started");

  return 0;
}

int pigeon_ws_stop(void) {
  k_mutex_lock(&pigeon_ws_lock, K_FOREVER);

  if (!pigeon_ws.running) {
    k_mutex_unlock(&pigeon_ws_lock);
    return 0;
  }

  pigeon_ws.stop_requested = true;

  int ws_sock = pigeon_ws.ws_sock;
  int real_sock = pigeon_ws.real_sock;

  /*
   * Capture-AND-CLEAR under this same lock, before closing outside it --
   * mirrors pigeon_ws_teardown()'s protocol exactly. Fixed from an earlier
   * revision that closed from these local copies without ever writing -1
   * back into pigeon_ws.ws_sock/real_sock: the worker thread's own
   * pigeon_ws_teardown() call, invoked unconditionally once the forced
   * close below unblocks its poll/recv and its inner loop breaks, would
   * otherwise re-read the same stale fd numbers and close them a *second*
   * time -- on fds Zephyr may have already freed for reuse by then (e.g.
   * the app's own transient HTTPS request socket, which this design
   * documents as running concurrently with the persistent WS socket).
   * With the clear happening here first, that second call sees -1/-1 and
   * correctly no-ops, exactly as pigeon_ws_teardown()'s own docstring
   * describes (this was previously false for this function specifically,
   * even though pigeon_ws_teardown() itself always followed the pattern).
   */
  pigeon_ws.ws_sock = -1;
  pigeon_ws.real_sock = -1;
  pigeon_ws.state = PIGEON_WS_STATE_DISCONNECTED;

  k_mutex_unlock(&pigeon_ws_lock);

  /*
   * Force the worker out of whatever blocking poll/recv it's in.
   * pigeon_ws_tx_lock (not pigeon_ws_lock -- see this file's header
   * comment on the two-lock split) is taken around the actual closes so
   * this waits for any in-flight send on these fds (this worker's own
   * ping, or a concurrent app-thread pigeon_ws_report_telemetry() call)
   * to finish first, rather than closing a live fd out from under it.
   * That wait is now bounded by SO_SNDTIMEO (pigeon_ws_open_tls_socket()),
   * not indefinite -- previously, websocket_disconnect()'s internal
   * CLOSE-frame echo requested SYS_FOREVER_MS with nothing capping the
   * underlying socket's own send timeout, so a stalled/half-dead TCP path
   * could hang this function (and therefore the shadow "reboot": true
   * path that calls it right before sys_reboot()) indefinitely.
   *
   * websocket_disconnect() only sends a CLOSE and unrefs the library's own
   * context, it never touches real_sock, so that always needs its own
   * zsock_close() regardless.
   */
  k_mutex_lock(&pigeon_ws_tx_lock, K_FOREVER);

  if (ws_sock >= 0) {
    websocket_disconnect(ws_sock);
  }
  if (real_sock >= 0) {
    zsock_close(real_sock);
  }

  k_mutex_unlock(&pigeon_ws_tx_lock);

  /*
   * Does not (and cannot cleanly) bound the case where stop_requested
   * lands while the worker is still inside pigeon_ws_connect_once() --
   * ws_sock/real_sock are only populated on a successful connect, so
   * there's nothing here to force-close, and this join can only wait for
   * that in-flight DNS lookup/TCP connect/TLS+HTTP-upgrade handshake to
   * resolve on its own. Accepted rather than fixed: unlike the SNDTIMEO
   * case above (a Zephyr socket-layer default of K_FOREVER with no
   * built-in bound at all), DNS/TCP connection establishment is already
   * bounded by the network stack's own retry/timeout Kconfig (e.g. TCP
   * SYN retransmission limits) rather than waiting forever by design, so
   * the residual exposure here is smaller and time-boxed by the stack
   * itself, not open-ended.
   */
  k_thread_join(&pigeon_ws_thread_data, K_FOREVER);

  k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
  pigeon_ws.running = false;
  pigeon_ws.state = PIGEON_WS_STATE_DISCONNECTED;
  pigeon_ws.ws_sock = -1;
  pigeon_ws.real_sock = -1;
  k_mutex_unlock(&pigeon_ws_lock);

  LOG_INF("WS: stopped");

  return 0;
}

bool pigeon_ws_connected(void) {
  k_mutex_lock(&pigeon_ws_lock, K_FOREVER);
  bool up = (pigeon_ws.state == PIGEON_WS_STATE_UP);
  k_mutex_unlock(&pigeon_ws_lock);

  return up;
}
