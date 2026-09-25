/*
 * NIDD connector: frames on a raw socket over a Non-IP PDN, which the carrier
 * hands to ThingSpace and ThingSpace posts to the platform. No TLS and no
 * token: the SIM authenticates the device to the carrier, the claim key binds
 * it to its pigeon, and a tag keyed by that claim key authenticates every frame
 * the platform sends.
 *
 * Like pigeon_mqtt.c it is both a transport (it defines pigeon_shadow_get,
 * pigeon_shadow_report and pigeon_transport_report_telemetry) and a receive
 * channel with a thread of its own, because replies and pushes arrive when the
 * network delivers them. docs/api.md in the pidgeiot repository ("NIDD frames",
 * "NIDD downlink and replies") is the authority on every byte. The library has
 * no cadence: it sends what the application asks for, plus HELLO.
 */
#include <errno.h>
#include <modem/lte_lc.h>
#include <nrf_modem_at.h>
#include <pigeon.h>
#include <psa/crypto.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include "pigeon_internal.h"

#if defined(CONFIG_PIGEON_TELEMETRY_BATCH)
#include "pigeon_telemetry_batch.h"
#endif

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

#define PIGEON_NIDD_SCHEME "nidd://"

/* The largest uplink frame the nRF9160 modem (mfw 1.3.7) was seen to accept; it refused 1283
 * bytes in send() before any radio access. */
#define PIGEON_NIDD_UPLINK_MAX 1273
/* capsules::NIDD_MAX_FRAME_BYTES, the carrier's downlink cap. */
#define PIGEON_NIDD_DOWNLINK_MAX 1358

/* A platform frame ends in the first 8 bytes of HMAC-SHA256 as lowercase hex. */
#define PIGEON_NIDD_TAG_BYTES 8
#define PIGEON_NIDD_TAG_CHARS (2 * PIGEON_NIDD_TAG_BYTES)
#define PIGEON_NIDD_KEY_BYTES 16
#define PIGEON_NIDD_KEY_CHARS (2 * PIGEON_NIDD_KEY_BYTES)
/* A header number is a u32 written in decimal. */
#define PIGEON_NIDD_HEADER_DIGITS 10

#define PIGEON_NIDD_TELEMETRY 0x01
#define PIGEON_NIDD_SHADOW_REPORT 0x02
#define PIGEON_NIDD_HELLO 0x04
#define PIGEON_NIDD_FROM_PLATFORM 0x80
#define PIGEON_NIDD_SHADOW 0x81
#define PIGEON_NIDD_STATUS 0x82

#define PIGEON_NIDD_STORED 0
#define PIGEON_NIDD_PAUSED 1
#define PIGEON_NIDD_UNCLAIMED 2

#define PIGEON_NIDD_PAUSE_MAX_SEC 86400
#define PIGEON_NIDD_HELLO_HOLD_MS (3600 * MSEC_PER_SEC)
#define PIGEON_NIDD_REPLY_WAIT_MS (CONFIG_PIGEON_NIDD_REPLY_WAIT_SEC * MSEC_PER_SEC)
#define PIGEON_NIDD_LOCK_WAIT K_SECONDS(10)
/* Opening the socket can activate a PDN, which is a radio access, so retries are minutes apart. */
#define PIGEON_NIDD_OPEN_BACKOFF_MIN_SEC 60
#define PIGEON_NIDD_OPEN_BACKOFF_MAX_SEC 1920
#define PIGEON_NIDD_PDN_WAIT K_SECONDS(60)
#define PIGEON_NIDD_STOP_WAIT K_SECONDS(10)
/* Below the application's own work, as the other connectors' threads are. */
#define PIGEON_NIDD_THREAD_PRIORITY 10

BUILD_ASSERT(
    PIGEON_TELEMETRY_BODY_MAX <= PIGEON_NIDD_UPLINK_MAX,
    "Lower CONFIG_PIGEON_TELEMETRY_MAX_KEYS: a flat telemetry body must fit one 1273-byte NIDD "
    "frame"
);

#if defined(CONFIG_PIGEON_TELEMETRY_BATCH)
BUILD_ASSERT(
    PIGEON_TELEMETRY_BATCH_BODY_MAX <= PIGEON_NIDD_UPLINK_MAX,
    "Lower CONFIG_PIGEON_TELEMETRY_BATCH_BUF_SIZE or CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH: a "
    "telemetry batch must fit one 1273-byte NIDD frame"
);
#endif

BUILD_ASSERT(
    CONFIG_PIGEON_SHADOW_CONFIG_MAX + 64 <= PIGEON_NIDD_UPLINK_MAX - 1,
    "Lower CONFIG_PIGEON_SHADOW_CONFIG_MAX: a shadow report must fit one 1273-byte NIDD frame"
);

BUILD_ASSERT(
    sizeof(CONFIG_PIGEON_NIDD_CLAIM_KEY) == PIGEON_NIDD_KEY_CHARS + 1,
    "Set CONFIG_PIGEON_NIDD_CLAIM_KEY to the pigeon's 32-character claim key, in a git-ignored "
    "conf file"
);

BUILD_ASSERT(
    IS_ENABLED(CONFIG_LTE_NETWORK_MODE_NBIOT) || IS_ENABLED(CONFIG_LTE_NETWORK_MODE_NBIOT_GPS) ||
        ((IS_ENABLED(CONFIG_LTE_NETWORK_MODE_LTE_M_NBIOT) ||
          IS_ENABLED(CONFIG_LTE_NETWORK_MODE_LTE_M_NBIOT_GPS)) &&
         (IS_ENABLED(CONFIG_LTE_MODE_PREFERENCE_NBIOT) ||
          IS_ENABLED(CONFIG_LTE_MODE_PREFERENCE_NBIOT_PLMN_PRIO))),
    "NIDD is served over NB-IoT only: set CONFIG_LTE_NETWORK_MODE_NBIOT"
);

K_THREAD_STACK_DEFINE(pigeon_nidd_stack, CONFIG_PIGEON_NIDD_THREAD_STACK_SIZE);
static struct k_thread pigeon_nidd_thread_data;

/*
 * Guards pigeon_nidd, the two cached configs and pigeon_nidd_tx. Held across one send or one
 * open, whose only wait is for pigeon_nidd_pdn_sem, and never across the event callback.
 */
K_MUTEX_DEFINE(pigeon_nidd_lock);

/* A newer SHADOW was cached. */
static K_SEM_DEFINE(pigeon_nidd_shadow_sem, 0, 1);
/* The pending report was confirmed or refused. */
static K_SEM_DEFINE(pigeon_nidd_report_sem, 0, 1);
/* A socket exists for the receive thread. */
static K_SEM_DEFINE(pigeon_nidd_open_sem, 0, 1);
/* The lte_lc handler saw the Non-IP context activate. */
static K_SEM_DEFINE(pigeon_nidd_pdn_sem, 0, 1);

static void pigeon_nidd_release(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(pigeon_nidd_release_work, pigeon_nidd_release);

static uint8_t pigeon_nidd_tx[PIGEON_NIDD_UPLINK_MAX];
/* The receive thread's alone. */
static uint8_t pigeon_nidd_rx[PIGEON_NIDD_DOWNLINK_MAX];
/* Written only by the receive thread, so it holds still during the event callback. */
static char pigeon_nidd_target[PIGEON_HTTPS_CONFIG_MAX];
/* The config this device last reported. */
static char pigeon_nidd_current[PIGEON_HTTPS_CONFIG_MAX];
/* pigeon_shadow_get()'s copy, so a SHADOW arriving mid-parse cannot rewrite what it handed out. */
static char pigeon_nidd_target_out[PIGEON_HTTPS_CONFIG_MAX];

static psa_key_id_t pigeon_nidd_key;
/* Points into CONFIG_PIGEON_ENDPOINT, past the scheme. */
static const char *pigeon_nidd_apn;
static bool pigeon_nidd_keepopen_logged;

/* Written by the lte_lc handler, which never takes pigeon_nidd_lock: an lte_lc PDN call made
 * under the lock completes on notifications delivered from the handler's own context. */
static atomic_t pigeon_nidd_cid;
static atomic_t pigeon_nidd_pdn_up;
static atomic_t pigeon_nidd_ctx_lost;
/* Seconds, as last granted; -1 until PSM is granted. */
static atomic_t pigeon_nidd_active_time = ATOMIC_INIT(-1);

static struct {
  bool configured;
  bool running; /* thread spawned, not yet exited */
  bool stop_requested;
  pigeon_event_cb_t cb;
  int fd;
  /* Bumped at every open and close, so a descriptor number reused by a newer socket is not
   * mistaken for the one the receive thread was reading. */
  uint32_t fd_gen;
  int64_t next_open_ms;
  uint32_t open_backoff_sec;
  bool have_shadow;
  int32_t target_version;
  int32_t current_version;
  int32_t report_version; /* -1 before the first report this boot */
  bool report_pending;
  int64_t report_sent_ms;
  int report_result;
  bool hello_due;
  bool hello_owed;
  int64_t hello_sent_ms;
  int64_t paused_until_ms;
  bool unclaimed; /* UNCLAIMED 1 seen; only a reboot clears it */
} pigeon_nidd = {
    .fd = -1,
    .report_version = -1,
    .open_backoff_sec = PIGEON_NIDD_OPEN_BACKOFF_MIN_SEC,
};

/* What one verified frame asks of the receive thread once the lock is released. */
struct pigeon_nidd_outcome {
  bool answered; /* settled a reply this device was owed */
  bool updated;  /* cached a newer SHADOW */
  bool rereport;
  bool hello;
};

static int pigeon_nidd_parse_endpoint(void) {
  const char *endpoint = CONFIG_PIGEON_ENDPOINT;
  const char *apn = NULL;

  if (strncmp(endpoint, PIGEON_NIDD_SCHEME, strlen(PIGEON_NIDD_SCHEME)) == 0) {
    apn = endpoint + strlen(PIGEON_NIDD_SCHEME);
  }

  if (!apn || *apn == '\0' || strpbrk(apn, "/:?")) {
    LOG_ERR("NIDD endpoint must be nidd://<APN>, e.g. nidd://VZWSCEF");
    return -EINVAL;
  }

  pigeon_nidd_apn = apn;

  return 0;
}

static int pigeon_nidd_load_key(void) {
  const char *hex = CONFIG_PIGEON_NIDD_CLAIM_KEY;
  uint8_t key[PIGEON_NIDD_KEY_BYTES];
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_status_t status;

  /* The key goes out in HELLO exactly as written, and the platform names it in lowercase. */
  for (size_t i = 0; i < PIGEON_NIDD_KEY_CHARS; i++) {
    if (!((hex[i] >= '0' && hex[i] <= '9') || (hex[i] >= 'a' && hex[i] <= 'f'))) {
      LOG_ERR("CONFIG_PIGEON_NIDD_CLAIM_KEY must be 32 lowercase hex characters");
      return -EINVAL;
    }
  }

  (void)hex2bin(hex, PIGEON_NIDD_KEY_CHARS, key, sizeof(key));

  status = psa_crypto_init();
  if (status == PSA_SUCCESS) {
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, 8 * PIGEON_NIDD_KEY_BYTES);
    status = psa_import_key(&attr, key, sizeof(key), &pigeon_nidd_key);
  }

  if (status != PSA_SUCCESS) {
    LOG_ERR("NIDD: claim key import failed: %d", status);
    return -EIO;
  }

  return 0;
}

static void pigeon_nidd_lte_handler(const struct lte_lc_evt *const evt) {
  switch (evt->type) {
    case LTE_LC_EVT_PSM_UPDATE:
      atomic_set(&pigeon_nidd_active_time, evt->psm_cfg.active_time);
      if (evt->psm_cfg.active_time < 0) {
        LOG_WRN("NIDD: network did not grant PSM");
        break;
      }
      LOG_INF(
          "NIDD: network granted PSM, TAU %d s, active time %d s", evt->psm_cfg.tau,
          evt->psm_cfg.active_time
      );
      if (evt->psm_cfg.active_time == 0) {
        LOG_WRN("NIDD: active time 0 s leaves no window in which a push can page this device");
      }
      break;
    case LTE_LC_EVT_EDRX_UPDATE: {
      if (evt->edrx_cfg.mode == LTE_LC_LTE_MODE_NONE) {
        LOG_INF("NIDD: eDRX not in use");
        break;
      }

      int cycle_ms = (int)(evt->edrx_cfg.edrx * 1000);
      int active_s = (int)atomic_get(&pigeon_nidd_active_time);

      LOG_INF(
          "NIDD: network eDRX cycle %d ms, paging window %d ms", cycle_ms,
          (int)(evt->edrx_cfg.ptw * 1000)
      );
      if (active_s > 0 && cycle_ms > active_s * 1000) {
        LOG_WRN(
            "NIDD: eDRX cycle exceeds the %d s active time: a push may never be paged", active_s
        );
      }
      break;
    }
    case LTE_LC_EVT_RRC_UPDATE:
      LOG_INF("NIDD: radio %s", evt->rrc_mode == LTE_LC_RRC_MODE_CONNECTED ? "connected" : "idle");
      break;
    case LTE_LC_EVT_PDN: {
      uint8_t cid = (uint8_t)atomic_get(&pigeon_nidd_cid);

      if (evt->pdn.cid != cid) {
        break;
      }

      switch (evt->pdn.type) {
        case LTE_LC_EVT_PDN_ACTIVATED:
          atomic_set(&pigeon_nidd_pdn_up, 1);
          k_sem_give(&pigeon_nidd_pdn_sem);
          LOG_INF("NIDD: Non-IP PDN up on CID %u", cid);
          break;
        case LTE_LC_EVT_PDN_DEACTIVATED:
        case LTE_LC_EVT_PDN_NETWORK_DETACH:
          atomic_clear(&pigeon_nidd_pdn_up);
          LOG_INF("NIDD: Non-IP PDN down on CID %u", cid);
          break;
        case LTE_LC_EVT_PDN_CTX_DESTROYED:
          /* lte_lc frees every context but the default one when the modem powers off. */
          atomic_set(&pigeon_nidd_ctx_lost, 1);
          atomic_clear(&pigeon_nidd_pdn_up);
          LOG_INF("NIDD: PDP context %u destroyed", cid);
          break;
        case LTE_LC_EVT_PDN_ESM_ERROR:
          LOG_WRN("NIDD: ESM error %d on CID %u", evt->pdn.esm_err, cid);
          break;
        default:
          break;
      }
      break;
    }
    default:
      break;
  }
}

/* Defines the Non-IP context: a new one, or CID 0 on a NIDD-only plan. */
static int pigeon_nidd_ctx_setup(void) {
  uint8_t cid = 0;
  int err = 0;

  if (IS_ENABLED(CONFIG_PIGEON_NIDD_DEDICATED_CID)) {
    err = lte_lc_pdn_ctx_create(&cid);
  }

  if (!err) {
    atomic_set(&pigeon_nidd_cid, cid);
    err = lte_lc_pdn_ctx_configure(cid, pigeon_nidd_apn, LTE_LC_PDN_FAM_NONIP, NULL);
  }

  return err;
}

int pigeon_nidd_configure(void) {
  int err;

  if (pigeon_nidd.configured) {
    return 0;
  }

  err = pigeon_nidd_parse_endpoint();
  if (!err) {
    err = pigeon_nidd_load_key();
  }
  if (err) {
    return err;
  }

  if (IS_ENABLED(CONFIG_PIGEON_NIDD_DEDICATED_CID)) {
    /* Set rather than assumed: an image without a dedicated context may have left CID 0
     * Non-IP. No APN means the one the subscription names. */
    err = lte_lc_pdn_ctx_configure(0, NULL, LTE_LC_PDN_FAM_IPV4V6, NULL);
  } else {
    err = lte_lc_pdn_default_ctx_events_enable();
  }
  if (!err) {
    err = pigeon_nidd_ctx_setup();
  }
  if (err) {
    LOG_ERR("NIDD: PDP context setup failed: %d (pigeon_init() must run before the attach)", err);
    return err;
  }

  lte_lc_register_handler(pigeon_nidd_lte_handler);

  /* The modem keeps both settings across images, so neither is left to what it holds. A
   * refusal is logged rather than returned: a power setting must not keep the device off the
   * network. */
  err = lte_lc_psm_req(true);
  if (err) {
    LOG_ERR("NIDD: PSM request failed: %d (check CONFIG_LTE_PSM_REQ_RPTAU and _RAT)", err);
  } else {
    LOG_INF("NIDD: PSM requested");
  }

  err = lte_lc_edrx_req(IS_ENABLED(CONFIG_LTE_EDRX_REQ));
  if (err) {
    LOG_ERR("NIDD: eDRX setting failed: %d (check CONFIG_LTE_EDRX_REQ)", err);
  } else {
    LOG_INF("NIDD: eDRX %s", IS_ENABLED(CONFIG_LTE_EDRX_REQ) ? "requested" : "off");
  }

  pigeon_nidd.configured = true;
  LOG_INF(
      "NIDD: Non-IP on CID %u, APN %s", (unsigned int)atomic_get(&pigeon_nidd_cid), pigeon_nidd_apn
  );

  return 0;
}

/* The only way a socket is closed, so no path closes a descriptor twice or one that a newer
 * socket now holds. */
static void pigeon_nidd_close_locked(void) {
  if (pigeon_nidd.fd >= 0) {
    (void)zsock_close(pigeon_nidd.fd);
    pigeon_nidd.fd = -1;
    pigeon_nidd.fd_gen++;
  }
}

static int pigeon_nidd_socket_locked(int pdn_id) {
  int one = 1;
  int fd = zsock_socket(AF_PACKET, SOCK_RAW, 0);

  if (fd < 0) {
    return -errno;
  }

  /* An unbound raw socket rides the default PDN and can take downlink meant for others. */
  if (zsock_setsockopt(fd, SOL_SOCKET, SO_BINDTOPDN, &pdn_id, sizeof(pdn_id))) {
    int err = -errno;

    (void)zsock_close(fd);
    return err;
  }

  /* Modem firmware older than mfw_nrf91x1 2.0.1 has no such option. Nothing depends on it: a
   * socket that outlived its PDN is re-created by the next open anyway. */
  if (zsock_setsockopt(fd, SOL_SOCKET, SO_KEEPOPEN, &one, sizeof(one)) &&
      !pigeon_nidd_keepopen_logged) {
    pigeon_nidd_keepopen_logged = true;
    LOG_INF("NIDD: this modem refuses SO_KEEPOPEN: %d", -errno);
  }

  pigeon_nidd.fd = fd;
  pigeon_nidd.fd_gen++;
  k_sem_give(&pigeon_nidd_open_sem);
  LOG_INF("NIDD: Non-IP socket open on PDN %d", pdn_id);

  return 0;
}

static int pigeon_nidd_open_locked(void) {
  uint8_t cid;
  int pdn_id = 0;
  int err = 0;

  if (k_uptime_get() < pigeon_nidd.next_open_ms) {
    return -ENOTCONN;
  }

  if (atomic_get(&pigeon_nidd_ctx_lost)) {
    pigeon_nidd_close_locked();
    err = pigeon_nidd_ctx_setup();
    if (!err) {
      atomic_clear(&pigeon_nidd_ctx_lost);
    }
  }

  cid = (uint8_t)atomic_get(&pigeon_nidd_cid);

  if (!err && !atomic_get(&pigeon_nidd_pdn_up)) {
    /* A socket whose PDN went down answers every call with an error until it is closed. */
    pigeon_nidd_close_locked();
    k_sem_reset(&pigeon_nidd_pdn_sem);
    if (IS_ENABLED(CONFIG_PIGEON_NIDD_DEDICATED_CID)) {
      err = lte_lc_pdn_activate(cid, NULL, NULL);
    }
    /* AT+CGACT answering is not the PDN being up: the activation event is. */
    if (!err && k_sem_take(&pigeon_nidd_pdn_sem, PIGEON_NIDD_PDN_WAIT)) {
      LOG_WRN("NIDD: no activation event for CID %u within 60 s", cid);
    }
  }

  if (!err && pigeon_nidd.fd >= 0) {
    return 0;
  }

  if (!err) {
    pdn_id = lte_lc_pdn_id_get(cid);
    err = pdn_id < 0 ? pdn_id : 0;
  }
  if (!err) {
    err = pigeon_nidd_socket_locked(pdn_id);
  }

  if (err) {
    pigeon_nidd.next_open_ms =
        k_uptime_get() + (int64_t)pigeon_nidd.open_backoff_sec * MSEC_PER_SEC;
    LOG_WRN(
        "NIDD: Non-IP socket not open: %d, next try in %u s", err, pigeon_nidd.open_backoff_sec
    );
    pigeon_nidd.open_backoff_sec =
        MIN(2 * pigeon_nidd.open_backoff_sec, PIGEON_NIDD_OPEN_BACKOFF_MAX_SEC);
    return err;
  }

  /* The PDN has an id, so it is up even if its activation event never arrived. */
  atomic_set(&pigeon_nidd_pdn_up, 1);
  pigeon_nidd.open_backoff_sec = PIGEON_NIDD_OPEN_BACKOFF_MIN_SEC;

  return 0;
}

/* Sends the frame in pigeon_nidd_tx. Never asks for release: the reply it may draw arrives only
 * while the connection this send opened is up. */
static int pigeon_nidd_transmit_locked(size_t len, const char *what) {
  int rai = RAI_ONGOING;
  int err;

  if (pigeon_nidd.fd < 0 || !atomic_get(&pigeon_nidd_pdn_up) || atomic_get(&pigeon_nidd_ctx_lost)) {
    err = pigeon_nidd_open_locked();
    if (err) {
      return err;
    }
  }

  /* A release requested after this send would cut the connection before its reply. */
  (void)k_work_cancel_delayable(&pigeon_nidd_release_work);

  if (zsock_setsockopt(pigeon_nidd.fd, SOL_SOCKET, SO_RAI, &rai, sizeof(rai))) {
    LOG_DBG("NIDD: SO_RAI RAI_ONGOING refused: %d", -errno);
  }

  if (zsock_send(pigeon_nidd.fd, pigeon_nidd_tx, len, 0) < 0) {
    err = -errno;
    LOG_WRN("NIDD: send of %s failed: %d", what, err);
    /* ENETUNREACH is what a socket kept open across a lost PDN answers. */
    if (err == -ENETDOWN || err == -ENETUNREACH) {
      atomic_clear(&pigeon_nidd_pdn_up);
    }
    return err;
  }

  LOG_INF("NIDD: sent %s, %u bytes", what, (unsigned int)len);

  return 0;
}

static int pigeon_nidd_hello_locked(void) {
  pigeon_nidd_tx[0] = PIGEON_NIDD_HELLO;
  memcpy(&pigeon_nidd_tx[1], CONFIG_PIGEON_NIDD_CLAIM_KEY, PIGEON_NIDD_KEY_CHARS);

  int err = pigeon_nidd_transmit_locked(1 + PIGEON_NIDD_KEY_CHARS, "HELLO");

  if (!err) {
    pigeon_nidd.hello_due = false;
    pigeon_nidd.hello_owed = true;
    pigeon_nidd.hello_sent_ms = k_uptime_get();
  }

  return err;
}

/* Refuses a billable frame without a radio access while it cannot go; otherwise first sends any
 * HELLO still due, since the platform stores nothing from an unclaimed pigeon. */
static int pigeon_nidd_gate_locked(void) {
  if (!pigeon_nidd.running || pigeon_nidd.stop_requested) {
    return -ENOTCONN;
  }
  if (pigeon_nidd.unclaimed) {
    return -EACCES;
  }
  if (k_uptime_get() < pigeon_nidd.paused_until_ms) {
    return -EAGAIN;
  }

  return pigeon_nidd.hello_due ? pigeon_nidd_hello_locked() : 0;
}

/* One report framing for the application's report and the receive thread's repeat of it. */
static int pigeon_nidd_send_report_locked(void) {
  int len = snprintk(
      (char *)&pigeon_nidd_tx[1], sizeof(pigeon_nidd_tx) - 1,
      "{\"current_config\":%s,\"current_version\":%d}", pigeon_nidd_current,
      pigeon_nidd.report_version
  );

  if (len < 0 || (size_t)len >= sizeof(pigeon_nidd_tx) - 1) {
    return -EMSGSIZE;
  }

  pigeon_nidd_tx[0] = PIGEON_NIDD_SHADOW_REPORT;

  int err = pigeon_nidd_transmit_locked(1 + (size_t)len, "SHADOW_REPORT");

  if (!err) {
    pigeon_nidd.report_pending = true;
    pigeon_nidd.report_sent_ms = k_uptime_get();
  }

  return err;
}

/* Compared without an early exit, so the time taken says nothing about the tag. */
static bool pigeon_nidd_tag_ok(const uint8_t *frame, size_t len) {
  uint8_t mac[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
  char hex[PIGEON_NIDD_TAG_CHARS + 1];
  size_t mac_len;
  uint8_t diff = 0;
  psa_status_t status = psa_mac_compute(
      pigeon_nidd_key, PSA_ALG_HMAC(PSA_ALG_SHA_256), frame, len - PIGEON_NIDD_TAG_CHARS, mac,
      sizeof(mac), &mac_len
  );

  if (status != PSA_SUCCESS) {
    LOG_ERR("NIDD: psa_mac_compute failed: %d", status);
    return false;
  }

  (void)bin2hex(mac, PIGEON_NIDD_TAG_BYTES, hex, sizeof(hex));

  for (size_t i = 0; i < PIGEON_NIDD_TAG_CHARS; i++) {
    diff |= (uint8_t)hex[i] ^ frame[len - PIGEON_NIDD_TAG_CHARS + i];
  }

  return diff == 0;
}

/* One header number: 1 to 10 digits, then exactly `end`. Returns the bytes read with `end`, or 0
 * when the text is not that. */
static size_t pigeon_nidd_header_number(const uint8_t *p, size_t len, uint8_t end, uint32_t *out) {
  uint64_t n = 0;
  size_t i = 0;

  while (i < len && i < PIGEON_NIDD_HEADER_DIGITS && p[i] >= '0' && p[i] <= '9') {
    n = n * 10 + (p[i] - '0');
    i++;
  }

  if (i == 0 || i == len || p[i] != end || n > UINT32_MAX) {
    return 0;
  }

  *out = (uint32_t)n;

  return i + 1;
}

/* Settles the pending report with `result`. Lock held. */
static void pigeon_nidd_settle_report_locked(int result, struct pigeon_nidd_outcome *out) {
  pigeon_nidd.report_pending = false;
  pigeon_nidd.report_result = result;
  k_sem_give(&pigeon_nidd_report_sem);
  out->answered = true;
}

static void pigeon_nidd_on_shadow(
    uint32_t tv, uint32_t cv, const uint8_t *config, size_t config_len,
    struct pigeon_nidd_outcome *out
) {
  int64_t now = k_uptime_get();

  LOG_INF("NIDD: SHADOW %u %u, %u config bytes", tv, cv, (unsigned int)config_len);

  pigeon_nidd.current_version = MAX(pigeon_nidd.current_version, (int32_t)cv);

  /* A SHADOW is the answer to HELLO. */
  if (pigeon_nidd.hello_owed) {
    pigeon_nidd.hello_owed = false;
    out->answered = true;
  }

  if (pigeon_nidd.report_pending && (int32_t)cv >= pigeon_nidd.report_version) {
    LOG_INF("NIDD: report v%d confirmed", pigeon_nidd.report_version);
    pigeon_nidd_settle_report_locked(0, out);
  }

  if (!pigeon_nidd.have_shadow || (int32_t)tv > pigeon_nidd.target_version) {
    if (config_len >= sizeof(pigeon_nidd_target)) {
      LOG_WRN(
          "NIDD: dropped SHADOW v%u: its %u-byte config exceeds "
          "CONFIG_PIGEON_SHADOW_CONFIG_MAX - 1",
          tv, (unsigned int)config_len
      );
    } else {
      memcpy(pigeon_nidd_target, config, config_len);
      pigeon_nidd_target[config_len] = '\0';
      pigeon_nidd.target_version = (int32_t)tv;
      pigeon_nidd.have_shadow = true;
      k_sem_give(&pigeon_nidd_shadow_sem);
      out->updated = true;
    }
  } else {
    LOG_INF(
        "NIDD: SHADOW v%u is not newer than v%d: read for its current_version", tv,
        pigeon_nidd.target_version
    );
  }

  /* The platform holds less than this device reported, so that report was lost; unless it was
   * only just sent, since telemetry sent before it can draw this SHADOW first. */
  if (pigeon_nidd.report_version >= 0 && (int32_t)cv < pigeon_nidd.report_version &&
      !(pigeon_nidd.report_pending &&
        now - pigeon_nidd.report_sent_ms < PIGEON_NIDD_REPLY_WAIT_MS)) {
    LOG_INF(
        "NIDD: platform holds v%u, below the applied v%d: reporting again", cv,
        pigeon_nidd.report_version
    );
    out->rereport = true;
  }
}

static void pigeon_nidd_on_status(uint32_t code, uint32_t arg, struct pigeon_nidd_outcome *out) {
  int64_t now = k_uptime_get();

  switch (code) {
    case PIGEON_NIDD_STORED:
      /* The argument is a version, bounded like one. */
      if (arg > INT32_MAX) {
        LOG_WRN("NIDD: dropped STATUS STORED with a malformed version");
        return;
      }
      LOG_INF("NIDD: STATUS STORED %u", arg);
      pigeon_nidd.current_version = MAX(pigeon_nidd.current_version, (int32_t)arg);
      if (pigeon_nidd.report_pending && (int32_t)arg >= pigeon_nidd.report_version) {
        LOG_INF("NIDD: report v%d confirmed", pigeon_nidd.report_version);
        pigeon_nidd_settle_report_locked(0, out);
      }
      return;
    case PIGEON_NIDD_PAUSED: {
      uint32_t hold = MIN(arg, (uint32_t)PIGEON_NIDD_PAUSE_MAX_SEC);

      pigeon_nidd.paused_until_ms = now + (int64_t)hold * MSEC_PER_SEC;
      LOG_INF("NIDD: account paused, billable sends held for %u s", hold);
      if (pigeon_nidd.report_pending) {
        pigeon_nidd_settle_report_locked(-EAGAIN, out);
      }
      return;
    }
    case PIGEON_NIDD_UNCLAIMED:
      if (arg == 1) {
        pigeon_nidd.unclaimed = true;
        if (pigeon_nidd.hello_owed) {
          pigeon_nidd.hello_owed = false;
          out->answered = true;
        }
        LOG_ERR(
            "NIDD: claim key refused: billable sends stop until reboot; rebuild with the "
            "pigeon's current key"
        );
        if (pigeon_nidd.report_pending) {
          pigeon_nidd_settle_report_locked(-EACCES, out);
        }
        return;
      }
      if (arg == 0) {
        /* A waiting report stays pending: the HELLO this notice asks for re-claims, and the
         * application reports again at its next wake. */
        if (pigeon_nidd.unclaimed) {
          return;
        }
        if (pigeon_nidd.hello_due || now - pigeon_nidd.hello_sent_ms >= PIGEON_NIDD_HELLO_HOLD_MS) {
          pigeon_nidd.hello_due = true;
          out->hello = true;
        } else {
          LOG_INF(
              "NIDD: unclaimed, HELLO sent %d s ago: not repeated",
              (int)((now - pigeon_nidd.hello_sent_ms) / MSEC_PER_SEC)
          );
        }
        return;
      }
      break;
    default:
      break;
  }

  LOG_INF("NIDD: ignored STATUS %u %u", code, arg);
}

/* After every verified frame: release the radio once nothing more is owed, unless the
 * application is about to report on this same connection. Any downlink restarts the quiet time
 * of a release already scheduled. */
static void pigeon_nidd_plan_release_locked(const struct pigeon_nidd_outcome *out) {
  int64_t now = k_uptime_get();
  bool owed =
      (pigeon_nidd.hello_owed && now - pigeon_nidd.hello_sent_ms < PIGEON_NIDD_REPLY_WAIT_MS) ||
      (pigeon_nidd.report_pending && now - pigeon_nidd.report_sent_ms < PIGEON_NIDD_REPLY_WAIT_MS);
  bool report_expected = out->updated && pigeon_nidd.target_version > pigeon_nidd.current_version;

  if (report_expected) {
    (void)k_work_cancel_delayable(&pigeon_nidd_release_work);
  } else if ((out->answered && !owed) || k_work_delayable_is_pending(&pigeon_nidd_release_work)) {
    (void)k_work_reschedule(&pigeon_nidd_release_work, K_MSEC(CONFIG_PIGEON_NIDD_RAI_IDLE_MS));
  }
}

static void pigeon_nidd_handle(const uint8_t *frame, size_t len) {
  struct pigeon_nidd_outcome out = {0};
  struct pigeon_shadow_doc doc = {0};
  uint32_t first = 0;
  uint32_t second = 0;
  size_t header = 0;
  size_t body_len;
  pigeon_event_cb_t cb;

  /* The bench's byte-for-byte evidence. Uplinks are never dumped: HELLO carries the key. */
  LOG_HEXDUMP_DBG(frame, len, "NIDD downlink");

  if (len < 1 + PIGEON_NIDD_TAG_CHARS) {
    LOG_WRN("NIDD: dropped a %u-byte frame: too short", (unsigned int)len);
    return;
  }
  if (!(frame[0] & PIGEON_NIDD_FROM_PLATFORM)) {
    LOG_WRN("NIDD: dropped a %u-byte frame: not a platform frame", (unsigned int)len);
    return;
  }
  if (!pigeon_nidd_tag_ok(frame, len)) {
    LOG_WRN("NIDD: dropped a %u-byte frame whose tag did not verify", (unsigned int)len);
    return;
  }

  body_len = len - 1 - PIGEON_NIDD_TAG_CHARS;

  if (frame[0] == PIGEON_NIDD_SHADOW || frame[0] == PIGEON_NIDD_STATUS) {
    size_t used = pigeon_nidd_header_number(&frame[1], body_len, ' ', &first);

    if (used) {
      size_t rest = pigeon_nidd_header_number(&frame[1 + used], body_len - used, '\n', &second);

      header = rest ? used + rest : 0;
    }

    if (!header || (frame[0] == PIGEON_NIDD_SHADOW && (first > INT32_MAX || second > INT32_MAX)) ||
        (frame[0] == PIGEON_NIDD_STATUS && header != body_len)) {
      LOG_WRN("NIDD: dropped platform frame 0x%02x: malformed header", frame[0]);
      return;
    }
  }

  k_mutex_lock(&pigeon_nidd_lock, K_FOREVER);

  if (frame[0] == PIGEON_NIDD_SHADOW) {
    pigeon_nidd_on_shadow(first, second, &frame[1 + header], body_len - header, &out);
  } else if (frame[0] == PIGEON_NIDD_STATUS) {
    pigeon_nidd_on_status(first, second, &out);
  } else {
    LOG_INF("NIDD: ignored platform frame type 0x%02x", frame[0]);
  }

  pigeon_nidd_plan_release_locked(&out);

  cb = pigeon_nidd.cb;
  doc.target_version = pigeon_nidd.target_version;
  doc.current_version = pigeon_nidd.current_version;
  doc.target_config = pigeon_nidd_target;
  doc.current_config = pigeon_nidd_current;

  k_mutex_unlock(&pigeon_nidd_lock);

  if (out.updated && cb) {
    cb(PIGEON_EVENT_SHADOW_UPDATE, &doc);
  }

  if (!out.rereport && !out.hello) {
    return;
  }

  if (k_mutex_lock(&pigeon_nidd_lock, PIGEON_NIDD_LOCK_WAIT)) {
    LOG_WRN("NIDD: busy, %s skipped", out.rereport ? "repeat report" : "HELLO");
    return;
  }

  int err = 0;

  if (out.rereport) {
    err = pigeon_nidd_gate_locked();
    if (!err) {
      err = pigeon_nidd_send_report_locked();
    }
  } else if (pigeon_nidd.running && !pigeon_nidd.stop_requested && pigeon_nidd.hello_due) {
    /* One that fails stays due, and the next billable send carries it first. */
    err = pigeon_nidd_hello_locked();
  }

  k_mutex_unlock(&pigeon_nidd_lock);

  if (err) {
    LOG_INF("NIDD: %s not sent: %d", out.rereport ? "repeat report" : "HELLO", err);
  }
}

static void pigeon_nidd_release(struct k_work *work) {
  int rai = RAI_NO_DATA;

  ARG_UNUSED(work);

  /* Busy means a send is under way, and that send wants the connection. */
  if (k_mutex_lock(&pigeon_nidd_lock, K_NO_WAIT)) {
    return;
  }

  if (pigeon_nidd.fd >= 0) {
    if (zsock_setsockopt(pigeon_nidd.fd, SOL_SOCKET, SO_RAI, &rai, sizeof(rai))) {
      LOG_DBG("NIDD: SO_RAI RAI_NO_DATA refused: %d", -errno);
    } else {
      LOG_INF("NIDD: requested radio release");
    }
  }

  k_mutex_unlock(&pigeon_nidd_lock);
}

static void pigeon_nidd_thread_fn(void *p1, void *p2, void *p3) {
  uint32_t announced_gen = 0;

  ARG_UNUSED(p1);
  ARG_UNUSED(p2);
  ARG_UNUSED(p3);

  while (true) {
    k_mutex_lock(&pigeon_nidd_lock, K_FOREVER);
    bool stop = pigeon_nidd.stop_requested;
    int fd = pigeon_nidd.fd;
    uint32_t gen = pigeon_nidd.fd_gen;
    pigeon_event_cb_t cb = pigeon_nidd.cb;
    k_mutex_unlock(&pigeon_nidd_lock);

    if (stop) {
      break;
    }

    if (fd < 0) {
      (void)k_sem_take(&pigeon_nidd_open_sem, K_FOREVER);
      continue;
    }

    if (gen != announced_gen) {
      announced_gen = gen;
      if (cb) {
        cb(PIGEON_EVENT_CONNECTED, NULL);
      }
    }

    ssize_t len = zsock_recv(fd, pigeon_nidd_rx, sizeof(pigeon_nidd_rx), 0);

    if (len > 0) {
      pigeon_nidd_handle(pigeon_nidd_rx, (size_t)len);
      continue;
    }

    int err = len < 0 ? -errno : -ENOTCONN;

    k_mutex_lock(&pigeon_nidd_lock, K_FOREVER);
    if (pigeon_nidd.fd_gen == gen) {
      pigeon_nidd_close_locked();
    }
    stop = pigeon_nidd.stop_requested;
    k_mutex_unlock(&pigeon_nidd_lock);

    if (!stop) {
      LOG_WRN("NIDD: receive ended: %d", err);
    }

    if (cb) {
      cb(PIGEON_EVENT_DISCONNECTED, NULL);
    }

    if (stop) {
      break;
    }
  }

  k_mutex_lock(&pigeon_nidd_lock, K_FOREVER);
  pigeon_nidd.running = false;
  k_mutex_unlock(&pigeon_nidd_lock);
}

int pigeon_nidd_start(pigeon_event_cb_t cb) {
  char imei[16];
  int err;

  k_mutex_lock(&pigeon_nidd_lock, K_FOREVER);

  if (!pigeon_nidd.configured) {
    k_mutex_unlock(&pigeon_nidd_lock);
    return -ENODEV;
  }

  if (pigeon_nidd.running) {
    k_mutex_unlock(&pigeon_nidd_lock);
    return -EALREADY;
  }

  /* Set in the same hold as the check, so a second start answers -EALREADY. */
  pigeon_nidd.running = true;
  pigeon_nidd.stop_requested = false;
  pigeon_nidd.cb = cb;
  pigeon_nidd.have_shadow = false;
  pigeon_nidd.report_version = -1;
  pigeon_nidd.report_pending = false;
  pigeon_nidd.hello_due = true;
  pigeon_nidd.hello_owed = false;
  pigeon_nidd.next_open_ms = 0;
  pigeon_nidd.open_backoff_sec = PIGEON_NIDD_OPEN_BACKOFF_MIN_SEC;
  /* A previous stop gave these. */
  k_sem_reset(&pigeon_nidd_shadow_sem);
  k_sem_reset(&pigeon_nidd_report_sem);
  k_sem_reset(&pigeon_nidd_open_sem);
  k_sem_reset(&pigeon_nidd_pdn_sem);

  k_mutex_unlock(&pigeon_nidd_lock);

  if (nrf_modem_at_scanf("AT+CGSN=1", "+CGSN: \"%15[0-9]\"", imei) == 1) {
    LOG_INF("NIDD: modem IMEI %s, the id this pigeon is registered under", imei);
  }

  k_mutex_lock(&pigeon_nidd_lock, K_FOREVER);
  err = pigeon_nidd_open_locked();
  k_mutex_unlock(&pigeon_nidd_lock);

  if (err) {
    LOG_WRN("NIDD: retrying the Non-IP socket at the next send");
  }

  k_tid_t tid = k_thread_create(
      &pigeon_nidd_thread_data, pigeon_nidd_stack, K_THREAD_STACK_SIZEOF(pigeon_nidd_stack),
      pigeon_nidd_thread_fn, NULL, NULL, NULL, PIGEON_NIDD_THREAD_PRIORITY, 0, K_NO_WAIT
  );

  if (!tid) {
    k_mutex_lock(&pigeon_nidd_lock, K_FOREVER);
    pigeon_nidd.running = false;
    pigeon_nidd_close_locked();
    k_mutex_unlock(&pigeon_nidd_lock);
    return -EAGAIN;
  }

  k_thread_name_set(tid, "pigeon_nidd");

  /* A HELLO that fails stays due, and the next billable send carries it first. */
  if (!k_mutex_lock(&pigeon_nidd_lock, PIGEON_NIDD_LOCK_WAIT)) {
    if (pigeon_nidd.hello_due) {
      (void)pigeon_nidd_hello_locked();
    }
    k_mutex_unlock(&pigeon_nidd_lock);
  }

  return 0;
}

int pigeon_nidd_stop(void) {
  k_mutex_lock(&pigeon_nidd_lock, K_FOREVER);
  bool running = pigeon_nidd.running;

  pigeon_nidd.stop_requested = true;
  /* Closing is what ends the receive thread's blocking recv. */
  pigeon_nidd_close_locked();
  if (pigeon_nidd.report_pending) {
    pigeon_nidd.report_pending = false;
    pigeon_nidd.report_result = -ENOTCONN;
    k_sem_give(&pigeon_nidd_report_sem);
  }
  k_mutex_unlock(&pigeon_nidd_lock);

  (void)k_work_cancel_delayable(&pigeon_nidd_release_work);

  if (!running) {
    return 0;
  }

  k_sem_give(&pigeon_nidd_open_sem);
  k_sem_give(&pigeon_nidd_shadow_sem);

  int err = k_thread_join(&pigeon_nidd_thread_data, PIGEON_NIDD_STOP_WAIT);

  if (err) {
    LOG_WRN("NIDD: receive thread did not exit within 10 s: %d", err);
  }

  return err;
}

int pigeon_shadow_get(struct pigeon_shadow_doc *out) {
  int err = 0;

  if (!out) {
    return -EINVAL;
  }

  k_mutex_lock(&pigeon_nidd_lock, K_FOREVER);
  bool running = pigeon_nidd.running;
  bool have = pigeon_nidd.have_shadow;
  k_mutex_unlock(&pigeon_nidd_lock);

  if (!running) {
    LOG_ERR("NIDD not started: call pigeon_nidd_start() after the attach");
    return -ENOTCONN;
  }

  if (!have && k_sem_take(&pigeon_nidd_shadow_sem, K_SECONDS(CONFIG_PIGEON_NIDD_SHADOW_WAIT_SEC))) {
    LOG_WRN("NIDD: no SHADOW within %d s", CONFIG_PIGEON_NIDD_SHADOW_WAIT_SEC);
    return -EAGAIN;
  }

  /* A stop gives the semaphore too. */
  k_mutex_lock(&pigeon_nidd_lock, K_FOREVER);
  if (!pigeon_nidd.running || pigeon_nidd.stop_requested) {
    err = -ENOTCONN;
  } else if (!pigeon_nidd.have_shadow) {
    err = -EAGAIN;
  } else {
    memcpy(pigeon_nidd_target_out, pigeon_nidd_target, sizeof(pigeon_nidd_target_out));
    out->target_version = pigeon_nidd.target_version;
    out->current_version = pigeon_nidd.current_version;
    out->target_config = pigeon_nidd_target_out;
    out->current_config = pigeon_nidd_current;
    out->updated_at = 0;
  }
  k_mutex_unlock(&pigeon_nidd_lock);

  return err;
}

int pigeon_shadow_report(int32_t current_version, const char *current_config) {
  int err;

  if (!current_config) {
    return -EINVAL;
  }

  /* The confirmation arrives on that thread, so waiting for it there cannot end. */
  if (k_current_get() == &pigeon_nidd_thread_data) {
    return -EDEADLK;
  }

  size_t config_len = strlen(current_config);

  if (config_len >= sizeof(pigeon_nidd_current)) {
    LOG_ERR("Shadow report does not fit (see CONFIG_PIGEON_SHADOW_CONFIG_MAX)");
    return -EMSGSIZE;
  }

  if (k_mutex_lock(&pigeon_nidd_lock, PIGEON_NIDD_LOCK_WAIT)) {
    return -EBUSY;
  }

  err = pigeon_nidd_gate_locked();
  if (!err) {
    memcpy(pigeon_nidd_current, current_config, config_len + 1);
    pigeon_nidd.report_version = current_version;
    pigeon_nidd.report_result = -ETIMEDOUT;
    k_sem_reset(&pigeon_nidd_report_sem);
    err = pigeon_nidd_send_report_locked();
  }

  k_mutex_unlock(&pigeon_nidd_lock);

  if (err) {
    return err;
  }

  /* Left pending on a timeout, so a late confirmation still counts. */
  if (k_sem_take(&pigeon_nidd_report_sem, K_SECONDS(CONFIG_PIGEON_NIDD_REPLY_WAIT_SEC))) {
    return -ETIMEDOUT;
  }

  k_mutex_lock(&pigeon_nidd_lock, K_FOREVER);
  err = pigeon_nidd.report_result;
  k_mutex_unlock(&pigeon_nidd_lock);

  return err;
}

int pigeon_transport_report_telemetry(
    const char *body, size_t body_len, struct pigeon_http_result *res
) {
  int err;

  if (res) {
    /* No HTTP status on this transport; only a pause's hold is carried back. */
    *res = (struct pigeon_http_result){0};
  }

  if (1 + body_len > sizeof(pigeon_nidd_tx)) {
    return -EMSGSIZE;
  }

  if (k_mutex_lock(&pigeon_nidd_lock, PIGEON_NIDD_LOCK_WAIT)) {
    return -EBUSY;
  }

  err = pigeon_nidd_gate_locked();
  if (err == -EAGAIN && res) {
    res->retry_after_sec =
        (uint32_t)DIV_ROUND_UP(pigeon_nidd.paused_until_ms - k_uptime_get(), (int64_t)MSEC_PER_SEC);
  }
  if (!err) {
    pigeon_nidd_tx[0] = PIGEON_NIDD_TELEMETRY;
    memcpy(&pigeon_nidd_tx[1], body, body_len);
    err = pigeon_nidd_transmit_locked(1 + body_len, "TELEMETRY");
  }

  k_mutex_unlock(&pigeon_nidd_lock);

  return err;
}
