/*
 * Custom Zephyr log backend: captures dictionary-mode binary log records
 * (Zephyr's CONFIG_LOG_DICTIONARY_SUPPORT -- source strings stay on the host
 * side, never in the firmware image or over the air) into a bounded ring
 * buffer, and flushes it in batches (size threshold + max interval) as a raw
 * binary POST to <CONFIG_PIGEON_ENDPOINT>/logs via pigeon_transport_upload_logs()
 * (pigeon_https.c). Opt-in, gated by CONFIG_PIGEON_LOG_UPLOAD -- see
 * zephyr/Kconfig; this file is only compiled in when that's set (see
 * CMakeLists.txt).
 *
 * Host-side decode: the build's log_dictionary.json (generated because
 * CONFIG_PIGEON_LOG_UPLOAD selects CONFIG_LOG_DICTIONARY_SUPPORT) plus
 * Zephyr's own scripts/logging/dictionary/log_parser.py turn a raw uploaded
 * chunk back into readable log lines -- see pigeon-examples' README for the
 * full flow, since the dictionary database is a build artifact that never
 * leaves the host.
 */

#include <pigeon.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log_backend.h>
#include <zephyr/logging/log_core.h>
#include <zephyr/logging/log_output.h>
#include <zephyr/logging/log_output_dict.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/ring_buffer.h>

#include "pigeon_internal.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

RING_BUF_DECLARE(pigeon_log_rb, CONFIG_PIGEON_LOG_UPLOAD_BUF_SIZE);

/* Bytes dropped because pigeon_log_rb was full when char_out() tried to
 * write. Not logged from char_out() itself (a backend's own process()/
 * char_out() avoiding LOG_* calls is standard practice, see
 * log_backend_uart.c/log_backend_net.c) -- surfaced instead from the flush
 * work handler, which runs on the system workqueue, not the logging thread. */
static atomic_t pigeon_log_dropped;

/* Scratch buffer LOG_OUTPUT_DEFINE requires, unused by the dictionary code
 * path: log_dict_output_msg_process() writes the header/package/data
 * straight through char_out() below rather than through log_output's
 * line-formatting machinery (that's only exercised by text/syst output). */
static uint8_t pigeon_log_output_buf[16];

static int pigeon_log_char_out(uint8_t *data, size_t length, void *ctx) {
  ARG_UNUSED(ctx);

  uint32_t written = ring_buf_put(&pigeon_log_rb, data, (uint32_t)length);

  if (written < length) {
    atomic_add(&pigeon_log_dropped, (atomic_val_t)(length - written));
  }

  /* log_output_write() loops until the full length is consumed, retrying
   * whatever a lower return leaves outstanding -- so always report the
   * whole length as "handled" even when part of it was silently dropped
   * above, or the log core spins retrying bytes this backend will never
   * accept (matches log_backend_uart.c's char_out(), which always returns
   * length regardless of what happened to the bytes). */
  return (int)length;
}

LOG_OUTPUT_DEFINE(
    pigeon_log_output, pigeon_log_char_out, pigeon_log_output_buf, sizeof(pigeon_log_output_buf)
);

static void pigeon_log_flush_work_handler(struct k_work *work);

static K_WORK_DELAYABLE_DEFINE(pigeon_log_flush_work, pigeon_log_flush_work_handler);

static void pigeon_log_schedule_flush(k_timeout_t delay) {
  /* Runs on the system workqueue, not the logging thread -- a slow/hanging
   * POST (up to the 10s http_client_req() timeout in pigeon_https.c) stalls
   * other system work rather than backing up the log message queue. This is
   * a background, best-effort upload path; nothing here blocks a caller of
   * pigeon_set_shadow_param()/LOG_* or the app's own control flow. */
  k_work_reschedule(&pigeon_log_flush_work, delay);
}

static void pigeon_log_flush_work_handler(struct k_work *work) {
  ARG_UNUSED(work);

  atomic_val_t dropped = atomic_set(&pigeon_log_dropped, 0);

  if (dropped) {
    LOG_WRN("Pigeon log upload ring buffer full: dropped %d bytes", (int)dropped);
  }

  static uint8_t flush_buf[CONFIG_PIGEON_LOG_UPLOAD_BUF_SIZE];

  uint32_t len = ring_buf_get(&pigeon_log_rb, flush_buf, sizeof(flush_buf));

  if (len > 0) {
    int err = pigeon_transport_upload_logs(flush_buf, len);

    if (err) {
      /* Best-effort, like dovecote's Durable-Object-to-Postgres mirror
       * sync: this batch is lost, not re-queued. Re-enqueueing risks
       * unbounded retry growth against a ring buffer that keeps producing
       * new records while offline, and this feature is explicitly an
       * opportunistic low-data channel, not a guaranteed-delivery log
       * shipper -- gaps are an acceptable tradeoff for staying bounded. */
      LOG_WRN("Pigeon log upload POST failed (%d), %u bytes dropped", err, len);
    }
  }

  pigeon_log_schedule_flush(K_MSEC(CONFIG_PIGEON_LOG_UPLOAD_MAX_INTERVAL_MS));
}

static void pigeon_log_backend_process(
    const struct log_backend *const backend, union log_msg_generic *msg
) {
  ARG_UNUSED(backend);

  log_dict_output_msg_process(&pigeon_log_output, &msg->log, 0);

  if (ring_buf_size_get(&pigeon_log_rb) >= CONFIG_PIGEON_LOG_UPLOAD_BATCH_SIZE) {
    /* Batch threshold crossed: flush now instead of waiting out the rest of
     * the max-interval timer. k_work_reschedule() cancels and re-arms the
     * pending timer, so the periodic max-interval flush below effectively
     * restarts its countdown from this point too. */
    pigeon_log_schedule_flush(K_NO_WAIT);
  }
}

static void pigeon_log_backend_dropped(const struct log_backend *const backend, uint32_t cnt) {
  ARG_UNUSED(backend);

  /* Zephyr's own log-core drop notification (its internal message buffer
   * overflowed before this backend ever saw those messages) -- distinct
   * from pigeon_log_dropped above, which counts bytes this backend itself
   * discarded after seeing them. Both are real drops, just at different
   * points in the pipeline; log_dict_output_dropped_process() encodes this
   * one as its own dictionary record so the host-side parser reports it. */
  log_dict_output_dropped_process(&pigeon_log_output, cnt);
}

static void pigeon_log_backend_panic(const struct log_backend *const backend) {
  ARG_UNUSED(backend);
  /* Nothing to flush synchronously to the network mid-panic -- the ring
   * buffer just stops draining until/unless the device comes back up
   * (mirrors log_backend_net.c's panic(), which also just gives up on
   * further network I/O rather than attempting one last send). */
}

static void pigeon_log_backend_init(const struct log_backend *const backend) {
  ARG_UNUSED(backend);

  pigeon_log_schedule_flush(K_MSEC(CONFIG_PIGEON_LOG_UPLOAD_MAX_INTERVAL_MS));
}

const struct log_backend_api pigeon_log_backend_api = {
    .process = pigeon_log_backend_process,
    .dropped = IS_ENABLED(CONFIG_LOG_MODE_IMMEDIATE) ? NULL : pigeon_log_backend_dropped,
    .panic = pigeon_log_backend_panic,
    .init = pigeon_log_backend_init,
};

LOG_BACKEND_DEFINE(pigeon_log_backend, pigeon_log_backend_api, true);
