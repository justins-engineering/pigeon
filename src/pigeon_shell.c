/*
 * Remote diagnostic shell over the device WebSocket channel (task #34).
 * Executes a small, owner-configured allowlist of shell commands relayed
 * by dovecote as "shell_cmd" frames (pigeon_ws.c's frame dispatch), and
 * replies with a "shell_output" frame (pigeon_ws_send_shell_output(),
 * pigeon_ws.c) -- see zephyr/Kconfig's CONFIG_PIGEON_SHELL help text and
 * pigeon's CLAUDE.md for the full design writeup this file implements.
 *
 * Deliberately NOT a transport module like pigeon_https.c/pigeon_coap.c:
 * it owns no connection of its own, just a dedicated execution thread fed
 * by pigeon_ws.c's frame dispatch and Zephyr's shell_dummy backend.
 */
#include <errno.h>
#include <pigeon.h>
#include <stdbool.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/shell/shell.h>
#include <zephyr/shell/shell_dummy.h>
#include <zephyr/shell/shell_log_backend.h>

#include "pigeon_internal.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

#define PIGEON_SHELL_REQUEST_ID_MAX 64
#define PIGEON_SHELL_CMD_MAX        128

/* One command in flight at a time, by design (see this file's header and
 * zephyr/Kconfig) -- a depth-1 msgq is both the queue and the enforcement
 * mechanism: a second shell_cmd arriving while one is still executing
 * simply can't be enqueued, see pigeon_shell_handle_cmd() below. */
struct pigeon_shell_request {
  char request_id[PIGEON_SHELL_REQUEST_ID_MAX];
  char cmd[PIGEON_SHELL_CMD_MAX];
};

K_MSGQ_DEFINE(pigeon_shell_msgq, sizeof(struct pigeon_shell_request), 1, 4);

/*
 * Checks cmd against CONFIG_PIGEON_SHELL_ALLOWLIST's comma-separated
 * prefixes -- a *positive* allowlist enforced here, before
 * shell_execute_cmd() is ever reached, rather than trusting "nothing
 * dangerous is compiled into the shell" (see this Kconfig option's help
 * text for why that posture is fragile). A prefix matches only at a
 * command-word boundary: "pigeon shadow" matches "pigeon shadow" and
 * "pigeon shadow foo", never "pigeon shadowfoo". An empty (default)
 * allowlist matches nothing, i.e. denies every command until the device
 * owner deliberately populates it -- CONFIG_PIGEON_SHELL_ALLOW_ALL is the
 * explicit, loudly-documented escape hatch for owners who want none of
 * this filtering at all.
 */
static bool pigeon_shell_cmd_allowed(const char *cmd) {
#if defined(CONFIG_PIGEON_SHELL_ALLOW_ALL)
  ARG_UNUSED(cmd);
  return true;
#else
  size_t cmd_len = strlen(cmd);
  const char *p = CONFIG_PIGEON_SHELL_ALLOWLIST;

  while (*p != '\0') {
    while (*p == ' ') {
      p++;
    }

    const char *comma = strchr(p, ',');
    size_t tok_len = comma ? (size_t)(comma - p) : strlen(p);

    while (tok_len > 0 && p[tok_len - 1] == ' ') {
      tok_len--;
    }

    if (tok_len > 0 && cmd_len >= tok_len && strncmp(cmd, p, tok_len) == 0 &&
        (cmd_len == tok_len || cmd[tok_len] == ' ')) {
      return true;
    }

    if (!comma) {
      break;
    }
    p = comma + 1;
  }

  return false;
#endif /* CONFIG_PIGEON_SHELL_ALLOW_ALL */
}

/*
 * Runs on the dedicated shell thread (never the CONFIG_PIGEON_WS worker
 * thread, see zephyr/Kconfig) for one already-dequeued request: allowlist
 * gate, execute via shell_dummy, capture output, reply. Every branch below
 * always sends exactly one shell_output frame back, even on denial --
 * silence would be indistinguishable from a lost frame to the operator.
 */
static void pigeon_shell_run(const struct pigeon_shell_request *req) {
  LOG_WRN("Shell: cmd requested id=%s cmd=\"%s\"", req->request_id, req->cmd);

  if (!pigeon_shell_cmd_allowed(req->cmd)) {
    LOG_WRN("Shell: cmd denied (not allowlisted) id=%s", req->request_id);
    pigeon_ws_send_shell_output(req->request_id, "command not permitted", -EACCES, false);
    return;
  }

  const struct shell *sh = shell_backend_dummy_get_ptr();

  /* CONFIG_SHELL_LOG_BACKEND defaults to y whenever CONFIG_LOG=y (see
   * zephyr/subsys/shell/Kconfig), and shell_dummy autostarts with it
   * enabled at CONFIG_SHELL_DUMMY_INIT_LOG_LEVEL (default: info) --
   * shell_execute_cmd() itself never touches this, it's purely a side
   * effect of the dummy shell being a live log sink like any other shell
   * backend. Log processing for this backend runs on shell_dummy's own
   * internal thread (woken by SHELL_SIGNAL_LOG_MSG), fully independent of
   * whichever thread is running our clear->execute->get_output window --
   * so *any* LOG_* call anywhere in the image (including this file's own
   * two log lines) that gets drained during that window lands straight in
   * sh_dummy->buf via the same write() shell_execute_cmd()'s own output
   * goes through. Confirmed empirically on native_sim: a background thread
   * logging every few ms contaminated ~40% of captured outputs with
   * interleaved log lines and shell escape sequences before this fix,
   * 0/30 after.
   *
   * z_shell_log_backend_disable() flips this backend's state to
   * SHELL_LOG_BACKEND_DISABLED, which its process() callback checks before
   * ever copying a new message into its mpsc buffer (shell_log_backend.c)
   * -- so nothing new can be queued for delivery here from the moment
   * this call returns. Disabling before clear_output(), not after, means
   * clear_output() also wipes out anything that landed in the tiny gap
   * between disable() and clear() (the one part of this window disable()
   * alone can't prevent: draining an already-queued message doesn't check
   * this state, only enqueuing a new one does). z_shell_log_backend_enable()
   * at the end restores normal shell log routing for the next poll/idle
   * period, and its own internal fifo_reset() discards anything that
   * queued up (and was rightly dropped) while we were disabled, so it
   * doesn't all land in the *next* command's capture window instead. */
  z_shell_log_backend_disable(sh->log_backend);
  shell_backend_dummy_clear_output(sh);

  int exit_code = shell_execute_cmd(sh, req->cmd);

  size_t out_len = 0;
  const char *output = shell_backend_dummy_get_output(sh, &out_len);

  z_shell_log_backend_enable(sh->log_backend, (void *)sh, sh->ctx->log_level);

  /* shell_dummy.c's write() silently drops anything past
   * sizeof(sh_dummy->buf) - 1 with no error signal of its own (confirmed
   * by reading it -- the only trace left behind is that the stored length
   * lands exactly on that ceiling). CONFIG_SHELL_BACKEND_DUMMY_BUF_SIZE is
   * the same Kconfig symbol pigeon_ws_send_shell_output() sizes its own
   * escape buffer off of, so this comparison and that one are always
   * checking the same real limit. */
  bool truncated = out_len >= (size_t)(CONFIG_SHELL_BACKEND_DUMMY_BUF_SIZE - 1);

  LOG_INF(
      "Shell: executed id=%s exit_code=%d truncated=%s", req->request_id, exit_code,
      truncated ? "true" : "false"
  );

  pigeon_ws_send_shell_output(req->request_id, output, exit_code, truncated);
}

static void pigeon_shell_thread_fn(void *p1, void *p2, void *p3) {
  ARG_UNUSED(p1);
  ARG_UNUSED(p2);
  ARG_UNUSED(p3);

  struct pigeon_shell_request req;

  while (1) {
    k_msgq_get(&pigeon_shell_msgq, &req, K_FOREVER);
    pigeon_shell_run(&req);
  }
}

/* Deliberately lower priority (higher number) than pigeon_ws.c's worker
 * thread (raw priority 10, see PIGEON_WS_THREAD_PRIORITY) -- if a command
 * ever does wedge this thread indefinitely, the WS worker must still win
 * scheduling contention so pings/reconnect keep working regardless (see
 * this file's header comment and zephyr/Kconfig's CONFIG_PIGEON_SHELL help
 * text: isolation onto a dedicated thread protects the WS channel from a
 * hung command, but only if that thread can never outrank it). */
#define PIGEON_SHELL_THREAD_PRIORITY 12

K_THREAD_DEFINE(
    pigeon_shell_tid, CONFIG_PIGEON_SHELL_THREAD_STACK_SIZE, pigeon_shell_thread_fn, NULL, NULL,
    NULL, PIGEON_SHELL_THREAD_PRIORITY, 0, 0
);

void pigeon_shell_handle_cmd(const char *request_id, const char *cmd) {
  if (!request_id || !cmd) {
    return;
  }

  struct pigeon_shell_request req;

  strncpy(req.request_id, request_id, sizeof(req.request_id) - 1);
  req.request_id[sizeof(req.request_id) - 1] = '\0';
  strncpy(req.cmd, cmd, sizeof(req.cmd) - 1);
  req.cmd[sizeof(req.cmd) - 1] = '\0';

  /* Depth-1 queue: K_NO_WAIT means this never blocks the caller (pigeon_ws's
   * frame dispatch, itself running on the WS worker thread -- must stay
   * fast, see zephyr/Kconfig). A full queue means a command is already
   * executing; reply immediately with a distinguishing exit_code instead
   * of silently dropping the new request or making the operator guess
   * whether it was lost in transit. */
  if (k_msgq_put(&pigeon_shell_msgq, &req, K_NO_WAIT) != 0) {
    LOG_WRN("Shell: busy, rejecting id=%s (previous command still executing)", req.request_id);
    pigeon_ws_send_shell_output(req.request_id, "device busy executing another command", -EBUSY, false);
  }
}
