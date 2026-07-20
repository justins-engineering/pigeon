#ifndef PIDGEIOT_PIGEON_INTERNAL_H_
#define PIDGEIOT_PIGEON_INTERNAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pigeon.h>

/*
 * Populated by pigeon_init() from config->connector.coap. Both fields stay
 * NULL if the active connector isn't PIGEON_CONNECTOR_COAP, or if the app
 * didn't supply PSK credentials for it. Lets pigeon_coap.c reach pigeon_init()'s
 * runtime config without pigeon_core.c's static state becoming public API.
 */
const struct pigeon_coap_config *pigeon_active_coap_config(void);

/*
 * Escapes '"' and '\', plus every RFC 8259 sec 7 control character
 * (0x00-0x1F), so an arbitrary caller string (a shadow telemetry key/val,
 * see pigeon_set_shadow_param()) can't break out of the JSON string it's
 * embedded in, or otherwise produce invalid JSON. Truncates rather than
 * overflows if out is too small. Implemented once in pigeon_core.c --
 * pigeon_https.c and pigeon_coap.c each used to carry their own identical
 * copy of this; pigeon_ws.c would have made a third, so this was promoted
 * out instead.
 */
size_t pigeon_json_escape(const char *in, char *out, size_t out_len);

/*
 * Implemented by whichever transport module is compiled in (pigeon_https.c
 * or pigeon_coap.c -- see CMakeLists.txt's zephyr_library_sources_ifdef, only
 * one is ever built). Sends a single telemetry key/val to the platform:
 * POST <endpoint>/telemetry, body {"key": "val"}, matching dovecote's
 * report_telemetry_device (see pigeon_shadow_flush() in pigeon.h).
 */
int pigeon_transport_report_shadow(const char *key, const char *val);

/*
 * Implemented only by pigeon_https.c (see zephyr/Kconfig: CONFIG_PIGEON_LOG_UPLOAD
 * depends on CONFIG_PIGEON_CONNECTOR_HTTPS -- CoAP has no equivalent transport
 * for this yet). POSTs a raw binary chunk of accumulated Zephyr dictionary-mode
 * log records to <endpoint>/logs, device-authenticated the same way as
 * pigeon_transport_report_shadow() above. Called only from
 * pigeon_log_backend.c's flush work handler, never from application code.
 */
int pigeon_transport_upload_logs(const uint8_t *data, size_t len);

#if defined(CONFIG_PIGEON_FOTA)
/*
 * Implemented only by pigeon_https.c (CONFIG_PIGEON_FOTA depends on
 * CONFIG_PIGEON_CONNECTOR_HTTPS -- no CoAP download transport yet). Issues
 * a device-authed HTTP Range GET against <endpoint>/firmware for
 * [offset, offset+buf_len) and copies whatever body bytes come back into
 * buf. *out_len is set to the number of bytes actually written to buf
 * (may be less than buf_len, e.g. on the final chunk). *out_total is set
 * from the response's Content-Range total field when present, 0
 * otherwise -- callers should treat 0 as "server didn't confirm a total
 * this response", not "total is zero". Returns 0 on success, negative
 * errno on transport/auth/HTTP-status failure. Called only from
 * pigeon_fota_apply() (pigeon_fota.c).
 */
int pigeon_transport_download_firmware(
    size_t offset, uint8_t *buf, size_t buf_len, size_t *out_len, size_t *out_total
);
#endif /* CONFIG_PIGEON_FOTA */

/*
 * Shared cap on a decoded shadow target_config/current_config's raw JSON
 * byte length. Originated in pigeon_https.c (see its history for the
 * 640/256 -> 320 bump when the "firmware" shadow key landed); moved here so
 * pigeon_ws.c's shadow_update frame decode (CONFIG_PIGEON_WS, below) can
 * share the exact same cap rather than drifting its own. pigeon_coap.c
 * intentionally keeps its own separate, smaller PIGEON_COAP_CONFIG_MAX --
 * CoAP has no WS counterpart and unifying the two isn't part of this reuse
 * rule.
 */
#define PIGEON_HTTPS_CONFIG_MAX 320

#if defined(CONFIG_PIGEON_WS)
/*
 * Implemented only by pigeon_ws.c. Sends {"type":"telemetry","metrics":
 * {"<key-esc>":"<val-esc>"}} over the open WS socket. Returns 0 on send
 * success, -ENOTCONN when the socket is down (caller falls back to the
 * HTTPS transport hook, pigeon_transport_report_shadow() above). This is
 * fire-and-forget: the server sends no ack and swallows internal failures
 * silently -- acceptable for latest-value-per-key telemetry, NOT
 * acceptable for shadow_report, which therefore stays on HTTPS where an
 * HTTP status confirms persistence (see pigeon_shadow_flush() in
 * pigeon_core.c for the fallback wiring).
 */
int pigeon_ws_report_telemetry(const char *key, const char *val);
#endif /* CONFIG_PIGEON_WS */

#if defined(CONFIG_PIGEON_SHELL)
/*
 * Implemented only by pigeon_ws.c. Builds and sends
 * {"type":"shell_output","request_id":"<id-esc>","output":"<output-esc>",
 * "exit_code":<n>,"truncated":<bool>} over the open WS socket -- same
 * "-ENOTCONN on a down socket" convention as pigeon_ws_report_telemetry()
 * above, though pigeon_shell.c's caller (the dedicated shell thread) has
 * nothing to fall back to if this fails, unlike pigeon_shadow_flush()'s
 * HTTPS fallback -- a shell reply that can't be delivered is simply lost,
 * same as any other WS send failure while reconnecting. `output` may be
 * NULL (encoded as an empty string) for a reply that never got as far as
 * capturing shell_dummy's buffer (e.g. a "device busy" or "not permitted"
 * reply). `truncated` is OR'd with this function's own internal detection
 * of the *escaped* output overflowing its own buffer -- see pigeon_ws.c
 * for why that's a second, independent truncation source from
 * pigeon_shell.c's shell_dummy-buffer-overflow check.
 */
int pigeon_ws_send_shell_output(
    const char *request_id, const char *output, int exit_code, bool truncated
);

/*
 * Implemented only by pigeon_shell.c. Called from pigeon_ws.c's inbound
 * frame dispatch (pigeon_ws_dispatch_frame()) on a "shell_cmd" frame.
 * Copies request_id/cmd into a fixed-size struct and hands it to the
 * dedicated shell execution thread via a depth-1 k_msgq -- returns
 * immediately either way, never runs shell_execute_cmd() on the caller's
 * own thread (the WS worker thread, which must stay free to keep sending
 * pings/handling reconnects -- see zephyr/Kconfig's CONFIG_PIGEON_SHELL
 * help text). If the msgq is already full (a command is still executing),
 * sends an immediate "busy" shell_output reply itself rather than queuing
 * or silently dropping the new request.
 */
void pigeon_shell_handle_cmd(const char *request_id, const char *cmd);
#endif /* CONFIG_PIGEON_SHELL */

#endif /* PIDGEIOT_PIGEON_INTERNAL_H_ */
