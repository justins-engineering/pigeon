#ifndef PIDGEIOT_PIGEON_INTERNAL_H_
#define PIDGEIOT_PIGEON_INTERNAL_H_

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

#endif /* PIDGEIOT_PIGEON_INTERNAL_H_ */
