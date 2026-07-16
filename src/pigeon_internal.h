#ifndef PIDGEIOT_PIGEON_INTERNAL_H_
#define PIDGEIOT_PIGEON_INTERNAL_H_

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

#endif /* PIDGEIOT_PIGEON_INTERNAL_H_ */
