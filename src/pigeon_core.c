#include <pigeon.h>
#include <stdbool.h>
#include <string.h>
#include <zephyr/logging/log.h>

#include "pigeon_internal.h"

LOG_MODULE_REGISTER(pigeon, CONFIG_PIGEON_LOG_LEVEL);

#define PIGEON_SHADOW_KEY_MAX 32
#define PIGEON_SHADOW_VAL_MAX 128

/* Single-slot pending shadow delta, flushed on demand by pigeon_shadow_flush()
 * via the active transport's pigeon_transport_report_shadow(). */
static struct {
  bool initialized;
  bool pending;
  char pending_key[PIGEON_SHADOW_KEY_MAX];
  char pending_val[PIGEON_SHADOW_VAL_MAX];
} pigeon_state;

/* Runtime CoAP config from pigeon_init()'s config->connector.coap, exposed to
 * pigeon_coap.c via pigeon_active_coap_config(). Zero-valued (NULL fields)
 * unless the active connector is PIGEON_CONNECTOR_COAP. */
static struct pigeon_coap_config pigeon_coap_cfg;

const struct pigeon_coap_config *pigeon_active_coap_config(void) {
  return &pigeon_coap_cfg;
}

int pigeon_init(const struct pigeon_config* config) {
  if (!config || !config->device_id) {
    LOG_ERR("Invalid configuration parameters supplied");
    return -EINVAL;
  }

  if (!*CONFIG_PIGEON_ENDPOINT || !*CONFIG_PIGEON_TOKEN) {
    LOG_ERR("CONFIG_PIGEON_ENDPOINT and CONFIG_PIGEON_TOKEN must be set");
    return -EINVAL;
  }

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

  return 0;
}

int pigeon_set_shadow_param(const char* key, const char* val) {
  if (!key || !val) {
    LOG_ERR("Shadow param key/val must not be NULL");
    return -EINVAL;
  }

  if (!pigeon_state.initialized) {
    LOG_ERR("pigeon_set_shadow_param called before pigeon_init");
    return -ENODEV;
  }

  if (strlen(key) >= sizeof(pigeon_state.pending_key) ||
      strlen(val) >= sizeof(pigeon_state.pending_val)) {
    LOG_ERR(
        "Shadow param '%s' exceeds buffer limits (key<%d, val<%d)", key, PIGEON_SHADOW_KEY_MAX,
        PIGEON_SHADOW_VAL_MAX
    );
    return -ENOSPC;
  }

  if (pigeon_state.pending) {
    LOG_WRN(
        "Overwriting unflushed pending shadow param '%s'='%s' with '%s'='%s'",
        pigeon_state.pending_key, pigeon_state.pending_val, key, val
    );
  }

  strcpy(pigeon_state.pending_key, key);
  strcpy(pigeon_state.pending_val, val);
  pigeon_state.pending = true;

  LOG_INF("Queued shadow param update: %s=%s", key, val);

  return 0;
}

int pigeon_shadow_flush(void) {
  if (!pigeon_state.initialized) {
    LOG_ERR("pigeon_shadow_flush called before pigeon_init");
    return -ENODEV;
  }

  if (!pigeon_state.pending) {
    return -ENODATA;
  }

  int err = pigeon_transport_report_shadow(pigeon_state.pending_key, pigeon_state.pending_val);

  if (err) {
    LOG_WRN(
        "Shadow flush failed for '%s'='%s': %d (still queued, will retry)",
        pigeon_state.pending_key, pigeon_state.pending_val, err
    );
    return err;
  }

  LOG_INF("Flushed shadow param: %s=%s", pigeon_state.pending_key, pigeon_state.pending_val);
  pigeon_state.pending = false;

  return 0;
}
