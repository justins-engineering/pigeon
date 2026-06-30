#include <pigeon.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(pigeon, CONFIG_PIGEON_LOG_LEVEL);

int pigeon_init(const struct pigeon_config *config) {
  if (!config || !config->device_id) {
    LOG_ERR("Invalid configuration parameters supplied");
    return -EINVAL;
  }

  LOG_INF("Initializing Pigeon tracking instance: %s", config->device_id);

  #if defined(CONFIG_PIGEON_CONNECTOR_COAP)
      LOG_INF("Transport mapped to low-overhead CoAP edge pipeline");
  #elif defined(CONFIG_PIGEON_CONNECTOR_HTTPS)
      LOG_INF("Transport mapped to secure HTTPS edge pipeline");
  #endif

  return 0;
}
