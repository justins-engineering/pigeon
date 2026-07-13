#include <pigeon.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(pigeon, CONFIG_PIGEON_LOG_LEVEL);

int pigeon_init(const struct pigeon_config *config) {
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
      break;
    default:
      LOG_ERR("Unknown connector type: %d", config->connector.type);
      return -EINVAL;
  }

  return 0;
}
