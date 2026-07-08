#include <pigeon.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(pigeon, CONFIG_PIGEON_LOG_LEVEL);

int pigeon_init(const struct pigeon_config *config) {
  if (!config || !config->device_id) {
    LOG_ERR("Invalid configuration parameters supplied");
    return -EINVAL;
  }

  LOG_INF("Initializing Pigeon tracking instance: %s", config->device_id);

  switch (config->connector.type) {
    case PIGEON_CONNECTOR_HTTPS:
      if (!config->connector.cfg.https.endpoint || !config->connector.cfg.https.token) {
        LOG_ERR("HTTPS connector requires endpoint and token");
        return -EINVAL;
      }
      LOG_INF(
          "Transport mapped to secure HTTPS edge pipeline: %s", config->connector.cfg.https.endpoint
      );
      break;
    case PIGEON_CONNECTOR_COAP:
      if (!config->connector.cfg.coap.endpoint || !config->connector.cfg.coap.token) {
        LOG_ERR("CoAP connector requires endpoint and token");
        return -EINVAL;
      }
      LOG_INF(
          "Transport mapped to low-overhead CoAP edge pipeline: %s",
          config->connector.cfg.coap.endpoint
      );
      break;
    default:
      LOG_ERR("Unknown connector type: %d", config->connector.type);
      return -EINVAL;
  }

  return 0;
}
