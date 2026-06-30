#ifndef PIDGEIOT_PIGEON_H_
#define PIDGEIOT_PIGEON_H_

#include <zephyr/types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum pigeon_connector_type {
  PIGEON_CONN_COAP,
  PIGEON_CONN_HTTPS
};

struct pigeon_config {
  const char *device_id;
  const char *auth_token;
  enum pigeon_connector_type connector;
};

/**
 * @brief Initialize the physical Pigeon client agent and restore shadow states
 * @param config Pointer to the instantiation parameters
 * @return 0 on success, negative error code on transport/auth initialization failure
 */
int pigeon_init(const struct pigeon_config *config);

/**
 * @brief Queue data or metrics to push to the digital twin edge instance
 * @param key The state key identifier
 * @param val The value payload string
 */
int pigeon_set_shadow_param(const char *key, const char *val);

#ifdef __cplusplus
}
#endif

#endif /* PIDGEIOT_PIGEON_H_ */
