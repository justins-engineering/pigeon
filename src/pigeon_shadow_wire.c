#include <errno.h>
#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include "pigeon_shadow_wire.h"

LOG_MODULE_DECLARE(pigeon, CONFIG_PIGEON_LOG_LEVEL);

const struct json_obj_descr pigeon_shadow_wire_descr[PIGEON_SHADOW_WIRE_FIELDS] = {
    JSON_OBJ_DESCR_PRIM(struct pigeon_shadow_wire, target_version, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct pigeon_shadow_wire, current_version, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct pigeon_shadow_wire, target_config, JSON_TOK_STRING_BUF),
    JSON_OBJ_DESCR_PRIM(struct pigeon_shadow_wire, current_config, JSON_TOK_STRING_BUF),
    JSON_OBJ_DESCR_PRIM(struct pigeon_shadow_wire, updated_at, JSON_TOK_INT64),
};

int pigeon_shadow_wire_doc(const struct pigeon_shadow_wire *wire, struct pigeon_shadow_doc *out) {
  /* Under the cap means a NUL within it, which also bounds the read of a buffer the parser
   * never filled. */
  if (!memchr(wire->target_config, '\0', CONFIG_PIGEON_SHADOW_CONFIG_MAX) ||
      !memchr(wire->current_config, '\0', CONFIG_PIGEON_SHADOW_CONFIG_MAX)) {
    LOG_ERR("Shadow config over CONFIG_PIGEON_SHADOW_CONFIG_MAX");
    return -EMSGSIZE;
  }

  out->target_version = wire->target_version;
  out->current_version = wire->current_version;
  out->target_config = wire->target_config;
  out->current_config = wire->current_config;
  out->updated_at = wire->updated_at;

  return 0;
}

int pigeon_shadow_wire_decode(
    char *json, size_t len, struct pigeon_shadow_wire *wire, struct pigeon_shadow_doc *out
) {
  int64_t decoded = json_obj_parse(
      json, len, pigeon_shadow_wire_descr, ARRAY_SIZE(pigeon_shadow_wire_descr), wire
  );

  if (decoded < 0) {
    LOG_ERR("Shadow JSON failed to parse: %lld", decoded);
    return (int)decoded;
  }

  if ((decoded & BIT_MASK(PIGEON_SHADOW_WIRE_FIELDS)) != BIT_MASK(PIGEON_SHADOW_WIRE_FIELDS)) {
    LOG_ERR("Shadow JSON is missing fields (decoded=0x%llx)", decoded);
    return -EBADMSG;
  }

  return pigeon_shadow_wire_doc(wire, out);
}
