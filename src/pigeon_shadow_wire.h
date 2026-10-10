#ifndef PIDGEIOT_PIGEON_SHADOW_WIRE_H_
#define PIDGEIOT_PIGEON_SHADOW_WIRE_H_

#include <stddef.h>
#include <stdint.h>
#include <zephyr/data/json.h>

#include <pigeon.h>

/*
 * capsules::PigeonShadow as every connector receives it: the body of a shadow GET over HTTPS or
 * CoAP, MQTT's retained target, and the "shadow" object of a WS shadow_update. Both configs are
 * JSON text carried inside JSON strings, so each arrives escaped, and JSON_TOK_STRING_BUF
 * unescapes it in place but refuses a string whose escaped length does not fit its buffer. Each
 * buffer therefore holds a quarter more than CONFIG_PIGEON_SHADOW_CONFIG_MAX (a quote or a
 * backslash costs one byte more on the wire), and pigeon_shadow_wire_doc() holds the decoded
 * text to the cap itself, which is what callers size their own copies by.
 */
#define PIGEON_SHADOW_CONFIG_WIRE_MAX \
  (CONFIG_PIGEON_SHADOW_CONFIG_MAX + CONFIG_PIGEON_SHADOW_CONFIG_MAX / 4)

/* The largest whole document: both configs at the wire cap plus the versions, the timestamp and
 * the key names, rounded up. */
#define PIGEON_SHADOW_DOC_MAX (2 * PIGEON_SHADOW_CONFIG_WIRE_MAX + 128)

struct pigeon_shadow_wire {
  int32_t target_version;
  int32_t current_version;
  char target_config[PIGEON_SHADOW_CONFIG_WIRE_MAX];
  char current_config[PIGEON_SHADOW_CONFIG_WIRE_MAX];
  int64_t updated_at;
};

#define PIGEON_SHADOW_WIRE_FIELDS 5

/* Sized so a containing descriptor can nest it with JSON_OBJ_DESCR_OBJECT. */
extern const struct json_obj_descr pigeon_shadow_wire_descr[PIGEON_SHADOW_WIRE_FIELDS];

/*
 * Points out's configs into wire, which must outlive out. -EMSGSIZE when either decoded config
 * is CONFIG_PIGEON_SHADOW_CONFIG_MAX bytes or more.
 */
int pigeon_shadow_wire_doc(const struct pigeon_shadow_wire *wire, struct pigeon_shadow_doc *out);

/*
 * 0 when config can be reported, -EMSGSIZE when it is CONFIG_PIGEON_SHADOW_CONFIG_MAX bytes or
 * more, or when escaped as the platform sends it back in every later shadow it would not fit a
 * config buffer above: the platform stores a report it accepts, and from then on every GET would
 * fail to decode, so the device would never see the target that lets it report a smaller one.
 * Counts a control character as \u00XX, the longest escape, so it may refuse a config the
 * platform would have shortened; it never accepts one that cannot come back.
 */
int pigeon_shadow_report_fits(const char *config);

/*
 * Parses one whole document from json[0..len), which the parse rewrites, into wire, then
 * pigeon_shadow_wire_doc(). -EBADMSG when a field is missing; a parse failure returns the
 * parser's own negative code.
 */
int pigeon_shadow_wire_decode(
    char *json, size_t len, struct pigeon_shadow_wire *wire, struct pigeon_shadow_doc *out
);

#endif /* PIDGEIOT_PIGEON_SHADOW_WIRE_H_ */
