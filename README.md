# pigeon

Zephyr RTOS module: the on-device client library for **PidgeIoT**. It runs on
the physical asset/gateway and talks to the `dovecote` edge backend over a
wire protocol shared with the `capsules` models in the main PidgeIoT
monorepo. This repo has its own git history — it's a standalone Zephyr
module, not a workspace member of the monorepo.

Sample applications that build and exercise this module live in the sibling
[`pigeon-examples`](https://github.com/justins-engineering/pigeon-examples)
repo.

## Status

Early scaffold. `pigeon_init()` is implemented; `pigeon_set_shadow_param()`
is declared in `pigeon.h` but has no body yet. `src/pigeon_coap.c` and
`src/pigeon_https.c` (the actual transports) don't exist yet — `pigeon.h`'s
data structures and `pigeon_init()` work today regardless, since
`CMakeLists.txt` compiles `pigeon_core.c` unconditionally.

## Data model

`include/pigeon.h` mirrors the wire shapes in `capsules::Connector` /
`HttpsConfig` / `CoapConfig` / `PigeonShadow` / `PigeonShadowUpdateRequest`,
so device code can build config and shadow payloads that stay compatible
with `dovecote`:

- `struct pigeon_config` — `device_id` (also the JWT audience) plus a
  `struct pigeon_connector`.
- `struct pigeon_connector` — tagged union of `struct pigeon_https_config`
  (`endpoint`, `token`) or `struct pigeon_coap_config` (adds
  `dtls_psk_identity`/`dtls_psk_secret`).
- `struct pigeon_shadow_doc` — `target_version`/`current_version` counters
  plus raw JSON `target_config`/`current_config` text, as returned by
  `GET /pigeon/shadow/get`.
- `struct pigeon_shadow_update_request` — the body for
  `POST /pigeon/shadow/update`.

## Build

This is a Zephyr **module**, not a standalone app — `CMakeLists.txt`
hard-fails if `ZEPHYR_BASE` isn't set. It must be pulled into a Zephyr
application/workspace, either via a west manifest project entry or
`ZEPHYR_EXTRA_MODULES` (see `pigeon-examples/samples/pigeon_module.cmake`
for the latter):

```cmake
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../pigeon)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
```

### Kconfig

- `CONFIG_PIGEON` — menuconfig gate for the connector choice below. Leaving
  it disabled is fine; `pigeon_init()` and the data structures work either
  way, since only the (not-yet-implemented) transport source files are
  gated behind it.
- `CONFIG_PIGEON_CONNECTOR_COAP` / `CONFIG_PIGEON_CONNECTOR_HTTPS` —
  mutually exclusive choice, only relevant once a transport is implemented.
- `CONFIG_PIGEON_LOG_LEVEL` — 0 (none) to 4 (debug), default 3.

## License

AGPLv3 — see [LICENSE](LICENSE).
