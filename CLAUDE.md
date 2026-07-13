# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`pigeon` is a Zephyr RTOS module: the on-device client library for **PidgeIoT**. It runs on the physical asset/gateway and is the counterpart to the `dovecote` edge backend and `capsules` shared models in the main PidgeIoT monorepo at **`~/pidgeiot`**. This repo is a standalone Zephyr module (own git history, no path/workspace relationship to `~/pidgeiot`) — the two only need to agree on the wire protocol.

**When working on anything protocol-, auth-, or connector-shaped here, read `~/pidgeiot/CLAUDE.md` first and cross-check against these backend source files**, since this device library must stay wire-compatible with them:

- `~/pidgeiot/capsules/src/lib.rs` — the `Connector` enum (`Https(HttpsConfig)` / `Coap(CoapConfig)`) this library's `enum pigeon_connector_type` and `struct pigeon_config` must match the shape of. `HttpsConfig`/`CoapConfig` carry `endpoint` + `token` (+ DTLS PSK identity/secret for CoAP); on this side, `endpoint`/`token` are build-time `CONFIG_PIGEON_ENDPOINT`/`CONFIG_PIGEON_TOKEN` Kconfig strings rather than runtime struct fields — `PIGEON_CONNECTOR_TYPE` is already a build-time choice, so only one endpoint/token pair is ever live. PSK fields stay in `struct pigeon_coap_config` since they're optional per-device.
- `~/pidgeiot/dovecote/src/helpers/auth.rs` (`require_device_auth`) — devices authenticate with an Ed25519-signed JWT, `Bearer`-prefixed, audience-scoped to the device's own Durable Object/pigeon ID. Whatever this library sends as `auth_token` must satisfy that verifier.
- `~/pidgeiot/dovecote/src/objects/pigeons.rs` (`build_http_endpoint`/`build_coap_endpoint`, and the `/pigeon/shadow/get`, `/pigeon/shadow/update` routes) — defines the actual endpoint URL shapes (`https://api.pidgeiot.com/device/pigeons/{id}`, `coaps://api.pidgeiot.com/device/pigeons/{id}`) and the shadow document (`target_config`/`current_config` + version counters) this library syncs against.
- The backend issues/rotates the device token via `token/refresh`; it is out of scope for this library to sign or validate tokens, only to present them.
- **Known wire-compat gap (intentional, as of this writing):** this device stack has no UDP support yet, so `struct pigeon_coap_config` speaks CoAP-over-TLS/TCP (RFC 8323 `coaps+tcp://`, fields `tls_psk_identity`/`tls_psk_secret`) while `capsules::CoapConfig`/`build_coap_endpoint` still only produce `coaps://` (UDP/DTLS) with `dtls_psk_identity`/`dtls_psk_secret`. This side is deliberately ahead of the backend; `~/pidgeiot` needs a corresponding `coaps+tcp://` mode before the CoAP connector can actually talk to it. Check whether that's landed yet before assuming wire-compat here.

## Current state

Early scaffold — only `pigeon_init` and `pigeon_set_shadow_param` (declared, not yet implemented) exist in `src/pigeon_core.c`. `src/pigeon_coap.c` and `src/pigeon_https.c` are referenced by `CMakeLists.txt` via `zephyr_library_sources_ifdef` but don't exist yet; add them when implementing each transport, gated on `CONFIG_PIGEON_CONNECTOR_COAP` / `CONFIG_PIGEON_CONNECTOR_HTTPS` respectively.

## Build

This is a Zephyr **module**, not a standalone buildable app — `CMakeLists.txt` hard-fails if `ZEPHYR_BASE` isn't set (see its guard clause). It must be built as a dependency from within a Zephyr application/workspace (`west build`), not compiled directly in this repo.

- `zephyr/module.yml` wires the module into a Zephyr manifest (`west.yml`) via `build.cmake`/`build.kconfig`.
- `zephyr/Kconfig` exposes `CONFIG_PIGEON` (menuconfig gate), a mutually-exclusive choice between `CONFIG_PIGEON_CONNECTOR_COAP` and `CONFIG_PIGEON_CONNECTOR_HTTPS`, `CONFIG_PIGEON_ENDPOINT`/`CONFIG_PIGEON_TOKEN` (string, required when `PIGEON` is enabled), and `CONFIG_PIGEON_LOG_LEVEL` (0-4).
- `.vscode/settings.json` expects clangd compile commands at `build/https_init/compile_commands.json` — a symlink at `build` points to `~/pigeon-examples/build`, the shared build dir of the `https_init` sample in the sibling `pigeon-examples` repo (`samples/https_init`), which pulls this module in via `ZEPHYR_EXTRA_MODULES`.

## Conventions

- 2-space indentation (no `.clang-format` yet — follow the existing style in `src/pigeon_core.c`).
- Public API lives in `include/pigeon.h` behind an `extern "C"` guard; keep new public symbols there, not in `src/`.
- Use Zephyr's own logging (`LOG_MODULE_REGISTER`/`LOG_INF`/`LOG_ERR`), gated by `CONFIG_PIGEON_LOG_LEVEL`, not `printf`.
