# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`pigeon` is a Zephyr RTOS module: the on-device client library for **PidgeIoT**. It runs on the physical asset/gateway and is the counterpart to the `dovecote` edge backend and `capsules` shared models in the main PidgeIoT monorepo at **`~/pidgeiot`**. This repo is a standalone Zephyr module (own git history, no path/workspace relationship to `~/pidgeiot`) — the two only need to agree on the wire protocol.

**When working on anything protocol-, auth-, or connector-shaped here, read `~/pidgeiot/CLAUDE.md` first and cross-check against these backend source files**, since this device library must stay wire-compatible with them:

- `~/pidgeiot/capsules/src/lib.rs` — the `Connector` enum (`Https(HttpsConfig)` / `Coap(CoapConfig)`) this library's `enum pigeon_connector_type` and `struct pigeon_config` must match the shape of. `HttpsConfig`/`CoapConfig` carry `endpoint` + `token` (+ DTLS PSK identity/secret for CoAP); on this side, `endpoint`/`token` are build-time `CONFIG_PIGEON_ENDPOINT`/`CONFIG_PIGEON_TOKEN` Kconfig strings rather than runtime struct fields — `PIGEON_CONNECTOR_TYPE` is already a build-time choice, so only one endpoint/token pair is ever live. PSK fields stay in `struct pigeon_coap_config` since they're optional per-device.
- `~/pidgeiot/dovecote/src/objects/pigeons.rs` (`get_shadow_device`) / `src/objects/helpers.rs` (`verify_device_token`) — devices authenticate with an opaque, **not-JWT** bearer credential, `Bearer`-prefixed: a 69-byte binary blob (`version | expires_at | Ed25519 signature`), base64url-encoded. It carries no pigeon-id claim of its own — the backend verifies it against whichever pigeon's own stored `device_public_key` the request's URL path resolves to, so this library never needs to embed or check its own identity beyond sending the right endpoint + token pair. (Rewritten 2026-07-15, replacing an earlier Ed25519-signed-JWT scheme (`require_device_auth`) that had two successive bugs — a `sub`-vs-`aud` claim mismatch, then a follow-on ACL check that 403'd every device request — both mooted by this rewrite rather than patched.) Whatever this library sends as `auth_token` must satisfy `verify_device_token`.
- `~/pidgeiot/dovecote/src/objects/pigeons.rs` (`build_http_endpoint`/`build_coap_endpoint`, and the `/pigeon/shadow/get` (dashboard), `/pigeon/device/shadow` (device, no `X-User-Id`/ACL check — see above), `/pigeon/shadow/update` routes) — defines the actual endpoint URL shapes (`https://api.pidgeiot.com/device/pigeons/{id}`, `coaps://api.pidgeiot.com/device/pigeons/{id}`) and the shadow document (`target_config`/`current_config` + version counters) this library syncs against.
- The backend issues/rotates the device token via `token/refresh`, which mints a **brand-new keypair** and overwrites the pigeon's stored public key — this revokes every previously-issued token for that pigeon, not just the one being replaced. Out of scope for this library to mint or verify tokens, only to present whatever it's given.
- **Known wire-compat gap (intentional, as of this writing):** this device stack has no UDP support yet, so `struct pigeon_coap_config` speaks CoAP-over-TLS/TCP (RFC 8323 `coaps+tcp://`, fields `tls_psk_identity`/`tls_psk_secret`) while `capsules::CoapConfig`/`build_coap_endpoint` still only produce `coaps://` (UDP/DTLS) with `dtls_psk_identity`/`dtls_psk_secret`. This side is deliberately ahead of the backend; `~/pidgeiot` needs a corresponding `coaps+tcp://` mode before the CoAP connector can actually talk to it. Check whether that's landed yet before assuming wire-compat here.

## Current state

`src/pigeon_core.c`: `pigeon_init` implemented; `pigeon_set_shadow_param` queues a single-slot pending key/val delta, flushed on demand by `pigeon_shadow_flush()` via the active transport's `pigeon_transport_report_shadow()`.

`src/pigeon_https.c` implements all three device-facing operations, each device-authenticated with `Authorization: Bearer <CONFIG_PIGEON_TOKEN>` via Zephyr's `http_client_req()`:
- `pigeon_shadow_get()` — GET `<CONFIG_PIGEON_ENDPOINT>/shadow`, decoded with the declarative JSON parser (`zephyr/data/json.h`) into `target_version`/`current_version`/`target_config`/`current_config`/`updated_at`. Requires `CONFIG_PIGEON_HTTPS_SEC_TAG` (default 1) to match whatever sec_tag the app provisioned its CA cert under.
- `pigeon_shadow_flush()` / `pigeon_transport_report_shadow()` — POST `<endpoint>/telemetry`, body `{"key":"val"}`, matching dovecote's `report_telemetry_device` (latest-value-per-key store).
- `pigeon_shadow_report()` — POST `<endpoint>/shadow`, body `{"current_config":<raw JSON>,"current_version":<int>}`, matching `capsules::PigeonShadowReportRequest`/dovecote's `report_shadow_device`. Call after applying a `target_config` fetched via `pigeon_shadow_get()`.

`src/pigeon_coap.c` mirrors all three operations over CoAP-over-TLS/TCP (`coaps+tcp://`, RFC 8323), using a shared `pigeon_coap_exchange()` with a `leaf` path segment (`"shadow"` vs `"telemetry"`) instead of separate builders per operation. The device bearer token rides in a Uri-Query option (CoAP has no header mechanism to mirror `Authorization: Bearer`). Untestable against the real backend yet — dovecote has no CoAP listener at all (see "Known wire-compat gap" above), so every exchange will fail at `connect()`; the client-side plumbing is in place for when that lands.

See `samples/https_init` in the sibling `pigeon-examples` repo for the reference consumer: `src/shadow.c` fetches the shadow, applies `target_config` (app-defined `log`/`telemetry_interval`/`reboot` fields — the pigeon library itself doesn't parse `target_config`, see below), and polls on a loop driven by the shadow's own `telemetry_interval`.

## Feature-parity gaps (noted 2026-07, not yet addressed)

Comparing against Circuit Dojo's "Lion" IoT server (https://www.circuitdojo.com/posts/introducing-lion-iot-server) and, more importantly, against what **AWS IoT customers** — the actual target market — already expect from AWS IoT Core (Device Shadow, Jobs, Device Defender, fleet provisioning). Lion's specific protocol choices are one data point, not a spec to copy verbatim; weigh each gap against the AWS IoT mental model, not Lion's.

Confirmed via `~/pidgeiot/capsules/src/lib.rs` and `~/pidgeiot/dovecote/src/lib.rs`: **none of the following exist on the backend yet** (grepped for `telemetry`, `generation`/`command`, `log_stream`/`dictionary`, `firmware`/`ota`/`block2` — zero hits). These are backend gaps, not just device-firmware gaps — device code can't usefully be written against endpoints that don't exist.

- ~~**Telemetry ingestion**: no endpoint at all.~~ **Resolved 2026-07-15**: `POST <endpoint>/telemetry` (`report_telemetry_device`, dovecote) + `pigeon_set_shadow_param()`/`pigeon_shadow_flush()` (device). Latest-value-per-key store, not a time-series log — a history/range-query table is a deliberately deferred follow-up, as is a `fancier` display view.
- ~~**Command execution with ack**: no device-side ack path back to the platform.~~ **Resolved 2026-07-15**: `POST <endpoint>/shadow` (`report_shadow_device`, dovecote) + `pigeon_shadow_report()` (device), called from `https_init`'s `shadow_sync()` after applying `target_config`. Still no formal command queue beyond `target_version`/`current_version` as an implicit generation counter (the `"reboot": true` one-shot-command pattern in `shadow.c`) — AWS IoT's Jobs service remains the closest analog worth studying if a real queue is wanted later.
- **Log streaming**: no endpoint, no dictionary/token-compressed log encoding wired up. Zephyr supports `CONFIG_LOG_DICTIONARY_SUPPORT` if this is wanted later, but there's nowhere to send it yet.
- **OTA / firmware rollout**: MCUboot is set up device-side (see `pigeon-examples/samples/https_init/sysbuild/mcuboot`) and MCUmgr/serial DFU works locally, but there is no remote fetch-and-flash path (Lion uses CoAP Block2; AWS IoT uses Jobs + S3-hosted images over MQTT/HTTPS) and no backend endpoint to serve images or track fleet rollout state.
- **Auth model**: current transport is HTTPS + a per-pigeon Ed25519 keypair with an opaque binary bearer token (see `get_shadow_device`/`verify_device_token`, not JWT as of 2026-07-15). Lion uses PSK+DTLS for bandwidth reasons on sleepy NB-IoT devices; AWS IoT's primary device auth is X.509 mutual TLS (though custom authorizers are supported). Worth deciding deliberately rather than drifting — per-device-keyed bearer tokens over HTTPS is a reasonable AWS-IoT-adjacent choice already, not obviously wrong.
- **RBAC**: dovecote has basic user-level auth (`require_auth`) and per-pigeon ACL rows, but no granular role model has been checked against what AWS IoT's Device Defender/policy model expects.

## Build

This is a Zephyr **module**, not a standalone buildable app — `CMakeLists.txt` hard-fails if `ZEPHYR_BASE` isn't set (see its guard clause). It must be built as a dependency from within a Zephyr application/workspace (`west build`), not compiled directly in this repo.

- `zephyr/module.yml` wires the module into a Zephyr manifest (`west.yml`) via `build.cmake`/`build.kconfig`.
- `zephyr/Kconfig` exposes `CONFIG_PIGEON` (menuconfig gate), a mutually-exclusive choice between `CONFIG_PIGEON_CONNECTOR_COAP` and `CONFIG_PIGEON_CONNECTOR_HTTPS`, `CONFIG_PIGEON_ENDPOINT`/`CONFIG_PIGEON_TOKEN` (string, required when `PIGEON` is enabled), and `CONFIG_PIGEON_LOG_LEVEL` (0-4).
- `.vscode/settings.json` expects clangd compile commands at `build/https_init/compile_commands.json` — a symlink at `build` points to `~/pigeon-examples/build`, the shared build dir of the `https_init` sample in the sibling `pigeon-examples` repo (`samples/https_init`), which pulls this module in via `ZEPHYR_EXTRA_MODULES`.

## Conventions

- 2-space indentation (no `.clang-format` yet — follow the existing style in `src/pigeon_core.c`).
- Public API lives in `include/pigeon.h` behind an `extern "C"` guard; keep new public symbols there, not in `src/`.
- Use Zephyr's own logging (`LOG_MODULE_REGISTER`/`LOG_INF`/`LOG_ERR`), gated by `CONFIG_PIGEON_LOG_LEVEL`, not `printf`.
