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

All three connectors are implemented and run against the live platform:
HTTPS, CoAP (over DTLS/UDP or over TLS/TCP), and MQTT. Around the
transports the module provides shadow sync, batched telemetry,
device-authenticated firmware updates with download resume and a
per-target attempt budget, remote dictionary-log upload, watchdog and
fatal-error recovery, and an optional remote diagnostic shell.

Everything past `pigeon_init()` and the data structures in `pigeon.h` is
selected through Kconfig, so a build compiles only what it asks for; a
device that only needs shadow sync over HTTPS pays for nothing else. See
[Kconfig](#kconfig) below.

## Data model

`include/pigeon.h` mirrors the wire shapes in `capsules::Connector` /
`HttpsConfig` / `CoapConfig` / `PigeonShadow` / `PigeonShadowUpdateRequest`,
so device code can build config and shadow payloads that stay compatible
with `dovecote`:

- `struct pigeon_config` — `device_id` plus a `struct pigeon_connector`.
  The HTTPS and CoAP connectors carry the pigeon's identity in the
  endpoint URL or the PSK identity and use `device_id` for logging only;
  the MQTT connector does not, so there it is the CONNECT client id and
  username and has to be the real pigeon id.
- `struct pigeon_connector` — a `type` (`PIGEON_CONNECTOR_HTTPS` /
  `PIGEON_CONNECTOR_COAP` / `PIGEON_CONNECTOR_MQTT`) plus
  `struct pigeon_coap_config` and `struct pigeon_mqtt_config`, each only
  consulted for its own connector. `endpoint`/`token` aren't struct fields
  — they're build-time `CONFIG_PIGEON_ENDPOINT`/`CONFIG_PIGEON_TOKEN`
  Kconfig strings, since the connector type is already a build-time choice
  (see Kconfig below).
  **Note:** the CoAP connector picks one of two transports at build time,
  CoAP-over-DTLS/UDP (RFC 7252, `coaps://`) or CoAP-over-TLS/TCP (RFC 8323,
  `coaps+tcp://`). The platform terminates both on one authority and port,
  so `CONFIG_PIGEON_ENDPOINT`'s scheme must name the transport the build
  selected.
- `struct pigeon_shadow_doc` — `target_version`/`current_version` counters
  plus raw JSON `target_config`/`current_config` text, as returned by
  `GET /pigeon/shadow/get`.
- `struct pigeon_shadow_update_request` — the body for
  `POST /pigeon/shadow/update`.

## Firmware updates (FOTA)

`CONFIG_PIGEON_FOTA` (off by default, `zephyr/Kconfig`) adds a device-driven
firmware update path on top of the shadow sync above: `pigeon.h` declares

- `struct pigeon_fota_info` — `version`/`size`/`sha256` (64 lowercase hex
  chars), the JSON decode target for target_config's app-defined `firmware`
  sub-object (mirrors the platform's shadow-driven FOTA route, documented
  in `docs/api.md` in the
  [`pidgeiot`](https://github.com/justins-engineering/pidgeiot) repository).
  Like the rest of `target_config`, this key is opaque to
  `pigeon_shadow_get()`; the app decodes it itself, same as
  `log`/`telemetry_interval`/`reboot`.
- `pigeon_fota_update_available(info)` — true when `info->version` differs
  from the build-time `CONFIG_PIGEON_FOTA_CURRENT_VERSION` string.
- `pigeon_fota_apply(info)` — chunked, device-authed HTTP Range GETs
  against `<CONFIG_PIGEON_ENDPOINT>/firmware`
  (`CONFIG_PIGEON_FOTA_CHUNK_SIZE` bytes at a time, HTTPS connector only),
  writing straight into MCUboot's secondary slot via Zephyr's `dfu_target`
  as each chunk arrives — the image is never held whole in RAM. Verifies
  the downloaded byte count and a streamed sha256 against `info` before
  scheduling a one-time MCUboot test-swap. Does **not** reboot: on success
  the caller must report its shadow `current_config` back
  (`pigeon_shadow_report()`) so the shadow converges before tearing down
  connectivity and calling `pigeon_reboot()` itself — same convention as the
  existing `"reboot": true` shadow command. On any failure (transport,
  size/hash mismatch, flash write) the secondary slot is left
  un-schedulable and the running image is untouched.
- `pigeon_fota_confirm_boot()` — call once per boot after establishing the
  device is healthy (e.g. after a successful `pigeon_shadow_get()`); a
  no-op once already confirmed. Skipping this is what makes MCUboot's
  test-swap fallback work: an image that's staged but never confirmed
  reverts back to the previous slot on the *next* reset, so a bad update
  self-heals without any server-side intervention. That fallback is the
  bootloader's, and it needs swap-with-revert: MCUboot's default, and what
  the nRF9160 builds get. Espressif's port is overwrite-only
  (`CONFIG_BOOT_UPGRADE_ONLY=y` in MCUboot's
  `boot/zephyr/socs/esp32c6_hpcore.conf`), so on the ESP32-C6 the staged
  image replaces the running one outright and no previous slot survives to
  return to. Confirming still runs there; what it cannot do is make a bad
  image recoverable without another update.

### Surviving a download that goes wrong

Three layers, smallest scope first.

Within one `pigeon_fota_apply()` call, a failed chunk is retried at the
same offset instead of ending the transfer
(`CONFIG_PIGEON_FOTA_CHUNK_RETRIES`), and an HTTP 429 is waited out on the
server's own `Retry-After` against a separate budget
(`CONFIG_PIGEON_FOTA_RATE_LIMIT_RETRIES`) — a rate limit is the server
pacing the download, not failing it, and must not spend the tolerance
reserved for real errors. Both counters are consecutive at one offset and
reset on every chunk that lands, so a long download over a flaky link is
never penalized for its length. Delays are clamped by
`CONFIG_PIGEON_FOTA_RETRY_AFTER_MAX_SEC`.

Across calls and **reboots**, `CONFIG_PIGEON_FOTA_RESUME` (on by default
wherever a settings backend exists) makes an interrupted
`pigeon_fota_apply()` resumable: the bytes already flushed to the secondary
slot are re-hashed from flash on the next call and only the remainder is
Range-requested, instead of restarting from byte 0. Requires the app to
provide a settings backend (`CONFIG_SETTINGS` + e.g. `CONFIG_NVS`) — without
one the symbol simply stays off; see the option's Kconfig help for the
invalidation rules (version change, failed verify, untrusted state). The
reconcile/persistence logic has a native_sim unit suite under
`tests/fota_resume` (build/run instructions in its `src/main.c` header).

Across the whole campaign, `CONFIG_PIGEON_FOTA_ATTEMPT_BUDGET` (opt-in)
bounds how many times one firmware target is chased, so an image that
downloads and verifies cleanly but then boot-loops afterwards cannot
re-download itself forever. The count is bound to the shadow
`target_version` that named the firmware rather than to the version string
alone, which is what keeps it recoverable: the platform advances
`target_version` when `target_config` changes, so a shadow write that keeps
the same firmware target and alters something else reopens the budget. A
byte-identical re-push does not, and nothing the device does by itself can.
The dashboard's "Re-push firmware" action supplies that change. Call
`pigeon_fota_attempt_allowed(info, shadow->target_version)` before
`pigeon_fota_apply()`, and `pigeon_fota_attempts_clear()` once the offered
version is confirmed to be the one running; both compile to no-ops when the
option is off. Unit suite under `tests/fota_attempts`.

A resumed continuation that moves the flushed offset forward costs nothing
against that budget — resuming is meant to be cheap. One that ends exactly
where it began made no progress and is charged like a fresh attempt, so a
transfer wedged at one offset still terminates.

**Signing key:** MCUboot's own image signature check (`sysbuild.conf`:
`SB_CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y`) is the actual security
boundary for firmware authenticity — `pigeon_fota_apply()`'s sha256 check
is only an integrity check against transport/flash corruption, not a
signature. With no `CONFIG_BOOT_SIGNATURE_KEY_FILE` override, MCUboot signs
against its upstream default dev key
(`bootloader/mcuboot/root-ec-p256.pem`, pulled in by `west update`) —
that key (and its matching private key) ships in the open-source MCUboot
repo, so anyone can forge a signature against it. **Never ship a
production device with the default key**: generate a real keypair
(`imgtool keygen`), point `CONFIG_BOOT_SIGNATURE_KEY_FILE` at the public
half in the MCUboot child image's own `prj.conf`
(`pigeon-examples/samples/https_init/sysbuild/mcuboot/prj.conf`), and keep
the private half off any machine that doesn't need to sign a release
image.

That boundary is per target, and on the ESP32-C6 it is currently absent
rather than weak: Espressif's MCUboot config sets
`CONFIG_BOOT_SIGNATURE_TYPE_NONE=y`
(`bootloader/mcuboot/boot/zephyr/socs/esp32c6_hpcore.conf`), so those
builds verify the image's own sha256 and check no signature at all. The
nRF9160 builds resolve to ECDSA P256 as described above. Read the built
`mcuboot/zephyr/.config` rather than assuming, and treat signing as
unsolved on the C6 until that override is replaced.

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

`zephyr/Kconfig` is the reference and every symbol carries help text. The
ones worth knowing before reading it:

- `CONFIG_PIGEON` — menuconfig gate for the connector choice and the
  optional features under it. Leaving it disabled is fine; `pigeon_init()`
  and the data structures work either way, since `CMakeLists.txt` compiles
  `pigeon_core.c` unconditionally and only the transport and feature
  sources are gated behind it.
- `CONFIG_PIGEON_CONNECTOR_HTTPS` / `CONFIG_PIGEON_CONNECTOR_COAP` /
  `CONFIG_PIGEON_CONNECTOR_MQTT` — mutually exclusive choice of transport.
  CoAP then chooses `CONFIG_PIGEON_COAP_TRANSPORT_TCP` (the default) or
  `_UDP`; MQTT chooses `CONFIG_PIGEON_MQTT_AUTH_CERT` or `_PSK`.
- `CONFIG_PIGEON_ENDPOINT` / `CONFIG_PIGEON_TOKEN` — the backend URL and
  the pigeon's bearer credential. Deliberately not nested under
  `CONFIG_PIGEON`, since `pigeon_core.c` reads them either way. The token
  is an opaque binary credential the platform verifies against this
  pigeon's own stored public key, not a JWT; the connectors that
  authenticate through a PSK handshake instead (CoAP, and MQTT in PSK
  mode) never read it, so those builds may leave it empty.
- Optional features, all `default n` unless noted:
  `CONFIG_PIGEON_WS` (a persistent push channel alongside HTTPS),
  `CONFIG_PIGEON_TELEMETRY_BATCH`, `CONFIG_PIGEON_FOTA` (with
  `_RESUME`, `default y` wherever a settings backend exists, and
  `_ATTEMPT_BUDGET`), `CONFIG_PIGEON_LOG_UPLOAD`,
  `CONFIG_PIGEON_WATCHDOG`, `CONFIG_PIGEON_REBOOT_ON_FATAL`,
  `CONFIG_PIGEON_SHELL`.
- `CONFIG_PIGEON_LOG_LEVEL` — 0 (none) to 4 (debug), default 3.

## License

AGPLv3 — see [LICENSE](LICENSE).
