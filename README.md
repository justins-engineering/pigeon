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

Four connectors are implemented: HTTPS, CoAP (over DTLS/UDP or over
TLS/TCP) and MQTT, which run against the live platform, and NIDD, the
carrier's Non-IP Data Delivery over NB-IoT. Around the
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
  username and has to be the real pigeon id. NIDD uses it for logging only
  too: the modem's IMEI names the pigeon.
- `struct pigeon_connector` — a `type` (`PIGEON_CONNECTOR_HTTPS` /
  `PIGEON_CONNECTOR_COAP` / `PIGEON_CONNECTOR_MQTT` /
  `PIGEON_CONNECTOR_NIDD`) plus `struct pigeon_coap_config` and
  `struct pigeon_mqtt_config`, each only consulted for its own connector.
  `endpoint`/`token` aren't struct fields — they're build-time
  `CONFIG_PIGEON_ENDPOINT`/`CONFIG_PIGEON_TOKEN` Kconfig strings, since the
  connector type is already a build-time choice (see Kconfig below). NIDD
  has no member of its own: its claim key is `CONFIG_PIGEON_NIDD_CLAIM_KEY`
  and its APN is in `CONFIG_PIGEON_ENDPOINT`.
  **Note:** the CoAP connector picks one of two transports at build time,
  CoAP-over-DTLS/UDP (RFC 7252, `coaps://`) or CoAP-over-TLS/TCP (RFC 8323,
  `coaps+tcp://`). The platform terminates both on one authority and port,
  so `CONFIG_PIGEON_ENDPOINT`'s scheme must name the transport the build
  selected.
- `struct pigeon_shadow_doc` — `target_version`/`current_version` counters
  plus raw JSON `target_config`/`current_config` text, as returned by
  `GET /device/pigeons/:pigeon_id/shadow`.
- `struct pigeon_shadow_update_request`: the body of the dashboard's
  `PUT /pigeons/:pigeon_id/shadow`.

## NIDD

`CONFIG_PIGEON_CONNECTOR_NIDD` (nRF Connect SDK and the nRF91 modem only,
`src/pigeon_nidd.c`) carries a pigeon over the carrier's Non-IP Data
Delivery: frames on a raw socket over a Non-IP PDN on the APN named in
`CONFIG_PIGEON_ENDPOINT` (`nidd://VZWSCEF` on Verizon), which the carrier
hands to ThingSpace and ThingSpace posts to the platform. There is no TLS
and no bearer token. The SIM authenticates the device to the carrier, the
modem's IMEI names the pigeon, and the claim key in
`CONFIG_PIGEON_NIDD_CLAIM_KEY` binds the device to its pigeon and verifies
every frame the platform sends. NIDD is not self-serve: the platform takes
NIDD traffic only from lines on its own ThingSpace account, and only
organizations enabled for NIDD can create a `Nidd` pigeon. Like the MQTT
connector it is a transport and a receive channel at once: call
`pigeon_init()` before the attach, `pigeon_nidd_start()` after it, and
`pigeon_nidd_stop()` before the modem is powered off.

`docs/api.md` in the
[`pidgeiot`](https://github.com/justins-engineering/pidgeiot) repository
("NIDD frames", "NIDD downlink and replies") is the authority on every
byte; this table summarises it:

| Byte 0 | Name | Direction | Body |
|---|---|---|---|
| `0x01` | `TELEMETRY` | device to platform | `<sequence>\n`, then a telemetry route body, flat or batched |
| `0x02` | `SHADOW_REPORT` | device to platform | A shadow report route body |
| `0x03` | reserved | device to platform | Log upload, not offered |
| `0x04` | `HELLO` | device to platform | The claim key as 32 lowercase hex characters |
| `0x81` | `SHADOW` | platform to device | `<target_version> <current_version>\n`, `target_config`, tag |
| `0x82` | `STATUS` | platform to device | `<code> <arg>\n`, tag; codes `0` STORED, `1` PAUSED, `2` UNCLAIMED |
| `0x83` | reserved | platform to device | Application data, not offered |

No frame holds a NUL byte. A platform frame ends in a 16-character tag,
the lowercase hex of the first 8 bytes of HMAC-SHA256 over every byte
before it, keyed by the claim key; the library drops a frame whose tag
does not verify. Device frames carry no tag. A `TELEMETRY` frame opens with
its send sequence, a u32 in decimal that starts at a random value each boot
and counts up by one per frame: the carrier can deliver one frame twice,
and the platform stores a frame it has already seen only once, so the
sequence is what keeps two sends of the same readings apart.

What the connector asks of the device, and what the library does about it:

- **At most four radio accesses an hour**, uplink and downlink together.
  The library has no cadence of its own and cannot count a paged downlink,
  so this is the application's to keep: wake no more often than every 15
  minutes, send each wake's readings as one batch
  (`CONFIG_PIGEON_TELEMETRY_BATCH`), and let replies ride the connection
  their uplink opened.
- **1273 bytes an uplink frame**, the largest an nRF9160 on modem firmware
  1.3.7 accepted. Build-time checks hold every frame under it, counting a
  telemetry frame's sequence at its longest (11 bytes), which is why a NIDD
  build defaults to 7 telemetry keys (8 keys at the worst-case sizes make a
  1323-byte body) and a 1024-byte batch arena at a depth of 6, and caps
  `CONFIG_PIGEON_SHADOW_CONFIG_MAX` at 1208. One reading of 7 keys at the
  worst-case sizes (1157 bytes) does not fit that arena and stays pending,
  which only pathological values reach.
- **`HELLO` at every start**, again ahead of the next billable frame when
  one drew no reply within `CONFIG_PIGEON_NIDD_REPLY_WAIT_SEC`, and after a
  `STATUS UNCLAIMED 0`, at most hourly. `UNCLAIMED 1`, a refused key, makes
  billable sends answer `-EACCES` until the next boot; `PAUSED` makes them
  answer `-EAGAIN` for the time it names. Both are answered without a radio
  access.
- **The connection is held for the reply.** Every send sets `RAI_ONGOING`;
  once the reply owed to a `HELLO` or a shadow report has arrived, the
  library requests release (`RAI_NO_DATA`) after
  `CONFIG_PIGEON_NIDD_RAI_IDLE_MS` of quiet. A wake of telemetry alone
  leaves the release to the network.
- **PSM and eDRX are written at every boot**, because the modem keeps both
  across images. The library requests PSM and writes eDRX from
  `pigeon_init()`; the application sets the timers. Verizon NB-IoT refused
  NCS's 30-minute periodic TAU and accepted 190 minutes, so a NIDD build
  sets `CONFIG_LTE_PSM_REQ=y` and `CONFIG_LTE_PSM_REQ_RPTAU="00010011"`.
  Keep eDRX off (`CONFIG_LTE_EDRX_REQ` unset) or its cycle shorter than the
  granted active time, or a pushed shadow may never be paged. The library
  logs what the network grants, and turns PSM off if the modem refuses the
  request, rather than keep whatever timers an earlier image left.
- **NB-IoT only.** The build fails unless the network mode is NB-IoT, or a
  dual mode preferring it.

`pigeon_shadow_get()` fetches nothing: it serves the newest `SHADOW` the
platform has sent. With none cached it waits only while the reply to a
`HELLO` is owed, up to `CONFIG_PIGEON_NIDD_SHADOW_WAIT_SEC` after that
`HELLO`, and otherwise answers `-EAGAIN` at once. `pigeon_shadow_report()`
waits up to `CONFIG_PIGEON_NIDD_REPLY_WAIT_SEC` for its confirmation, and
answers `-EDEADLK` from the event callback, which runs on the thread that
receives that confirmation. The library receives a `target_config` of at most
`CONFIG_PIGEON_SHADOW_CONFIG_MAX - 1` bytes (319 by default); the platform
accepts larger ones, which the device drops with a log line saying so.
`CONFIG_PIGEON_WATCHDOG` is fed only by a delivered flush, so a NIDD build
that enables it needs a timeout above its wake interval plus any `PAUSED`
hold.

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
  (`CONFIG_PIGEON_FOTA_CHUNK_SIZE` bytes at a time, always over HTTPS: on
  the HTTPS connector, on MQTT, and on NIDD with a dedicated Non-IP
  context, the last two fetching from `CONFIG_PIGEON_FOTA_HTTPS_ENDPOINT`),
  writing straight into MCUboot's secondary slot via Zephyr's `flash_img`
  (NCS's `dfu_target` with `CONFIG_PIGEON_FOTA_NCS`)
  as each chunk arrives — the image is never held whole in RAM. Verifies
  the downloaded byte count and a streamed sha256 against `info` before
  scheduling a one-time MCUboot test-swap. Does **not** reboot: on success
  the caller must report its shadow `current_config` back
  (`pigeon_shadow_report()`) before tearing down connectivity and calling
  `pigeon_reboot()` itself, same convention as the existing `"reboot": true`
  shadow command. That report should still name the version this device is
  running and be made at the platform's existing `current_version`: a staged
  image is not one the bootloader has accepted, and the image that boots is
  the only thing that can honestly claim to be running. On any failure (transport,
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

**Signing key:** MCUboot's own image signature check (ECDSA P-256, which
pigeon-examples selects for every board in
`samples/Kconfig.sysbuild.signing`) is the actual security boundary for
firmware authenticity — `pigeon_fota_apply()`'s sha256 check is only an
integrity check against transport/flash corruption, not a signature. With no
`CONFIG_BOOT_SIGNATURE_KEY_FILE` override, MCUboot signs against its
upstream default dev key (`bootloader/mcuboot/root-ec-p256.pem`, pulled in
by `west update`) — that key (and its matching private key) ships in the
open-source MCUboot repo, so anyone can forge a signature against it.
**Never ship a production device with the default key**: generate a real
keypair (`imgtool keygen -k <path> -t ecdsa-p256`), keep it outside the
tree, and export `PIGEON_BOOT_SIGNATURE_KEY_FILE=<path>` in every build
shell. pigeon-examples feeds that one file to both the bootloader and the
image signer, which must always agree, so set the key there and nowhere
else; an application of your own sets sysbuild's
`SB_CONFIG_BOOT_SIGNATURE_KEY_FILE`, the symbol behind that variable. Keep
the key off any machine that doesn't need to sign a release image.

That boundary is per target. The ESP32-C6 board defaults the signature type
to none (`zephyr/boards/espressif/esp32c6_devkitc/Kconfig.sysbuild`, echoed
by MCUboot's `boot/zephyr/socs/esp32c6_hpcore.conf`), which checks no
signature at all. pigeon-examples overrides that default to ECDSA P256 in
`samples/Kconfig.sysbuild.signing`, so its ESP32-C6 builds verify a
signature like the nRF91 ones, and an application of your own needs the same
override. Read the built `mcuboot/zephyr/.config` rather than assuming.

## Build

This is a Zephyr **module**, not a standalone app — `CMakeLists.txt`
hard-fails if `ZEPHYR_BASE` isn't set. It must be pulled into a Zephyr
application/workspace, either via a west manifest project entry or
`ZEPHYR_EXTRA_MODULES` (see `pigeon-examples/samples/common/app.cmake`
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
  `CONFIG_PIGEON_CONNECTOR_MQTT` / `CONFIG_PIGEON_CONNECTOR_NIDD` — mutually
  exclusive choice of transport. CoAP then chooses
  `CONFIG_PIGEON_COAP_TRANSPORT_TCP` (the default) or `_UDP`; MQTT chooses
  `CONFIG_PIGEON_MQTT_AUTH_CERT` or `_PSK`; NIDD needs
  `CONFIG_PIGEON_NIDD_CLAIM_KEY` and has `_DEDICATED_CID` (default y),
  `_RAI_IDLE_MS`, `_REPLY_WAIT_SEC`, `_SHADOW_WAIT_SEC` and
  `_THREAD_STACK_SIZE`.
- `CONFIG_PIGEON_ENDPOINT` / `CONFIG_PIGEON_TOKEN` — the backend URL and
  the pigeon's bearer credential. Deliberately not nested under
  `CONFIG_PIGEON`, since `pigeon_core.c` reads them either way. The token
  is an opaque binary credential the platform verifies against this
  pigeon's own stored public key, not a JWT; the connectors that
  authenticate through a PSK handshake instead (CoAP, and MQTT in PSK
  mode) never read it, so those builds may leave it empty, unless an MQTT
  build also enables `CONFIG_PIGEON_FOTA`: its image download is an HTTPS
  request that carries the token. NIDD reads it only for FOTA over the IP
  PDN.
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
