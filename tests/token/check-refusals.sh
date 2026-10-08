#!/bin/sh
# Builds this suite once beside each symbol CONFIG_PIGEON_TOKEN_ROTATION must refuse, and once
# beside each neighbour it must not. Run from inside a west workspace:
#   check-refusals.sh <empty build root>
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=${1:?usage: check-refusals.sh <build root>}
status=0

try() {
  expect=$1 name=$2 defs=$3
  log="$root/$name.log"

  if west build -p always -b native_sim/native/64 -s "$here" -d "$root/$name" -- \
      "-DTOKEN_REFUSAL=$defs" >"$log" 2>&1; then
    got=builds
  else
    got=refused
  fi

  if [ "$got" != "$expect" ]; then
    echo "FAIL $name: $got"
    status=1
  elif [ "$got" = refused ] && ! grep -q "CONFIG_PIGEON_TOKEN_ROTATION refuses" "$log"; then
    echo "FAIL $name: refused for another reason, see $log"
    status=1
  else
    echo "ok   $name: $got"
  fi
}

try refused http-debug "CONFIG_NET_HTTP_LOG_LEVEL=4"
try builds http-info "CONFIG_NET_HTTP_LOG_LEVEL=3"
try refused shell-allow-all "CONFIG_PIGEON_SHELL=1;CONFIG_PIGEON_SHELL_ALLOW_ALL=1"
try refused shell-settings "CONFIG_PIGEON_SHELL=1;CONFIG_SETTINGS_SHELL=1"
try refused shell-flash "CONFIG_PIGEON_SHELL=1;CONFIG_FLASH_SHELL=1"
try builds shell-alone "CONFIG_PIGEON_SHELL=1"
try builds settings-shell-alone "CONFIG_SETTINGS_SHELL=1"
try refused mbedtls-debug-info "CONFIG_MBEDTLS_DEBUG=1;CONFIG_MBEDTLS_DEBUG_LEVEL=3"
try builds mbedtls-debug-warn "CONFIG_MBEDTLS_DEBUG=1;CONFIG_MBEDTLS_DEBUG_LEVEL=2"
try refused mcumgr-settings "CONFIG_MCUMGR_GRP_SETTINGS=1"

exit $status
