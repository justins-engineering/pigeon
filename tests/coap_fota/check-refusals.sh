#!/bin/sh
# Builds this suite once beside each setting a CoAP build with FOTA must refuse at build time,
# and once beside each neighbour it must not. Run from inside a west workspace:
#   check-refusals.sh <empty build root>
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=${1:?usage: check-refusals.sh <build root>}
status=0

try() {
  expect=$1 name=$2 why=$3
  shift 3
  log="$root/$name.log"

  if west build -p always -b native_sim/native/64 -s "$here" -d "$root/$name" -- "$@" \
      >"$log" 2>&1; then
    got=builds
  else
    got=refused
  fi

  if [ "$got" != "$expect" ]; then
    echo "FAIL $name: $got"
    status=1
  elif [ "$got" = refused ] && ! grep -q "$why" "$log"; then
    echo "FAIL $name: refused for another reason, see $log"
    status=1
  else
    echo "ok   $name: $got"
  fi
}

try refused no-firmware-host "FOTA_HTTPS_ENDPOINT must name" \
  '-DCONFIG_PIGEON_FOTA_HTTPS_ENDPOINT=""'
try refused coaps-firmware-host "must start with https://" \
  '-DCONFIG_PIGEON_FOTA_HTTPS_ENDPOINT="coaps://127.0.0.1/device/pigeons/test"'
try refused http-firmware-host "must start with https://" \
  '-DCONFIG_PIGEON_FOTA_HTTPS_ENDPOINT="http://127.0.0.1/device/pigeons/test"'
try refused no-token "PIGEON_TOKEN must be set for FOTA" '-DCONFIG_PIGEON_TOKEN=""'
try refused shared-tag "HTTPS_SEC_TAG must differ" -DCONFIG_PIGEON_HTTPS_SEC_TAG=45
try refused default-tags "HTTPS_SEC_TAG must differ" -DCONFIG_PIGEON_HTTPS_SEC_TAG=1 \
  -DCONFIG_PIGEON_COAP_SEC_TAG=1
try builds tcp-transport - -DCONFIG_PIGEON_COAP_TRANSPORT_TCP=y \
  '-DCONFIG_PIGEON_ENDPOINT="coaps+tcp://127.0.0.1:56842/device/pigeons/test"'

exit $status
