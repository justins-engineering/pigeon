#!/bin/sh
# Builds this suite once beside each setting the CoAP connector must refuse at build time, and
# once beside each neighbour it must not. Run from inside a west workspace:
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

try refused handshake-5s "HANDSHAKE_TIMEOUT_SEC must be" -DCONFIG_PIGEON_COAP_DTLS_HANDSHAKE_TIMEOUT_SEC=5
try builds handshake-7s - -DCONFIG_PIGEON_COAP_DTLS_HANDSHAKE_TIMEOUT_SEC=7
try builds handshake-123s - -DCONFIG_PIGEON_COAP_DTLS_HANDSHAKE_TIMEOUT_SEC=123
try builds handshake-off - -DCONFIG_PIGEON_COAP_DTLS_HANDSHAKE_TIMEOUT_SEC=0

scheme="must start with coaps://"
try refused https-endpoint "$scheme" '-DCONFIG_PIGEON_ENDPOINT="https://example.invalid/p/1"'
try refused tcp-endpoint "$scheme" '-DCONFIG_PIGEON_ENDPOINT="coaps+tcp://example.invalid/p/1"'
try refused no-scheme "$scheme" '-DCONFIG_PIGEON_ENDPOINT="example.invalid/p/1"'
try builds empty-endpoint - '-DCONFIG_PIGEON_ENDPOINT=""'
try refused tcp-build "must start with coaps+tcp://" -DCONFIG_PIGEON_COAP_TRANSPORT_TCP=y
try builds tcp-build-tcp-endpoint - -DCONFIG_PIGEON_COAP_TRANSPORT_TCP=y \
  '-DCONFIG_PIGEON_ENDPOINT="coaps+tcp://example.invalid/p/1"'

exit $status
