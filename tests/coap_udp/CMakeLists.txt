cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# The module is pulled in for its include path and the always-defined
# CONFIG_PIGEON_* Kconfig symbols -- but the source under test is compiled
# directly into the app below: pigeon_coap_udp_match.c is the deliberately
# pure (socket-free, Kconfig-free) RFC 7252 matching/dedup unit of the CoAP
# DTLS/UDP transport, exactly so it can run here without any network stack
# or CONFIG_PIGEON_CONNECTOR_COAP build. Same pattern as ../fota_resume.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pigeon_coap_udp_match_test)

target_sources(app PRIVATE
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src/pigeon_coap_udp_match.c
)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src)
