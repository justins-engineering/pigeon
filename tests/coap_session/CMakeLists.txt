cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# The whole CoAP DTLS/UDP connector, built by the module as an application would build it,
# against a DTLS server in the same process on Zephyr's own loopback: real sessions, real
# datagrams, both ends in mbedTLS.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pigeon_coap_session_test)

target_sources(app PRIVATE src/main.c)
