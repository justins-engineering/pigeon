cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# The whole CoAP DTLS/UDP connector, built by the module as an application would build it, over
# native_sim's host sockets with DTLS in mbedTLS. No server answers: the peer here is a bound
# UDP socket that never replies.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pigeon_coap_dtls_test)

target_sources(app PRIVATE src/main.c)
