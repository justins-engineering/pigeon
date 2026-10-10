cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# The whole CoAP DTLS/UDP connector, built by the module as an application would build it, over
# native_sim's host sockets with DTLS in mbedTLS. No handshake ever completes: the peer is a
# bound UDP socket that stays silent or refuses.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pigeon_coap_dtls_test)

target_sources(app PRIVATE src/main.c)

# A request is as large as the biggest telemetry body, and the log upload sends one from the
# system workqueue, so no CoAP frame may hold one on the stack. native_sim cannot measure a
# thread's stack, so the compiler holds the line instead.
get_filename_component(pigeon_root ${CMAKE_CURRENT_SOURCE_DIR}/../.. ABSOLUTE)
set_source_files_properties(
  ${pigeon_root}/src/pigeon_coap.c
  ${pigeon_root}/src/pigeon_coap_udp.c
  ${pigeon_root}/src/pigeon_coap_tcp.c
  TARGET_DIRECTORY pigeon
  PROPERTIES COMPILE_OPTIONS -Werror=frame-larger-than=1024
)
