cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# pigeon_coap.c, the transport-agnostic half of the CoAP connector, compiled straight into the
# app over a scripted transport (src/main.c defines pigeon_coap_transport_exchange()), so every
# request it frames and every answer it reads can be checked with no socket and no server. The
# module supplies pigeon.h, the transport lock and the pigeon log module, as in ../token.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pigeon_coap_core_test)

target_sources(app PRIVATE
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src/pigeon_coap.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src/pigeon_shadow_wire.c
)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src)

# The connector's Kconfig depends on a network stack this suite has no use for, so its values
# reach the app target alone, at their defaults.
target_compile_definitions(app PRIVATE
  CONFIG_PIGEON_CONNECTOR_COAP=1
  CONFIG_PIGEON_COAP_TRANSPORT_UDP=1
  CONFIG_PIGEON_COAP_SEC_TAG=1
  CONFIG_PIGEON_SHADOW_CONFIG_MAX=320
  CONFIG_PIGEON_COAP_AUTH_BACKOFF_SEC=900
  CONFIG_PIGEON_COAP_AUTH_BACKOFF_FIRST_SEC=60
  CONFIG_PIGEON_COAP_BLOCK2_SIZE=512
)
