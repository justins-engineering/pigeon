cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# The CoAP shadow GET's Block2 client (pigeon_coap.c) over a scripted transport that splits a
# document the way loft's JSON handler does, as ../coap_core drives the rest of the core.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pigeon_coap_block2_test)

target_sources(app PRIVATE
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src/pigeon_coap.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src/pigeon_shadow_wire.c
)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src)

# A DTLS/UDP build at the defaults, but with the departure board's config cap, which its shadow
# with a firmware target needs.
target_compile_definitions(app PRIVATE
  CONFIG_PIGEON_CONNECTOR_COAP=1
  CONFIG_PIGEON_COAP_TRANSPORT_UDP=1
  CONFIG_PIGEON_COAP_SEC_TAG=1
  CONFIG_PIGEON_SHADOW_CONFIG_MAX=768
  CONFIG_PIGEON_COAP_AUTH_BACKOFF_SEC=900
  CONFIG_PIGEON_COAP_AUTH_BACKOFF_FIRST_SEC=60
  CONFIG_PIGEON_COAP_BLOCK2_SIZE=512
)
