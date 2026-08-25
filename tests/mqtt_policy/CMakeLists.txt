cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# The module is pulled in for its include path and the always-defined
# CONFIG_PIGEON_* Kconfig symbols -- but the source under test is compiled
# directly into the app below: pigeon_mqtt_policy.c is the deliberately pure
# (socket-free, Kconfig-free, MQTT-library-free) decision layer of the MQTT
# connector, exactly so it can run here without a broker, a network stack or
# a CONFIG_PIGEON_CONNECTOR_MQTT build. Same pattern as ../coap_udp.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pigeon_mqtt_policy_test)

target_sources(app PRIVATE
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src/pigeon_mqtt_policy.c
)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src)
