cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Same shape as tests/fota_resume: the module is pulled in for pigeon.h's
# include path and the always-defined CONFIG_PIGEON_* symbols, while the
# source under test is compiled straight into the test app -- native_sim has
# no MCUboot, so CONFIG_PIGEON_FOTA (which is what builds this file in a
# real app) can never be enabled here.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pigeon_http_status_test)

target_sources(app PRIVATE
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src/pigeon_http_status.c
)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src)
