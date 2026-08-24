cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# The module is pulled in for pigeon.h's include path and the always-defined
# CONFIG_PIGEON_* symbols. Unlike the other suites here, the source under test
# is NOT recompiled into the test app: the module builds
# src/pigeon_http_status.c unconditionally (the telemetry POST reads
# Retry-After on every build, not just FOTA ones), so a second copy in the app
# is a duplicate-symbol link error rather than the workaround it is elsewhere.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pigeon_http_status_test)

target_sources(app PRIVATE
  src/main.c
)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src)
