cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Same arrangement as tests/fota_attempts: the module is pulled in for its
# include path, while the source under test is compiled straight into the test
# app. CONFIG_PIGEON_TELEMETRY_BATCH depends on the HTTPS connector, and
# turning that on here would drag http_client and a TLS stack into a test that
# never opens a socket.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pigeon_telemetry_batch_test)

target_sources(app PRIVATE
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src/pigeon_telemetry_batch.c
)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src)

# Deliberately not the shipped defaults. The buffer's interesting behavior is
# what it does at its bounds, and a 2048-byte arena with a depth of 6 would
# need a case to write ~2 KB of fragments before reaching one. These are
# scaled so both bounds -- readings and bytes -- are a few records away, and
# so the byte bound bites BEFORE the depth bound (BUF_SIZE / 70 = 3 < 6),
# which is the ordering the high-water and compaction cases depend on.
target_compile_definitions(app PRIVATE
  CONFIG_PIGEON_TELEMETRY_BATCH=1
  CONFIG_PIGEON_TELEMETRY_BATCH_DEPTH=6
  CONFIG_PIGEON_TELEMETRY_BATCH_BUF_SIZE=256
  CONFIG_PIGEON_TELEMETRY_BATCH_MAX_AGE_SEC=30
  CONFIG_PIGEON_TELEMETRY_BATCH_BACKOFF_MAX_SEC=120
)
