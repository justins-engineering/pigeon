cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Same arrangement as tests/fota_resume: the module supplies pigeon.h and the
# pigeon log module, while the source under test is compiled straight into
# the test app, because CONFIG_PIGEON_FOTA (and so this feature's own
# Kconfig) can never be enabled on native_sim -- there is no MCUboot for it
# to depend on.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pigeon_fota_attempts_test)

target_sources(app PRIVATE
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src/pigeon_fota_attempts.c
)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src)

# Defining the two Kconfig symbols for this target only is what lets the
# gate itself -- pigeon_fota_attempt_allowed(), the function an application
# actually calls -- be exercised here rather than only the pure decision
# underneath it. They cannot come from Kconfig on this board for the reason
# above, and they reach the app target alone, so the module's own
# translation units still see the no-op inline declarations in pigeon.h.
target_compile_definitions(app PRIVATE
  CONFIG_PIGEON_FOTA_ATTEMPT_BUDGET=1
  CONFIG_PIGEON_FOTA_MAX_ATTEMPTS_PER_VERSION=3
)
