cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# The module is pulled in for pigeon.h's include path, the always-defined
# CONFIG_PIGEON_* Kconfig symbols, and pigeon_core.c's log module -- but the
# source under test is compiled directly into the app below: on native_sim
# CONFIG_PIGEON_FOTA (and so CONFIG_PIGEON_FOTA_RESUME) can never be enabled
# (no MCUboot), which is exactly why the resume/reconcile logic lives in its
# own MCUboot-free translation unit.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pigeon_fota_resume_test)

target_sources(app PRIVATE
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src/pigeon_fota_resume.c
)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src)
