cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Same arrangement as tests/fota_resume: the module supplies pigeon.h and the pigeon log module,
# while the source under test is compiled straight into the app, because
# CONFIG_PIGEON_TOKEN_ROTATION depends on the HTTPS connector and so on a network stack this
# suite has no use for.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pigeon_token_test)

target_sources(app PRIVATE
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src/pigeon_token.c
)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src)

# Reaches the app target alone, so the module's own sources keep the option off.
target_compile_definitions(app PRIVATE CONFIG_PIGEON_TOKEN_ROTATION=1)

# check-refusals.sh passes one Kconfig symbol the option must refuse to build beside.
if(DEFINED TOKEN_REFUSAL)
  target_compile_definitions(app PRIVATE ${TOKEN_REFUSAL})
endif()
