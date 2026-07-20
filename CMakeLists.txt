# Guard clause ensuring this is handled via a Zephyr project build pass
if(NOT ZEPHYR_BASE)
  message(FATAL_ERROR "Zephyr base environment not found. This module must be built within a Zephyr app context.")
endif()

zephyr_library_named(pigeon)

# Public include directory path allows users to simply call #include <pigeon.h>
# Must be zephyr_include_directories (global/INTERFACE), not the _library_
# variant, which only adds PRIVATE to this library's own sources — consumers
# like an app's main.c would still fail to find the header otherwise.
zephyr_include_directories(include)

# Bind the underlying core implementation sources
zephyr_library_sources(src/pigeon_core.c)

# Conditionally compile modules based on structural Kconfig choices
zephyr_library_sources_ifdef(CONFIG_PIGEON_CONNECTOR_COAP  src/pigeon_coap.c)
zephyr_library_sources_ifdef(CONFIG_PIGEON_CONNECTOR_HTTPS src/pigeon_https.c)
zephyr_library_sources_ifdef(CONFIG_PIGEON_LOG_UPLOAD      src/pigeon_log_backend.c)
zephyr_library_sources_ifdef(CONFIG_PIGEON_FOTA            src/pigeon_fota.c)
zephyr_library_sources_ifdef(CONFIG_PIGEON_WS              src/pigeon_ws.c)
zephyr_library_sources_ifdef(CONFIG_PIGEON_SHELL           src/pigeon_shell.c)
