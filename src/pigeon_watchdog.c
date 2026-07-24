#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/task_wdt/task_wdt.h>

#include "pigeon_internal.h"

LOG_MODULE_REGISTER(pigeon_watchdog, CONFIG_PIGEON_LOG_LEVEL);

/* -1 until pigeon_watchdog_start() successfully arms a channel; every
 * pigeon_watchdog_feed() call is then a no-op, same convention as the rest
 * of this library treating an unstarted optional feature as harmless. */
static int pigeon_watchdog_channel = -1;

void pigeon_watchdog_start(void) {
  const struct device *hw_wdt = NULL;

/* `watchdog0` is a standard Zephyr devicetree alias, not an ESP32-specific
 * concept -- any board that wires one up gets the hardware fallback for
 * free, no vendor-specific Kconfig select needed here (see zephyr/Kconfig's
 * CONFIG_PIGEON_WATCHDOG help). */
#if DT_NODE_EXISTS(DT_ALIAS(watchdog0))
  hw_wdt = DEVICE_DT_GET(DT_ALIAS(watchdog0));
  if (!device_is_ready(hw_wdt)) {
    LOG_WRN(
        "watchdog0 device not ready -- falling back to a software-only task "
        "watchdog (see CONFIG_PIGEON_WATCHDOG's help: this cannot recover from a "
        "fully-wedged, interrupts-disabled hang, only a real hardware watchdog can)"
    );
    hw_wdt = NULL;
  }
#else
  LOG_WRN(
      "no 'watchdog0' devicetree alias on this board -- falling back to a "
      "software-only task watchdog (see CONFIG_PIGEON_WATCHDOG's help: this cannot "
      "recover from a fully-wedged, interrupts-disabled hang, only a real hardware "
      "watchdog can)"
  );
#endif

  int err = task_wdt_init(hw_wdt);

  if (err) {
    LOG_ERR("task_wdt_init failed: %d (watchdog NOT armed)", err);
    return;
  }

  /* NULL callback: task_wdt's own default behavior on expiry is
   * sys_reboot(SYS_REBOOT_COLD) (see task_wdt_trigger() in
   * zephyr/subsys/task_wdt/task_wdt.c) -- exactly what a headless,
   * unattended device needs, no custom callback required. */
  pigeon_watchdog_channel =
      task_wdt_add(CONFIG_PIGEON_WATCHDOG_TIMEOUT_SEC * 1000, NULL, NULL);

  if (pigeon_watchdog_channel < 0) {
    LOG_ERR("task_wdt_add failed: %d (watchdog NOT armed)", pigeon_watchdog_channel);
    return;
  }

  LOG_INF(
      "Wedge-recovery watchdog armed: %ds timeout, %s", CONFIG_PIGEON_WATCHDOG_TIMEOUT_SEC,
      hw_wdt ? "hardware fallback active" : "SOFTWARE-ONLY (no hardware fallback)"
  );
}

void pigeon_watchdog_feed(void) {
  if (pigeon_watchdog_channel < 0) {
    return;
  }

  (void)task_wdt_feed(pigeon_watchdog_channel);
}
