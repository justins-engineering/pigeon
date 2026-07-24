#include <zephyr/fatal.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/sys/reboot.h>

LOG_MODULE_REGISTER(pigeon_fatal, CONFIG_PIGEON_LOG_LEVEL);

/* Overrides Zephyr's own weak k_sys_fatal_error_handler() (see
 * zephyr/include/zephyr/fatal.h and zephyr/kernel/fatal.c's default, which
 * locks interrupts and spins forever) -- see zephyr/Kconfig's
 * CONFIG_PIGEON_REBOOT_ON_FATAL help for the full rationale. Every fatal
 * error reaching this hook is treated as unrecoverable for this headless
 * device (there is no operator console to intervene from), so this always
 * reboots rather than trying to classify `reason`. */
void k_sys_fatal_error_handler(unsigned int reason, const struct arch_esf *esf) {
  ARG_UNUSED(esf);

  /* Per fatal.h's own doc comment: "If the error is determined to be
   * unrecoverable, LOG_PANIC() should be invoked to flush any pending
   * logging buffers." -- gives the reboot reason a chance to actually reach
   * the serial console before sys_reboot() cuts power to everything. */
  LOG_PANIC();
  LOG_ERR("Fatal error (reason %u) -- rebooting instead of hanging (see "
          "CONFIG_PIGEON_REBOOT_ON_FATAL)", reason);

  sys_reboot(SYS_REBOOT_COLD);

  CODE_UNREACHABLE;
}
