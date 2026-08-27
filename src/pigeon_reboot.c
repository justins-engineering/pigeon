#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>

#include "pigeon.h"

#if defined(CONFIG_SOC_SERIES_ESP32C6)
#include <esp_rom_serial_output.h>
#include <esp_rom_sys.h>
#endif

/* Zephyr's sys_reboot() on this part ends in esp_restart_noos(), which pulses
 * a reset across the modem power domain -- where the C6 keeps the analog
 * register I2C master -- and then resets the CPU alone, so nothing ever puts
 * that block back. The next image to boot enables the REGI2C master and
 * immediately writes a clock trim through it, and that write's busy-wait
 * never completes. The board goes dark before any log subsystem exists to
 * say so, and the boot path has already disarmed the RTC watchdog by then,
 * so nothing recovers it short of a power cycle: a self-reboot for a
 * firmware swap, an unhandled fault, or a wedged main loop would each strand
 * an unattended device permanently. A full system reset clears that domain
 * the way a power cycle does. The C5 and H2 keep the same block in the same
 * place and are likely to want this too, but only the C6 has been measured.
 */
FUNC_NORETURN void pigeon_reboot(void) {
#if defined(CONFIG_SOC_SERIES_ESP32C6)
  /* esp_restart_noos() masks interrupts before it touches anything, so that
   * nothing scheduled can run against half-torn-down hardware. */
  (void)irq_lock();

  /* Let the last line of the caller's log reach the wire, the same courtesy
   * esp_restart_noos() pays before it resets the UART. */
  esp_rom_output_tx_wait_idle(0);

  esp_rom_software_reset_system();

  /* The ROM routine returns: the reset itself lands a few cycles later.
   * Spin rather than run on into whatever the compiler put next, which is
   * what every caller of it in the HAL does. */
  for (;;) {
  }
#else
  sys_reboot(SYS_REBOOT_COLD);

  CODE_UNREACHABLE;
#endif
}
