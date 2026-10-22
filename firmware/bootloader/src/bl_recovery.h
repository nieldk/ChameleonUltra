/* Recovery from a hung or crashing application, independent of app state. */
#ifndef BL_RECOVERY_H__
#define BL_RECOVERY_H__

#include <stdbool.h>

/* Start the watchdog just before the app is started, so an app that hangs
 * (even before it starts its own watchdog) is reset and the bootloader runs
 * again. No-op if the watchdog is already running. */
void bl_recovery_arm_wdt(void);

/* True if the last reset was a watchdog reset. Clears that flag so it does
 * not trigger again on later resets. */
bool bl_recovery_wdt_reset_consume(void);

#endif
