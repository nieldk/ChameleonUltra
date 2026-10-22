#include "bl_recovery.h"

#include "nrf.h"

/* The app feeds the inherited watchdog from its first instruction
 * (wdt_feed_inherited() in app_main.c). The timeout is locked once started, so
 * it also becomes the app's runtime timeout; 10 s leaves room for a slow first
 * boot (FDS init). */
#define APP_WDT_TIMEOUT_MS  10000UL

void bl_recovery_arm_wdt(void)
{
    if (NRF_WDT->RUNSTATUS & WDT_RUNSTATUS_RUNSTATUS_Msk) {
        return;
    }
    NRF_WDT->CONFIG = (WDT_CONFIG_SLEEP_Run << WDT_CONFIG_SLEEP_Pos) |
                      (WDT_CONFIG_HALT_Pause << WDT_CONFIG_HALT_Pos);
    NRF_WDT->CRV    = (APP_WDT_TIMEOUT_MS * 32768UL) / 1000UL - 1UL;
    NRF_WDT->RREN   = WDT_RREN_RR0_Msk;
    NRF_WDT->TASKS_START = 1;
}

bool bl_recovery_wdt_reset_consume(void)
{
    if (NRF_POWER->RESETREAS & POWER_RESETREAS_DOG_Msk) {
        NRF_POWER->RESETREAS = POWER_RESETREAS_DOG_Msk;   /* write 1 to clear */
        return true;
    }
    return false;
}
