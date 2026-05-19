# ================================================================
RECOVERY-MODE BUILD — revert from UF2 bootloader to stock

This builds a “recovery” application whose only job is to:

1. Boot
1. Write the stock bootloader into the BL region
1. Erase its own vector table (so the new BL won’t boot it)
1. Reset

After it runs, the device has the stock bootloader and no valid
application — exactly the state for pushing a stock signed
application via the stock flash-dfu-app.sh flow.

-----

## STEP 1 — extract the stock BL from upstream release zip

Download the upstream zip from RfidResearchGroup/ChameleonUltra
releases, then:

```
python3 make_recovery_header.py \\
    ultra-dfu-full.zip \\
    firmware/application/src/embedded_bootloader.h
```

This overwrites the embedded_bootloader.h that’s normally generated
from your own bootloader.hex. Don’t run this in a working tree you
care about — it’ll clobber your normal-build header.

-----

## STEP 2 — drop in the updated bl_updater files

Copy the new bl_updater.c and bl_updater.h into
firmware/application/src/. They are backward-compatible with the
existing UF2-mode build — bl_updater_run() still works for forward
updates.

-----

## STEP 3 — patch app_main.c

Near the top of app_main.c, alongside the other #include directives:

```
#ifdef RECOVERY_MODE
#include "bl_updater.h"
#include "nrf_gpio.h"
#endif
```

Inside main(), as the very first statement (before any other init):

```
int main(void) {
#ifdef RECOVERY_MODE
    /* Recovery build: this is a one-shot revert-to-stock app.
     * Skip all normal application initialisation and run the
     * bootloader replacement immediately. Doesn't return. */
    (void)bl_updater_run_and_invalidate_app();
    /* If validation failed, fall through to halt with no LEDs.
     * The user can power-cycle and try again with a fresh push. */
    while (1) { __WFE(); }
#endif

    /* ... normal application init follows ... */
```

Put the #ifdef block BEFORE log init, BEFORE clock init, BEFORE
USB init — recovery mode wants nothing else running. The SoftDevice
isn’t enabled yet at this point, so bl_updater_run_and_invalidate_app()
will skip the SD-disable step.

-----

## STEP 4 — Makefile flag

In firmware/application/Makefile, somewhere near the other CFLAGS
additions:

```
ifdef RECOVERY_MODE
CFLAGS += -DRECOVERY_MODE=1
endif
```

-----

## STEP 5 — build

```
cd firmware
RECOVERY_MODE=1 ./build.sh
```

Verify the recovery app is significantly smaller than a normal app
(it’s essentially just bl_updater + startup code):

```
ls -la objects/application.bin
# should be ~50 KB or less, not ~280 KB
```

-----

## STEP 6 — convert to UF2

```
tools/uf2conv.py objects/application.hex -o chameleon-revert-to-stock.uf2
```

Distribute that file. The filename matters less than the contents —
this is what end users drag onto the CHAMELEON drive.

# ================================================================
END USER FLOW

1. Cold-boot the device, hold B, plug back in (UF2 DFU mode)
1. CHAMELEON drive appears
1. Drag chameleon-revert-to-stock.uf2 onto the drive
1. Wait ~2 seconds (LEDs may flicker briefly)
1. Device resets; stock BL boots, enters DFU mode (no valid app)
1. Push stock app: ./flash-dfu-app.sh from the upstream release
1. Standard signed-DFU flow works again

# ================================================================
SAFETY NOTES

- This is one-shot. Once the user runs the recovery UF2, the
  device’s UF2 bootloader is gone and the only way to put it back
  is to rebuild and re-flash via the bl_updater path (assuming
  you’ve kept your UF2 firmware) or via SWD.
- The recovery app self-destructs after success. Don’t expect the
  device to “stay on” the recovery UF2 — by design, the first
  invocation is also the last.
- If make_recovery_header.py emits a CRC that differs from
  0xF3AC4889 for the September 2025 upstream release, the BL bytes
  changed between releases and the embed should be regenerated.
- The bricking window is the same ~1.4 seconds as a normal
  bl_updater run. Keep the device powered.