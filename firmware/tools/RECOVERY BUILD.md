# ================================================================
RECOVERY-MODE BUILD — revert from UF2 bootloader to stock

This builds a “recovery” application whose only job is to:

1. Boot
1. Write the stock bootloader (extracted from an upstream release zip)
   into the BL region
1. Erase its own vector table (so the new BL won’t boot it again)
1. Reset

After it runs, the device has the stock bootloader and no valid
application — exactly the state for pushing a stock signed
application via the stock flash-dfu-app.sh flow.

Once the one-time setup below is done, building a fresh recovery UF2
for any upstream release is a single command:

```
RECOVERY_ZIP=path/to/ultra-dfu-full.zip ./build.sh
```

# ================================================================
ONE-TIME SETUP

Three small additions to the tree, then build.sh handles the rest.

-----

1. Drop in the helper scripts

-----

Copy into firmware/tools/:

```
gen_embedded_bl.py        # extracts BL from your own bootloader.hex
                          # (already in place from the normal build flow)
make_recovery_header.py   # extracts stock BL from an upstream zip
```

Both emit firmware/application/src/embedded_bootloader.h. The
build.sh runs whichever one applies for the current build mode.

-----

1. Drop in bl_updater

-----

Copy into firmware/application/src/:

```
bl_updater.c
bl_updater.h
```

Both expose two entry points:
bl_updater_run()                       — replace BL, reset (app stays)
bl_updater_run_and_invalidate_app()    — replace BL, erase our own
vector table, reset

The first is what `hw update_bl` calls in your normal UF2 build. The
second is what the RECOVERY_MODE build calls on boot.

-----

1. Patch firmware/application/src/app_main.c

-----

Near the top of app_main.c, alongside the other #include directives:

```
#ifdef RECOVERY_MODE
#include "bl_updater.h"
#endif
```

Inside main(), as the very first statement (before any other init):

```
int main(void) {
#ifdef RECOVERY_MODE
    /* Recovery build: this is a one-shot revert-to-stock app.
     * Skip all normal application initialisation and run the
     * bootloader replacement immediately. Doesn't return on
     * success. On validation failure, halt — the user can
     * power-cycle and try again with a fresh push. */
    (void)bl_updater_run_and_invalidate_app();
    while (1) { __WFE(); }
#endif

    /* ... normal application init follows ... */
```

Put the #ifdef block BEFORE log init, BEFORE clock init, BEFORE
USB init — recovery mode wants nothing else running. The
SoftDevice isn’t enabled at this point, so the SD-disable step
inside bl_updater is a no-op (which is correct).

-----

1. Patch firmware/application/Makefile

-----

Near the other CFLAGS additions, add:

```
ifdef RECOVERY_MODE
CFLAGS += -DRECOVERY_MODE=1
endif
```

-----

1. Replace build.sh

-----

Use the updated build.sh (in this directory). The diff from the
existing script:

- Always: runs gen_embedded_bl.py after the bootloader build, so
  embedded_bootloader.h is automatically refreshed from THIS
  build’s bootloader.hex. No manual step between bootloader
  changes and application rebuilds.
- Always: produces ${device_type}-application.uf2 in objects/
  after a normal build, for drag-and-drop application updates
  via the UF2 bootloader.
- If RECOVERY_ZIP env var is set: skips the bootloader build
  entirely, runs make_recovery_header.py against the zip,
  passes RECOVERY_MODE=1 to Make, emits only the
  ${device_type}-revert-to-stock.uf2.

# ================================================================
BUILDING A RECOVERY UF2 (per upstream release)

For every new upstream stable release:

```
cd firmware
RECOVERY_ZIP=~/Downloads/ultra-dfu-full.zip ./build.sh
```

Output: objects/ultra-revert-to-stock.uf2 (or
lite-revert-to-stock.uf2 if CURRENT_DEVICE_TYPE=lite).

The build will print the CRC32 of the embedded stock BL — pin
this in your release notes so users with mismatched bytes know
to grab the right recovery UF2 for their target stock release:

```
manifest: SD = 153140 bytes, BL = 43428 bytes
  initial SP    : 0x20038000
  reset handler : 0x000F4F74  (BL region — OK)
Wrote application/src/embedded_bootloader.h
  size  : 43428 bytes
  CRC32 : 0xF3AC4889         ← include in release notes
```

Before publishing: push the recovery UF2 to one of your own
Chameleons, confirm `dmesg` shows the stock BL’s USB descriptor
afterwards, confirm `flash-dfu-app.sh` completes the stock app
push. CRC validation in bl_updater_validate() catches data
corruption in transit, but not a packaging mistake on your end
where the wrong BL got embedded.

Suggested filename for distribution:

```
chameleon-revert-to-stock-v<UPSTREAM_VERSION>.uf2
```

The version tag matters if upstream ever changes the bootloader
between releases — versioned filenames let users match what they
intend to revert to.

# ================================================================
END USER FLOW

1. Cold-boot the device, hold B, plug back in (UF2 DFU mode)
1. CHAMELEON drive appears
1. Drag chameleon-revert-to-stock-vX.uf2 onto the drive
1. Wait ~2 seconds. The drive will disappear. This is normal —
   the device resets twice in quick succession: once into the
   recovery app, then again into the stock bootloader.
1. Stock BL boots, finds no valid app, enters DFU mode
   automatically
1. Push stock app via the upstream release’s flash-dfu-app.sh
   (or `nrfutil` directly with the upstream signed zip)

The second reset is what trips up first-time users. Tell them
to expect the CHAMELEON drive to vanish — that’s the success
signal, not a failure.

# ================================================================
SAFETY NOTES

- This is one-shot. Once the user runs the recovery UF2, the
  device’s UF2 bootloader is gone and the only way to put it
  back is to rebuild your normal firmware and re-flash via the
  bl_updater path (assuming you’ve kept your UF2 firmware) or
  via SWD.
- The recovery app self-destructs after success. Don’t expect
  the device to “stay on” the recovery UF2 — by design, the
  first invocation is also the last.
- If make_recovery_header.py emits a CRC that differs from the
  one in your release notes for a given upstream version, the
  BL bytes have changed between releases and the recovery UF2
  needs to be regenerated.
- The bricking window is ~1.4 seconds — the time NVMC needs to
  erase 11 pages and write ~43 KB. Keep the device powered.
  Power loss during this window leaves the BL region in an
  indeterminate state, recoverable only with SWD.
- Power loss AFTER the BL is written but BEFORE the self-destruct
  completes is safe: on next boot the (still valid) recovery app
  runs again, sees `bl_updater_validate()` passes, attempts the
  BL write (writes the same bytes — wasted operation, not
  destructive), then self-destructs and resets. Either way the
  device converges to the working “stock BL + DFU mode” state.

# ================================================================
SHARED INFRASTRUCTURE

bl_updater.c and bl_updater.h are the same files in both the
normal UF2 build and the RECOVERY_MODE build. Only the embedded
bootloader bytes differ (via embedded_bootloader.h), and only
which entry point gets called (manual `hw update_bl` from the
CLI vs automatic on-boot in recovery mode).

This means:

- One source tree, two build targets
- Changes to the bootloader update mechanism land in both
  paths simultaneously
- The CRC validation catches accidentally building one variant
  with the other’s embedded BL header