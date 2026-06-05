================================================================
RECOVERY-MODE BUILD — revert from UF2 bootloader to stock

This tree ships with a built-in path back to the upstream stock
firmware. The mechanism: build a small "recovery" application that,
on boot, writes the stock bootloader (extracted from an upstream
release zip) into the BL region, erases its own vector table so the
new BL won't try to boot it again, and resets. The device ends up
in stock DFU mode, ready for a fresh signed application push via
the upstream `flash-dfu-app.sh`.

All the source-level integration is already in place. To produce a
recovery UF2 for a given upstream release, you only need to point
build.sh at the upstream zip.

================================================================
QUICK START

Grab the upstream stable release zip from
<https://github.com/RfidResearchGroup/ChameleonUltra/releases>
(file: ultra-dfu-full.zip or lite-dfu-full.zip), then:

```
cd firmware
RECOVERY_ZIP=~/Downloads/ultra-dfu-full.zip ./build.sh
```

Output: objects/ultra-revert-to-stock.uf2 (or lite-revert-to-stock.uf2
if CURRENT_DEVICE_TYPE=lite).

That's it. Distribute the .uf2 to end users.

================================================================
HOW IT WORKS

When RECOVERY_ZIP is set, build.sh takes a different code path:

- Skips the bootloader build entirely (we're embedding the STOCK
  bootloader from the upstream zip, not our own UF2 one).
- Runs tools/make_recovery_header.py against the upstream zip.
  This script parses the zip's manifest, slices the bootloader
  bytes out of sd_bl.bin at the offset declared in the manifest's
  info_read_only_metadata, sanity-checks the vector table, and
  emits application/src/embedded_bootloader.h.
- Builds the application with RECOVERY_MODE=1, which gates the
  bl_updater hook at the very top of main(). The compiled
  application's main() does ONLY this:
  
  ```
  (void)bl_updater_run_and_invalidate_app();
  while (1) { __WFE(); }
  ```
  
  bl_updater_run_and_invalidate_app() validates the embedded BL
  via CRC32, disables the SoftDevice (no-op here since SD isn't
  enabled yet), erases the BL region pages, writes the stock BL
  bytes, erases our own first page (the vector table), and resets.
- Converts application.hex to UF2 via tools/uf2conv.py and emits
  only the ${device_type}-revert-to-stock.uf2. No signed DFU zips,
  no merged hex — those don't make sense for this artifact (users
  running this don't have SWD; that's the whole point).

Note: the UF2 transport in this fork writes to the region
0x1000–0xF3000, which covers both the SoftDevice and application
areas. The recovery UF2 therefore carries the full stock firmware
(SoftDevice + application), and a single drag-and-drop is all that
is needed — no follow-up flash-dfu-app.sh required after the
device reboots into the stock bootloader.

================================================================
WHAT TO PUBLISH

Each time you build a new recovery UF2, the build will print the
CRC32 of the embedded stock BL. Pin this in your release notes so
users can match the right recovery UF2 to their target stock
release:

```
manifest: SD = 153140 bytes, BL = 43428 bytes
  initial SP    : 0x20038000
  reset handler : 0x000F4F74  (BL region — OK)
Wrote application/src/embedded_bootloader.h
  size  : 43428 bytes
  CRC32 : 0xF3AC4889         ← include in release notes
```

The Make output will also confirm RECOVERY_MODE is active:

```
Chameleon <Application>: RECOVERY_MODE build — revert-to-stock UF2.
```

If you don't see that line, RECOVERY_MODE didn't propagate — likely
build.sh didn't get the env var, or the patches in the Makefile
were reverted by a merge. See Appendix B for the patch details.

Suggested distribution filename:

```
chameleon-revert-to-stock-v<UPSTREAM_VERSION>.uf2
```

The version tag matters because if upstream ever changes the
bootloader between releases, a versioned filename lets users match
what they intend to revert to.

Before publishing, push the recovery UF2 to one of your own
Chameleons:

- Confirm dmesg shows the stock BL's USB descriptor afterwards
- Confirm the device enters stock DFU mode automatically (no valid
  app found)
- Confirm flash-dfu-app.sh completes the stock app push

The CRC validation in bl_updater_validate() catches data corruption
in transit, but not a packaging mistake where the wrong BL got
embedded. Round-trip every release at least once.

================================================================
END USER FLOW

This is what to communicate to users of the recovery UF2:

1. Cold-boot the device, hold B, plug back in (UF2 DFU mode)
1. CHAMELEON drive appears
1. Drag chameleon-revert-to-stock-vX.uf2 onto the drive
1. Wait ~2 seconds. The drive will disappear. This is normal —
   the device resets twice in quick succession: once into the
   recovery app (which writes the stock bootloader), then again
   into the stock bootloader.
1. Stock BL boots, finds no valid app, enters DFU mode
   automatically.
1. Push the stock app via the upstream release's
   flash-dfu-app.sh (or nrfutil directly with the upstream signed
   zip).

Step 4 is what trips up first-time users. Tell them up front that
the CHAMELEON drive will vanish — that's the success signal, not a
failure.

================================================================
SAFETY NOTES

- This is one-shot. Once a user runs the recovery UF2, the device's
  UF2 bootloader is gone. To restore it, drag the
  ${device_type}-fullimage.uf2 (built from this fork) onto the
  stock DFU drive — no SWD required, provided the stock bootloader
  is still intact and ACL protection was removed from the UF2
  bootloader build.
- The recovery app self-destructs after success. Don't expect the
  device to "stay on" the recovery UF2 — by design, the first
  invocation is also the last.
- If make_recovery_header.py emits a CRC that differs from the one
  in your release notes for a given upstream version, the upstream
  BL bytes have changed between releases. Regenerate the recovery
  UF2.
- The bricking window is ~1.4 seconds — the time NVMC needs to
  erase the BL region pages and write ~43 KB. Keep the device
  powered. Power loss during this window leaves the BL region in
  an indeterminate state, recoverable only with SWD.
- Power loss AFTER the BL is written but BEFORE the self-destruct
  completes is safe: on next boot the (still valid) recovery app
  runs again, sees bl_updater_validate() passes, attempts the BL
  write (writes the same bytes — wasted operation, not
  destructive), then self-destructs and resets. Either way the
  device converges to the working "stock BL + DFU mode" state.

================================================================
APPENDIX A — file layout in this tree

The patches are already in place. For reference, this is where
each piece lives:

```
firmware/build.sh                        # gated by RECOVERY_ZIP
firmware/application/Makefile            # RECOVERY_MODE CFLAGS
firmware/application/src/app_main.c      # main() recovery hook
firmware/application/src/bl_updater.c    # update mechanism
firmware/application/src/bl_updater.h
firmware/application/src/embedded_bootloader.h  # regenerated
                                                # per build
firmware/tools/gen_embedded_bl.py        # normal-build header gen
firmware/tools/make_recovery_header.py   # recovery-build header gen
firmware/tools/uf2conv.py                # ihex/bin -> uf2
```

================================================================
APPENDIX B — porting these patches to another fork

If you're integrating this recovery mechanism into a different
ChameleonUltra fork or a future merge breaks one of the source-level
hooks, here's the minimal set of changes needed beyond dropping in
bl_updater.c/h, the tools, and build.sh:

-----

 B.1  firmware/application/Makefile

Add bl_updater.c to SRC_FILES alongside the other application
sources:

```
SRC_FILES += \
  $(PROJ_DIR)/bl_updater.c \
  ...
```

After the CHAMELEON_ULTRA / CHAMELEON_LITE conditional block
(just before the NRF_LOG_UART block), add:

```
ifdef RECOVERY_MODE
  CFLAGS += -DRECOVERY_MODE=1
$(info  Chameleon <Application>: RECOVERY_MODE build — revert-to-stock UF2.)
endif
```

The $(info) line gives a visible build-time signal you're producing
a recovery firmware vs a normal one — useful when scanning logs.

-----

 B.2  firmware/application/src/app_main.c

After the existing `#if defined(PROJECT_CHAMELEON_ULTRA) / #include "rc522.h" / #endif` block near the top of the file, add:

```
#ifdef RECOVERY_MODE
#include "bl_updater.h"
#endif
```

Inside main(), as the VERY FIRST statement (before hw_connect_init,
before any other peripheral or SoftDevice init):

```
int main(void) {
#ifdef RECOVERY_MODE
    (void)bl_updater_run_and_invalidate_app();
    while (1) { __WFE(); }
#endif

    hw_connect_init();    // existing code follows
    ...
```

Order matters here: SoftDevice must NOT be enabled when bl_updater
runs (the SD-disable inside it relies on a clean "SD not yet up"
state for the no-op path). Putting the hook at the very top of
main() guarantees this. Don't reorder it later in the init flow.

In a non-RECOVERY build, the #ifdef block compiles away to nothing —
the normal init flow is bit-for-bit unchanged.

-----

 B.3  firmware/build.sh

Replace with this fork's build.sh (or merge the RECOVERY_ZIP env
var branch into your own). The key behaviour:

- Always: after the bootloader build, run gen_embedded_bl.py to
  refresh embedded_bootloader.h from THIS build's bootloader.hex.
  This removes a footgun where a bl_updater run could write a
  stale bootloader from a previous build.
- If RECOVERY_ZIP is set: skip the bootloader build, run
  make_recovery_header.py against the zip, build the application
  with `make -j RECOVERY_MODE=1`, emit only the
  ${device_type}-revert-to-stock.uf2.

================================================================
APPENDIX C — design rationale

Why bl_updater_run_and_invalidate_app() instead of just running
bl_updater_run() in the recovery build?

bl_updater_run() replaces the BL but leaves the application valid —
which is correct when you're updating a UF2 BL to a newer UF2 BL,
because the app keeps working. For revert-to-stock, the app is the
recovery app itself, and you specifically do NOT want the new
(stock) bootloader to keep booting it. So after a successful BL
write, the recovery variant erases the application's first page
(containing the vector table). The new stock BL boots up, fails to
validate the now-headless application, and Nordic's standard "no
valid app" behaviour is to fall through to DFU mode automatically.
Exactly the state the user needs.

Why is the BL-write-then-self-destruct pair power-loss-safe?

If power drops *after* the BL is written but *before* the
self-destruct erase completes, the device has stock BL + still-valid
recovery app. On next boot, recovery app runs again, sees
bl_updater_validate() passes, attempts the BL write (overwrites
stock BL with the same stock BL bytes — wasted operation, not
destructive), and then self-destructs. Either way the user
converges to "stock BL + no app + DFU mode" without needing SWD.

The only genuinely dangerous window is the BL erase + write itself
(~1.4 seconds), during which the BL region is partially populated.
Power loss there is unrecoverable without SWD.

Why can't the UF2 transport write the stock BL directly?

Originally the UF2 transport refused writes at or above 0xF3000 to
prevent userspace from bricking the bootloader region via a bad
drag-and-drop. bl_updater was the controlled break in that
protection.

In this fork, ACL flash protection has been removed from the
bootloader build (main.c). As a result the bootloader region is
writable via UF2 drag-and-drop, and build.sh now produces a
${device_type}-fullimage.uf2 covering the full address range
(MBR + SoftDevice + bootloader + app + settings). Dropping this
file onto a device running this fork's UF2 bootloader will restore
everything in a single operation — including the bootloader itself
— without SWD.

The bl_updater path (and the revert-to-stock UF2) still uses the
application-side write mechanism, because the stock bootloader's
UF2 transport does enforce the 0xF3000 boundary. bl_updater
bypasses it from the application context and includes CRC32
validation to compensate.
