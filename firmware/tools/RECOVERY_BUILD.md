# ================================================================
FULL IMAGE RESTORE — reinstall or recover the UF2 bootloader

With ACL flash protection removed from this fork’s bootloader,
the UF2 transport can write to the full flash range including
the bootloader region. A single drag-and-drop of the full image
UF2 restores everything: MBR, SoftDevice, bootloader, application,
and settings.

================================================================
QUICK START

1. Build normally:
   
   cd firmware
   ./build.sh
   
   Output: objects/ultra-fullimage.uf2  (or lite-fullimage.uf2)
1. Enter UF2 DFU mode on the device:
   Cold-boot, hold B, plug USB. The CHAMELEON drive appears.
1. Drag objects/ultra-fullimage.uf2 onto the CHAMELEON drive.
1. Wait ~2 seconds. The drive disappears and the device resets
   into the restored firmware.

That’s it.

================================================================
WHEN TO USE THIS

- First-time install of this fork’s UF2 bootloader onto a device
  running the stock bootloader (stock BL also presents a DFU
  drive; the full image UF2 works there too).
- Recovering a device after a bad firmware update.
- Restoring a device that was reverted to stock with the upstream
  flash-dfu-app.sh.
- Replacing the bootloader without SWD.

================================================================
WHAT THE FULL IMAGE COVERS

The fullimage.hex (and derived UF2) produced by build.sh is a
merge of:

softdevice.hex   — Nordic S140 SoftDevice
bootloader.hex   — this fork’s UF2 bootloader (ACL removed)
application.hex  — ChameleonUltra application
settings.hex     — nrfutil DFU settings page

It covers the full flash range from 0x0000 (MBR) through the
bootloader region at 0xF3000–0xFE000. Every region is restored
in a single operation.

================================================================
NOTES

- The device running the full image UF2 must have a UF2-capable
  bootloader already installed (either this fork’s, or the stock
  bootloader which also presents a DFU MSC drive). If the
  bootloader is completely gone, SWD is required to recover.
- Power loss during the ~2 second write window could leave flash
  in an inconsistent state. Keep the device powered until the
  drive disappears.
- The stock bootloader enforces a write boundary at 0xF3000 and
  will ignore writes to the bootloader region. If you are using
  the stock bootloader as the entry point, only the SoftDevice
  and application portions of the full image will be written.
  Install this fork’s bootloader first via SWD if you need the
  full restore from stock.