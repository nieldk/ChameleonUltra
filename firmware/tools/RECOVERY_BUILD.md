# ================================================================
FULL IMAGE RESTORE — reinstall or recover the complete firmware

This document covers how to build and deploy a full image UF2
that restores everything on the device: MBR, SoftDevice,
bootloader, application, and settings — in a single drag-and-drop.

Because ACL flash protection has been removed from this fork’s
bootloader, the UF2 transport can write to the full flash range
including the bootloader region. No SWD required.

================================================================
PREREQUISITES

You need a working build environment. If you haven’t set one up
yet, follow the full instructions in firmware/tools/UF2_INSTALL.md
first. In short:

- arm-none-eabi-gcc (10.x or newer)
- nrfutil
- mergehex (from Nordic nRF Command Line Tools)
- Python 3

You also need both repositories:

1. This fork (the UF2 bootloader fork):
   <https://github.com/nieldk/ChameleonUltra>  (branch: UF2)
1. RfidResearchGroup’s upstream repo (for the full SDK and
   nrf52_sdk tree that build.sh expects):
   <https://github.com/RfidResearchGroup/ChameleonUltra>

================================================================
STEP 1 — set up the directory structure

Clone both repositories and copy the required files from this
fork into the upstream tree. The build system expects to run from
within the RRG repo structure.

# Clone upstream RRG repo

git clone <https://github.com/RfidResearchGroup/ChameleonUltra.git>
cd ChameleonUltra

# Clone this fork alongside it (or use an existing checkout)

git clone -b UF2 <https://github.com/nieldk/ChameleonUltra.git> ../ChameleonUltra-UF2

# Copy the patched build script and uf2conv tool into place

cp ../ChameleonUltra-UF2/firmware/build.sh         firmware/build.sh
cp ../ChameleonUltra-UF2/firmware/tools/uf2conv.py firmware/tools/uf2conv.py

The patched build.sh differs from upstream in two ways:

- Generates ultra-fullimage.uf2 / lite-fullimage.uf2 in addition
  to the standard artifacts.
- Includes the gen_embedded_bl.py / bl_updater integration for
  bootloader self-update from the application.

================================================================
STEP 2 — fetch upstream tags

The build uses `git describe` to embed a version string. Tags only
exist on the upstream remote:

git remote add upstream <https://github.com/RfidResearchGroup/ChameleonUltra.git>
git fetch upstream –tags

Verify:

git describe –tags

# e.g. v2.0.0-15-gabc1234

If you see “No names found”, run:

git fetch upstream ‘refs/tags/*:refs/tags/*’

================================================================
STEP 3 — build

cd firmware
./build.sh

A normal build takes 30–90 seconds. The relevant output artifact
is in firmware/objects/:

ultra-fullimage.uf2   (or lite-fullimage.uf2)

This file contains the merged MBR + SoftDevice + UF2 bootloader
(ACL removed) + application + settings, converted to UF2 format.

================================================================
STEP 4 — flash

Enter UF2 DFU mode on the device:

1. Unplug the device.
1. Press and hold the B button.
1. Plug in USB while still holding B.
1. Release B after ~2 seconds.
1. The CHAMELEON drive appears.

Drag the full image UF2 onto the drive:

# Linux

cp objects/ultra-fullimage.uf2 /run/media/$USER/CHAMELEON/

# macOS

cp objects/ultra-fullimage.uf2 /Volumes/CHAMELEON/

# Windows

copy objects\ultra-fullimage.uf2 D:\

The drive disappears and the device resets. Boot is complete in
~2 seconds.

================================================================
WHEN TO USE THIS

- Restoring a device after a bad firmware update.
- Installing this fork’s UF2 bootloader onto a device already
  running any UF2-capable bootloader (including stock DFU).
- Recovering a device that was reverted to stock firmware.
- Replacing the bootloader without SWD during development.

================================================================
NOTE ON STOCK BOOTLOADER ENTRY POINT

If the device is currently running the stock RRG bootloader (not
this fork’s), the stock bootloader enforces a write boundary at
0xF3000 and will ignore writes to the bootloader region. In that
case:

- The SoftDevice and application portions of the full image
  will be written correctly.
- The bootloader region will not be updated.

To fully restore including the bootloader from a stock-bootloader
device, use SWD for the first install (see UF2_INSTALL.md,
Steps 3–4), then use the full image UF2 for all subsequent
restores.

================================================================