# Flashing & the UF2 bootloader

This fork uses a single composite bootloader at `0xF3000` (UF2/MSC + CDC serial
DFU). Understanding what the UF2 path can and cannot write is essential —
flashing the wrong image over UF2 will brick the device to an SWD-only state.

## Flash map

```
0x00000 - 0x27000   SoftDevice (S140)
0x27000 - 0xF3000   Application     <- the ONLY region UF2 will write
0xF3000 - 0xFE000   Bootloader (44 KB)
0xFE000 - 0xFF000   MBR params
0xFF000 - 0x100000  Bootloader / DFU settings
```

## The UF2 write window

The UF2 transport (`firmware/bootloader/src/nrf_dfu_uf2.c`,
`uf2_ghostfat.h`) hard-guards writes to the application region only:

```c
#define UF2_FLASH_APP_START 0x00027000UL
#define UF2_FLASH_APP_END   0x000F3000UL
// uf2_flash_write() rejects any block outside [START, END)
```

Consequences:

* **`*-application.uf2` is safe.** It is built from `application.hex` and lands
  entirely inside the app region.
* **`*-fullimage.uf2` must NOT be dragged onto the UF2 drive.** It contains the
  SoftDevice, bootloader and settings page, all outside the write window. Those
  blocks are dropped while the app blocks land, leaving an inconsistent state
  that won't boot — recoverable only over SWD. `fullimage.uf2` is for SWD use.
* The **DFU settings page (`0xFF000`) can never be written over UF2.** Anything
  that must live there cannot be delivered by the UF2 drive.

## Normal flashing (application)

```bash
cd firmware
./build.sh
./flash-uf2-app.sh      # hold B, plug USB to enter UF2 mode; copies *-application.uf2
```

`flash-uf2-app.sh` waits for the `CHAMELEON` UF2 drive, copies the application
UF2, and the device resets into the new application.

## Flashing SoftDevice / bootloader

These are outside the UF2 window, so use one of:

* **SWD** — the `flash_stlink` make target (OpenOCD + ST-Link) or `nrfjprog`,
  flashing `fullimage.hex` / the merged hex.
* **Serial / CDC DFU** — `./flash-dfu-sdbl.sh` (the SD+BL DFU zip). This is the
  only non-SWD way to update the bootloader itself.

## Recovering an SWD-only device

If a bad `fullimage.uf2` (or an interrupted BL flash) left the device
unresponsive, reflash a known-good image over SWD (`flash_stlink` /
`nrfjprog`), or use the recovery build (`revert-to-stock.sh` /
`RECOVERY_ZIP=…`). After recovery the normal application-UF2 path works again.

## Downgrade prevention

This fork **does not enforce firmware downgrade prevention**:

* `NRF_DFU_APP_DOWNGRADE_PREVENTION = 0` in the bootloader `sdk_config.h`, so
  `fw_version_ok()` accepts any application/SoftDevice version.
* The bootloader branch of `fw_version_ok()`
  (`nrf52_sdk/.../nrf_dfu_ver_validation.c`) is patched to return `true`
  unconditionally, so an equal or older bootloader is accepted — re-flashing
  the same build and revert-to-stock both work.

Because of this, the `bootloader_version` value carries no monotonic
constraint here; it is free to use as the `hw blver` display value (see
[versioning.md](versioning.md)).

Still enforced (not downgrade checks): the hardware-version match, the
SoftDevice compatibility gate for SoftDevice-type updates, and the DFU package
signature (`NRF_DFU_REQUIRE_SIGNED_APP_UPDATE = 1`). Packages must be signed
with the fork's DFU key.
