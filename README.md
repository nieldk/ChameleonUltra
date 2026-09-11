# Phreakbyte

**Phreakbyte edition** is an independent firmware and tooling distribution for the
ChameleonUltra hardware, focused on fast, frictionless flashing and iteration.

It is a standalone project with its own roadmap. It is derived from
[RfidResearchGroup/ChameleonUltra](https://github.com/RfidResearchGroup/ChameleonUltra)
and remains GPLv3. See [Credits and license](#credits-and-license).

- **Maintainer:** [nieldk](https://github.com/nieldk) at [sec1.dk](https://sec1.dk)
- **Hardware:** ChameleonUltra / ChameleonLite (unmodified)

![overview](docs/images/ultra-overview.png)

## Why Phreakbyte

The stock firmware ships a signed Nordic Secure DFU bootloader, so every update
means `nrfutil`, signed packages, and driver handling. Phreakbyte replaces that
with a UF2 drag-and-drop bootloader. Day-to-day updates become "copy a `.uf2`
onto a USB drive." That is the whole point: shorter build-flash-test loops.

## What is different from stock

- **UF2 bootloader.** Firmware is flashed by copying a `.uf2` file onto the
  `CHAMELEON` mass-storage drive. No `nrfutil`, no signed packages, no driver
  install for routine updates.
- **`bl_updater`.** Bootstrap a new bootloader from the running application,
  without an SWD probe. A freshly built bootloader is embedded in the
  application and written to flash via a CLI command.
- **Multi-image DFU flashing.** Combined images can be pushed in a single pass.
- **Revert-to-stock UF2.** A single drag-and-drop restores the signed Nordic
  Secure DFU bootloader whenever you want it back. See
  [`firmware/tools/RECOVERY_BUILD.md`](firmware/tools/RECOVERY_BUILD.md).
- **Native cross-platform BLE.** The desktop CLI connects over BLE (Nordic UART)
  as well as USB.

The RFID/NFC research feature set and the client protocol are carried forward,
so existing tooling such as ChameleonUltraGUI continues to work.

## Install

**Prebuilt UF2 (recommended):** follow
[`firmware/tools/UF2_INSTALL.md`](firmware/tools/UF2_INSTALL.md). In short: enter
the bootloader, then drag the `.uf2` onto the `CHAMELEON` drive.

**Build from source:**

```
cd firmware
./build.sh
```

Then flash with the UF2 helper:

```
./flash-uf2-app.sh
```

Other flash paths (`flash-dfu-app.sh`, `flash-dfu-full.sh`, `flash-dfu-sdbl.sh`)
remain available for SWD and signed-DFU workflows.

## Revert to stock

To return to the upstream signed-DFU bootloader:

```
cd firmware
./revert-to-stock.sh
```

Details and the recovery-image build are documented in
[`firmware/tools/RECOVERY_BUILD.md`](firmware/tools/RECOVERY_BUILD.md).

## Client

The Python CLI lives in `software/script`.

```
cd software/script
python3 -m pip install -r requirements.txt
python3 chameleon_cli_main.py
```

Connect over USB or BLE from the `hw connect` command. Run `hw version` to see
the running firmware and build.

## Versioning

Device version is derived at build time from `git describe` against `v*.*` tags
(`firmware/Makefile.defs`). Releases are tagged `vMAJOR.MINOR`, and `hw version`
reports the tag plus the short commit.

## Commands

A complete list and arguments for all CLI commands in this fork.
[`docs/command.md`](docs/command.md).

## Credits and license

Phreakbyte is built on the work of the
[RfidResearchGroup ChameleonUltra](https://github.com/RfidResearchGroup/ChameleonUltra)
project and its contributors. Thanks to Iceman and the RRG team. The detachment
into a standalone project was made with their knowledge.

This project is licensed under the **GNU General Public License v3.0**. Upstream
copyright notices and `AUTHORS.md` are preserved. See [`LICENSE`](LICENSE).
