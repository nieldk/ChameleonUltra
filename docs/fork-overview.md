# Fork overview

What this fork adds on top of upstream ChameleonUltra. At the time of writing
the branch is ~300 commits ahead of `RfidResearchGroup/ChameleonUltra` main —
roughly **15,000 added lines across 85 files**, plus a handful of vendored nRF
SDK files patched for the UF2 bootloader and DFU behaviour.

For general device usage see the
[upstream wiki](https://github.com/RfidResearchGroup/ChameleonUltra/wiki); the
pages linked from [README.md](README.md) cover the fork-specific behaviour in
detail.

## UF2 bootloader

A composite **UF2 (MSC) + CDC serial DFU** bootloader — drag-and-drop firmware
updates over a virtual mass-storage drive, no external flasher required for the
application.

* Bootloader: `nrf_dfu_uf2.c`, `uf2.h`, `uf2_blockdev.[ch]`,
  `uf2_ghostfat.[ch]`, `uf2_status.[ch]` (ghostfat derived from tinyuf2,
  `LICENSE.MIT`); reworked `bootloader/Makefile`, `main.c`, `app_config.h`,
  `sdk_config.h`; linker split (`bootloader-stage1.ld`).
* Application self-update path: `bl_updater.[ch]`.
* Host tooling: `gen_embedded_bl.py`, `flash-uf2-app.sh`, `flash-dfu-sdbl.sh`,
  `revert-to-stock.sh`, a rewritten `build.sh` (app / fullimage / recovery
  outputs), and `firmware/tools/UF2_INSTALL.md`.
* Several vendored SDK bootloader/USB files patched to support it.

See [flashing-and-bootloader.md](flashing-and-bootloader.md) for the flash map,
the UF2 write window, and recovery.

## Standalone-mode framework

Run captures/actions on the device with no host attached; results persist to
flash and are pulled later.

* Core: `app_standalone.[ch]`, `app_cmd_standalone.c`, `standalone_led.[ch]`.
* Modes (`standalone_modes/`): `mode_template.c`, `mode_authtrace.c`,
  `mode_emultrace.c`, `mode_hf14a_tap_sniff.c`, `mode_relay.c`,
  `mode_slot_cycle.c`, with `CONTRIBUTING STANDALONE.md` and `TESTING.md`.
* Client `standalone` command group: status, set-mode, trigger, disarm,
  get-result, ls, clear-result, config.

## HF-14A sniffing

* Sniff callbacks and passive-tap mode in `nfc_14a.[ch]`; card-side passive
  receive in `rc522.[ch]`; sniff engine, capture buffer and finalize in
  `app_cmd.c`.
* Client decoders, MIFARE Classic nonce extraction and mfkey glue.
* Standalone `hf14a_tap_sniff` mode and Proxmark3 `.trace` export — see
  [hf14a-sniff-pm3-trace.md](hf14a-sniff-pm3-trace.md).

## HF relay

BLE reader/tag relay: `ble_relay.[ch]`, `nfc_relay_tag.[ch]`, `mode_relay.c`.

## Client transport & DFU

* `chameleon_ble.py` — native cross-platform BLE (Nordic UART) transport for
  the Python CLI.
* `chameleon_dfu.py` — serial/BLE DFU driven from the CLI.

## LF FDX-B

`fdxb.[ch]`, `lf_fdxb_data.c`, client `fdxb_country.py`, plus LF reader / T55xx
changes (`lf_125khz_radio`, `lf_em4x05_data`, `lf_reader_*`, `lf_t55xx_data`,
`t55xx.h`, `tag_base_type.h`).

## DFU behaviour & versioning

* Firmware downgrade prevention removed — see the downgrade section of
  [flashing-and-bootloader.md](flashing-and-bootloader.md).
* Manual (non-git-tag) versioning and the flat `hw blver` — see
  [versioning.md](versioning.md).
