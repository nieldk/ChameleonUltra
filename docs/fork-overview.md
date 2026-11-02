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
* Host tooling: `flash-uf2-app.sh`, `flash-dfu-sdbl.sh`,
  a rewritten `build.sh` (app / fullimage
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

## Logic analyser

`hw logic`: timestamped chip-select and field-LED edges plus an RC522 register
log with values, plotted or exported as VCD. Hooks in `rc522.c` and
`hw_connect.h`, engine in `logic_analyzer.[ch]`, `common/logic_hook.h`,
client `cli_hw_logic.py`. Command IDs 3037-3040. See
[logic-analyzer.md](logic-analyzer.md).

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

FDX-B is also an emulation slot type (`TAG_TYPE_FDXB`): `fdxb_modulator()` in
`fdxb.c` drives the PWM (1 MHz base, 119 µs half-bit, 238 µs bit = 32 cycles of
134.2 kHz), set per slot with `lf fdxb econfig`. Command IDs 5016/5017.
`lf/tests/` holds a host test that round-trips the modulator through the
decoder (`make -C firmware/application/src/rfid/nfctag/lf/tests test`).

Known limit: the emulation loads the antenna through a fixed switched load
(LF_MOD drives the load MOSFET), so modulation depth is set by the hardware and
cannot be raised in firmware. The antenna is tuned for 125 kHz, so one Chameleon
reading another's FDX-B emulation at 134.2 kHz couples weakly and the result
varies between units. A raw `lf sniff` capture of the emulation shows the
intended 238 µs bit period (118 µs half-bit).

## DESFire EV3 slot types

`TAG_TYPE_DESFIRE_EV3_2K/4K/8K` (1306–1308) sit beside the EV1/EV2 types. The
engine already emulated EV3 from the credential; the slot type is the label, and
`hf des eload` now sets it from the credential generation (1/2/3) and storage
tier. Previously an EV3 credential was labelled EV1.

## DFU behaviour & versioning

* Firmware downgrade prevention removed — see the downgrade section of
  [flashing-and-bootloader.md](flashing-and-bootloader.md).
* Manual (non-git-tag) versioning and the flat `hw blver` — see
  [versioning.md](versioning.md).
