# Phreakbyte CLI Command Reference

Complete reference for the Phreakbyte edition ChameleonUltra client (`chameleon_cli_main.py`). Auto-generated from the CLI source: 26 command groups, 129 commands.

Notation: `<...>` are values you supply. Options shown with their flags, help text, allowed choices, whether required, and default when set. Run any command with `-h` in the client for the same information live.

## Top-level commands

### `clear`

Clear screen

### `rem`

Timestamped comment

- `comment` — Your comment  (required)

### `exit`

Exit client

### `dump_help`

Dump available commands

- `-d`, `--show-desc` — Dump full command description
- `-g`, `--show-groups` — Dump command groups as well

## `hw`

Hardware-related commands

### `hw connect`

Connect to chameleon by serial port, TCP, or BLE. Examples: -p /dev/ttyACM0 | -p tcp:127.0.0.1:4321 | -p ble (scan) | -p ble:AA:BB:CC:DD:EE:FF (needs 'bleak')

- `-p`, `--port`

### `hw disconnect`

Disconnect chameleon

### `hw mode`

Get or change device mode: tag reader or tag emulator

- `-r`, `--reader` — Set reader mode
- `-e`, `--emulator` — Set emulator mode

### `hw chipid`

Get device chipset ID

### `hw address`

Get device address (used with Bluetooth)

### `hw version`

Get current device firmware version

### `hw blver`

Get bootloader version

### `hw freemem`

Get device heap memory usage

### `hw dfu`

Restart application to bootloader/DFU mode

### `hw flash`

Flash a DFU firmware package (.zip) to the device over Secure DFU. Enters bootloader mode automatically, then uploads with no external tools required (no nrfutil).

- `file` — Path to the DFU package .zip  (required)
- `--no-enter` — Skip enter-bootloader; device is already in DFU mode
- `-p`, `--port` — Override the upload transport (default: the same transport the client is connected on). A serial port path, or 'ble' / 'ble:AA:BB:CC:DD:EE:FF' to force BLE DFU (needs bleak)
- `--wait` — Seconds to wait for the DFU device to appear (default: 30)  (default: 30.0)

### `hw factory_reset`

Wipe all slot data and custom settings and return to factory settings

- `--force` — Just to be sure

### `hw battery`

Get battery information, voltage and level

### `hw raw`

Send raw command

- `-c`, `--command` COMMAND — Command: ADC_GENERIC_READ, CHANGE_DEVICE_MODE, DELETE_ALL_BLE_BONDS, DELETE_SLOT_SENSE_TYPE, DELETE_SLOT_TAG_NICK, EM410X_ELECTRA_WRITE_TO_T55XX, EM410X_GET_EMU_ID, EM410X_SCAN, EM410X_SET_EMU_ID, EM410X_WRITE_TO_T55XX, EM4X05_READSNIFF, EM4X05_SCAN, ENTER_BOOTLOADER, FDXB_SCAN, FDXB_WRITE_TO_T55XX, GET_ACTIVE_SLOT, GET_ALL_SLOT_NICKS, GET_ANIMATION_MODE, GET_APP_VERSION, GET_BATTERY_INFO, GET_BLE_PAIRING_ENABLE, GET_BLE_PAIRING_KEY, GET_BOOTLOADER_VERSION, GET_BUTTON_PRESS_CONFIG, GET_DEVICE_ADDRESS, GET_DEVICE_CAPABILITIES, GET_DEVICE_CHIP_ID, GET_DEVICE_MODE, GET_DEVICE_MODEL, GET_DEVICE_SETTINGS, GET_ENABLED_SLOTS, GET_FREE_MEMORY, GET_GIT_VERSION, GET_LONG_BUTTON_PRESS_CONFIG, GET_SLEEP_TIMEOUT, GET_SLOT_INFO, GET_SLOT_TAG_NICK, HF14A_4_APDU_RECV, HF14A_4_APDU_SEND, HF14A_4_EMV_SCAN, HF14A_4_READER_APDU, HF14A_4_SET_ANTI_COLL, HF14A_4_STATIC_RESP, HF14A_AUTH_TRACE, HF14A_GET_ANTI_COLL_DATA, HF14A_GET_CONFIG, HF14A_RAW, HF14A_SCAN, HF14A_SCAN_KEEP, HF14A_SET_ANTI_COLL_DATA, HF14A_SET_CONFIG, HF14A_SNIFF, HIDPROX_GET_EMU_ID, HIDPROX_SCAN, HIDPROX_SET_EMU_ID, HIDPROX_WRITE_TO_T55XX, IDTECK_GET_EMU_ID, IDTECK_SET_EMU_ID, IDTECK_WRITE_TO_T55XX, IOPROX_COMPOSE_ID, IOPROX_DECODE_RAW, IOPROX_GET_EMU_ID, IOPROX_SCAN, IOPROX_SET_EMU_ID, IOPROX_WRITE_TO_T55XX, JABLOTRON_GET_EMU_ID, JABLOTRON_SCAN, JABLOTRON_SET_EMU_ID, JABLOTRON_WRITE_TO_T55XX, LF_SEARCH, LF_SNIFF, LF_T55XX_READ, LF_T55XX_WRITE, MF0_NTAG_GET_COUNTER_DATA, MF0_NTAG_GET_DETECTION_COUNT, MF0_NTAG_GET_DETECTION_ENABLE, MF0_NTAG_GET_DETECTION_LOG, MF0_NTAG_GET_EMULATOR_CONFIG, MF0_NTAG_GET_PAGE_COUNT, MF0_NTAG_GET_SIGNATURE_DATA, MF0_NTAG_GET_UID_MAGIC_MODE, MF0_NTAG_GET_VERSION_DATA, MF0_NTAG_GET_WRITE_MODE, MF0_NTAG_READ_EMU_PAGE_DATA, MF0_NTAG_RESET_AUTH_CNT, MF0_NTAG_SET_COUNTER_DATA, MF0_NTAG_SET_DETECTION_ENABLE, MF0_NTAG_SET_SIGNATURE_DATA, MF0_NTAG_SET_UID_MAGIC_MODE, MF0_NTAG_SET_VERSION_DATA, MF0_NTAG_SET_WRITE_MODE, MF0_NTAG_WRITE_EMU_PAGE_DATA, MF1_AUTH_ONE_KEY_BLOCK, MF1_CHECK_KEYS_OF_SECTORS, MF1_CHECK_KEYS_ON_BLOCK, MF1_DARKSIDE_ACQUIRE, MF1_DETECT_NT_DIST, MF1_DETECT_PRNG, MF1_DETECT_SUPPORT, MF1_ENC_NESTED_ACQUIRE, MF1_GET_BLOCK_ANTI_COLL_MODE, MF1_GET_DETECTION_COUNT, MF1_GET_DETECTION_ENABLE, MF1_GET_DETECTION_LOG, MF1_GET_EMULATOR_CONFIG, MF1_GET_FIELD_OFF_DO_RESET, MF1_GET_GEN1A_MODE, MF1_GET_GEN2_MODE, MF1_GET_PRNG_TYPE, MF1_GET_WRITE_MODE, MF1_HARDNESTED_ACQUIRE, MF1_MANIPULATE_VALUE_BLOCK, MF1_NESTED_ACQUIRE, MF1_READ_EMU_BLOCK_DATA, MF1_READ_ONE_BLOCK, MF1_SET_BLOCK_ANTI_COLL_MODE, MF1_SET_DETECTION_ENABLE, MF1_SET_FIELD_OFF_DO_RESET, MF1_SET_GEN1A_MODE, MF1_SET_GEN2_MODE, MF1_SET_PRNG_TYPE, MF1_SET_WRITE_MODE, MF1_STATIC_NESTED_ACQUIRE, MF1_WRITE_EMU_BLOCK_DATA, MF1_WRITE_ONE_BLOCK, PAC_GET_EMU_ID, PAC_SCAN, PAC_SET_EMU_ID, PAC_WRITE_TO_T55XX, RESET_SETTINGS, SAVE_SETTINGS, SEOS_READ_EMU_DATA, SEOS_WRITE_EMU_DATA, SEOS_WRITE_EMU_KEYS, SET_ACTIVE_SLOT, SET_ANIMATION_MODE, SET_BLE_PAIRING_ENABLE, SET_BLE_PAIRING_KEY, SET_BUTTON_PRESS_CONFIG, SET_LONG_BUTTON_PRESS_CONFIG, SET_SLEEP_TIMEOUT, SET_SLOT_DATA_DEFAULT, SET_SLOT_ENABLE, SET_SLOT_TAG_NICK, SET_SLOT_TAG_TYPE, SLOT_DATA_CONFIG_SAVE, STANDALONE_CLEAR_RESULT, STANDALONE_DISARM, STANDALONE_GET_CONFIG, STANDALONE_GET_MODE, STANDALONE_GET_RESULT, STANDALONE_GET_SIZES, STANDALONE_RELAY_DIAG, STANDALONE_SET_CONFIG, STANDALONE_SET_MODE, STANDALONE_TRIGGER, UPDATE_BL, VIKING_GET_EMU_ID, VIKING_SCAN, VIKING_SET_EMU_ID, VIKING_WRITE_TO_T55XX, WIPE_FDS  (choices: ADC_GENERIC_READ, CHANGE_DEVICE_MODE, DELETE_ALL_BLE_BONDS, DELETE_SLOT_SENSE_TYPE, DELETE_SLOT_TAG_NICK, EM410X_ELECTRA_WRITE_TO_T55XX, EM410X_GET_EMU_ID, EM410X_SCAN, EM410X_SET_EMU_ID, EM410X_WRITE_TO_T55XX, EM4X05_READSNIFF, EM4X05_SCAN, ENTER_BOOTLOADER, FDXB_SCAN, FDXB_WRITE_TO_T55XX, GET_ACTIVE_SLOT, GET_ALL_SLOT_NICKS, GET_ANIMATION_MODE, GET_APP_VERSION, GET_BATTERY_INFO, GET_BLE_PAIRING_ENABLE, GET_BLE_PAIRING_KEY, GET_BOOTLOADER_VERSION, GET_BUTTON_PRESS_CONFIG, GET_DEVICE_ADDRESS, GET_DEVICE_CAPABILITIES, GET_DEVICE_CHIP_ID, GET_DEVICE_MODE, GET_DEVICE_MODEL, GET_DEVICE_SETTINGS, GET_ENABLED_SLOTS, GET_FREE_MEMORY, GET_GIT_VERSION, GET_LONG_BUTTON_PRESS_CONFIG, GET_SLEEP_TIMEOUT, GET_SLOT_INFO, GET_SLOT_TAG_NICK, HF14A_4_APDU_RECV, HF14A_4_APDU_SEND, HF14A_4_EMV_SCAN, HF14A_4_READER_APDU, HF14A_4_SET_ANTI_COLL, HF14A_4_STATIC_RESP, HF14A_AUTH_TRACE, HF14A_GET_ANTI_COLL_DATA, HF14A_GET_CONFIG, HF14A_RAW, HF14A_SCAN, HF14A_SCAN_KEEP, HF14A_SET_ANTI_COLL_DATA, HF14A_SET_CONFIG, HF14A_SNIFF, HIDPROX_GET_EMU_ID, HIDPROX_SCAN, HIDPROX_SET_EMU_ID, HIDPROX_WRITE_TO_T55XX, IDTECK_GET_EMU_ID, IDTECK_SET_EMU_ID, IDTECK_WRITE_TO_T55XX, IOPROX_COMPOSE_ID, IOPROX_DECODE_RAW, IOPROX_GET_EMU_ID, IOPROX_SCAN, IOPROX_SET_EMU_ID, IOPROX_WRITE_TO_T55XX, JABLOTRON_GET_EMU_ID, JABLOTRON_SCAN, JABLOTRON_SET_EMU_ID, JABLOTRON_WRITE_TO_T55XX, LF_SEARCH, LF_SNIFF, LF_T55XX_READ, LF_T55XX_WRITE, MF0_NTAG_GET_COUNTER_DATA, MF0_NTAG_GET_DETECTION_COUNT, MF0_NTAG_GET_DETECTION_ENABLE, MF0_NTAG_GET_DETECTION_LOG, MF0_NTAG_GET_EMULATOR_CONFIG, MF0_NTAG_GET_PAGE_COUNT, MF0_NTAG_GET_SIGNATURE_DATA, MF0_NTAG_GET_UID_MAGIC_MODE, MF0_NTAG_GET_VERSION_DATA, MF0_NTAG_GET_WRITE_MODE, MF0_NTAG_READ_EMU_PAGE_DATA, MF0_NTAG_RESET_AUTH_CNT, MF0_NTAG_SET_COUNTER_DATA, MF0_NTAG_SET_DETECTION_ENABLE, MF0_NTAG_SET_SIGNATURE_DATA, MF0_NTAG_SET_UID_MAGIC_MODE, MF0_NTAG_SET_VERSION_DATA, MF0_NTAG_SET_WRITE_MODE, MF0_NTAG_WRITE_EMU_PAGE_DATA, MF1_AUTH_ONE_KEY_BLOCK, MF1_CHECK_KEYS_OF_SECTORS, MF1_CHECK_KEYS_ON_BLOCK, MF1_DARKSIDE_ACQUIRE, MF1_DETECT_NT_DIST, MF1_DETECT_PRNG, MF1_DETECT_SUPPORT, MF1_ENC_NESTED_ACQUIRE, MF1_GET_BLOCK_ANTI_COLL_MODE, MF1_GET_DETECTION_COUNT, MF1_GET_DETECTION_ENABLE, MF1_GET_DETECTION_LOG, MF1_GET_EMULATOR_CONFIG, MF1_GET_FIELD_OFF_DO_RESET, MF1_GET_GEN1A_MODE, MF1_GET_GEN2_MODE, MF1_GET_PRNG_TYPE, MF1_GET_WRITE_MODE, MF1_HARDNESTED_ACQUIRE, MF1_MANIPULATE_VALUE_BLOCK, MF1_NESTED_ACQUIRE, MF1_READ_EMU_BLOCK_DATA, MF1_READ_ONE_BLOCK, MF1_SET_BLOCK_ANTI_COLL_MODE, MF1_SET_DETECTION_ENABLE, MF1_SET_FIELD_OFF_DO_RESET, MF1_SET_GEN1A_MODE, MF1_SET_GEN2_MODE, MF1_SET_PRNG_TYPE, MF1_SET_WRITE_MODE, MF1_STATIC_NESTED_ACQUIRE, MF1_WRITE_EMU_BLOCK_DATA, MF1_WRITE_ONE_BLOCK, PAC_GET_EMU_ID, PAC_SCAN, PAC_SET_EMU_ID, PAC_WRITE_TO_T55XX, RESET_SETTINGS, SAVE_SETTINGS, SEOS_READ_EMU_DATA, SEOS_WRITE_EMU_DATA, SEOS_WRITE_EMU_KEYS, SET_ACTIVE_SLOT, SET_ANIMATION_MODE, SET_BLE_PAIRING_ENABLE, SET_BLE_PAIRING_KEY, SET_BUTTON_PRESS_CONFIG, SET_LONG_BUTTON_PRESS_CONFIG, SET_SLEEP_TIMEOUT, SET_SLOT_DATA_DEFAULT, SET_SLOT_ENABLE, SET_SLOT_TAG_NICK, SET_SLOT_TAG_TYPE, SLOT_DATA_CONFIG_SAVE, STANDALONE_CLEAR_RESULT, STANDALONE_DISARM, STANDALONE_GET_CONFIG, STANDALONE_GET_MODE, STANDALONE_GET_RESULT, STANDALONE_GET_SIZES, STANDALONE_RELAY_DIAG, STANDALONE_SET_CONFIG, STANDALONE_SET_MODE, STANDALONE_TRIGGER, UPDATE_BL, VIKING_GET_EMU_ID, VIKING_SCAN, VIKING_SET_EMU_ID, VIKING_WRITE_TO_T55XX, WIPE_FDS)
- `-n`, `--num_command` <dec> — Numeric command ID: <dec>
- `-d`, `--data` <hex> — Data to send  (default: )
- `-t`, `--timeout` <dec> — Timeout in seconds  (default: 3)

### `hw slot`

Emulation slots commands

#### `hw slot list`

Get information about slots

- `--short` — Hide slot nicknames and Mifare Classic emulator settings

#### `hw slot prng`

Get or set the PRNG type for the MF1 emulator of a slot. PRNG controls the nonce used during MIFARE Classic authentication: 0=Static (fixed), 1=Weak (LFSR/predictable), 2=Hard (unpredictable). Omit --type to read the current setting.

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-t`, `--type` <0|1|2> — PRNG type: 0=Static, 1=Weak, 2=Hard  (choices: 0, 1, 2)

#### `hw slot change`

Set emulation tag slot activated

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8; required)

#### `hw slot type`

Set emulation tag type

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-t`, `--type` TAG_TYPE — Tag Type: EM410X, EM410X_16, EM410X_32, EM410X_64, EM410X_ELECTRA, FDXB, PAC, Viking, Jablotron, HIDProx, ioProx, IDTECK, MIFARE_Mini, MIFARE_1024, MIFARE_2048, MIFARE_4096, NTAG_213, NTAG_215, NTAG_216, MF0ICU1, MF0ICU2, MF0UL11, MF0UL21, NTAG_210, NTAG_212, HF14A_4, SEOS  (choices: EM410X, EM410X_16, EM410X_32, EM410X_64, EM410X_ELECTRA, FDXB, PAC, Viking, Jablotron, HIDProx, ioProx, IDTECK, MIFARE_Mini, MIFARE_1024, MIFARE_2048, MIFARE_4096, NTAG_213, NTAG_215, NTAG_216, MF0ICU1, MF0ICU2, MF0UL11, MF0UL21, NTAG_210, NTAG_212, HF14A_4, SEOS; required)

#### `hw slot delete`

Delete sense type data for a specific slot

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--hf` — HF type
- `--lf` — LF type

#### `hw slot init`

Set emulation tag data to default

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-t`, `--type` TAG_TYPE — Tag Type: EM410X, EM410X_16, EM410X_32, EM410X_64, EM410X_ELECTRA, FDXB, PAC, Viking, Jablotron, HIDProx, ioProx, IDTECK, MIFARE_Mini, MIFARE_1024, MIFARE_2048, MIFARE_4096, NTAG_213, NTAG_215, NTAG_216, MF0ICU1, MF0ICU2, MF0UL11, MF0UL21, NTAG_210, NTAG_212, HF14A_4, SEOS  (choices: EM410X, EM410X_16, EM410X_32, EM410X_64, EM410X_ELECTRA, FDXB, PAC, Viking, Jablotron, HIDProx, ioProx, IDTECK, MIFARE_Mini, MIFARE_1024, MIFARE_2048, MIFARE_4096, NTAG_213, NTAG_215, NTAG_216, MF0ICU1, MF0ICU2, MF0UL11, MF0UL21, NTAG_210, NTAG_212, HF14A_4, SEOS; required)

#### `hw slot enable`

Enable tag slot

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--hf` — HF type
- `--lf` — LF type

#### `hw slot disable`

Disable tag slot

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--hf` — HF type
- `--lf` — LF type

#### `hw slot nick`

Get/Set/Delete tag nick name for slot

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--hf` — HF type
- `--lf` — LF type
- `-n`, `--name` — Set tag nick name for slot
- `-d`, `--delete` — Delete tag nick name for slot

#### `hw slot store`

Store slots config & data to device flash

#### `hw slot openall`

Open all slot and set to default data

### `hw settings`

Chameleon settings commands

#### `hw settings animation`

Get or change current animation mode value

- `-m`, `--mode` MODE — Mode: FULL, MINIMAL, SYMMETRIC, NONE  (choices: FULL, MINIMAL, SYMMETRIC, NONE)

#### `hw settings sleeptimeout`

Get or set the wake timeout after a button press (5-60 seconds)

- `-s`, `--seconds` SECONDS — Wake timeout in seconds (5-60)

#### `hw settings bleclearbonds`

Clear all BLE bindings. Warning: effect is immediate!

- `--force` — Just to be sure

#### `hw settings store`

Store current settings to flash

#### `hw settings reset`

Reset settings to default values

- `--force` — Just to be sure

#### `hw settings btnpress`

Get or set button press function of Button A and Button B

- `-a`, `-A` — Button A
- `-b`, `-B` — Button B
- `-s`, `--short` — Short-press (default)
- `-l`, `--long` — Long-press
- `-f`, `--function` FUNCTION — Function: NONE (No Function), NEXTSLOT (Select next slot), PREVSLOT (Select previous slot), CLONE (Read then simulate the ID/UID card number), BATTERY (Show Battery Level), FIELDGEN (Toggle NFC Field Generator), STANDALONE_DISARM (Disarm active standalone mode)  (choices: NONE, NEXTSLOT, PREVSLOT, CLONE, BATTERY, FIELDGEN, STANDALONE_DISARM)

#### `hw settings blekey`

Get or set the ble connect key

- `-k`, `--key` — Ble connect key for your device

#### `hw settings blepair`

Show or configure BLE pairing

- `-e`, `--enable` — Enable BLE pairing
- `-d`, `--disable` — Disable BLE pairing

## `hf`

High Frequency commands

### `hf 14a`

ISO14443-a commands

#### `hf 14a config`

Configure 14a settings (use with caution)

- `--std` — Reset default configuration (follow standard)
- `--bcc` — follow standard / fix bad BCC / ignore bad BCC, always use card BCC  (choices: std, fix, ignore)
- `--cl2` — follow standard / always do CL2 / always skip CL2  (choices: std, force, skip)
- `--cl3` — follow standard / always do CL3 / always skip CL3  (choices: std, force, skip)
- `--rats` — follow standard / always do RATS / always skip RATS  (choices: std, force, skip)

#### `hf 14a scan`

Scan 14a tag, and print basic information

#### `hf 14a info`

Scan 14a tag, and print detail information

#### `hf 14a raw`

Send raw command

- `-a`, `--activate-rf` — Active signal field ON without select
- `-s`, `--select-tag` — Active signal field ON with select
- `-d`, `--data` <hex> — Data to be sent
- `-b`, `--bits` <dec> — Number of bits to send. Useful for send partial byte
- `-c`, `--crc` — Calculate and append CRC
- `-r`, `--no-response` — Do not read response
- `-cc`, `--crc-clear` — Verify and clear CRC of received data
- `-k`, `--keep-rf` — Keep signal field ON after receive
- `-t`, `--timeout` <dec> — Timeout in ms  (default: 100)

#### `hf 14a sniff`

Capture ISO14443A reader frames while CU acts as a tag. Place CU near a reader — all commands the reader sends are logged. Useful for understanding what a reader expects before configuring emulation.

- `--timeout` MS — Listen duration in milliseconds (default: 5000, max: 30000, firmware blocks for full duration)  (default: 5000)
- `--tap` — Passive tap: CU stays silent while a REAL card answers the reader. Captures reader->card on NFCT and card->reader via the RC522. Place CU, card, and reader in the same field.
- `-o`, `--trace` — Write capture as a Proxmark3 .trace file

#### `hf 14a info`

Capture ISO14443A reader frames while CU acts as a tag. Place CU near a reader — all commands the reader sends are logged. Useful for understanding what a reader expects before configuring emulation.

- `--timeout` MS — Listen duration in milliseconds (default: 5000, max: 30000, firmware blocks for full duration)  (default: 5000)
- `--tap` — Passive tap: CU stays silent while a REAL card answers the reader. Captures reader->card on NFCT and card->reader via the RC522. Place CU, card, and reader in the same field.
- `-o`, `--trace` — Write capture as a Proxmark3 .trace file

#### `hf 14a auth-trace`

Run a full reader-side ISO14443A + MIFARE Classic Crypto1 auth against a real card and print every wire frame: REQA → ATQA → anticoll/SELECT → SAK → (RATS/ATS) → AUTH(0x60/0x61) → NT → NR||AR (enc) → AT (enc), with host-side Crypto1 decryption of the auth sub-frames for verification.

- `--blk`, `--block` <dec> — Target block number  (required)
- `-a`, `-A` — Use Key A (default)
- `-b`, `-B` — Use Key B
- `-k`, `--key` <hex> — 6-byte sector key (12 hex chars)  (required)
- `-t`, `--timeout` <ms> — Tag-presence polling timeout in ms (1-30000, default 5000)  (default: 5000)

### `hf mf`

MIFARE Classic commands

#### `hf mf nested`

Mifare Classic nested recover key

- `--blk`, `--known-block` <dec> — Known key block number  (required)
- `-a`, `-A` — Known key is A key (default)
- `-b`, `-B` — Known key is B key
- `-k`, `--key` <hex> — Known key  (required)
- `--tblk`, `--target-block` <dec> — Target key block number  (required)
- `--ta`, `--tA` — Target A key (default)
- `--tb`, `--tB` — Target B key

#### `hf mf darkside`

Mifare Classic darkside recover key

#### `hf mf hardnested`

Mifare Classic hardnested recover key

- `--blk`, `--known-block` <dec> — Known key block number  (required)
- `-a`, `-A` — Known key is A key (default)
- `-b`, `-B` — Known key is B key
- `-k`, `--key` <hex> — Known key  (required)
- `--tblk`, `--target-block` <dec> — Target key block number  (required)
- `--ta`, `--tA` — Target A key (default)
- `--tb`, `--tB` — Target B key
- `--slow` — Use slower acquisition mode (more nonces)
- `--keep-nonce-file` — Keep the generated nonce file (nonces.bin)
- `--max-runs` <dec> — Maximum acquisition runs per attempt before giving up (default: 200)  (default: 200)
- `--max-attempts` <dec> — Maximum acquisition attempts if MSB sum is invalid (default: 3)  (default: 3)

#### `hf mf senested`

Mifare Classic static encrypted recover key via backdoor

- `--key`, `-k` <hex> — Backdoor key (as hex[12] format), currently known: A396EFA4E24F (default), A31667A8CEC1, 518B3354E760. See https://eprint.iacr.org/2024/1275  (default: A396EFA4E24F)
- `--sectors`, `-s` <dec> — Sector count  (default: 16)
- `--starting-sector` <dec> — Start recovery from this sector

#### `hf mf autopwn`

Mifare Classic auto recovery tool

- `-k`, `--key` <hex> — Known key

#### `hf mf fchk`

Mifare Classic fast key check on sectors

- `--mini` — MIFARE Classic Mini / S20  (default: 16)
- `--1k` — MIFARE Classic 1k / S50 (default)  (default: 16)
- `--2k` — MIFARE Classic/Plus 2k  (default: 16)
- `--4k` — MIFARE Classic 4k / S70  (default: 16)
- `<hex>` — Key (as hex[12] format)  (required)
- `--key` — Read keys from .key format file
- `--dic` — Read keys from .dic format file
- `--export-key` — Export result as .key format, file will be [31mOVERWRITTEN[0m if exists
- `--export-dic` — Export result as .dic format, file will be [31mOVERWRITTEN[0m if exists
- `-m`, `--mask` <hex> — Which sectorKey to be skip, 1 bit per sectorKey. `0b1` represent to skip to check. (in hex[20] format)  (default: 00000000000000000000)

#### `hf mf rdbl`

Mifare Classic read one block

- `--blk`, `--block` <dec> — The block where the key of the card is known  (required)
- `-a`, `-A` — Known key is A key (default)
- `-b`, `-B` — Known key is B key
- `-k`, `--key` <hex> — tag sector key  (required)

#### `hf mf wrbl`

Mifare Classic write one block

- `--blk`, `--block` <dec> — The block where the key of the card is known  (required)
- `-a`, `-A` — Known key is A key (default)
- `-b`, `-B` — Known key is B key
- `-k`, `--key` <hex> — tag sector key  (required)
- `-d`, `--data` <hex> — Your block data, as hex string.  (required)

#### `hf mf view`

Display content from tag memory or dump file

- `--mini` — MIFARE Classic Mini / S20  (default: 16)
- `--1k` — MIFARE Classic 1k / S50 (default)  (default: 16)
- `--2k` — MIFARE Classic/Plus 2k  (default: 16)
- `--4k` — MIFARE Classic 4k / S70  (default: 16)
- `-d`, `--dump-file` — Dump file to read
- `-k`, `--key-file` — File containing keys of tag to write (exported with fchk --export)

#### `hf mf dump`

Mifare Classic dump tag

- `-t`, `--dump-file-type` — Dump file content type  (choices: bin, hex)
- `-f`, `--dump-file` — Dump file to write data from tag  (required)
- `-d`, `--dic` — Read keys (to communicate with tag to dump) from .dic format file  (required)

#### `hf mf clone`

Mifare Classic clone tag from dump

- `-t`, `--dump-file-type` — Dump file content type  (choices: bin, hex)
- `-a`, `--clone-access` — Write ACL from original dump too (! could brick your tag)
- `-f`, `--dump-file` — Dump file containing data to write on new tag  (required)
- `-d`, `--dic` — Read keys (to communicate with tag to write) from .dic format file  (required)

#### `hf mf value`

Scan FDX-B animal tag (134.2 kHz) and print id

- `--raw` — also print the raw 13-byte frame
- `-@` — continuous scan until a key is pressed (helps locate an implant)

#### `hf mf elog`

MF1 Detection log count/decrypt

- `--decrypt` — Decrypt key from MF1 log list

#### `hf mf eload`

Load data to emulator memory

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-f`, `--file` — file path  (required)
- `-t`, `--type` — content type  (choices: bin, hex)

#### `hf mf esave`

Read data from emulator memory

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-f`, `--file` — file path  (required)
- `-t`, `--type` — content type  (choices: bin, hex)

#### `hf mf eview`

View data from emulator memory

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)

#### `hf mf econfig`

Settings of Mifare Classic emulator

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--uid` <hex> — Unique ID
- `--atqa` <hex> — Answer To Request
- `--sak` <hex> — Select AcKnowledge
- `--ats` <hex> — Answer To Select
- `--delete-ats` — Delete Answer To Select
- `--enable-gen1a` — Enable Gen1a magic mode
- `--disable-gen1a` — Disable Gen1a magic mode
- `--enable-gen2` — Enable Gen2 magic mode
- `--disable-gen2` — Disable Gen2 magic mode
- `--enable-block0` — Use anti-collision data from block 0 for 4 byte UID tags
- `--disable-block0` — Use anti-collision data from settings
- `--write` MODE — Write Mode: NORMAL, DENIED, DECEIVE, SHADOW  (choices: NORMAL, DENIED, DECEIVE, SHADOW)
- `--enable-log` — Enable logging of MFC authentication data
- `--disable-log` — Disable logging of MFC authentication data
- `--enable_field_off_do_reset` — Enable FIELD_OFF_DO_RESET
- `--disable_field_off_do_reset` — Disable FIELD_OFF_DO_RESET

### `hf mfu`

MIFARE Ultralight / NTAG commands

#### `hf mfu ercnt`

Read MIFARE Ultralight / NTAG counter value.

- `-c`, `--counter` — Counter index.  (required)

#### `hf mfu ewcnt`

Write MIFARE Ultralight / NTAG counter value.

- `-c`, `--counter` — Counter index.  (required)
- `-v`, `--value` — Counter value (24-bit).  (required)
- `-t`, `--reset-tearing` — Reset tearing event flag.

#### `hf mfu rdpg`

MIFARE Ultralight / NTAG read one page

- `-k`, `--key` <hex> — Authentication key (EV1/NTAG 4 bytes).
- `-l` — Swap endianness of the key.
- `-p`, `--page` <dec> — The page where the key will be used against  (required)

#### `hf mfu wrpg`

MIFARE Ultralight / NTAG write one page

- `-k`, `--key` <hex> — Authentication key (EV1/NTAG 4 bytes).
- `-l` — Swap endianness of the key.
- `-p`, `--page` <dec> — The index of the page to write to.  (required)
- `-d`, `--data` <hex> — Your page data, as a 4 byte (8 character) hex string.  (required)

#### `hf mfu eview`

MIFARE Ultralight / NTAG view emulator data

#### `hf mfu eload`

MIFARE Ultralight / NTAG load emulator data

- `-f`, `--file` — File to load data from.  (required)
- `-t`, `--type` — Force writing as either raw binary or hex.  (choices: bin, hex)

#### `hf mfu esave`

MIFARE Ultralight / NTAG save emulator data

- `-f`, `--file` — File to save data to.  (required)
- `-t`, `--type` — Force writing as either raw binary or hex.  (choices: bin, hex)

#### `hf mfu rcnt`

MIFARE Ultralight / NTAG read counter

- `-k`, `--key` <hex> — Authentication key (EV1/NTAG 4 bytes).
- `-l` — Swap endianness of the key.
- `-c`, `--counter` <dec> — Index of the counter to read (always 0 for NTAG, 0-2 for Ultralight EV1).  (required)

#### `hf mfu dump`

MIFARE Ultralight dump pages

- `-k`, `--key` <hex> — Authentication key (EV1/NTAG 4 bytes).
- `-l` — Swap endianness of the key.
- `-p`, `--page` <dec> — Manually set number of pages to dump
- `-q`, `--qty` <dec> — Manually set number of pages to dump
- `-f`, `--file` — Specify a filename for dump file  (default: )
- `-t`, `--type` — Force writing as either raw binary or hex.  (choices: bin, hex)

#### `hf mfu version`

Request MIFARE Ultralight / NTAG version data.

#### `hf mfu signature`

Request MIFARE Ultralight / NTAG ECC signature data.

#### `hf mfu authnonce`

Get authentication nonce from MIFARE Ultralight C tag.

#### `hf mfu ulcg`

Key recovery for Giantec ULCG and USCUID-UL cards (won't work on NXP cards!)

- `-c`, `--challenges` — Number of challenges to collect (default: 1000)  (default: 1000)
- `-t`, `--threads` — Number of threads for key recovery (default: 1)  (default: 1)
- `-j`, `--json` — Path to JSON file to load or save challenges
- `-o`, `--offline` — Use offline mode with pre-collected challenges

#### `hf mfu econfig`

Settings of Mifare Ultralight / NTAG emulator

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--uid` <hex> — Unique ID
- `--atqa` <hex> — Answer To Request
- `--sak` <hex> — Select AcKnowledge
- `--ats` <hex> — Answer To Select
- `--delete-ats` — Delete Answer To Select
- `--enable-uid-magic` — Enable UID magic mode
- `--disable-uid-magic` — Disable UID magic mode
- `--write` MODE — Write Mode: NORMAL, DENIED, DECEIVE, SHADOW  (choices: NORMAL, DENIED, DECEIVE, SHADOW)
- `--set-version` — Set data to be returned by the GET_VERSION command.
- `--set-signature` — Set data to be returned by the READ_SIG command.
- `--reset-auth-cnt` — Resets the counter of unsuccessful authentication attempts.
- `--enable-log` — Enable password authentication logging
- `--disable-log` — Disable password authentication logging

#### `hf mfu edetect`

Get Mifare Ultralight / NTAG emulator detection logs

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--count` COUNT — Number of log entries to retrieve
- `--index` INDEX — Starting index (default: 0)

### `hf des`

MIFARE DESFire commands

#### `hf des auth-trace`

Run a full DESFire authentication against a real card and print every wire frame: REQA → ATQA → anticoll → SELECT → SAK → RATS → ATS → (optional SELECT AID) → AUTHENTICATE → E(RndB) → E(RndA||RndB') → E(RndA'), with host-side AES / 3DES / 3K3DES decryption of the random nonces for verification.

Supports AuthenticateDES (0x0A, D40), AuthenticateAES (0xAA, EV1+) and AuthenticateISO 3K3DES (0x1A). Requires the 'cryptography' Python package.

- `--keyno` <n> — DESFire key number (default 0 = master)
- `-k`, `--key` <hex> — Auth key in hex. 8 bytes = DES, 16 bytes = AES or 2TDEA (use --type to disambiguate), 24 bytes = 3K3DES.  (required)
- `--type` — Auth type. Auto-detected if omitted: 8=DES, 16=AES, 24=3K3DES.  (choices: des, aes, 3k3des)
- `--aid` <hex> — Optional 3-byte AID to select before auth. Pass in the same form `hf des info` displays (e.g. --aid 808020 if info shows 'AID: 808020'). Default: PICC level (no SelectApplication).
- `-t`, `--timeout` <ms> — Tag-presence polling timeout in ms (default 5000). Reader keeps the field on and polls for a card; auth aborts if no card appears within this window.  (default: 5000)

#### `hf des info`

Get MIFARE DESFire card information (version, UID, AIDs).

#### `hf des chk`

Check DESFire keys against a card (dictionary / pattern / single key). Tries DES, 2TDEA, and AES for each key. Iterates all AIDs on card unless --aid is specified.

- `--aid` <hex> — Target AID (3 hex bytes, e.g. 123456). Default: PICC master (000000) + all apps.
- `-n`, `--keyno` <0-13> — Key number to authenticate with (default: 0)
- `-k`, `--key` <hex> — Single key to try (8, 16 or 24 hex bytes)
- `-f`, `--file` <file> — Dictionary file (one hex key per line)
- `--pattern1b` — Try all 1-byte patterns (0000..00, 0101..01, ..., FFFF..FF) for DES and AES
- `--pattern2b` — Try all 2-byte patterns for AES (0000..00 to FFFF..FF, step 0x0101)
- `-t`, `--timeout` <ms> — Card presence timeout ms (default 5000)  (default: 5000)

### `hf seos`

SEOS commands

#### `hf seos eview`

View data from emulator memory

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)

#### `hf seos eload`

Load data into emulator memory

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--uid` <hex> — Unique ID
- `--atqa` <hex> — Answer To Request
- `--sak` <hex> — Select AcKnowledge
- `--ats` <hex> — Answer To Select
- `--delete-ats` — Delete Answer To Select
- `-d`, `--data` <hex> — Data to present to reader (2-255 bytes). Must be valid BER-TLV.
- `-o`, `--oid` <hex> — Target OID (1-32 bytes).
- `-t`, `--tag` <hex> — Tag of presented data (1-2 bytes).
- `--diversifier` <hex> — Simulated card diversifier (1-16 bytes).

#### `hf seos keys`

Load data into emulator memory

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-a`, `--auth` <hex> — Auth key (16 bytes)  (required)
- `-e`, `--privenc` <hex> — PrivEnc key (16 bytes)  (required)
- `-m`, `--privmac` <hex> — PrivMac key (16 bytes)  (required)

## `lf`

Low Frequency commands

### `lf search`

Search for any supported LF tag — tries every decoder in turn (PM3-style) and reports the first match

### `lf clone`

Clone a LF card ID onto a blank T55xx tag.
Supported types: em410x, electra, hid, ioprox, pac, viking, idteck.
Only supported on Chameleon Ultra (Lite has no LF writer).

- `-t`, `--type` TYPE — Card type: em410x, electra, hid, ioprox, pac, viking, idteck  (choices: em410x, electra, hid, ioprox, pac, viking, idteck; required)
- `--id` HEX — Card ID in hex: 10 for em410x, 26 for electra, 8 for viking, 8 or 16 for idteck; 8 ASCII chars for pac
- `-f`, `--format` FORMAT — HID Prox format, e.g. H10301 (required for hid type)  (choices: H10301, IND26, IND27, INDASC27, TECOM27, W2804, IND29, ATSW30, ADT31, HCP32, HPP32, KASTLE, KANTECH, WIE32, D10202, H10306, N10002, OPTUS34, SMP34, BQT34, C1K35S, C15001, S12906, ACTPHID, SIE36, H10320, H10302, H10304, P10004, HGEN37, MDI37)
- `--fc` INT — Facility code (HID / ioProx)
- `--cn` INT — Card number (HID / ioProx)
- `--il` INT — Issue level (HID, optional)
- `--oem` INT — OEM code (HID, optional)
- `--ver` INT — Version byte (ioProx)
- `--raw8` HEX — ioProx raw 8 bytes in hex, e.g. 007854E03A5D65AB

### `lf sniff`

Capture raw LF field ADC samples (125kHz, 8µs/sample). ~0x80 = field on, lower values = gap or no field.

- `--timeout` MS — Capture duration in milliseconds (default: 2000, max: 10000, firmware blocks for full duration)  (default: 2000)
- `--out` FILE — Save raw samples to binary file (for offline analysis)
- `--hex` — Print hex dump of samples to screen

### `lf em`

EM commands

#### `lf em 4x05`

EM4x05/EM4x69 commands

##### `lf em 4x05 read`

Scan EM4x05 or EM4x69 tag (reader-talk-first) and print config, UID

#### `lf em 410x`

EM410x commands

##### `lf em 410x read`

Scan em410x tag and print id

##### `lf em 410x write`

Write em410x id to t55xx

- `--id` <hex> — EM410x tag id  (required)

##### `lf em 410x econfig`

Set emulated em410x card id

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--id` <hex> — EM410x tag id

### `lf hid`

HID commands

#### `lf hid prox`

HID Prox commands

##### `lf hid prox read`

Scan hid prox tag and print card format, facility code, card number, issue level and OEM code

- `-f`, `--format` — HIDProx card format hint  (choices: H10301, IND26, IND27, INDASC27, TECOM27, W2804, IND29, ATSW30, ADT31, HCP32, HPP32, KASTLE, KANTECH, WIE32, D10202, H10306, N10002, OPTUS34, SMP34, BQT34, C1K35S, C15001, S12906, ACTPHID, SIE36, H10320, H10302, H10304, P10004, HGEN37, MDI37)

##### `lf hid prox write`

Write hidprox card data to t55xx

- `-f`, `--format` — HIDProx card format  (choices: H10301, IND26, IND27, INDASC27, TECOM27, W2804, IND29, ATSW30, ADT31, HCP32, HPP32, KASTLE, KANTECH, WIE32, D10202, H10306, N10002, OPTUS34, SMP34, BQT34, C1K35S, C15001, S12906, ACTPHID, SIE36, H10320, H10302, H10304, P10004, HGEN37, MDI37; required)
- `--fc` <int> — HIDProx tag facility code
- `--cn` <int> — HIDProx tag card number  (required)
- `--il` <int> — HIDProx tag issue level
- `--oem` <int> — HIDProx tag OEM

##### `lf hid prox econfig`

Set emulated hidprox card id

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-f`, `--format` — HIDProx card format  (choices: H10301, IND26, IND27, INDASC27, TECOM27, W2804, IND29, ATSW30, ADT31, HCP32, HPP32, KASTLE, KANTECH, WIE32, D10202, H10306, N10002, OPTUS34, SMP34, BQT34, C1K35S, C15001, S12906, ACTPHID, SIE36, H10320, H10302, H10304, P10004, HGEN37, MDI37)
- `--fc` <int> — HIDProx tag facility code
- `--cn` <int> — HIDProx tag card number
- `--il` <int> — HIDProx tag issue level
- `--oem` <int> — HIDProx tag OEM

### `lf ioprox`

ioProx commands

#### `lf ioprox read`

Scan ioProx tag and print version, facility, card number and raw

- `-v`, `--verbose` — Verbose output

#### `lf ioprox write`

Write ioProx card data to t55xx

- `--ver` <int> — ioProx version
- `--fc` <str> — ioProx facility code, e.g., 83 or 0x53
- `--cn` <int> — ioProx card number
- `--raw8` <hex8> — ioProx raw 8 bytes hex (e.g. 00AABBCCDDEEFF55)

#### `lf ioprox econfig`

Set/Get emulated ioProx card id (stored in slot)

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--ver` <int> — ioProx version
- `--fc` <str> — ioProx facility code, e.g., 83 or 0x53
- `--cn` <int> — ioProx card number
- `--raw8` <hex8> — ioProx raw 8 bytes hex (e.g. 00AABBCCDDEEFF55)

### `lf pac`

PAC/Stanley commands

#### `lf pac read`

Scan PAC/Stanley tag and print card ID

#### `lf pac write`

Write PAC/Stanley id to T55xx

- `--cn` <ascii> — Card number (8 ASCII characters, e.g. CARD0001)
- `--raw` <hex> — T55XX bitstream (32 hex chars, PM3 raw format)

#### `lf pac econfig`

Set emulated PAC/Stanley card ID

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--cn` <ascii> — Card number (8 ASCII characters, e.g. CARD0001)
- `--raw` <hex> — T55XX bitstream (32 hex chars, PM3 raw format)

### `lf viking`

Viking commands

#### `lf viking read`

Scan Viking tag and print id

#### `lf viking write`

Write Viking id to t55xx

- `--id` <hex> — Viking tag id  (required)

#### `lf viking econfig`

Set emulated Viking card id

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--id` <hex> — Viking tag id

### `lf jablotron`

Jablotron commands

#### `lf jablotron read`

Scan Jablotron tag and print id

#### `lf jablotron write`

Write Jablotron id to t55xx

- `--id` <hex> — Jablotron tag id (5 bytes hex)  (required)

#### `lf jablotron econfig`

Set emulated Jablotron card id

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--id` <hex> — Jablotron tag id (5 bytes hex)

### `lf fdxb`

FDX-B animal tag commands (134.2 kHz)

#### `lf fdxb read`

Scan FDX-B animal tag (134.2 kHz) and print id

- `--raw` — also print the raw 13-byte frame
- `-@` — continuous scan until a key is pressed (helps locate an implant)

#### `lf fdxb write`

Write FDX-B frame to T55xx (by fields, or raw --id)

- `--country` <0-1023> — country/manufacturer code (ISO 3166 numeric, e.g. 208 for Denmark)
- `--national` <id> — national ID, up to 274877906943 (38-bit)
- `--animal` — animal flag (default 1)  (choices: 0, 1; default: 1)
- `--extended` <0-0xFFFFFF> — optional 24-bit extended data (default 0)
- `--id` <hex> — raw 26-hex frame instead of fields (advanced; not validated for reserved bits)

#### `lf fdxb clone`

Clone FDX-B animal tag to T55xx (alias for 'write')

- `--country` <0-1023> — country/manufacturer code (ISO 3166 numeric, e.g. 208 for Denmark)
- `--national` <id> — national ID, up to 274877906943 (38-bit)
- `--animal` — animal flag (default 1)  (choices: 0, 1; default: 1)
- `--extended` <0-0xFFFFFF> — optional 24-bit extended data (default 0)
- `--id` <hex> — raw 26-hex frame instead of fields (advanced; not validated for reserved bits)

### `lf generic`

Generic commands

#### `lf generic adcread`

Read ADC and return the array

### `lf idteck`

IDTECK commands

#### `lf idteck write`

Clone an IDTECK PSK1 frame onto a T55xx tag.

- `--id` <hex> — IDTECK frame in hex: 16 chars for the full 64-bit frame, or 8 chars for the 32-bit payload only (preamble 4944544B is auto-prepended).  (required)

#### `lf idteck econfig`

Get or set the IDTECK emulated id on a slot. Provide --id to set; omit it to read back the current value.

- `-s`, `--slot` <1-8> — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot  (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--id` <hex> — IDTECK frame in hex: 16 chars for the full 64-bit frame, or 8 chars for the 32-bit payload only (preamble 4944544B is auto-prepended).

### `lf t55xx`

T55xx/T5577 raw block commands

#### `lf t55xx write`

Write a raw 32-bit word to a T55xx block

- `-b`, `--block` <0-7> — Block number (0-7 on page 0, 0-3 on page 1)  (required)
- `-d`, `--data` <hex> — 32-bit data word, 4 hex bytes  (required)
- `-p`, `--pwd` <hex> — Password, 4 hex bytes (password-protected write)
- `--pg1` — Target page 1

#### `lf t55xx wipe`

Wipe a T55xx: default config to block 0, zeros to blocks 1-7

- `-c`, `--cfg` <hex> — Override config block 0 (4 hex bytes)
- `-p`, `--pwd` <hex> — Current password, 4 hex bytes (to auth the wipe)
- `--q5` — Target Q5/T5555 (config 0x6001F004)
- `--extended` — Also zero block 3 page 1 (extended-mode config)

#### `lf t55xx detect`

Detect a T55xx tag by reading block 0 and stride-locking its config: slides a 32-bit window over the demodulated stream and accepts the first window that repeats and parses to a valid config at the read rate. Tries Manchester (amplitude path) and biphase (firmware diphase). FSK/PSK are not wired; streaming tags with no addressable config block (e.g. FDX-B) are reported as such. Sets the default RF/n for subsequent `read`.

- `-p`, `--pwd` <hex> — Password, 4 hex bytes (if block 0 is read-protected)

#### `lf t55xx read`

Read a T55xx block (Manchester) and dump the demodulated bitstream

- `-b`, `--block` <0-7>  (required)
- `--rf` <n> — Bitrate divisor RF/n (default: from `detect`, else 32; em410x uses 64)
- `-p`, `--pwd` <hex> — Password, 4 hex bytes
- `--pg1` — Target page 1
- `--expect` <hex> — Verify: report whether this 32-bit word (4 hex bytes) is present
- `--raw` — Diagnostic: dump raw edge intervals (carrier cycles) instead of decoding
- `--adc` — Diagnostic: dump raw SAADC envelope amplitude (robust for dense data)
- `--regread` — Diagnostic: skip the addressed downlink, capture the regular-read stream
- `--mod` — Demod: manchester (SAADC amplitude, robust) or biphase (firmware diphase_feed). auto = whatever `detect` found (else manchester).  (choices: auto, manchester, biphase; default: auto)

## `data`

Data analysis and visualization commands

### `data hexsamples`

Dump last LF sniff capture as hex bytes (PM3 style)

- `-n`, `--num` N — Number of bytes to display (default: 512)  (default: 512)

### `data plot`

Graphical waveform plot of last LF sniff capture (PyQt5 or matplotlib)

- `--start` N — Start sample (default: 0)
- `--len` N — Number of samples to plot (default: all)  (default: 4000)
- `--ascii` — Force ASCII plot even if GUI is available

### `data manrawdecode`

Manchester decode the last LF sniff capture

- `--clock` N — Clock divisor in Tc (default: 64 = RF/64)  (default: 64)
- `--invert` — Invert logic (high=0, low=1)

### `data modulation`

Detect clock rate and modulation type in last LF capture

## `emv`

EMV contactless payment card commands

### `emv scan`

EMV contactless card scan (reader mode) — like PM3 emv scan -at

- `-f`, `--file` <path> — Save results to JSON file (PM3-compatible format)  (default: )
- `-s`, `--slot` <1-8> — Also load scanned card into this slot for emulation

### `emv debug`

Show T=CL emulation debug counters

### `emv load`

Load EMV APDU responses into HF14A_4 slot for autonomous emulation

- `-f`, `--file` <path> — Load from PM3 emv scan JSON file  (default: )
- `-s`, `--slot` <1-8> — Target slot when using --file (default: active)
- `--clear` — Clear all static responses from active slot
- `--cmd` <hex> — Command APDU prefix to match (hex)  (default: )
- `--resp` <hex> — Response APDU to return (hex)  (default: )
- `--defaults` — Load built-in Mastercard test responses

### `emv apdu`

ISO14443-4 T=CL interactive APDU relay (manual response mode)

- `--timeout` <ms> — Total relay timeout in ms (default: 15000)  (default: 15000)

## `standalone`

Host-less standalone modes

### `standalone status`

Show standalone subsystem state

### `standalone set-mode`

Set standalone mode

- `mode` — mode name (authtrace, emul-trace, relay, slot-cycle, autoclone, read-replay, dict-check, hf14a-tap-sniff, disabled)  (required)
- `--opt-in` — set HOST_OPTED_IN flag (required for autoclone and read-replay)
- `--quiet-buzzer`
- `--quiet-led`

### `standalone trigger`

Trigger active standalone mode

### `standalone disarm`

Disarm standalone mode and save results

### `standalone get-result`

Read standalone result buffer

- `-f`, `--file` <path> — write output to file instead of stdout
- `--raw` — dump raw bytes (no parsing)
- `--json` — emit parsed sessions as JSON
- `--dump` — dump every frame in each session
- `--pm3` <prefix> — write each session as a Proxmark3 .trace (<prefix>-NN.trace)

### `standalone ls`

List stored standalone result data

### `standalone clear-result`

Clear standalone result buffer

### `standalone config`

Read or write mode-specific config

- `mode` — target mode name  (required)
- `--block` — [authtrace] target block (0-255)
- `--key-type` — [authtrace] MIFARE key type  (choices: A, B)
- `--key` — [authtrace] 12-hex-char sector key (e.g. FFFFFFFFFFFF)
- `--timeout` — [authtrace] tag-poll timeout in ms (100-30000); [hf14a-tap-sniff] capture duration in ms (100-30000); [relay] WTX ms (500-10000)

