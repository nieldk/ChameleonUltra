# Phreakbyte CLI Command Reference

Complete reference for the Phreakbyte edition ChameleonUltra client (`chameleon_cli_main.py`), auto-generated from the live CLI parser: 27 command groups, 142 commands.

Notation: `<...>` are values you supply. Each option lists its flags, help, allowed `choices`, whether it is `required`, and its `default`. Run any command with `-h` in the client for the same information live.

## File formats

Several commands read and write **Proxmark3-compatible** files, sniffed by content so the extension is a convenience, not a requirement:

| Card | Command | Reads | Writes |
|------|---------|-------|--------|
| MIFARE Classic | `hf mf eload` / `hf mf esave` | `.bin`, `.eml`, PM3 `mfc v2` `.json` | `.bin`, `.eml`, PM3 `mfc v2` `.json` |
| DESFire | `hf des eload` / `hf des edump` / `hf des parse` | `.dfc`, `.dfcb`, PM3 `mfdes v1` `.json` | `.dfcb`, PM3 `mfdes v1` `.json` |
| EMV | `emv scan` / `emv load` | PM3 `emv scan` `.json` | PM3 `emv scan` `.json` |
| Keys | `hf mf fchk` | `.dic`, `.key` | `.dic`, `.key` |
| Traces | `hf 14a sniff -o` / `standalone get-result --pm3` | — | PM3 `.trace` |

Round-trips are validated against Proxmark3's own tooling: a `hf des edump -f x.json` file loads in `hf mfdes view`, and a `hf mfdes dump` file loads via `hf des eload`. Absent DESFire keys/files are preserved honestly (version-only keys carry no key bytes; unread files carry no data), per PM3's `mfdes v1` spec.


## `clear`

Clear screen


## `data`

Data analysis and visualization commands

### `data hexsamples`

Dump last LF sniff capture as hex bytes (PM3 style)

- `-n`, `--num` — Number of bytes to display (default: 512) (default: 512)

### `data manrawdecode`

Manchester decode the last LF sniff capture

- `--clock` — Clock divisor in Tc (default: 64 = RF/64) (default: 64)
- `--invert` — Invert logic (high=0, low=1)

### `data modulation`

Detect clock rate and modulation type in last LF capture


### `data plot`

Graphical waveform plot of last LF sniff capture (PyQt5 or matplotlib)

- `--start` — Start sample (default: 0)
- `--len` — Number of samples to plot (default: all) (default: 4000)
- `--ascii` — Force ASCII plot even if GUI is available

## `dump_help`

Dump available commands

- `-d`, `--show-desc` — Dump full command description
- `-g`, `--show-groups` — Dump command groups as well

## `emv`

EMV contactless payment card commands

### `emv apdu`

ISO14443-4 T=CL interactive APDU relay (manual response mode)

- `--timeout` — Total relay timeout in ms (default: 15000) (default: 15000)

### `emv debug`

Show T=CL emulation debug counters


### `emv load`

Load EMV APDU responses into HF14A_4 slot for autonomous emulation

- `-f`, `--file` — Load from PM3 emv scan JSON file (default: )
- `-s`, `--slot` — Target slot when using --file (default: active)
- `--clear` — Clear all static responses from active slot
- `--cmd` — Command APDU prefix to match (hex) (default: )
- `--resp` — Response APDU to return (hex) (default: )
- `--defaults` — Load built-in Mastercard test responses

### `emv scan`

EMV contactless card scan (reader mode) — like PM3 emv scan -at

- `-f`, `--file` — Save results to JSON file (PM3-compatible format) (default: )
- `-s`, `--slot` — Also load scanned card into this slot for emulation

## `exit`

Exit client


## `hf`

High Frequency commands

### `hf 14a`

ISO14443-a commands

#### `hf 14a auth-trace`

Run a full reader-side ISO14443A + MIFARE Classic Crypto1 auth against a real card and print every wire frame: REQA → ATQA → anticoll/SELECT → SAK → (RATS/ATS) → AUTH(0x60/0x61) → NT → NR||AR (enc) → AT (enc), with host-side Crypto1 decryption of the auth sub-frames for verification.

- `--blk`, `--block` — Target block number (required)
- `-a`, `-A` — Use Key A (default)
- `-b`, `-B` — Use Key B
- `-k`, `--key` — 6-byte sector key (12 hex chars) (required)
- `-t`, `--timeout` — Tag-presence polling timeout in ms (1-30000, default 5000) (default: 5000)

```
examples:
  hf 14a auth-trace --blk 0 -k FFFFFFFFFFFF
  hf 14a auth-trace --blk 4 -b -k A0A1A2A3A4A5
  hf 14a auth-trace --blk 0 -k FFFFFFFFFFFF -t 10000   # wait up to 10s for tag
```

#### `hf 14a config`

Configure 14a settings (use with caution)

- `--std` — Reset default configuration (follow standard)
- `--bcc` — follow standard / fix bad BCC / ignore bad BCC, always use card BCC (choices: std, fix, ignore)
- `--cl2` — follow standard / always do CL2 / always skip CL2 (choices: std, force, skip)
- `--cl3` — follow standard / always do CL3 / always skip CL3 (choices: std, force, skip)
- `--rats` — follow standard / always do RATS / always skip RATS (choices: std, force, skip)

#### `hf 14a info`

Scan 14a tag, and print detail information


#### `hf 14a raw`

Send raw command

- `-a`, `--activate-rf` — Active signal field ON without select
- `-s`, `--select-tag` — Active signal field ON with select
- `-d`, `--data` — Data to be sent
- `-b`, `--bits` — Number of bits to send. Useful for send partial byte
- `-c`, `--crc` — Calculate and append CRC
- `-r`, `--no-response` — Do not read response
- `-cc`, `--crc-clear` — Verify and clear CRC of received data
- `-k`, `--keep-rf` — Keep signal field ON after receive
- `-t`, `--timeout` — Timeout in ms (default: 100)

```
examples/notes:
  hf 14a raw -b 7 -d 40 -k
  hf 14a raw -d 43 -k
  hf 14a raw -d 3000 -c
  hf 14a raw -sc -d 6000
```

#### `hf 14a scan`

Scan 14a tag, and print basic information


#### `hf 14a sniff`

Capture ISO14443A reader frames while CU acts as a tag. Place CU near a reader — all commands the reader sends are logged. Useful for understanding what a reader expects before configuring emulation.

- `--timeout` — Listen duration in milliseconds (default: 5000, max: 30000, firmware blocks for full duration) (default: 5000)
- `--tap` — Passive tap: CU stays silent while a REAL card answers the reader. Captures reader->card on NFCT and card->reader via the RC522. Place CU, card, and reader in the same field.
- `-o`, `--trace` — Write capture as a Proxmark3 .trace file

### `hf des`

MIFARE DESFire commands

#### `hf des auth-trace`

Run a full DESFire authentication against a real card and print every wire frame: REQA → ATQA → anticoll → SELECT → SAK → RATS → ATS → (optional SELECT AID) → AUTHENTICATE → E(RndB) → E(RndA||RndB') → E(RndA'), with host-side AES / 3DES / 3K3DES decryption of the random nonces for verification.

Supports AuthenticateDES (0x0A, D40), AuthenticateAES (0xAA, EV1+) and AuthenticateISO 3K3DES (0x1A). Requires the 'cryptography' Python package.

- `--keyno` — DESFire key number (default 0 = master)
- `-k`, `--key` — Auth key in hex. 8 bytes = DES, 16 bytes = AES or 2TDEA (use --type to disambiguate), 24 bytes = 3K3DES. (required)
- `--type` — Auth type. Auto-detected if omitted: 8=DES, 16=AES, 24=3K3DES. (choices: des, aes, 3k3des)
- `--aid` — Optional 3-byte AID to select before auth. Pass in the same form `hf des info` displays (e.g. --aid 808020 if info shows 'AID: 808020'). Default: PICC level (no SelectApplication).
- `-t`, `--timeout` — Tag-presence polling timeout in ms (default 5000). Reader keeps the field on and polls for a card; auth aborts if no card appears within this window. (default: 5000)

```
examples:
  hf des auth-trace -k 00000000000000000000000000000000
        # AES default key, PICC master
  hf des auth-trace -k 0000000000000000 --type des
        # legacy DES (D40)
  hf des auth-trace --type 3k3des -k 000000000000000000000000000000000000000000000000
        # 3K3DES (24-byte key)
  hf des auth-trace --aid 010203 --keyno 1 -k <16-byte AES key>
        # auth against key 1 of application 010203
  hf des auth-trace -k 00000000000000000000000000000000 -t 15000
        # wait up to 15s for a card to be placed on the antenna
```

#### `hf des chk`

Check DESFire keys against a card (dictionary / pattern / single key). Tries DES, 2TDEA, and AES for each key. Iterates all AIDs on card unless --aid is specified.

- `--aid` — Target AID (3 hex bytes, e.g. 123456). Default: PICC master (000000) + all apps.
- `-n`, `--keyno` — Key number to authenticate with (default: 0)
- `-k`, `--key` — Single key to try (8, 16 or 24 hex bytes)
- `-f`, `--file` — Dictionary file (one hex key per line)
- `--pattern1b` — Try all 1-byte patterns (0000..00, 0101..01, ..., FFFF..FF) for DES and AES
- `--pattern2b` — Try all 2-byte patterns for AES (0000..00 to FFFF..FF, step 0x0101)
- `-t`, `--timeout` — Card presence timeout ms (default 5000) (default: 5000)

```
examples:
  hf des chk                              -> try built-in defaults on all AIDs
  hf des chk --aid 123456 -k 00112233445566778899AABBCCDDEEFF
  hf des chk -f mykeys.txt
  hf des chk --pattern1b
```

#### `hf des eblank`

Reset a DESFire emulation slot to a blank card: one application, one all-zero DES key, and one writable Standard Data file.

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-u`, `--uid` — 7-byte UID in hex, must start with 04. Random if omitted.

```
examples:
  hf des eblank
  hf des eblank -u 04112233445566
```

#### `hf des edump`

Read a DESFire emulation slot's credential back.

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-f`, `--file` — write the credential here; .json -> Proxmark3 mfdes-v1 dump, else raw .dfcb

```
examples:
  hf des edump
  hf des edump -f slot.dfcb
  hf des edump -f hf-mfdes-dump.json
```

#### `hf des einfo`

Show the DESFire emulation slot summary.

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)

```
examples:
  hf des einfo
```

#### `hf des eload`

Load a credential, in either encoding, into a DESFire emulation slot.

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-f`, `--file` — path to a .dfc, .dfcb, or Proxmark3 mfdes-v1 .json file (required)

```
examples:
  hf des eload -f card.dfc
  hf des eload -f hf-mfdes-<UID>-dump.json
  hf des eload -f card.dfcb -s 2
```

#### `hf des estats`

DESFire emulation diagnostics. max_handler_us is the worst observed engine time for one frame; it must stay well under the ~19 ms frame delay budget. entropy_starvations should stay at 0.


```
examples:
  hf des estats
```

#### `hf des info`

Get MIFARE DESFire card information (version, UID, AIDs).


```
examples:
  hf des info
```

#### `hf des parse`

Parse a credential file, in either encoding, and show what it contains. Needs no device, so it is the quickest way to check a file before loading it.

- `-f`, `--file` — path to a .dfc, .dfcb, or Proxmark3 mfdes-v1 .json file (required)
- `--hexdump` — also print the .dfcb octets the device would receive

```
examples:
  hf des parse -f card.dfc
  hf des parse -f card.dfcb
  hf des parse -f hf-mfdes-<UID>-dump.json
```

### `hf mf`

MIFARE Classic commands

#### `hf mf autopwn`

Mifare Classic auto recovery tool

- `-k`, `--key` — Known key

#### `hf mf clone`

Mifare Classic clone tag from dump

- `-t`, `--dump-file-type` — Dump file content type (choices: bin, hex)
- `-a`, `--clone-access` — Write ACL from original dump too (! could brick your tag)
- `-f`, `--dump-file` — Dump file containing data to write on new tag (required)
- `-d`, `--dic` — Read keys (to communicate with tag to write) from .dic format file (required)

#### `hf mf darkside`

Mifare Classic darkside recover key


#### `hf mf dump`

Mifare Classic dump tag

- `-t`, `--dump-file-type` — Dump file content type (choices: bin, hex)
- `-f`, `--dump-file` — Dump file to write data from tag (required)
- `-d`, `--dic` — Read keys (to communicate with tag to dump) from .dic format file (required)

#### `hf mf econfig`

Settings of Mifare Classic emulator

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--uid` — Unique ID
- `--atqa` — Answer To Request
- `--sak` — Select AcKnowledge
- `--ats` — Answer To Select
- `--delete-ats` — Delete Answer To Select
- `--enable-gen1a` — Enable Gen1a magic mode
- `--disable-gen1a` — Disable Gen1a magic mode
- `--enable-gen2` — Enable Gen2 magic mode
- `--disable-gen2` — Disable Gen2 magic mode
- `--enable-block0` — Use anti-collision data from block 0 for 4 byte UID tags
- `--disable-block0` — Use anti-collision data from settings
- `--write` — Write Mode: NORMAL, DENIED, DECEIVE, SHADOW (choices: NORMAL, DENIED, DECEIVE, SHADOW)
- `--enable-log` — Enable logging of MFC authentication data
- `--disable-log` — Disable logging of MFC authentication data
- `--enable_field_off_do_reset` — Enable FIELD_OFF_DO_RESET
- `--disable_field_off_do_reset` — Disable FIELD_OFF_DO_RESET

#### `hf mf eload`

Load data to emulator memory

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-f`, `--file` — file path (required)
- `-t`, `--type` — content type (choices: bin, hex)

#### `hf mf elog`

MF1 Detection log count/decrypt

- `--decrypt` — Decrypt key from MF1 log list

#### `hf mf esave`

Read data from emulator memory

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-f`, `--file` — file path (required)
- `-t`, `--type` — content type (choices: bin, hex)

#### `hf mf eview`

View data from emulator memory

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)

#### `hf mf fchk`

Mifare Classic fast key check on sectors

- `--mini` — MIFARE Classic Mini / S20 (default: 16)
- `--1k` — MIFARE Classic 1k / S50 (default) (default: 16)
- `--2k` — MIFARE Classic/Plus 2k (default: 16)
- `--4k` — MIFARE Classic 4k / S70 (default: 16)
- `keys` — Key (as hex[12] format) (required)
- `--key` — Read keys from .key format file
- `--dic` — Read keys from .dic format file
- `--export-key` — Export result as .key format, file will be OVERWRITTEN if exists
- `--export-dic` — Export result as .dic format, file will be OVERWRITTEN if exists
- `-m`, `--mask` — Which sectorKey to be skip, 1 bit per sectorKey. `0b1` represent to skip to check. (in hex[20] format) (default: 00000000000000000000)

#### `hf mf hardnested`

Mifare Classic hardnested recover key

- `--blk`, `--known-block` — Known key block number (required)
- `-a`, `-A` — Known key is A key (default)
- `-b`, `-B` — Known key is B key
- `-k`, `--key` — Known key (required)
- `--tblk`, `--target-block` — Target key block number (required)
- `--ta`, `--tA` — Target A key (default)
- `--tb`, `--tB` — Target B key
- `--slow` — Use slower acquisition mode (more nonces)
- `--keep-nonce-file` — Keep the generated nonce file (nonces.bin)
- `--max-runs` — Maximum acquisition runs per attempt before giving up (default: 200) (default: 200)
- `--max-attempts` — Maximum acquisition attempts if MSB sum is invalid (default: 3) (default: 3)

#### `hf mf nested`

Mifare Classic nested recover key

- `--blk`, `--known-block` — Known key block number (required)
- `-a`, `-A` — Known key is A key (default)
- `-b`, `-B` — Known key is B key
- `-k`, `--key` — Known key (required)
- `--tblk`, `--target-block` — Target key block number (required)
- `--ta`, `--tA` — Target A key (default)
- `--tb`, `--tB` — Target B key

#### `hf mf rdbl`

Mifare Classic read one block

- `--blk`, `--block` — The block where the key of the card is known (required)
- `-a`, `-A` — Known key is A key (default)
- `-b`, `-B` — Known key is B key
- `-k`, `--key` — tag sector key (required)

#### `hf mf senested`

Mifare Classic static encrypted recover key via backdoor

- `--key`, `-k` — Backdoor key (as hex[12] format), currently known: A396EFA4E24F (default), A31667A8CEC1, 518B3354E760. See https://eprint.iacr.org/2024/1275 (default: A396EFA4E24F)
- `--sectors`, `-s` — Sector count (default: 16)
- `--starting-sector` — Start recovery from this sector

#### `hf mf value`

MIFARE Classic value block commands

- `--get` — get value from src block
- `--set` — set value X (-2147483647 ~ 2147483647) to src block
- `--inc` — increment value by X (0 ~ 2147483647) from src to dst
- `--dec` — decrement value by X (0 ~ 2147483647) from src to dst
- `--res`, `--cp` — copy value from src to dst (Restore and Transfer)
- `--blk`, `--src-block` — block number of src (required)
- `-a`, `-A` — key of src is A key (default)
- `-b`, `-B` — key of src is B key
- `-k`, `--src-key` — key of src (required)
- `--tblk`, `--dst-block` — block number of dst (default to src)
- `--ta`, `--tA` — key of dst is A key (default to src)
- `--tb`, `--tB` — key of dst is B key (default to src)
- `--tkey`, `--dst-key` — key of dst (default to src)

#### `hf mf view`

Display content from tag memory or dump file

- `--mini` — MIFARE Classic Mini / S20 (default: 16)
- `--1k` — MIFARE Classic 1k / S50 (default) (default: 16)
- `--2k` — MIFARE Classic/Plus 2k (default: 16)
- `--4k` — MIFARE Classic 4k / S70 (default: 16)
- `-d`, `--dump-file` — Dump file to read
- `-k`, `--key-file` — File containing keys of tag to write (exported with fchk --export)

#### `hf mf wrbl`

Mifare Classic write one block

- `--blk`, `--block` — The block where the key of the card is known (required)
- `-a`, `-A` — Known key is A key (default)
- `-b`, `-B` — Known key is B key
- `-k`, `--key` — tag sector key (required)
- `-d`, `--data` — Your block data, as hex string. (required)

### `hf mfu`

MIFARE Ultralight / NTAG commands

#### `hf mfu authnonce`

Get authentication nonce from MIFARE Ultralight C tag.


#### `hf mfu dump`

MIFARE Ultralight dump pages

- `-k`, `--key` — Authentication key (EV1/NTAG 4 bytes).
- `-l` — Swap endianness of the key.
- `-p`, `--page` — Manually set number of pages to dump
- `-q`, `--qty` — Manually set number of pages to dump
- `-f`, `--file` — Specify a filename for dump file (default: )
- `-t`, `--type` — Force writing as either raw binary or hex. (choices: bin, hex)

#### `hf mfu econfig`

Settings of Mifare Ultralight / NTAG emulator

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--uid` — Unique ID
- `--atqa` — Answer To Request
- `--sak` — Select AcKnowledge
- `--ats` — Answer To Select
- `--delete-ats` — Delete Answer To Select
- `--enable-uid-magic` — Enable UID magic mode
- `--disable-uid-magic` — Disable UID magic mode
- `--write` — Write Mode: NORMAL, DENIED, DECEIVE, SHADOW (choices: NORMAL, DENIED, DECEIVE, SHADOW)
- `--set-version` — Set data to be returned by the GET_VERSION command.
- `--set-signature` — Set data to be returned by the READ_SIG command.
- `--reset-auth-cnt` — Resets the counter of unsuccessful authentication attempts.
- `--enable-log` — Enable password authentication logging
- `--disable-log` — Disable password authentication logging

#### `hf mfu edetect`

Get Mifare Ultralight / NTAG emulator detection logs

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--count` — Number of log entries to retrieve
- `--index` — Starting index (default: 0)

#### `hf mfu eload`

MIFARE Ultralight / NTAG load emulator data

- `-f`, `--file` — File to load data from. (required)
- `-t`, `--type` — Force writing as either raw binary or hex. (choices: bin, hex)

#### `hf mfu ercnt`

Read MIFARE Ultralight / NTAG counter value.

- `-c`, `--counter` — Counter index. (required)

#### `hf mfu esave`

MIFARE Ultralight / NTAG save emulator data

- `-f`, `--file` — File to save data to. (required)
- `-t`, `--type` — Force writing as either raw binary or hex. (choices: bin, hex)

#### `hf mfu eview`

MIFARE Ultralight / NTAG view emulator data


#### `hf mfu ewcnt`

Write MIFARE Ultralight / NTAG counter value.

- `-c`, `--counter` — Counter index. (required)
- `-v`, `--value` — Counter value (24-bit). (required)
- `-t`, `--reset-tearing` — Reset tearing event flag.

#### `hf mfu ndefread`

Read an NDEF message from a MIFARE Ultralight / NTAG tag (Type 2 Tag TLV area, starting at the first user memory page).

- `-k`, `--key` — Authentication key (EV1/NTAG 4 bytes).
- `-l` — Swap endianness of the key.
- `-p`, `--page` — First page to start scanning the TLV area from (default: 4). (default: 4)
- `-q`, `--qty` — Number of pages to read before giving up (default: read until an empty response or a Terminator TLV is found).
- `-f`, `--file` — Save the raw NDEF message bytes to this file. (default: )
- `--raw` — Only print the raw NDEF message hex, skip record decoding.

#### `hf mfu ndefwrite`

Write an NDEF message to a MIFARE Ultralight / NTAG tag (Type 2 Tag TLV area, starting at the first user memory page).

- `-k`, `--key` — Authentication key (EV1/NTAG 4 bytes).
- `-l` — Swap endianness of the key.
- `-u`, `--uri` — Write a URI record, e.g. a URL.
- `-t`, `--text` — Write a Text record.
- `-m`, `--mime` — Write a MIME record payload as hex, requires --mime-type.
- `-r`, `--raw` — Write a complete, already-encoded raw NDEF message as hex (will still be TLV-wrapped).
- `--lang` — Text record language code (default: en). (default: en)
- `--mime-type` — MIME type for --mime, e.g. text/plain.
- `-p`, `--page` — First page to write the TLV area at (default: 4). (default: 4)
- `-q`, `--qty` — Number of available user pages on the tag, used as a safety check before writing (default: no check).

#### `hf mfu nfcimport`

Import a Flipper Zero .nfc file into a MIFARE Ultralight / NTAG emulator slot

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-f`, `--file` — Path to Flipper Zero .nfc file (required)
- `--amiibo` — Derive and write correct PWD/PACK for amiibo (NTAG215)

#### `hf mfu rcnt`

MIFARE Ultralight / NTAG read counter

- `-k`, `--key` — Authentication key (EV1/NTAG 4 bytes).
- `-l` — Swap endianness of the key.
- `-c`, `--counter` — Index of the counter to read (always 0 for NTAG, 0-2 for Ultralight EV1). (required)

#### `hf mfu rdpg`

MIFARE Ultralight / NTAG read one page

- `-k`, `--key` — Authentication key (EV1/NTAG 4 bytes).
- `-l` — Swap endianness of the key.
- `-p`, `--page` — The page where the key will be used against (required)

#### `hf mfu signature`

Request MIFARE Ultralight / NTAG ECC signature data.


#### `hf mfu ulcg`

Key recovery for Giantec ULCG and USCUID-UL cards (won't work on NXP cards!)

- `-c`, `--challenges` — Number of challenges to collect (default: 1000) (default: 1000)
- `-t`, `--threads` — Number of threads for key recovery (default: 1) (default: 1)
- `-j`, `--json` — Path to JSON file to load or save challenges
- `-o`, `--offline` — Use offline mode with pre-collected challenges

#### `hf mfu version`

Request MIFARE Ultralight / NTAG version data.


#### `hf mfu wrpg`

MIFARE Ultralight / NTAG write one page

- `-k`, `--key` — Authentication key (EV1/NTAG 4 bytes).
- `-l` — Swap endianness of the key.
- `-p`, `--page` — The index of the page to write to. (required)
- `-d`, `--data` — Your page data, as a 4 byte (8 character) hex string. (required)

### `hf seos`

SEOS commands

#### `hf seos eload`

Load data into emulator memory

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--uid` — Unique ID
- `--atqa` — Answer To Request
- `--sak` — Select AcKnowledge
- `--ats` — Answer To Select
- `--delete-ats` — Delete Answer To Select
- `-d`, `--data` — Data to present to reader (2-255 bytes). Must be valid BER-TLV.
- `-o`, `--oid` — Target OID (1-32 bytes).
- `-t`, `--tag` — Tag of presented data (1-2 bytes).
- `--diversifier` — Simulated card diversifier (1-16 bytes).

#### `hf seos eview`

View data from emulator memory

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)

#### `hf seos keys`

Load data into emulator memory

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-a`, `--auth` — Auth key (16 bytes) (required)
- `-e`, `--privenc` — PrivEnc key (16 bytes) (required)
- `-m`, `--privmac` — PrivMac key (16 bytes) (required)

## `hw`

Hardware-related commands

### `hw address`

Get device address (used with Bluetooth)


### `hw battery`

Get battery information, voltage and level


### `hw blver`

Get bootloader version


### `hw chipid`

Get device chipset ID


### `hw connect`

Connect to chameleon by serial port, TCP, or BLE. Examples: -p /dev/ttyACM0 | -p tcp:127.0.0.1:4321 | -p ble (scan) | -p ble:AA:BB:CC:DD:EE:FF (needs 'bleak')

- `-p`, `--port`

### `hw dfu`

Restart application to bootloader/DFU mode


### `hw disconnect`

Disconnect chameleon


### `hw factory_reset`

Wipe all slot data and custom settings and return to factory settings

- `--force` — Just to be sure

### `hw flash`

Flash a DFU firmware package (.zip) to the device over Secure DFU. Enters bootloader mode automatically, then uploads with no external tools required (no nrfutil).

- `file` — Path to the DFU package .zip (required)
- `--no-enter` — Skip enter-bootloader; device is already in DFU mode
- `-p`, `--port` — Override the upload transport (default: the same transport the client is connected on). A serial port path, or 'ble' / 'ble:AA:BB:CC:DD:EE:FF' to force BLE DFU (needs bleak)
- `--wait` — Seconds to wait for the DFU device to appear (default: 30) (default: 30.0)

### `hw freemem`

Get device heap memory usage


### `hw mode`

Get or change device mode: tag reader or tag emulator

- `-r`, `--reader` — Set reader mode
- `-e`, `--emulator` — Set emulator mode

### `hw raw`

Send raw command

- `-c`, `--command` — Command: ADC_GENERIC_READ, CHANGE_DEVICE_MODE, DELETE_ALL_BLE_BONDS, DELETE_SLOT_SENSE_TYPE, DELETE_SLOT_TAG_NICK, DESFIRE_FACTORY_BLANK, DESFIRE_GET_CREDENTIAL, DESFIRE_GET_INFO, DESFIRE_GET_STATS, DESFIRE_SET_CREDENTIAL, EM410X_ELECTRA_WRITE_TO_T55XX, EM410X_GET_EMU_ID, EM410X_SCAN, EM410X_SET_EMU_ID, EM410X_WRITE_TO_T55XX, EM4X05_READSNIFF, EM4X05_SCAN, ENTER_BOOTLOADER, FDXB_SCAN, FDXB_WRITE_TO_T55XX, GET_ACTIVE_SLOT, GET_ALL_SLOT_NICKS, GET_ANIMATION_MODE, GET_APP_VERSION, GET_BATTERY_INFO, GET_BLE_NAME, GET_BLE_PAIRING_ENABLE, GET_BLE_PAIRING_KEY, GET_BOOTLOADER_VERSION, GET_BUTTON_PRESS_CONFIG, GET_DEVICE_ADDRESS, GET_DEVICE_CAPABILITIES, GET_DEVICE_CHIP_ID, GET_DEVICE_MODE, GET_DEVICE_MODEL, GET_DEVICE_SETTINGS, GET_ENABLED_SLOTS, GET_FREE_MEMORY, GET_GIT_VERSION, GET_LONG_BUTTON_PRESS_CONFIG, GET_SLEEP_TIMEOUT, GET_SLOT_INFO, GET_SLOT_TAG_NICK, HF14A_4_APDU_RECV, HF14A_4_APDU_SEND, HF14A_4_EMV_SCAN, HF14A_4_READER_APDU, HF14A_4_SET_ANTI_COLL, HF14A_4_STATIC_RESP, HF14A_AUTH_TRACE, HF14A_GET_ANTI_COLL_DATA, HF14A_GET_CONFIG, HF14A_RAW, HF14A_SCAN, HF14A_SCAN_KEEP, HF14A_SET_ANTI_COLL_DATA, HF14A_SET_CONFIG, HF14A_SNIFF, HIDPROX_GET_EMU_ID, HIDPROX_SCAN, HIDPROX_SET_EMU_ID, HIDPROX_WRITE_TO_T55XX, IDTECK_GET_EMU_ID, IDTECK_SET_EMU_ID, IDTECK_WRITE_TO_T55XX, INDALA_SCAN, INDALA_WRITE_TO_T55XX, IOPROX_COMPOSE_ID, IOPROX_DECODE_RAW, IOPROX_GET_EMU_ID, IOPROX_SCAN, IOPROX_SET_EMU_ID, IOPROX_WRITE_TO_T55XX, JABLOTRON_GET_EMU_ID, JABLOTRON_SCAN, JABLOTRON_SET_EMU_ID, JABLOTRON_WRITE_TO_T55XX, LF_SEARCH, LF_SNIFF, LF_T55XX_READ, LF_T55XX_WRITE, MF0_NTAG_GET_COUNTER_DATA, MF0_NTAG_GET_DETECTION_COUNT, MF0_NTAG_GET_DETECTION_ENABLE, MF0_NTAG_GET_DETECTION_LOG, MF0_NTAG_GET_EMULATOR_CONFIG, MF0_NTAG_GET_PAGE_COUNT, MF0_NTAG_GET_SIGNATURE_DATA, MF0_NTAG_GET_UID_MAGIC_MODE, MF0_NTAG_GET_VERSION_DATA, MF0_NTAG_GET_WRITE_MODE, MF0_NTAG_READ_EMU_PAGE_DATA, MF0_NTAG_RESET_AUTH_CNT, MF0_NTAG_SET_COUNTER_DATA, MF0_NTAG_SET_DETECTION_ENABLE, MF0_NTAG_SET_SIGNATURE_DATA, MF0_NTAG_SET_UID_MAGIC_MODE, MF0_NTAG_SET_VERSION_DATA, MF0_NTAG_SET_WRITE_MODE, MF0_NTAG_WRITE_EMU_PAGE_DATA, MF1_AUTH_ONE_KEY_BLOCK, MF1_CHECK_KEYS_OF_SECTORS, MF1_CHECK_KEYS_ON_BLOCK, MF1_DARKSIDE_ACQUIRE, MF1_DETECT_NT_DIST, MF1_DETECT_PRNG, MF1_DETECT_SUPPORT, MF1_ENC_NESTED_ACQUIRE, MF1_GET_BLOCK_ANTI_COLL_MODE, MF1_GET_DETECTION_COUNT, MF1_GET_DETECTION_ENABLE, MF1_GET_DETECTION_LOG, MF1_GET_EMULATOR_CONFIG, MF1_GET_FIELD_OFF_DO_RESET, MF1_GET_GEN1A_MODE, MF1_GET_GEN2_MODE, MF1_GET_PRNG_TYPE, MF1_GET_WRITE_MODE, MF1_HARDNESTED_ACQUIRE, MF1_MANIPULATE_VALUE_BLOCK, MF1_NESTED_ACQUIRE, MF1_READ_EMU_BLOCK_DATA, MF1_READ_ONE_BLOCK, MF1_SET_BLOCK_ANTI_COLL_MODE, MF1_SET_DETECTION_ENABLE, MF1_SET_FIELD_OFF_DO_RESET, MF1_SET_GEN1A_MODE, MF1_SET_GEN2_MODE, MF1_SET_PRNG_TYPE, MF1_SET_WRITE_MODE, MF1_STATIC_NESTED_ACQUIRE, MF1_WRITE_EMU_BLOCK_DATA, MF1_WRITE_ONE_BLOCK, PAC_GET_EMU_ID, PAC_SCAN, PAC_SET_EMU_ID, PAC_WRITE_TO_T55XX, RESET_DEVICE, RESET_SETTINGS, SAVE_SETTINGS, SEOS_READ_EMU_DATA, SEOS_WRITE_EMU_DATA, SEOS_WRITE_EMU_KEYS, SET_ACTIVE_SLOT, SET_ANIMATION_MODE, SET_BLE_NAME, SET_BLE_PAIRING_ENABLE, SET_BLE_PAIRING_KEY, SET_BUTTON_PRESS_CONFIG, SET_LONG_BUTTON_PRESS_CONFIG, SET_SLEEP_TIMEOUT, SET_SLOT_DATA_DEFAULT, SET_SLOT_ENABLE, SET_SLOT_TAG_NICK, SET_SLOT_TAG_TYPE, SLOT_DATA_CONFIG_SAVE, STANDALONE_CLEAR_RESULT, STANDALONE_DISARM, STANDALONE_GET_CONFIG, STANDALONE_GET_MODE, STANDALONE_GET_RESULT, STANDALONE_GET_SIZES, STANDALONE_RELAY_DIAG, STANDALONE_SET_CONFIG, STANDALONE_SET_MODE, STANDALONE_TRIGGER, UPDATE_BL, VIKING_GET_EMU_ID, VIKING_SCAN, VIKING_SET_EMU_ID, VIKING_WRITE_TO_T55XX, WIPE_FDS (choices: ADC_GENERIC_READ, CHANGE_DEVICE_MODE, DELETE_ALL_BLE_BONDS, DELETE_SLOT_SENSE_TYPE, DELETE_SLOT_TAG_NICK, DESFIRE_FACTORY_BLANK, DESFIRE_GET_CREDENTIAL, DESFIRE_GET_INFO, DESFIRE_GET_STATS, DESFIRE_SET_CREDENTIAL, EM410X_ELECTRA_WRITE_TO_T55XX, EM410X_GET_EMU_ID, EM410X_SCAN, EM410X_SET_EMU_ID, EM410X_WRITE_TO_T55XX, EM4X05_READSNIFF, EM4X05_SCAN, ENTER_BOOTLOADER, FDXB_SCAN, FDXB_WRITE_TO_T55XX, GET_ACTIVE_SLOT, GET_ALL_SLOT_NICKS, GET_ANIMATION_MODE, GET_APP_VERSION, GET_BATTERY_INFO, GET_BLE_NAME, GET_BLE_PAIRING_ENABLE, GET_BLE_PAIRING_KEY, GET_BOOTLOADER_VERSION, GET_BUTTON_PRESS_CONFIG, GET_DEVICE_ADDRESS, GET_DEVICE_CAPABILITIES, GET_DEVICE_CHIP_ID, GET_DEVICE_MODE, GET_DEVICE_MODEL, GET_DEVICE_SETTINGS, GET_ENABLED_SLOTS, GET_FREE_MEMORY, GET_GIT_VERSION, GET_LONG_BUTTON_PRESS_CONFIG, GET_SLEEP_TIMEOUT, GET_SLOT_INFO, GET_SLOT_TAG_NICK, HF14A_4_APDU_RECV, HF14A_4_APDU_SEND, HF14A_4_EMV_SCAN, HF14A_4_READER_APDU, HF14A_4_SET_ANTI_COLL, HF14A_4_STATIC_RESP, HF14A_AUTH_TRACE, HF14A_GET_ANTI_COLL_DATA, HF14A_GET_CONFIG, HF14A_RAW, HF14A_SCAN, HF14A_SCAN_KEEP, HF14A_SET_ANTI_COLL_DATA, HF14A_SET_CONFIG, HF14A_SNIFF, HIDPROX_GET_EMU_ID, HIDPROX_SCAN, HIDPROX_SET_EMU_ID, HIDPROX_WRITE_TO_T55XX, IDTECK_GET_EMU_ID, IDTECK_SET_EMU_ID, IDTECK_WRITE_TO_T55XX, INDALA_SCAN, INDALA_WRITE_TO_T55XX, IOPROX_COMPOSE_ID, IOPROX_DECODE_RAW, IOPROX_GET_EMU_ID, IOPROX_SCAN, IOPROX_SET_EMU_ID, IOPROX_WRITE_TO_T55XX, JABLOTRON_GET_EMU_ID, JABLOTRON_SCAN, JABLOTRON_SET_EMU_ID, JABLOTRON_WRITE_TO_T55XX, LF_SEARCH, LF_SNIFF, LF_T55XX_READ, LF_T55XX_WRITE, MF0_NTAG_GET_COUNTER_DATA, MF0_NTAG_GET_DETECTION_COUNT, MF0_NTAG_GET_DETECTION_ENABLE, MF0_NTAG_GET_DETECTION_LOG, MF0_NTAG_GET_EMULATOR_CONFIG, MF0_NTAG_GET_PAGE_COUNT, MF0_NTAG_GET_SIGNATURE_DATA, MF0_NTAG_GET_UID_MAGIC_MODE, MF0_NTAG_GET_VERSION_DATA, MF0_NTAG_GET_WRITE_MODE, MF0_NTAG_READ_EMU_PAGE_DATA, MF0_NTAG_RESET_AUTH_CNT, MF0_NTAG_SET_COUNTER_DATA, MF0_NTAG_SET_DETECTION_ENABLE, MF0_NTAG_SET_SIGNATURE_DATA, MF0_NTAG_SET_UID_MAGIC_MODE, MF0_NTAG_SET_VERSION_DATA, MF0_NTAG_SET_WRITE_MODE, MF0_NTAG_WRITE_EMU_PAGE_DATA, MF1_AUTH_ONE_KEY_BLOCK, MF1_CHECK_KEYS_OF_SECTORS, MF1_CHECK_KEYS_ON_BLOCK, MF1_DARKSIDE_ACQUIRE, MF1_DETECT_NT_DIST, MF1_DETECT_PRNG, MF1_DETECT_SUPPORT, MF1_ENC_NESTED_ACQUIRE, MF1_GET_BLOCK_ANTI_COLL_MODE, MF1_GET_DETECTION_COUNT, MF1_GET_DETECTION_ENABLE, MF1_GET_DETECTION_LOG, MF1_GET_EMULATOR_CONFIG, MF1_GET_FIELD_OFF_DO_RESET, MF1_GET_GEN1A_MODE, MF1_GET_GEN2_MODE, MF1_GET_PRNG_TYPE, MF1_GET_WRITE_MODE, MF1_HARDNESTED_ACQUIRE, MF1_MANIPULATE_VALUE_BLOCK, MF1_NESTED_ACQUIRE, MF1_READ_EMU_BLOCK_DATA, MF1_READ_ONE_BLOCK, MF1_SET_BLOCK_ANTI_COLL_MODE, MF1_SET_DETECTION_ENABLE, MF1_SET_FIELD_OFF_DO_RESET, MF1_SET_GEN1A_MODE, MF1_SET_GEN2_MODE, MF1_SET_PRNG_TYPE, MF1_SET_WRITE_MODE, MF1_STATIC_NESTED_ACQUIRE, MF1_WRITE_EMU_BLOCK_DATA, MF1_WRITE_ONE_BLOCK, PAC_GET_EMU_ID, PAC_SCAN, PAC_SET_EMU_ID, PAC_WRITE_TO_T55XX, RESET_DEVICE, RESET_SETTINGS, SAVE_SETTINGS, SEOS_READ_EMU_DATA, SEOS_WRITE_EMU_DATA, SEOS_WRITE_EMU_KEYS, SET_ACTIVE_SLOT, SET_ANIMATION_MODE, SET_BLE_NAME, SET_BLE_PAIRING_ENABLE, SET_BLE_PAIRING_KEY, SET_BUTTON_PRESS_CONFIG, SET_LONG_BUTTON_PRESS_CONFIG, SET_SLEEP_TIMEOUT, SET_SLOT_DATA_DEFAULT, SET_SLOT_ENABLE, SET_SLOT_TAG_NICK, SET_SLOT_TAG_TYPE, SLOT_DATA_CONFIG_SAVE, STANDALONE_CLEAR_RESULT, STANDALONE_DISARM, STANDALONE_GET_CONFIG, STANDALONE_GET_MODE, STANDALONE_GET_RESULT, STANDALONE_GET_SIZES, STANDALONE_RELAY_DIAG, STANDALONE_SET_CONFIG, STANDALONE_SET_MODE, STANDALONE_TRIGGER, UPDATE_BL, VIKING_GET_EMU_ID, VIKING_SCAN, VIKING_SET_EMU_ID, VIKING_WRITE_TO_T55XX, WIPE_FDS)
- `-n`, `--num_command` — Numeric command ID: <dec>
- `-d`, `--data` — Data to send (default: )
- `-t`, `--timeout` — Timeout in seconds (default: 3)

### `hw reset`

Reboot the device. Plain restart only — slots and settings are untouched.


### `hw settings`

Chameleon settings commands

#### `hw settings animation`

Get or change current animation mode value

- `-m`, `--mode` — Mode: FULL, MINIMAL, SYMMETRIC, NONE (choices: FULL, MINIMAL, SYMMETRIC, NONE)

#### `hw settings bleclearbonds`

Clear all BLE bindings. Warning: effect is immediate!

- `--force` — Just to be sure

#### `hw settings blekey`

Get or set the ble connect key

- `-k`, `--key` — Ble connect key for your device

#### `hw settings blename`

Get or set the BLE advertised name (max 20 chars). Pass an empty string to reset to the firmware default.

- `-n`, `--name` — BLE advertised name for your device (max 20 chars), or "" to reset to default

#### `hw settings blepair`

Show or configure BLE pairing

- `-e`, `--enable` — Enable BLE pairing
- `-d`, `--disable` — Disable BLE pairing

#### `hw settings btnpress`

Get or set button press function of Button A and Button B

- `-a`, `-A` — Button A
- `-b`, `-B` — Button B
- `-s`, `--short` — Short-press (default)
- `-l`, `--long` — Long-press
- `-f`, `--function` — Function: NONE (No Function), NEXTSLOT (Select next slot), PREVSLOT (Select previous slot), CLONE (Read then simulate the ID/UID card number), BATTERY (Show Battery Level), FIELDGEN (Toggle NFC Field Generator), STANDALONE_DISARM (Disarm active standalone mode) (choices: NONE, NEXTSLOT, PREVSLOT, CLONE, BATTERY, FIELDGEN, STANDALONE_DISARM)

#### `hw settings reset`

Reset settings to default values

- `--force` — Just to be sure

#### `hw settings sleeptimeout`

Get or set the wake timeout after a button press (5-60 seconds)

- `-s`, `--seconds` — Wake timeout in seconds (5-60)

#### `hw settings store`

Store current settings to flash


### `hw slot`

Emulation slots commands

#### `hw slot change`

Set emulation tag slot activated

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8; required)

#### `hw slot delete`

Delete sense type data for a specific slot

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--hf` — HF type
- `--lf` — LF type

#### `hw slot disable`

Disable tag slot

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--hf` — HF type
- `--lf` — LF type

#### `hw slot enable`

Enable tag slot

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--hf` — HF type
- `--lf` — LF type

#### `hw slot init`

Set emulation tag data to default

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-t`, `--type` — Tag Type: EM410X, EM410X_16, EM410X_32, EM410X_64, EM410X_ELECTRA, FDXB, PAC, Viking, Jablotron, HIDProx, ioProx, IDTECK, MIFARE_Mini, MIFARE_1024, MIFARE_2048, MIFARE_4096, NTAG_213, NTAG_215, NTAG_216, MF0ICU1, MF0ICU2, MF0UL11, MF0UL21, NTAG_210, NTAG_212, DESFIRE_EV1_2K, DESFIRE_EV1_4K, DESFIRE_EV1_8K, DESFIRE_EV2_2K, DESFIRE_EV2_4K, DESFIRE_EV2_8K, HF14A_4, SEOS (choices: EM410X, EM410X_16, EM410X_32, EM410X_64, EM410X_ELECTRA, FDXB, PAC, Viking, Jablotron, HIDProx, ioProx, IDTECK, MIFARE_Mini, MIFARE_1024, MIFARE_2048, MIFARE_4096, NTAG_213, NTAG_215, NTAG_216, MF0ICU1, MF0ICU2, MF0UL11, MF0UL21, NTAG_210, NTAG_212, DESFIRE_EV1_2K, DESFIRE_EV1_4K, DESFIRE_EV1_8K, DESFIRE_EV2_2K, DESFIRE_EV2_4K, DESFIRE_EV2_8K, HF14A_4, SEOS; required)

#### `hw slot list`

Get information about slots

- `--short` — Hide slot nicknames and Mifare Classic emulator settings

#### `hw slot nick`

Get/Set/Delete tag nick name for slot

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--hf` — HF type
- `--lf` — LF type
- `-n`, `--name` — Set tag nick name for slot
- `-d`, `--delete` — Delete tag nick name for slot

#### `hw slot openall`

Open all slot and set to default data


#### `hw slot prng`

Get or set the PRNG type for the MF1 emulator of a slot. PRNG controls the nonce used during MIFARE Classic authentication: 0=Static (fixed), 1=Weak (LFSR/predictable), 2=Hard (unpredictable). Omit --type to read the current setting.

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-t`, `--type` — PRNG type: 0=Static, 1=Weak, 2=Hard (choices: 0, 1, 2)

#### `hw slot store`

Store slots config & data to device flash


#### `hw slot type`

Set emulation tag type

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-t`, `--type` — Tag Type: EM410X, EM410X_16, EM410X_32, EM410X_64, EM410X_ELECTRA, FDXB, PAC, Viking, Jablotron, HIDProx, ioProx, IDTECK, MIFARE_Mini, MIFARE_1024, MIFARE_2048, MIFARE_4096, NTAG_213, NTAG_215, NTAG_216, MF0ICU1, MF0ICU2, MF0UL11, MF0UL21, NTAG_210, NTAG_212, DESFIRE_EV1_2K, DESFIRE_EV1_4K, DESFIRE_EV1_8K, DESFIRE_EV2_2K, DESFIRE_EV2_4K, DESFIRE_EV2_8K, HF14A_4, SEOS (choices: EM410X, EM410X_16, EM410X_32, EM410X_64, EM410X_ELECTRA, FDXB, PAC, Viking, Jablotron, HIDProx, ioProx, IDTECK, MIFARE_Mini, MIFARE_1024, MIFARE_2048, MIFARE_4096, NTAG_213, NTAG_215, NTAG_216, MF0ICU1, MF0ICU2, MF0UL11, MF0UL21, NTAG_210, NTAG_212, DESFIRE_EV1_2K, DESFIRE_EV1_4K, DESFIRE_EV1_8K, DESFIRE_EV2_2K, DESFIRE_EV2_4K, DESFIRE_EV2_8K, HF14A_4, SEOS; required)

### `hw status`

Show a one-shot summary of connection, firmware and hardware status


### `hw version`

Get current device firmware version


## `lf`

Low Frequency commands

### `lf clone`

Clone a LF card ID onto a blank T55xx tag.
Supported types: em410x, electra, hid, ioprox, pac, viking, idteck.
Only supported on Chameleon Ultra (Lite has no LF writer).

- `-t`, `--type` — Card type: em410x, electra, hid, ioprox, pac, viking, idteck (choices: em410x, electra, hid, ioprox, pac, viking, idteck; required)
- `--id` — Card ID in hex: 10 for em410x, 26 for electra, 8 for viking, 8 or 16 for idteck; 8 ASCII chars for pac
- `-f`, `--format` — HID Prox format, e.g. H10301 (required for hid type) (choices: H10301, IND26, IND27, INDASC27, TECOM27, W2804, IND29, ATSW30, ADT31, HCP32, HPP32, KASTLE, KANTECH, WIE32, D10202, H10306, N10002, OPTUS34, SMP34, BQT34, C1K35S, C15001, S12906, ACTPHID, SIE36, H10320, H10302, H10304, P10004, HGEN37, MDI37)
- `--fc` — Facility code (HID / ioProx)
- `--cn` — Card number (HID / ioProx)
- `--il` — Issue level (HID, optional)
- `--oem` — OEM code (HID, optional)
- `--ver` — Version byte (ioProx)
- `--raw8` — ioProx raw 8 bytes in hex, e.g. 007854E03A5D65AB

### `lf em`

EM commands

#### `lf em 410x`

EM410x commands

##### `lf em 410x econfig`

Set emulated em410x card id

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--id` — EM410x tag id

##### `lf em 410x read`

Scan em410x tag and print id


##### `lf em 410x write`

Write em410x id to t55xx

- `--id` — EM410x tag id (required)

#### `lf em 4x05`

EM4x05/EM4x69 commands

##### `lf em 4x05 read`

Scan EM4x05 or EM4x69 tag (reader-talk-first) and print config, UID


### `lf fdxb`

FDX-B animal tag commands (134.2 kHz)

#### `lf fdxb clone`

Clone FDX-B animal tag to T55xx (alias for 'write')

- `--country` — country/manufacturer code (ISO 3166 numeric, e.g. 208 for Denmark)
- `--national` — national ID, up to 274877906943 (38-bit)
- `--animal` — animal flag (default 1) (choices: 0, 1; default: 1)
- `--extended` — optional 24-bit extended data (default 0)
- `--id` — raw 26-hex frame instead of fields (advanced; not validated for reserved bits)

#### `lf fdxb read`

Scan FDX-B animal tag (134.2 kHz) and print id

- `--raw` — also print the raw 13-byte frame
- `-@` — continuous scan until a key is pressed (helps locate an implant)

#### `lf fdxb write`

Write FDX-B frame to T55xx (by fields, or raw --id)

- `--country` — country/manufacturer code (ISO 3166 numeric, e.g. 208 for Denmark)
- `--national` — national ID, up to 274877906943 (38-bit)
- `--animal` — animal flag (default 1) (choices: 0, 1; default: 1)
- `--extended` — optional 24-bit extended data (default 0)
- `--id` — raw 26-hex frame instead of fields (advanced; not validated for reserved bits)

### `lf generic`

Generic commands

#### `lf generic adcread`

Read ADC and return the array


### `lf hid`

HID commands

#### `lf hid prox`

HID Prox commands

##### `lf hid prox econfig`

Set emulated hidprox card id

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `-f`, `--format` — HIDProx card format (choices: H10301, IND26, IND27, INDASC27, TECOM27, W2804, IND29, ATSW30, ADT31, HCP32, HPP32, KASTLE, KANTECH, WIE32, D10202, H10306, N10002, OPTUS34, SMP34, BQT34, C1K35S, C15001, S12906, ACTPHID, SIE36, H10320, H10302, H10304, P10004, HGEN37, MDI37)
- `--fc` — HIDProx tag facility code
- `--cn` — HIDProx tag card number
- `--il` — HIDProx tag issue level
- `--oem` — HIDProx tag OEM

##### `lf hid prox read`

Scan hid prox tag and print card format, facility code, card number, issue level and OEM code

- `-f`, `--format` — HIDProx card format hint (choices: H10301, IND26, IND27, INDASC27, TECOM27, W2804, IND29, ATSW30, ADT31, HCP32, HPP32, KASTLE, KANTECH, WIE32, D10202, H10306, N10002, OPTUS34, SMP34, BQT34, C1K35S, C15001, S12906, ACTPHID, SIE36, H10320, H10302, H10304, P10004, HGEN37, MDI37)

##### `lf hid prox write`

Write hidprox card data to t55xx

- `-f`, `--format` — HIDProx card format (choices: H10301, IND26, IND27, INDASC27, TECOM27, W2804, IND29, ATSW30, ADT31, HCP32, HPP32, KASTLE, KANTECH, WIE32, D10202, H10306, N10002, OPTUS34, SMP34, BQT34, C1K35S, C15001, S12906, ACTPHID, SIE36, H10320, H10302, H10304, P10004, HGEN37, MDI37; required)
- `--fc` — HIDProx tag facility code
- `--cn` — HIDProx tag card number (required)
- `--il` — HIDProx tag issue level
- `--oem` — HIDProx tag OEM

### `lf idteck`

IDTECK commands

#### `lf idteck econfig`

Get or set the IDTECK emulated id on a slot. Provide --id to set; omit it to read back the current value.

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--id` — IDTECK frame in hex: 16 chars for the full 64-bit frame, or 8 chars for the 32-bit payload only (preamble 4944544B is auto-prepended).

#### `lf idteck write`

Clone an IDTECK PSK1 frame onto a T55xx tag.

- `--id` — IDTECK frame in hex: 16 chars for the full 64-bit frame, or 8 chars for the 32-bit payload only (preamble 4944544B is auto-prepended). (required)

### `lf indala`

Indala commands

#### `lf indala read`

Scan for an Indala tag


#### `lf indala write`

Clone Indala tag to T55XX (use -r <hex>, or --fc <n> --cn <n>)

- `-r`, `--raw` — Raw 64-bit frame (16 hex chars)
- `--fc` — Facility code (26-bit format, use with --cn)
- `--cn` — Card number (26-bit format, use with --fc)

### `lf ioprox`

ioProx commands

#### `lf ioprox econfig`

Set/Get emulated ioProx card id (stored in slot)

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--ver` — ioProx version
- `--fc` — ioProx facility code, e.g., 83 or 0x53
- `--cn` — ioProx card number
- `--raw8` — ioProx raw 8 bytes hex (e.g. 00AABBCCDDEEFF55)

#### `lf ioprox read`

Scan ioProx tag and print version, facility, card number and raw

- `-v`, `--verbose` — Verbose output

#### `lf ioprox write`

Write ioProx card data to t55xx

- `--ver` — ioProx version
- `--fc` — ioProx facility code, e.g., 83 or 0x53
- `--cn` — ioProx card number
- `--raw8` — ioProx raw 8 bytes hex (e.g. 00AABBCCDDEEFF55)

### `lf jablotron`

Jablotron commands

#### `lf jablotron econfig`

Set emulated Jablotron card id

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--id` — Jablotron tag id (5 bytes hex)

#### `lf jablotron read`

Scan Jablotron tag and print id


#### `lf jablotron write`

Write Jablotron id to t55xx

- `--id` — Jablotron tag id (5 bytes hex) (required)

### `lf pac`

PAC/Stanley commands

#### `lf pac econfig`

Set emulated PAC/Stanley card ID

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--cn` — Card number (8 ASCII characters, e.g. CARD0001)
- `--raw` — T55XX bitstream (32 hex chars, PM3 raw format)

#### `lf pac read`

Scan PAC/Stanley tag and print card ID


#### `lf pac write`

Write PAC/Stanley id to T55xx

- `--cn` — Card number (8 ASCII characters, e.g. CARD0001)
- `--raw` — T55XX bitstream (32 hex chars, PM3 raw format)

### `lf search`

Search for any supported LF tag — tries every decoder in turn (PM3-style) and reports the first match


### `lf sniff`

Capture raw LF field ADC samples (125kHz, 8µs/sample). ~0x80 = field on, lower values = gap or no field.

- `--timeout` — Capture duration in milliseconds (default: 2000, max: 10000, firmware blocks for full duration) (default: 2000)
- `--out` — Save raw samples to binary file (for offline analysis)
- `--hex` — Print hex dump of samples to screen

### `lf t55xx`

T55xx/T5577 raw block commands

#### `lf t55xx detect`

Detect a T55xx tag by reading block 0 and stride-locking its config: slides a 32-bit window over the demodulated stream and accepts the first window that repeats and parses to a valid config at the read rate. Tries Manchester (amplitude path) and biphase (firmware diphase). FSK/PSK are not wired; streaming tags with no addressable config block (e.g. FDX-B) are reported as such. Sets the default RF/n for subsequent `read`.

- `-p`, `--pwd` — Password, 4 hex bytes (if block 0 is read-protected)

#### `lf t55xx read`

Read a T55xx block (Manchester) and dump the demodulated bitstream

- `-b`, `--block` (required)
- `--rf` — Bitrate divisor RF/n (default: from `detect`, else 32; em410x uses 64)
- `-p`, `--pwd` — Password, 4 hex bytes
- `--pg1` — Target page 1
- `--expect` — Verify: report whether this 32-bit word (4 hex bytes) is present
- `--raw` — Diagnostic: dump raw edge intervals (carrier cycles) instead of decoding
- `--adc` — Diagnostic: dump raw SAADC envelope amplitude (robust for dense data)
- `--regread` — Diagnostic: skip the addressed downlink, capture the regular-read stream
- `--mod` — Demod: manchester (SAADC amplitude, robust) or biphase (firmware diphase_feed). auto = whatever `detect` found (else manchester). (choices: auto, manchester, biphase; default: auto)

#### `lf t55xx wipe`

Wipe a T55xx: default config to block 0, zeros to blocks 1-7

- `-c`, `--cfg` — Override config block 0 (4 hex bytes)
- `-p`, `--pwd` — Current password, 4 hex bytes (to auth the wipe)
- `--q5` — Target Q5/T5555 (config 0x6001F004)
- `--extended` — Also zero block 3 page 1 (extended-mode config)

#### `lf t55xx write`

Write a raw 32-bit word to a T55xx block

- `-b`, `--block` — Block number (0-7 on page 0, 0-3 on page 1) (required)
- `-d`, `--data` — 32-bit data word, 4 hex bytes (required)
- `-p`, `--pwd` — Password, 4 hex bytes (password-protected write)
- `--pg1` — Target page 1

### `lf viking`

Viking commands

#### `lf viking econfig`

Set emulated Viking card id

- `-s`, `--slot` — Slot Index: [1, 2, 3, 4, 5, 6, 7, 8] Default: active slot (choices: 1, 2, 3, 4, 5, 6, 7, 8)
- `--id` — Viking tag id

#### `lf viking read`

Scan Viking tag and print id


#### `lf viking write`

Write Viking id to t55xx

- `--id` — Viking tag id (required)

## `rem`

Timestamped comment

- `comment` — Your comment (required)

## `standalone`

Host-less standalone modes

### `standalone clear-result`

Clear standalone result buffer


### `standalone config`

Read or write mode-specific config

- `mode` — target mode name (required)
- `--block` — [authtrace] target block (0-255)
- `--key-type` — [authtrace] MIFARE key type (choices: A, B)
- `--key` — [authtrace] 12-hex-char sector key (e.g. FFFFFFFFFFFF)
- `--timeout` — [authtrace] tag-poll timeout in ms (100-30000); [hf14a-tap-sniff] capture duration in ms (100-30000); [relay] WTX ms (500-10000)

### `standalone disarm`

Disarm standalone mode and save results


### `standalone get-result`

Read standalone result buffer

- `-f`, `--file` — write output to file instead of stdout
- `--raw` — dump raw bytes (no parsing)
- `--json` — emit parsed sessions as JSON
- `--dump` — dump every frame in each session
- `--pm3` — write each session as a Proxmark3 .trace (<prefix>-NN.trace)

### `standalone ls`

List stored standalone result data


### `standalone set-mode`

Set standalone mode

- `mode` — mode name (authtrace, emul-trace, relay, slot-cycle, autoclone, read-replay, dict-check, hf14a-tap-sniff, disabled) (required)
- `--opt-in` — set HOST_OPTED_IN flag (required for autoclone and read-replay)
- `--quiet-buzzer`
- `--quiet-led`

### `standalone status`

Show standalone subsystem state


### `standalone trigger`

Trigger active standalone mode


