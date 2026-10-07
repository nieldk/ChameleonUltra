# Standalone Modes

Standalone modes let the ChameleonUltra work **without a host** ,  no laptop, no
app, just the device and its two buttons. You configure a mode over the CLI
once, **arm** it, then walk away. The device runs the mode on button presses,
saves results to flash, and you pull them back at the bench later.

Most built-in modes are **safe by default**: they never write to a target card
or to your emulation slots. The few that do (`autoclone`, `read_replay`) must
declare it, and the framework refuses to arm them unless you pass `--opt-in`.

Every mode is **excluded by default at build time** to keep the image
small. If `standalone set-mode <name>` can't find a mode documented here,
it most likely wasn't built in — see
[`CONTRIBUTING STANDALONE.md`](CONTRIBUTING%20STANDALONE.md#3-add-to-the-makefile)
for the build flags and `../../../standalone_modes.mk.sample` for a
persistent per-build config, or ask whoever built your firmware which
modes they included.

## How every mode works (the pattern)

1. **Select** the mode: `standalone set-mode <name>`
2. **Configure** it (options are per-mode): `standalone config <name> [flags]`
3. **Arm** it: `standalone trigger` (from the CLI), or press **both buttons,
   long** on the device.
4. **Walk away.** Press **both buttons, short** to run one capture/action.
5. **Disarm** to save results: `standalone disarm`, or **both buttons, long**.
6. **Retrieve**: `standalone get-result` (over USB/BLE).

`standalone status` shows the current mode, armed state, and stored-result
count. `standalone ls` lists the modes. `standalone clear-result` discards
stored results.

## Buttons while armed (chord = press both together)

| Chord | Meaning |
|-------|---------|
| **Both, short** | Run the mode's action (one capture / advance slot). |
| **Both, long** | Arm ⇄ disarm. |
| **Both, very-long** | Discard all stored results for this mode. |

## LED feedback (all modes)

The slot LEDs signal state and confirm each action landed ,  watch them before
you walk away:

| LED pattern | Meaning |
|-------------|---------|
| Mode-colour **sweep → solid** | Armed. |
| Reverse sweep → **all off** | Disarmed. |
| **Green triple-flash** | Action succeeded (a capture landed). |
| **Red triple-flash** | Action failed. |
| **Red double-flash** | Refused ,  mode needs `--opt-in`. |
| Brief mode-colour **wave** | A long operation started / finished. |

---

## `authtrace` ,  reader-side auth capture  *(Ultra only)*

CU acts as a **reader**. Each press runs one full HF14A authentication against a
real card and records every frame (REQA…ATS, auth, `nt`, `nr‖ar`, `at`).

```
standalone set-mode authtrace
standalone config authtrace --key-type A --block 4 --key FFFFFFFFFFFF --timeout 1000
standalone trigger                 # arm  (or: both-buttons long on device)
#  → walk to the card, press both-short per auth attempt (green flash = captured)
standalone disarm                  # or both-buttons long ,  saves results
standalone get-result              # pull the traces
```

**Config** (16-byte blob; the CLI sets it via the flags): `--key-type A|B`,
`--block <0-255>` (e.g. `4` = first non-MAD sector key A), `--key <12 hex>`
(candidate sector key), `--timeout <100-30000>` (per-session tag-poll, ms).
**Buttons:** BOTH_SHORT = run one auth session · BOTH_LONG = arm/disarm ·
BOTH_VLONG = discard all sessions.
No `--opt-in` needed (never writes target memory or slots).

## `emultrace` ,  card-side auth capture  *(Lite + Ultra)*

CU emulates a **card** and captures the exchange when a real reader
authenticates to it. A new REQA (7-bit `0x26`) arriving mid-capture marks a
session boundary; everything before it commits as one session. Only sessions
with enough trace data commit (isolated/back-to-back REQAs are filtered), and an
idle gap auto-commits the current one. Same wire format as `authtrace`; feeds
mfkey32v2.

```
standalone set-mode emul-trace
standalone trigger                 # arm ,  then present CU to the reader
#  captures happen automatically as the reader authenticates
standalone disarm
standalone get-result
```

**Config:** none. **Buttons:** BOTH_LONG = arm/disarm. Sessions commit
automatically (on the next REQA or after the idle timeout) ,  no short-press
capture. **Works on Lite and Ultra** (emulation only).

## `hf14a-tap-sniff` ,  passive tap  *(Ultra only)*

CU stays **silent** and listens: NFCT captures the reader→card downlink, RC522
captures the card→reader uplink from the shared coil. Never interferes with the
transaction.

```
standalone set-mode hf14a-tap-sniff
standalone config hf14a-tap-sniff --timeout 2000
standalone trigger                 # arm
#  → position CU by the live reader/card, press both-short to capture a session
standalone disarm
standalone get-result
```

**Config** (8-byte blob): `--timeout <100-30000>` (per-capture listen duration,
ms). **Buttons:** BOTH_SHORT = capture one session · BOTH_LONG = arm/disarm ·
BOTH_VLONG = discard all sessions. No `--opt-in` needed.

## `nfc-canary` ,  reader tripwire  *(Lite + Ultra)*

CU sits armed as a **bait card** and tells you when something probes it: a
reader's field appearing, a poll, an anticollision/SELECT, or anything deeper
(RATS, AUTH, READ, magic-card wake-ups). The **active emulation slot** is the
bait ,  use a slot with a real HF tag, otherwise readers rarely get past
`poll`. Nothing is written to any slot or card.

```
standalone set-mode nfc-canary
standalone config nfc-canary --min-level poll --cooldown 15 --ble both
standalone trigger                 # arm (or both-buttons long on device)
#  ... leave it somewhere ...
standalone disarm
standalone get-result              # table of probe windows
```

**Levels** (deepest the reader got): `field` < `poll` < `select` < `engage`.
A **window** is one burst of related activity: it opens on the first sign of
a reader and closes after `--cooldown` quiet seconds with the field gone (or
after 300 s, so a reader that never leaves still re-alerts). A reader pulsing
its field every second is therefore **one** window, not one alert per pulse.
Within a window you get at most one **alert** per level, and only for levels
>= `--min-level`.

**Config** (4-byte blob): `--min-level field|poll|select|engage` (default
`field`), `--cooldown 1-255` seconds (default 10), `--ble off|alert|end|both`
(default `both`).

**Buttons:** BOTH_SHORT = send a **TEST** BLE event (green = delivered, red =
no BLE client connected) ,  do this before walking away ·
BOTH_LONG = arm/disarm · BOTH_VLONG = clear the log.

**Notifications.** With a BLE client connected, alerts arrive as standard
data frames, cmd `7010`, 10-byte payload: `type(1=alert,2=end,3=test) level
cmd seq dur_s(u16) field_ons flags frames(u16)`, little-endian. `seq`
increments for every event even if nobody was connected, so a gap after
reconnecting means you missed some. The CLI helper `canary_event_decode()`
decodes a payload, and `canary_listen.py` (a small `bleak` script) prints them
live: `python canary_listen.py` (`--selftest` checks the decoder with no
hardware). Without a client, you still get a red LED flash on each alert and
the log; `set-mode --quiet-led` silences the flash.

**Command names.** The `cmd` byte is shown with a readable name in the
`get-result` table and in `canary_listen.py` (e.g. `50` = HLTA, `e0` = RATS,
`60` = AUTH-A / GET_VERSION). Only byte 0 of the *last* frame at the deepest
level is kept, so it is a hint, not a full decode; `6a` is Apple's Enhanced
Contactless Polling frame (iPhone Express Mode / Wallet readers); a byte with no
known meaning is shown as `unknown`. Names live in `software/script/canary_cmd.py`.

**Log.** Each reportable window is stored as a 16-byte record (oldest first,
up to 130, oldest evicted when full) and survives reboots. Flash writes are
rate-limited to one per 30 s plus one on disarm, so a power loss while armed
can lose up to 30 s of records. `start` in the table is seconds since that
arm; the `arm` column is a counter that distinguishes arms.

**Power.** The sleep timer is held off while armed, so the device stays awake.
Expect days, not weeks, on a battery. Unit tests for the logic:
`make -C firmware/application/src/standalone_modes/tests`.

## `relay` ,  two-device BLE relay  *(Ultra only, needs two CUs)*

A transparent Bluetooth relay between **two** ChameleonUltras. Roles are
assigned automatically by BLE MAC: the **lower MAC becomes CARD** (NFCT, faces
the reader), the **higher MAC becomes READER** (RC522, faces the card).

**Setup ,  do this on BOTH devices:**
```
standalone set-mode relay --opt-in    # relay requires --opt-in
standalone config relay --timeout 3000   # --timeout is reused as the WTX window, ms (500-10000)
standalone trigger                    # arm both; they pair over BLE automatically
```
On arm, each device starts BLE (`ble_relay_start`) and the two pair
automatically. On connect, each device flashes green (success) and then goes
**solid in its role colour**:

| LED (solid) | Role | Faces | Uses |
|-------------|------|-------|------|
| **Blue** | CARD | the real **reader** | NFCT emulation |
| **Green** | READER | the real **card** | RC522 |

So: put the **blue** device on the reader, the **green** device on the card. If
the LEDs aren't blue/green solid yet, the two haven't paired ,  keep them in BLE
range.

Then present the devices; frames relay automatically and are recorded.
```
standalone disarm                     # saves the session trace
standalone get-result
```
**Buttons:** BOTH_LONG = arm/disarm · **BOTH_VLONG = discard results and
restart pairing** (stops BLE, clears the trace, re-links from scratch ,  use it if
roles didn't assign or a device dropped). Relay has no short-press action; frames
relay automatically once paired.
**Config flag:** `--timeout <500-10000>` ,  reused as the WTX
(waiting-time-extension) window in ms, tuned for BLE round-trip latency. Relay
ignores `--block/--key-type/--key`.

### What relay can and cannot carry

Relay is transparent ,  it forwards frames byte-for-byte and lets the real reader
and real card do all the cryptography end to end. Whether a given card *can* be
relayed comes down to one thing: **timing**, and whether the protocol lets the
relay buy time to cover the Bluetooth round-trip (typically 35-80 ms).

**ISO 14443-4 cards (DESFire, EMV, most contactless payment/ID): relayed.**
These run T=CL, which has a **Waiting-Time-Extension (WTX)** S-block. On each
I-block the relay sends `S(WTX)` to the reader within the first response window;
the reader grants more time and re-opens the window; the relayed answer is sent
when it arrives. This is the `--timeout` (WTX ms) you configure. Encrypted
payloads (DESFire secure messaging, EMV) relay fine because they are opaque
I-block bytes ,  the endpoints handle the crypto.

**MIFARE Classic (Crypto1 authentication): NOT relayable, by protocol.** This is
a hard limit, not a missing feature, for two independent reasons:

1. **No WTX exists at this layer.** Crypto1 auth happens over ISO 14443-**3**,
   *before* T=CL ,  the reader never sent RATS, so it does not understand
   S-blocks. Sending `S(WTX)` to a Crypto1 reader is meaningless to it; it will
   treat the auth as failed and abort. WTX is a two-party T=CL agreement, and a
   Crypto1 reader is not a party to it. Adding WTX code changes nothing the
   reader would honour.

2. **The timing cannot be extended.** Crypto1 auth is three tightly-timed,
   back-to-back exchanges (`nt` → `nr‖ar` → `at`), each with a fixed
   frame-delay time of microseconds to a few milliseconds and **no legal way to
   ask the reader to wait**. Without WTX, the relay falls back to widening the
   NFCT frame-delay window to its ~77 ms hardware ceiling ,  and a BLE round-trip
   sits right at or beyond that for even one exchange, let alone three in a row.

(There is also a lower-level obstacle: the firmware strips the encrypted parity
bits from received frames before the relay handler sees them, and Crypto1's
parity is part of the cipher stream. But even if parity were preserved, reasons
1 and 2 above make Crypto1 relay impossible over BLE.)

This is not specific to the ChameleonUltra ,  MIFARE Classic auth is unrelayable
over any high-latency link; hardware relay rigs that manage it use sub-
millisecond wired or tuned-RF links, not Bluetooth.

## `slot-cycle` ,  rotate emulation slots  *(Lite + Ultra)*

Rotates the active emulation slot through a chosen set at a fixed interval. No
RF interaction, no writes ,  the safest mode.

```
standalone set-mode slot-cycle
standalone trigger                 # arm ,  rotation begins (uses firmware defaults)
```
Defaults are sensible (all slots, start at 0, 3000 ms dwell), so you usually
don't configure it. To override, pass the raw 6-byte config blob with `-d`
(the CLI has no named flags for slot-cycle):
```
#  bytes: version(01) slot_mask start_slot reserved(00) interval_ms(LE)
#  e.g. slots 0-3, start 0, 2000 ms = 01 0F 00 00 D0 07
standalone config slot-cycle -d 010F0000D007
```

Fields (6-byte blob): `version=01`, `slot_mask` (bit N = include slot N),
`start_slot` (must be set in the mask), `reserved=00`, `interval_ms` little-endian
(100-60000, default 3000). **Buttons:** BOTH_SHORT = advance now (resumes if
paused) · BOTH_LONG = arm/disarm · BOTH_VLONG = pause/resume.

## `read_replay` ,  clone a card into a slot and emulate it  *(Ultra only)*

CU acts as a **reader**, scans a card, loads it into the **active emulation
slot** as MIFARE Classic 1K, then emulates it ,  a one-press "read it, become
it". The anti-collision data (UID/ATQA/SAK/ATS) is always cloned; the data
blocks optionally. **Overwrites the active slot**, so switch to a scratch slot
first.

```
hw slot change -s 8                       # scratch slot ,  read_replay overwrites the active one
standalone set-mode read-replay --opt-in  # writes_slot ,  --opt-in required
standalone config read-replay --read-blocks on
standalone trigger                        # scan the card ,  it is now cloned and emulating
standalone get-result                     # uid / atqa / sak / sectors read/total
standalone disarm
```

**Config** (4-byte blob): `--read-blocks on|off` (default `on`). With it on, each
sector is read with the default key `FFFFFFFFFFFF`; sectors with other keys are
skipped and stay factory, and `sectors read/total` shows the shortfall. With it
off, only the card identity is cloned. **Buttons:** BOTH_SHORT = scan + clone one
card · BOTH_LONG = arm/disarm · BOTH_VLONG = discard results. **Requires
`--opt-in`** (writes the active slot). MIFARE Classic 1K source assumed.

## `autoclone` ,  auto-sensing clone  *(Ultra only)*

Two-press clone that **auto-detects the source frequency** and writes to the
matching card: an HF MIFARE Classic goes to a **gen1a "magic" card**, an LF
EM410x goes to a **T5577**. The first press reads the source and buffers it; the
second writes it to the blank card you then present.

```
standalone set-mode autoclone --opt-in       # writes_tag + writes_slot ,  --opt-in required
standalone config autoclone --also-slot on   # optional: also clone HF source into the active slot
#  place the SOURCE card (HF 14A or LF EM410x), then:
standalone trigger                           # 1st press: detect + read + buffer the source
#  swap to the matching blank (gen1a magic for HF, T5577 for LF), then:
standalone trigger                           # 2nd press: write the clone
standalone get-result                        # result / uid (HF) or EM id (LF) / blocks written
standalone disarm
```

**Detection:** the first press tries HF 14A first; if no HF card is present it
falls back to LF and reads an EM410x. Whichever it finds decides the target on
the second press. **HF:** source blocks are read with the default key
`FFFFFFFFFFFF`; sectors with other keys are skipped, so `blocks written` reflects
what was readable, and the target must be a gen1a magic card (block-0 writable).
**LF:** the 5-byte EM410x ID is written to a T5577 (`blocks` = 1 on success).
`--also-slot` applies to the HF path only.
**Config** (4-byte blob): `--also-slot on|off` (default `off`).
**Buttons:** BOTH_SHORT = read source, then (2nd) write target · BOTH_LONG =
arm/disarm · BOTH_VLONG = discard the buffered source and results. **Requires
`--opt-in`** (writes target memory, and the slot with `--also-slot`). The device
stays armed after a write, so trigger → trigger repeats for the next card.

## `dict-check` ,  key dictionary check  *(Ultra only)*

CU acts as a **reader** and tries a small built-in key dictionary against each
sector of a MIFARE Classic card (key A and key B), logging which keys work.
Read-only.

```
standalone set-mode dict-check            # read-only ,  no --opt-in
standalone config dict-check --sectors 16
standalone trigger                        # hold the card still ,  this takes several seconds
standalone get-result                     # per-sector: A <key|-->  B <key|-->
```

**Config** (4-byte blob): `--sectors 1-16` (default 16). The dictionary is a fixed
set of ~13 common keys (`FFFFFFFFFFFF`, `A0A1A2A3A4A5`, `D3F7D3F7D3F7`, …);
sectors whose key is not in it show `--`. Because a failed auth halts the card,
the mode **re-selects before every key attempt**, so a full 16-sector run takes
~10-20 s ,  keep the card on the antenna until it finishes. **Buttons:**
BOTH_SHORT = run one check · BOTH_LONG = arm/disarm · BOTH_VLONG = discard
results. No `--opt-in` needed (never writes).

---
## `--opt-in` and quiet flags

`set-mode` takes optional flags:
- `--opt-in` ,  sets `HOST_OPTED_IN`. **Required** for modes that write a target
  card or slot (`autoclone`, `read_replay`) or act on real targets (`relay`);
  arming without it gives a **red double-flash** and a "requires --opt-in"
  refusal.
- `--quiet-buzzer` / `--quiet-led` ,  silence the buzzer / LEDs for covert use.

## CLI reference (`standalone` group)

| Command | Purpose |
|---------|---------|
| `ls` | List available modes. |
| `status` | Current mode, armed state, stored-result count. |
| `set-mode <name> [--opt-in] [--quiet-buzzer] [--quiet-led]` | Select the active mode. |
| `config <name> [--block --key-type --key --timeout --min-level --cooldown --ble --read-blocks --also-slot --sectors \| -d <hex>]` | Write the mode's config. `authtrace` uses `--block/--key-type/--key/--timeout`; `hf14a-tap-sniff` uses `--timeout`; `relay` reuses `--timeout` as WTX; `nfc-canary` uses `--min-level/--cooldown/--ble`; `read-replay` uses `--read-blocks`; `autoclone` uses `--also-slot`; `dict-check` uses `--sectors`; `slot-cycle` uses raw `-d <hex>`. |
| `trigger` | Arm the active mode from the host. |
| `disarm` | Disarm and save results. |
| `get-result` | Retrieve stored session results. |
| `clear-result` | Discard stored results. |

CLI vs firmware names: the CLI uses hyphens (`emul-trace`, `hf14a-tap-sniff`,
`nfc-canary`, `slot-cycle`); `status` reports the firmware's underscored names
(`emul_trace`, `hf14a_tap_sniff`, `nfc_canary`, `slot_cycle`). They refer to the same modes.

## Result format

`authtrace`, `emultrace`, and `hf14a-tap-sniff` write the **same** record layout,
so host tooling parses them identically:

```
u8  session_num     0-based session index
u8  status          STATUS_HF_* result code
u16 trace_len       length of the trace bytes
u8  trace[trace_len]   verbatim wire trace (same format as CMD 2017)
```

Traces are Proxmark3-decoder-compatible ,  feed them to mfkey32v2 / mfkey64.
`relay` wraps the same trace bytes with per-session role, UID, ATQA/SAK, and
frame count.

`nfc-canary` uses its own fixed 16-byte record instead (one per closed window,
oldest first, little-endian):

```
u8  type=1   u8 level(0 field..3 engage)   u8 cmd   u8 arm_counter
u32 start_s  (seconds since that arm)
u16 dur_s    u16 field_ons   u16 frames   (all saturating)
u8  flags (1=forced close, 2=closed by disarm)   u8 reserved=0
```

`read-replay`, `autoclone`, and `dict-check` each use a small fixed record,
repeated, little-endian:

```
read-replay (13 B, one per clone):
  u8 uid_len   u8 uid[7]   u8 atqa[2]   u8 sak   u8 sectors_read   u8 sectors_total

autoclone  (11 B, one per attempt):
  u8 result (0 ok, 1 no source, 2 no target, 3 write fail)
  u8 uid_len   u8 uid[7]   u8 blocks_written   (+1 pad)

dict-check (15 B, one per sector):
  u8 sector   u8 found_a   u8 key_a[6]   u8 found_b   u8 key_b[6]
```

## Writing your own mode

`mode_template.c` is a fully commented reference for the
`standalone_mode_iface_t` contract; `slot_cycle` is the simplest real example.
Key rules: a mode that writes tag memory must set `writes_tag`, one that writes
slots must set `writes_slot` (the framework enforces the opt-in), and
`on_button`/`on_enter`/`on_exit` may block only briefly. See
`CONTRIBUTING STANDALONE.md` and `TESTING.md` here for the full contract.
