# Standalone Modes

Standalone modes let the ChameleonUltra work **without a host** ,  no laptop, no
app, just the device and its buttons. You configure a mode over the CLI
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
3. **Arm** it: `standalone trigger` (from the CLI), or the button bound to
   `STANDALONE_TOGGLE` (see below).
4. **Walk away.** Press the `STANDALONE_ACTION` button to run one capture/action.
5. **Disarm** to save results: `standalone disarm`, or the `STANDALONE_TOGGLE` button.
6. **Retrieve**: `standalone get-result` (over USB/BLE).

`standalone status` shows the current mode, armed state, and stored-result
count. `standalone ls` lists the modes. `standalone clear-result` discards
stored results.

## Buttons

Standalone is driven by single-button presses. Bind each function to a button
with `hw settings btnpress`; short and long press of A and B are set separately:

| Function | Use |
|----------|-----|
| `STANDALONE_TOGGLE` | arm / disarm |
| `STANDALONE_ACTION` | run the armed mode (one capture / advance slot) |
| `STANDALONE_CLEAR`  | discard stored results for this mode |
| `STANDALONE_DISARM` | disarm only |

The standalone functions are not bound by default. The same actions are
available from the host: `standalone trigger` (arms if disarmed, then runs the
action), `standalone disarm`, `standalone clear-result`.

Example: keep the slot buttons for slot cycling and put the standalone actions
on the long presses:

```
hw settings btnpress -a -l -f STANDALONE_TOGGLE   # A long: arm / disarm
hw settings btnpress -b -l -f STANDALONE_ACTION   # B long: run
hw settings store
```

The functions do nothing while no standalone mode is selected. A button bound to
one of them no longer does its previous job (cycling slots, battery, clone), so
rebind it when you stop using standalone modes.

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
standalone trigger                 # arm  (or: STANDALONE_TOGGLE button)
#  → walk to the card, press the ACTION button per auth attempt (green flash = captured)
standalone disarm                  # or STANDALONE_TOGGLE button ,  saves results
standalone get-result              # pull the traces
```

**Config** (16-byte blob; the CLI sets it via the flags): `--key-type A|B`,
`--block <0-255>` (e.g. `4` = first non-MAD sector key A), `--key <12 hex>`
(candidate sector key), `--timeout <100-30000>` (per-session tag-poll, ms).
**Buttons:** ACTION = run one auth session · TOGGLE = arm/disarm ·
CLEAR = discard all sessions.
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

**Config:** none. **Buttons:** TOGGLE = arm/disarm. Sessions commit
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
#  → position CU by the live reader/card, press the ACTION button to capture a session
standalone disarm
standalone get-result
```

**Config** (8-byte blob): `--timeout <100-30000>` (per-capture listen duration,
ms). **Buttons:** ACTION = capture one session · TOGGLE = arm/disarm ·
CLEAR = discard all sessions. No `--opt-in` needed.

## `nfc-canary` ,  reader tripwire  *(Lite + Ultra)*

CU sits armed as a **bait card** and tells you when something probes it: a
reader's field appearing, a poll, an anticollision/SELECT, or anything deeper
(RATS, AUTH, READ, magic-card wake-ups). The **active emulation slot** is the
bait ,  use a slot with a real HF tag, otherwise readers rarely get past
`poll`. Nothing is written to any slot or card.

```
standalone set-mode nfc-canary
standalone config nfc-canary --min-level poll --cooldown 15 --ble both
standalone trigger                 # arm (or STANDALONE_TOGGLE button)
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

**Buttons:** ACTION = send a **TEST** BLE event (green = delivered, red =
no BLE client connected) ,  do this before walking away ·
TOGGLE = arm/disarm · CLEAR = clear the log.

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
**Buttons:** TOGGLE = arm/disarm · **CLEAR = discard results and
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
(100-60000, default 3000). **Buttons:** ACTION = advance now (resumes if
paused) · TOGGLE = arm/disarm · CLEAR = pause/resume.

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
off, only the card identity is cloned. **Buttons:** ACTION = scan + clone one
card · TOGGLE = arm/disarm · CLEAR = discard results. **Requires
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
**Buttons:** ACTION = read source, then (2nd) write target · TOGGLE =
arm/disarm · CLEAR = discard the buffered source and results. **Requires
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
ACTION = run one check · TOGGLE = arm/disarm · CLEAR = discard
results. No `--opt-in` needed (never writes).

## `gdb_gateway` ,  GDB memory/flash gateway over USB or BLE  *(Lite + Ultra)*

The odd one out: instead of running host-less, this mode turns the device's
active link ,  USB-CDC or BLE NUS, whichever is up ,  into a **GDB server**.
While armed, that link speaks the GDB Remote Serial Protocol instead of the
CLI, so `arm-none-eabi-gdb` can `target remote` the device, read/dump memory,
program flash, and (by default) set **breakpoints** and **step** ,  all with
no SWD probe and no wires. Replies go out the same link the request came in
on, picked the same way the normal CLI protocol auto-selects USB over BLE
(`app_cmd.c`'s `auto_response_data`).

Execution control is monitor-mode debug (Cortex-M DebugMonitor + FPB/DWT):
**up to 6 hardware breakpoints, 4 watchpoints**, continue and register access.
Its limits are inherent: you **cannot break inside the SoftDevice or
high-priority ISRs** (the monitor sits below them so the link and radio
keep running while you are stopped), it is **not a true halt** (higher-priority
interrupts keep executing at a breakpoint), and it only works with no SWD
debugger attached. There is **no async interrupt** (gdb Ctrl-C): stopping would
have to come from the USB/BLE RSP path, which reenters the USB/SoftDevice
stack, so you **stop a running target by hitting a breakpoint**, not by
interrupting. **Stepping is software single-step:** hardware single-step is
not advertised (resuming for one instruction lets a USB/SoftDevice interrupt
escape the step and drop the link), so gdb steps with temporary breakpoints +
continue over the same breakpoint path ,  `step`/`next`/`stepi` work, using
1-2 FPB slots while stepping. Build-time flag `GDB_GATEWAY_EXEC` (default `1`)
gates it; set `GDB_GATEWAY_EXEC=0` for a smaller memory/flash-only gateway.

**Transfer speed:** over USB the CDC link is bulk (the `hw status` baud is
cosmetic), so bulk reads are bounded by RSP round-trips, not line rate. Over
BLE each round-trip is also capped by the negotiated ATT MTU (typically far
below `GDB_PACKET_SIZE`), so BLE is noticeably slower for `dump`/`load` ,  fine
for register/memory pokes, painful for a full-chip dump. `GDB_GATEWAY_PKT`
(default `0x200`) sets the advertised PacketSize and the derived RX/TX buffers;
raise it (e.g. `0x800`) to move more per USB round-trip and cut a full-chip
`dump`/`find` several-fold, for a few KB more RAM ,  it does not help the BLE
MTU ceiling. Reads also feed the watchdog, so a long scan won't reset the
device.

gdb itself has no BLE transport, so the BLE path needs a local bridge
(`software/script/gdb_ble_bridge.py`) that opens a TCP port and pumps raw
bytes to/from the device over `chameleon_ble`; gdb then targets that TCP port
exactly as it would a serial port.

```
standalone set-mode gdb-gateway --opt-in   # can program flash ,  --opt-in required
#  ARM: press the TOGGLE button (green LED), or `standalone trigger` / the
#  host's STANDALONE_TRIGGER command -- app_standalone_trigger() arms in
#  software if disarmed, no button needed. Either way the active link is
#  now GDB RSP, so exit the CLI (or, over BLE, disconnect it) first.
arm-none-eabi-gdb -ex 'target remote /dev/ttyACM0'      # USB
#  or, over BLE:
python3 software/script/gdb_ble_bridge.py
arm-none-eabi-gdb -ex 'target remote localhost:3333'    # BLE, via the bridge
#  (gdb) dump memory flash.bin 0x0 0x100000     # full-chip dump
#  (gdb) restore blob.bin binary 0x000c7000     # write a non-running region
#  DISARM: TOGGLE button again, or `standalone disarm` / STANDALONE_DISARM
```

**Reads are unrestricted:** dump any flash/RAM/peripheral address (the whole
1 MB flash, RAM at `0x20000000`, UICR at `0x10001000`). **Writes are confined to
`0xC7000-0x100000`** (FDS, bootloader, settings/param pages); any erase or write
below that ,  the MBR, SoftDevice, or the **running application** ,  is refused
with gdb error `E02`, so a `load` of the app over itself fails cleanly instead of
crashing. Use UF2/DFU to replace the app. Writes go through the SoftDevice and
are still subject to ACL, so an ACL-locked region returns `E01`. The app floor
can be lowered at runtime with `monitor unlock-app` (see below) for targeted
patches; MBR and SoftDevice stay protected.

**Config:** none. **Buttons:** TOGGLE = arm/disarm; no short-press or
very-long action. Arm/disarm also works without a button: `standalone trigger`/
`standalone disarm` (STANDALONE_TRIGGER/STANDALONE_DISARM), which is what the
web terminal's `hw gdb arm`/`hw gdb disarm` use. **Produces no results**
(`get-result` is unused). **Requires `--opt-in`** (it can program flash).
Works on Lite and Ultra ,  no reader hardware is touched. Detaching gdb (or
the web terminal's `hw gdb exit`) leaves the mode armed so you can reconnect;
disarm with the TOGGLE button or `hw gdb disarm`. For big transfers, `set
remotetimeout 60` in gdb.

**In-browser client:** `phreakbyte.html`'s terminal tab has `hw gdb` ,  a small
RSP client built straight into the page (`terminal.js`), so BLE users can
arm, read/write memory, erase/write/flash-done, and run `monitor` commands
with no arm-none-eabi-gdb and no bridge script. It has no breakpoints or
stepping; for those, use real gdb via USB or `gdb_ble_bridge.py` above.

**Monitor commands** (gdb `monitor <cmd>`, served over the same link):
- `monitor help` ,  list the commands.
- `monitor info` ,  flash write window (shows `[app unlocked]` when lowered), and
  (with `GDB_GATEWAY_EXEC`) exec state, usable hardware-breakpoint count,
  watchpoint count, halted/running.
- `monitor unlock-app` ,  lower the write floor to the app base `0x27000`, so
  writes into the app region are allowed. **Danger:** erasing or writing a page
  the running app, SoftDevice or this monitor executes from hardfaults (flash is
  single-bank, the CPU stalls during NVMC); a full app `load` from the running
  app cannot work ,  use UF2/DFU. Targeted patches to idle pages only. Re-armed
  to the default on every arm.
- `monitor lock` ,  restore the default `0xC7000` write floor.
- `monitor reset` ,  reboot the device. The gdb link drops (the device is the
  target), coming back up disarmed. Over BLE, `gdb_ble_bridge.py` reconnects
  automatically on the next gdb session; gdb itself still needs reattaching.

---
## `u2f` ,  FIDO U2F (CTAP1) authenticator over NFC  *(Lite + Ultra)*

Emulates an ISO-14443-4 token answering the FIDO U2F applet (AID
`A0000006472F0001`). A reader does `SELECT` → `REGISTER` / `AUTHENTICATE`; the
CU generates a credential and signs assertions. Reuses the tested T=CL engine
(`nfc_14a_4`), so the NFC tap is the whole interaction ,  no buttons, no USB.

**Stateless key wrapping ,  no per-credential storage.** A credential's private
key is derived on the fly, not stored:
```
priv = HMAC-SHA256(mk, 0x01 | appId | nonce)
kh   = nonce | HMAC-SHA256(mk, 0x02 | appId | nonce)
```
Only a 32-byte master key and a 4-byte global counter live in FDS (file
`0x1020`). The handle's MAC binds it to its origin, so a handle cannot be
replayed on another site. Crypto is self-contained SHA-256/HMAC plus micro-ecc
(uECC) for P-256; the NFC tap is the user-presence gesture (always asserted).
Oversized `REGISTER` replies are returned with ISO-7816 `61xx`/GET-RESPONSE
chaining. Keys sit in internal flash, **not a secure element** ,  research use.

**Platform support:** CTAP1/U2F only. Works where the host still does the U2F
NFC path ,  **Android** (Chrome) and **PC/SC** readers. **iOS Safari does not**:
its NFC WebAuthn requires CTAP2/FIDO2 and silently ignores a U2F-only applet.
For iPhone you need the CTAP2 layer (not built here).

**Build:** off by default. Set `STANDALONE_U2F=1` and vendor micro-ecc into
`src/crypto/micro-ecc/` (whole repo ,  `uECC.c` pulls in its `.h`/`.inc`).
No source edits are needed for attestation ,  provision it at runtime:
```
firmware/tools/gen_u2f_attestation.sh          # make a P-256 key + cert
hw u2f set-attestation -k att.key -c att.crt   # stored in FDS, survives reboot
```
Until a key/cert are provisioned, `REGISTER` output is not a usable credential.

```
standalone set-mode u2f        # no --opt-in needed; writes no tag/slot
#  press the TOGGLE button to ARM (blue LED); present the CU to an NFC reader
#  Android: Chrome -> webauthn.io -> register a security key -> tap
#  PC/SC:   python3 firmware/tools/u2f_nfc_test.py   (full register+auth verify)
```

**Config:** none. **Buttons:** TOGGLE = arm/disarm. **Produces no results.**
Works on Lite and Ultra (NFCT only, no reader hardware). First boot generates
the master key; it persists, so credentials survive reboots.

---
## `usb-net` ,  USB Ethernet, CLI over TCP  *(Lite + Ultra, TinyUSB build)*

Adds a USB Ethernet interface (CDC-ECM or RNDIS) next to the serial port. The
host gets `192.168.16.2` from a built-in DHCP server, the device is
`192.168.16.1` (also `chameleon.local` over mDNS), and TCP port `18888` carries
the normal framed CLI protocol:

```
standalone config usb-net --auto on     # once: on whenever USB is attached
hw connect -p usbnet                    # = tcp:192.168.16.1:18888
```

It is a transport, not an exclusive mode. Two ways to turn it on:
- **`--auto on`** (stored): the interface is up from boot whenever the cable is
  attached, beside whatever mode is armed (authtrace, canary, ...). Nothing to arm.
- **Arming the `usb-net` mode** (`standalone set-mode usb-net`, `standalone trigger`):
  on for the session, off again on disarm unless `--auto` is on.

Turning it on or off, or changing the class, re-enumerates the USB device (about
1 s) and drops an open serial session.

**Build:** off by default. It replaces the nRF SDK USB stack with TinyUSB and
lwIP (pinned, fetched by `firmware/fetch_usbnet_deps.sh` into `firmware/deps/`):

```
./fetch_usbnet_deps.sh
STANDALONE_USB_NET=1 ./build.sh
```

The CDC serial port keeps working with the same VID/PID. While a TCP client is
connected it owns the command link and replies go to it; a new connection
replaces the old one. BLE is unaffected.

**Config** (`standalone config usb-net ...`, applied immediately):
- `--auto on|off`: always-on transport (default off).
- `--class ecm|rndis|default`: host class. ECM for Linux and macOS, RNDIS for
  Windows. `default` is the build default (`USBNET_CLASS`, ecm unless set).
- `--port N`: TCP port (default 18888).
- `--gateway on|off`: DHCP offers the CU, 192.168.16.1, as default router
  (default off). Some hosts (NetworkManager, for one) prefer the USB adapter's
  default route over their real one and lose internet; the CU does not route.

**Costs and limits:** about 12 KB of RAM on Ultra (check `free before stack` in
the linker map before combining with other modes; the link fails with "region
RAM overflowed" when it does not fit) and about 45 KB of flash (about 50 KB stay free on Ultra). The MTU is 1514
(`USBNET_MTU` to change; RNDIS needs full size on Windows). One client at a
time, no authentication: the interface only exists on the USB cable.
**Buttons:** TOGGLE = arm/disarm. **Produces no results.** No `--opt-in` needed.

**Status.** `standalone status` shows the USB profile, class, MTU, host
enumeration, mDNS name, DHCP lease, TCP client and byte/frame counters. When
another mode is selected the same lines appear as `net_*`:

```
 status:
   usb         ethernet on=auto
   class       ecm mtu=1514
   host_usb    configured
   name        chameleon.local
   addr        192.168.16.1:18888 gateway=none
   lease       192.168.16.2 02:43:55:12:34:56
   tcp_client  connected accepted=1 rx=412 tx=1180 bytes
   frames      rx 96 tx 71
   errors      rx_drops 0 write_stalls 0
```

**Reaching the CU from other machines.** The DHCP reply carries no DNS, and no
gateway unless `--gateway on`, so the CU has no route beyond 192.168.16.0/24 and
cannot share the host's internet. To let another machine use the CU, relay port
18888 on the host (`ssh -L` or `socat`), or DNAT it. The MASQUERADE rule is
required, because the CU has no default route:

```
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING  -i <lan> -s <laptop-ip> -p tcp --dport 18888 -j DNAT --to-destination 192.168.16.1:18888
iptables -t nat -A POSTROUTING -o <usb-if> -d 192.168.16.1 -p tcp --dport 18888 -j MASQUERADE
```

If the FORWARD chain drops by default (Docker, ufw), also allow it:

```
iptables -A FORWARD -i <lan> -o <usb-if> -s <laptop-ip> -d 192.168.16.1 -p tcp --dport 18888 -j ACCEPT
iptables -A FORWARD -i <usb-if> -o <lan> -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

Then run `hw connect -p tcp:<host-ip>:18888` on the other machine. Only one TCP
client is accepted; a new connection replaces the current one. The port has no
authentication, so restrict the source with `-s`.

---
## `zigbee` ,  passive 802.15.4 receive  *(Lite + Ultra, needs `STANDALONE_ZIGBEE=1`)*

Receive only, nothing is transmitted. One channel, or hopping over 11-26. The SoftDevice
owns the radio, so RX runs in chained 50 ms timeslots; frames between slots are missed and
BLE shares the radio time (`blocked`/`canceled` count refused or revoked slots).

```
standalone config zigbee --channel 15      # 11..26, default 11
standalone config zigbee --channel 0 --dwell 500   # hop 11..26, 500 ms per channel
standalone set-mode zigbee
standalone trigger                         # or the TOGGLE button
standalone status
standalone zigbee scan -t 60               # networks per channel/PAN (beacons, traffic)
standalone zigbee devices -t 60            # sources per PAN: addresses, tx count, raw LQI
standalone zigbee dump -t 10               # each frame decoded + hex; also auto-tries known
                                            # keys (NWK fallback + APS join-key capture, see below)
standalone zigbee dump -k <32 hex>         # also decrypt NWK payloads with your network key
```

If BLE activity leaves no gap for a slot, the SoftDevice cancels or blocks the request (`canceled`/`blocked`
rise). Requests time out after 200 ms and are re-issued from the 20 ms tick. The slot length is halved on each cancel or block down to 5 ms (`slot_us` in `status`) and grown again after
every 16 granted slots. A NORMAL-priority timeslot yields to connection events.

`ed` is the largest raw energy-detect sample (EDSAMPLE, not converted) taken at the end of a slot on
that channel; `framestart` counts frames whose length field was seen. If `ed` stays 0 everywhere while
Wi-Fi or Zigbee is active, the receive path is not working.

`ed ok`/`timeout` count finished and unfinished energy-detect samples; `radio_state` is NRF_RADIO->STATE just
before the slot ends (2 = RXIDLE, 3 = RX, 0 = disabled).

`rxen` shows whether the receiver ramped up after RXEN (`ready`/`timeout`), the radio state right after
the wait and the RADIO POWER register as found at slot start.

`sig` counts radio-callback signals (`radio`, `timer0`), session idle events and the last
`sd_radio_request` return code (0 = ok); a chain that stops shows up as `slots` not rising.

`status` shows the channel, slot counters (`us` = current slot length), frames with a good/bad FCS,
a count per frame type, log fill, and while hopping the frame count and the largest raw
energy-detect sample (`ed`, EDSAMPLE, not converted) per channel 11-26. The last frame's length
and raw LQI byte are not converted to dBm or the IEEE range and not temperature-compensated
(nRF52840 errata 153). Length excludes the FCS, which the radio does not store.

If BLE activity leaves no gap for a slot, the SoftDevice cancels or blocks the request. Requests
time out after 200 ms and are re-issued from the 20 ms tick; the slot length is halved on each
cancel or block (down to 5 ms) and grown after every 16 granted slots.

`diag` is for bring-up: `cb=radio/timer0/idle` slot signals, `rxen=ok/timeout` receiver ramp-up,
`ed=ok/timeout` energy-detect samples, `st=` radio state after ramp-up / before slot end
(2 RXIDLE, 3 RX), `pw` RADIO POWER as found at slot start, `rc` last request result, `fs`
frames whose length field was seen. The status reply is built in a 512-byte buffer, so keep
this output short.

Frames are appended to a 2 KiB RAM log (`channel, lqi, len, MPDU`) and drained by the
host commands above, which parse MAC, beacon and NWK headers in Python (`zb_parse.py`).
If the host does not drain, the log fills and later frames are counted as `overflow`.
Only cleartext headers are decoded:
secured payloads stay opaque, beacons with GTS/pending-address fields are shown as
unparsed. The log is freed only by `standalone clear-result` (or `standalone zigbee clear-result`), same as other modes; it is not freed just because `get-result`/`scan`/`devices`/`dump` drained it, so a long capture can still fill the 2 KiB log and start counting `overflow` even after everything so far was read. `standalone zigbee get-result` (the generic result reader) decodes each record the same way `dump` does (channel, LQI, MAC/beacon/NWK header), without the `-k` decryption step.

The log also persists to flash on disarm (and immediately on an explicit clear), and reloads on the next arm or on a disarmed `get-result`/`ls` -- results survive a disarm or reset, same as other modes (nfc-canary, authtrace, relay, ...). A power loss while armed can still lose whatever was logged since the last flush. The persisted buffer is capped at 2 KiB (the framework's 2080-byte limit per mode), so the log is smaller than it would otherwise need to be; clear it between long sessions if you hit `overflow`.

`dump` tries three well-known public keys automatically as NWK-key guesses: the Zigbee
HA/ZLL default Trust Center link key (`ZigBeeAlliance09`, many consumer devices use it
instead of a provisioned key), the ZLL master key, and the ZLL certification link key
(the last two leaked/published for touchlink commissioning, far less likely to hit).
Pass `-k <32 hex>` for your own network's key, or `--no-default-key` to skip all three.
`dump -k`/the built-in fallbacks decrypt NWK payloads (AES-CCM*, 32-bit MIC, nonce from
the aux header's source IEEE address) and report MIC ok/fail. Important caveat: none of
the three built-in keys are *meant* to be a network's ongoing NWK key -- they are
one-time key-*transport* keys used only while a device joins. A MIC-ok hit from one of
them here means the device non-compliantly reused its TC link key as its NWK key; MIC
FAIL (the common case) just means this network provisions a real random key, which is
the normal, secure outcome. The CCM code itself was checked against the RFC 3610 vector
and the ciphertext of a published Zigbee NWK example, but the MIC of that example did
not reproduce, so the MIC check is unverified against real Zigbee traffic beyond what's
captured here. While hopping, a network is only seen when it transmits during a dwell.

### Recovering a network's real key: APS Transport Key capture

The correct way to get a network's actual (random) NWK key is to catch it being handed
to a device during (re-)join: the Trust Center sends it inside an APS "Transport Key"
command, itself encrypted under the TC link key (normally `ZigBeeAlliance09`) rather
than the NWK key -- so it's readable even though the NWK layer around it is still
unsecured (the joining device has no NWK key yet). `dump` watches for this automatically:
for every captured frame whose NWK layer is unsecured data, it tries to parse an APS
command frame underneath and decrypt it with each of `APS_JOIN_KEYS` (same three keys
as above, used here in their *correct* role as TC link keys). A hit prints as:

```
      *** APS Transport Key [ZigBeeAlliance09 (HA default TC link key), MIC ok] type=standard network key ***
          network key: <32 hex>  seq=<n> dst=<ieee> src=<ieee>
```

**Caveat, stated plainly:** the Transport-Key command's field layout (key type, 16-byte
key, sequence number, then 8-byte destination/source IEEE addresses, in that order) is
reconstructed from the ZigBee specification's Transport-Key command definition and
cross-checked against Microchip's/Silicon Labs' `APS_TransportKeyReq_t`/key-type struct
docs and Wireshark's `packet-zbee-aps.c` field names -- but the dissector's C source
itself could not be fetched (gitea.osmocom.org blocks automated fetches; GitHub's raw
source isn't reachable from here) to confirm the byte order line-by-line. The CCM*
mechanics (nonce/AAD construction, offsets into the APS aux header) were verified with a
synthetic hand-built frame and decrypt correctly; what's **not** yet verified is that
this layout matches a real captured join. Only the Standard Network Key case (key type
`0x01`) is decoded; other key types (TC link key, application link key, ...) are
reported by type but not parsed further. Treat the first real hit as something to
sanity-check (does the recovered key, fed back into `dump -k`, actually decrypt that
network's regular traffic with MIC ok?) rather than as unconditionally trusted.

Radio setup and buffer layout follow the nRF52840 Product Specification (RADIO, IEEE 802.15.4
operation). Not tested on hardware at the time of writing.

## `--opt-in` and quiet flags

`set-mode` takes optional flags:
- `--opt-in` ,  sets `HOST_OPTED_IN`. **Required** for modes that write a target
  card or slot (`autoclone`, `read_replay`), act on real targets (`relay`), or
  can program flash (`gdb_gateway`); arming without it gives a **red
  double-flash** and a "requires --opt-in" refusal.
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
`nfc-canary`, `slot-cycle`, `gdb-gateway`, `usb-net`, `zigbee`); `status` reports the firmware's
underscored names (`emul_trace`, `hf14a_tap_sniff`, `nfc_canary`, `slot_cycle`,
`gdb_gateway`, `usb_net`). They refer to the same modes.

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
