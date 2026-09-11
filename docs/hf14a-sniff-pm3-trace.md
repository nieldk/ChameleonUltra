# HF-14A sniff → Proxmark3 `.trace`

Captures from the HF-14A sniffer can be exported as Proxmark3 `.trace` files and
opened in the PM3 client for protocol decoding and analysis. This works for
both the interactive `hf 14a sniff` command and the standalone
`hf14a_tap_sniff` mode, because both produce the same record stream.

Conversion is host-side, in `software/script/pm3_trace.py`. No firmware change
is needed.

## Capture record format (device side)

`hf14a_sniff_finalize()` emits, per frame:

```
[hdr_be16][data...]
    hdr  : big-endian u16.  bit15 = direction (0 reader->card, 1 card->reader),
           low 15 bits = frame length in bits.
    data : ceil(bits/8) bytes.
```

Reader-side frames are carried 9-bits-per-byte (8 data + 1 parity), so real
parity is recovered. Card-side frames are byte-granular with no captured
parity. Capture timestamps are stripped during finalize, so only frame order
survives.

## Interactive capture

```
[usb] chameleon --> hf 14a sniff --tap -o capture.trace
```

`-o/--trace FILE` writes the capture as a PM3 `.trace` alongside the normal
on-screen decode. Works with or without `--tap`.

## Standalone `hf14a_tap_sniff` mode

Passive tap sniffer that runs without a host attached; sessions are stored to
flash and pulled later.

Button chord while armed:

| Chord | Action |
|-------|--------|
| BOTH_SHORT | run one capture at the configured timeout |
| BOTH_LONG | arm / disarm |
| BOTH_VLONG | discard all stored sessions |

Up to 8 sessions, 256 trace bytes each. Config blob (8 bytes): `version`,
reserved, `timeout_ms` (u16, 100–30000, default 5000), reserved. Results
persist across reboot.

Drain the stored sessions and write one `.trace` per session with the `--pm3`
option of `standalone get-result`:

```
[usb] chameleon --> standalone get-result --pm3 run1
  run1-00.trace  (3 frame(s), status 0x00)
  run1-02.trace  (2 frame(s), status 0x00)
```

Files are named `<prefix>-NN.trace` by session number. `--pm3` only applies
when the active mode is `hf14a_tap_sniff`.

Under the hood this calls `pm3_trace.export_tap_sniff_sessions_to_pm3(raw,
prefix)`, which re-parses the drained buffer with the parity-aware parser
(keeping real reader-side parity, unlike the default `get-result` decode which
strips it). The stored session buffer layout is `u8 session_num, u8 status,
u16 trace_len (LE), trace[trace_len]` per session;
`pm3_trace.iter_tap_sniff_sessions()` walks it.

## Standalone conversion without the client

`pm3_trace.py` runs on its own against a dumped buffer:

```bash
# a single sniff record stream:
python pm3_trace.py capture.bin -o capture.trace

# a full standalone result buffer (multiple sessions):
python pm3_trace.py sessions.bin --sessions --prefix run1
```

## Loading in Proxmark3

```
[usb] pm3 --> trace load -f capture.trace
[usb] pm3 --> trace list -t 14a
```

## `.trace` record format (Proxmark3)

Verified against `RfidResearchGroup/proxmark3` `include/pm3_cmd.h`
(`tracelog_hdr_t`) and `client/src/cmdtrace.c`. Records are concatenated with
no file header:

```
u32  timestamp                     (little-endian)
u16  duration                      (little-endian)
u16  data_len:15 | isResponse<<15  (little-endian)
u8   data[data_len]
u8   parity[ceil(data_len/8)]      bit (7-(j&7)) of byte j>>3 = parity of data byte j
```

`isResponse` = 1 for card→reader. Parity is odd (ISO14443-A): reader-side frames
use the captured parity; card-side frames get computed odd parity.

## Caveats

* **Timing is synthetic.** The firmware strips capture timestamps, so the
  converter fabricates monotonic timestamps. Frame order and protocol decode
  are correct, but PM3's timing column is not real time. Real timing would
  require a firmware change to preserve the µs timestamp through
  `hf14a_sniff_finalize()` and widen the stored record.
* **Card-side parity is computed, not captured.** A genuine card-side parity
  error will not be surfaced (the RC522 path doesn't capture sub-byte/parity).
  Reader-side parity is real.
* **Short frames** (REQA/WUPA, 7 bits) are stored as `data_len = 1`; PM3
  annotates them by value.
