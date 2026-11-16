# Interactive LF engine & Hitag2 emulation (`lf interactive`, `lf hitag2`)

A general-purpose framework for emulating a reader-interrogated LF tag (one
that must decode a reader's command and answer it in time), plus Hitag2
password mode as its first protocol. Earlier LF emulation types (FDX-B,
EM410x, ...) only ever transmit; Hitag2 is the first that has to listen and
respond, which this engine exists for.

## Use

```
lf hitag2 econfig --uid 11223344 --pwd AABBCCDD      # set a slot's Hitag2 pages
lf hitag2 econfig                                     # show them
```

Put the slot in emulation mode and present it to a reader. If it never
answers, the usual first checks:

```
lf interactive trace                 # commands seen, decoded bits, what was sent back
lf interactive tuning --thr-pct 85   # live-adjust the gap detector, no reflash
lf interactive env arm               # then present the tag, then:
lf interactive env read              # raw ADC envelope, to see gap depth directly
```

`lf interactive clear` resets the trace and its counters.

## How it works

`lf_ia_engine.c` owns the hardware: SAADC on `LF_RSSI_PIN` (field envelope,
100 kHz), TIMER3 (1 MHz time base), PWM0 (125 kHz, drives `LF_MOD` for the
tag's own modulation). A gap detector (`det_sample()`) tracks a drifting
field-on level and calls a gap whenever the smoothed signal dips below
`thr_pct` percent of it. `lf_ia_codec.c`'s `lf_ia_decode_intervals()` turns
the gap-to-gap timings of one command into bits by splitting them into a
short and a long class; `lf_ia_hitag2.c` is the Hitag2 module on top --
5/10/32-bit reader commands, Manchester answers at RF/32.

Protocol files (`firmware/application/src/rfid/nfctag/lf/interactive/`):
`lf_ia.h` (module interface), `lf_ia_codec.[ch]` (interval decode/encode, run
encode/decode -- no hardware state, also used by a host test), `lf_ia_engine.c`
(SAADC/TIMER/PWM, the state machine), `lf_ia_hitag2.[ch]` (the protocol),
`lf_ia_trace.[ch]` (retained exchange trace), `lf_ia_debug.h` (tuning,
counters, envelope ring).

### Debugging tools

* **Trace** (`lf interactive trace`): one record per command -- gaps, decoded
  bits, decode status, what the module answered, when it went out versus when
  it was due. Kept in retained RAM (`.noinit`), survives sleep and a USB
  reconnect, so a run at a reader on battery can be read back afterwards.
* **Tuning** (`lf interactive tuning`): live-adjustable `settle_us`,
  `lost_us`, `min_gap_us`, `thr_pct`, `tx_lead_us`, etc., so a timing
  hypothesis can be tested without reflashing. Lost on reset.
* **Envelope capture** (`lf interactive env arm` / `env read`): the raw
  smoothed ADC samples the gap detector itself sees, 10 µs apart. For seeing
  gap depth directly when the trace shows nothing (gaps too shallow to clear
  `thr_pct`, or the field never settling).

By default (`LF_IA_DEBUG=0`, see below) the trace keeps only the latest
record and the envelope ring is a token size -- both commands still work,
just with ~no history. Build with `LF_IA_DEBUG=1` for the full ring (32
records, 10.24 ms of envelope) when actually debugging a new protocol or a
new board's RX circuit; see `firmware/application/Makefile`.

## Lessons from bringing Hitag2 up on real hardware

Two bugs took real reader captures to find, and are worth knowing before
porting a second protocol onto this engine:

* **`thr_pct` is board-specific.** The engine's default (50, a gap dips below
  half the tracked field-on level) assumes nothing about the RX circuit. On
  this board's `LF_RSSI` coupling, a real reader's gaps only reach ~72-79% of
  the field-on level -- confirmed via `env read` -- so the default never saw a
  single gap. Fixed by raising the default to 85
  (`lf_ia_engine.c`'s `m_tuning` initializer). Worth re-checking (`env arm`
  then `env read` against a real reader) on a new board revision.
* **A same-bit-value frame has nothing to self-calibrate against.**
  `lf_ia_decode_intervals()` deliberately classifies a frame's bits by its
  own observed min/max span, so it tracks a reader's own clock rather than a
  fixed threshold -- but that only works if both bit values appear at least
  once. A 32-bit password of all zero bits (a real, protocol-valid frame)
  left no second class to compare against, so it always read as
  `LF_IA_DECODE_ONE_CLASS`. Fixed with an optional fixed `t0_us`/`t1_us`
  fallback on `lf_ia_decode_cfg_t`, used only when the self-calibrated check
  already failed; Hitag2 sets it to the protocol's documented 20/30
  carrier-period bit timing. A future protocol with its own fixed bit timing
  should set the same fields.

## RAM layout

The debug ring above, and the retained-RAM mechanism it uses, live in
`.noinit` -- a fixed-size region reserved at the top of RAM (`noinit.ld`),
entirely separate from the application's own RAM region that
`STANDALONE_*` builds can overflow. Sizing one does not free RAM for the
other; see `firmware/common/noinit.ld`'s comment for the current split and
headroom (checked against the map file, not assumed).
