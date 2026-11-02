# Logic analyser (`hw logic`)

Records timestamped events from inside the device while other commands run,
and shows them as a timeline, a plot or a VCD file. No extra hardware.
Ultra only.

Three sources:

| Source | What it records |
|--------|-----------------|
| `hf_cs` | RC522 chip-select edges (one low pulse per register access) |
| `field_led` | Reader field LED, low = field on |
| `spi` | Every RC522 register read/write with its value |

## Use

Arm, run what you want to observe, stop:

```
hw mode -r
hw logic start spi hf_cs field_led --merge 15
hf 14a scan
hw logic stop --plot --vcd scan.vcd
```

`hw logic capture hf_cs field_led --ms 500 --plot` arms, waits and stops in
one command, for activity that does not need another command in between.

| Option | Meaning |
|--------|---------|
| `--rate 1/2/4/8/16` | Tick rate in MHz (default 1). The 32-bit stamp wraps after 2^32 ticks. |
| `--merge US` | Drop a chip-select pulse that falls within US µs of the previous rising edge. Turns a polling loop into one long low period. |
| `--plot`, `--ascii` | Stacked step plot (matplotlib) or ASCII plot. |
| `--vcd FILE` | Write VCD for PulseView/GTKWave. Edge channels only. |
| `--decode` | Print the timeline (always printed when `spi` is armed). |

`hw logic plot` and `hw logic decode` re-show the last capture.

## Output

Times are in ms from the first edge or SPI access. Example, ISO 14443-A
selection of a card with a 7-byte UID:

```
     t (ms)  event
     20.113  FIELD ON   14.610 ms
     28.120  CS  held low 0.643 ms (one access or merged polling)  [field on]
     28.239  SPI W  FIFODataReg <- 52  [1 B]
     28.251  SPI W  CommandReg = 0x0C (Transceive)
     28.288  SPI R  ComIrqReg = 0x04  x8 over 0.093 ms
     28.649  SPI R  ComIrqReg = 0x64
     28.716  SPI R  FIFODataReg -> 44 07 02  [3 B]
     28.850  SPI W  FIFODataReg <- 93 20  [2 B]
     29.688  SPI R  FIFODataReg -> 88 04 63 b7 58  [5 B]
```

* `SPI W/R reg = val` is a single access. `<-` / `->` is a FIFO burst; the first
  24 bytes are kept and the true length is shown.
* `xN over T` folds N identical consecutive reads (polling) into one line.
  The count is capped at 256 per line.
* `CommandReg` writes show the command name. Register names come from
  `rc522.h`.
* `CS burst` lines group chip-select pulses closer than `--gap` µs (default
  100). A single long low period is shown as "held low".
* The FIFO bytes are shown raw. They are not decoded as ISO 14443 frames.

## How it works

```
RC522_DOSEL/UNSEL, TAG_FIELD_LED_ON/OFF ──► logic_hook() ──► edge buffer
read/write_register_single/_buffer ───────► logic_spi()  ──► SPI buffer
                                   TIMER4 capture = timestamp
```

The firmware logs the signals where it drives them (`rc522.c`,
`hw_connect.h`, hooks in `firmware/common/logic_hook.h`). GPIOTE pin events
were tried first and did not fire on the output-driven pins tested, so the
named sources do not use them.

* Hooks compile in only with `CONFIG_LOGIC_HOOKS`, which the Ultra application
  Makefile defines. The bootloader and Lite builds get empty inline stubs.
* Idle cost is one flag check per access. While armed, each access calls a
  short logging function, so absolute timings are slightly stretched.
* TIMER4: CC0-3 stamp edge channels, CC5 stamps SPI entries. Ticks are 16 MHz
  >> prescaler.
* Edge buffer: 1024 events of 5 bytes (`u32 BE tick`, `level<<7 | channel`).
  Merged chip-select pulses are removed from it, not stored.
* SPI buffer: 4 KiB of packed entries. Single: `tick(4) hdr val rep`. Burst:
  `tick(4) hdr len data[min(len,24)]`. `hdr` = `read<<7 | burst<<6 | reg`.
  `rep` counts extra identical reads. A full buffer sets an overflow flag.
* At most 4 sources per capture; `spi` counts as one.

## Commands

| ID | Name | Payload |
|----|------|---------|
| 3037 | `LOGIC_ARM` | `prescaler(1) n(1) src(n) [merge_ticks(2)]`; src: 0 `hf_cs`, 1 `field_led`, 2 `spi`, `0x40 \| pin` raw |
| 3038 | `LOGIC_READ` | `offset(2) count(2)` events, max 96 per call |
| 3039 | `LOGIC_STOP` | none; returns overflow, event count, handler calls, 4 capture stamps |
| 3040 | `LOGIC_SPI_READ` | `offset(2) count(2)` bytes, max 480 per call; returns overflow, drops, total |

## Limits

* Chip select, the field LED and RC522 register traffic only. The SPI lines,
  the RF signal and the card side are not captured.
* Raw pins (`Px.yy`) use GPIOTE events and are experimental: no events were
  seen for `hf_cs`/`field_led` through that path.
* A pin is only observed where the firmware logs it; other nets are not
  reachable.
* 1024 edges / 4 KiB: long polling loops fill the edge buffer, use `--merge`.
  The SPI log folds repeated reads and normally holds a full `hf des info`.
* RAM cost is about 10 KiB (edge buffer 5 KiB, SPI buffer 4 KiB, read buffers
  about 1 KiB).
