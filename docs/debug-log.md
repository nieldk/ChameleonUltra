# Persistent debug log

Records the firmware's `NRF_LOG` output to flash so it survives resets and
crashes, and can be read without a debug probe: over USB/BLE with `hw log`, or
as `LOG.TXT` on the `CHAMELEON` drive in UF2 mode.

## Use

```
hw log level debug     # off | error | warning | info | debug (0-4), persisted
hw log status          # level, bytes stored / pending / dropped, boot count
hw log dump -o log.txt # read the stored log (omit -o to print)
hw log clear
```

The default level is `off`: nothing is recorded and nothing is written to
flash. After a crash or odd behaviour, enter UF2 mode (hold B, plug USB) and
copy `LOG.TXT` off the drive. It only appears when the log holds data.

The RTT output is unchanged (still INFO and above); the level only controls
what goes to flash.

## How it works

```
NRF_LOG ──► logflash backend ──► 2 KiB RAM ring (.noinit, survives reset)
                                       │  word-sized chunks, async via SoftDevice
                                       ▼
                             flash ring 0xBF000-0xC7000 (8 x 4 KiB pages)
                                       │
                 hw log dump ◄─────────┴─────────► LOG.TXT in the bootloader
```

* Each flash page starts with `{magic "CLOG", seq}`. A page is filled
  completely before the next is erased, so only the newest page has an erased
  tail; the oldest page is the one after it, cyclically. The reader is shared
  by app and bootloader: `firmware/common/logring.h`.
* The RAM ring keeps the last unflushed lines across a soft reset (fault
  handler, watchdog, `NVIC_SystemReset`). The next boot writes them to flash
  and adds a `--- boot N rst=0x... recovered=B level=L ---` marker.
* Capacity is about 32 KB of text; the oldest page is erased when the ring
  wraps. Roughly 28-32 KB of the most recent output is always kept.
* A short tail is padded with newlines after 500 ms of silence so the last
  line reaches flash. The commanded reset, DFU entry, System OFF and the LF-field wake reset flush first; a bare `NVIC_SystemReset` (e.g. the 3.3 V regulator fix-up at boot) does not, but its RAM tail is recovered on the next boot.
* If the RAM ring fills before flash catches up (long blocking operations),
  new text is dropped and `[logflash: N bytes dropped]` is inserted.

## Layout

```
0x027000 - 0x0BF000   Application (linker limit, was 0xF3000)
0x0BF000 - 0x0C7000   Log ring
0x0C7000 - 0x0F3000   FDS (22 x 8 KiB virtual pages)
0x0F3000 - 0x0FE000   Bootloader
```

`logflash.c` has a compile-time check that the ring stays below FDS. The
application linker region now ends at the ring, so an image that grows into it
fails at link time instead of corrupting it.

## Limits

* No timestamps (`NRF_LOG_USES_TIMESTAMP` is off).
* Text is lost if power is cut before the RAM tail is written (battery pulled,
  brown-out). Soft resets and watchdog resets are covered.
* The UF2 drive only exists in bootloader mode. A crash is read by rebooting
  into UF2 mode afterwards; it cannot be streamed live.
* Compile-time log level is DEBUG and runtime filters are enabled so the level
  can change without a rebuild; this costs about 17 KB of flash.
* A UF2 application image larger than 0xBF000 would overwrite the ring.
