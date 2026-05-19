#!/usr/bin/env python3
"""
gen_embedded_bl.py — turn a bootloader.hex into a C header containing
just the bootloader-region bytes as a const array, ready to be embedded
in the application.

Reads Intel HEX directly and extracts only the bytes that fall inside
[0xF3000, 0xFE000) — that way we don't pick up UICR (which sits at
0x10001000 and would inflate a raw `objcopy -O binary` to ~255 MB) or
any other out-of-region sections.

Supports both ihex extended-address mechanisms:
  - Type 02: Extended Segment Address.  base = segment << 4
  - Type 04: Extended Linear Address.    base = linear << 16
Both are valid; whichever record was last seen sets the current base.

Usage:
    ./gen_embedded_bl.py objects/bootloader.hex application/src/embedded_bootloader.h
"""
import os
import sys
import zlib


BL_REGION_START = 0x000F3000
BL_REGION_END   = 0x000FE000   # exclusive
BL_REGION_BYTES = BL_REGION_END - BL_REGION_START


def parse_ihex_region(path, start, end):
    """Read Intel HEX, return (bytes, populated_length)."""
    region = bytearray(b'\xff' * (end - start))
    populated_end = 0
    addr_base = 0   # current extended-address base; updated by type 02/04 records

    with open(path, 'r') as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line.startswith(':'):
                continue
            try:
                n = int(line[1:3], 16)
                addr_lo = int(line[3:7], 16)
                rectype = int(line[7:9], 16)
                payload_hex = line[9:9 + 2 * n]
                payload = bytes(
                    int(payload_hex[i:i + 2], 16)
                    for i in range(0, len(payload_hex), 2)
                )
            except ValueError as e:
                raise ValueError(f"malformed ihex at line {lineno}: {e}")

            if rectype == 0x00:  # data
                full_addr = addr_base + addr_lo
                for i, b in enumerate(payload):
                    target = full_addr + i
                    if start <= target < end:
                        offset = target - start
                        region[offset] = b
                        if offset + 1 > populated_end:
                            populated_end = offset + 1
            elif rectype == 0x01:  # EOF
                break
            elif rectype == 0x02:  # Extended Segment Address: base = seg << 4
                if len(payload) != 2:
                    raise ValueError(f"bad ESA record at line {lineno}")
                seg = (payload[0] << 8) | payload[1]
                addr_base = seg << 4
            elif rectype == 0x04:  # Extended Linear Address: base = linear << 16
                if len(payload) != 2:
                    raise ValueError(f"bad ELA record at line {lineno}")
                linear = (payload[0] << 8) | payload[1]
                addr_base = linear << 16
            elif rectype in (0x03, 0x05):
                # Start Segment / Start Linear Address: entry-point hints,
                # not data placement — ignore.
                pass

    return region, populated_end


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)

    in_path, out_path = sys.argv[1], sys.argv[2]

    if not in_path.endswith('.hex'):
        print(
            f"warning: {in_path} doesn't end in .hex — pass the Intel HEX, "
            "not a raw bin (objcopy on .out includes UICR and produces a "
            "255MB file)",
            file=sys.stderr,
        )

    region, populated_end = parse_ihex_region(in_path, BL_REGION_START, BL_REGION_END)

    if populated_end == 0:
        print(
            f"error: no bytes in {in_path} fell inside "
            f"[0x{BL_REGION_START:X}, 0x{BL_REGION_END:X}) — "
            "is this really the bootloader hex?",
            file=sys.stderr,
        )
        sys.exit(1)

    # The bootloader almost certainly doesn't fill the entire 44 KB region.
    # Embed only up to the last actual byte from the source. Trailing 0xFF
    # bytes inside the region are just empty flash; the runtime erase
    # clears those pages to 0xFF anyway.
    data = bytes(region[:populated_end])
    crc = zlib.crc32(data) & 0xFFFFFFFF

    with open(out_path, "w") as f:
        f.write(f"/* Auto-generated from {os.path.basename(in_path)} — do not edit by hand. */\n")
        f.write(f"/* BL region [0x{BL_REGION_START:08X}, 0x{BL_REGION_END:08X}) */\n")
        f.write("#ifndef EMBEDDED_BOOTLOADER_H\n")
        f.write("#define EMBEDDED_BOOTLOADER_H\n\n")
        f.write("#include <stdint.h>\n\n")
        f.write(f"#define EMBEDDED_BOOTLOADER_BIN_SIZE  {len(data)}u\n")
        f.write(f"#define EMBEDDED_BOOTLOADER_BIN_CRC32 0x{crc:08X}u\n\n")
        f.write("static const uint8_t EMBEDDED_BOOTLOADER_BIN[EMBEDDED_BOOTLOADER_BIN_SIZE]\n")
        f.write("    __attribute__((aligned(4))) = {\n")
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_bytes = ", ".join(f"0x{b:02x}" for b in chunk)
            f.write(f"    {hex_bytes},\n")
        f.write("};\n\n")
        f.write("#endif /* EMBEDDED_BOOTLOADER_H */\n")

    print(f"Wrote {out_path}: {len(data)} bytes, CRC32 = 0x{crc:08X}")
    print(f"BL region usage: {len(data)} / {BL_REGION_BYTES} bytes "
          f"({100.0 * len(data) / BL_REGION_BYTES:.1f}%)")


if __name__ == "__main__":
    main()
