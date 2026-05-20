#!/usr/bin/env python3
"""
uf2conv.py — convert .hex or .bin to .uf2 for ChameleonUltra UF2 bootloader.

Minimal reimplementation of the public microsoft/uf2 conversion logic,
adapted for the nRF52840 family ID (0x1B57745F).

Usage:
    uf2conv.py firmware.hex -o firmware.uf2
    uf2conv.py firmware.bin --base 0x27000 -o firmware.uf2

MIT License.
"""
import argparse
import struct
import sys
from pathlib import Path

UF2_MAGIC_START0 = 0x0A324655
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END    = 0x0AB16F30
UF2_FLAG_FAMILYID = 0x00002000
FAMILY_NRF52840  = 0x1B57745F
PAYLOAD_SIZE     = 256


def parse_hex(text):
    """Parse Intel HEX into a dict {addr: byte}. Tiny, no segment/start handling
    beyond extended linear address records (type 04)."""
    mem = {}
    upper = 0
    for ln in text.splitlines():
        if not ln.startswith(":"):
            continue
        raw = bytes.fromhex(ln[1:])
        count = raw[0]
        addr  = (raw[1] << 8) | raw[2]
        rtype = raw[3]
        data  = raw[4:4 + count]

        if rtype == 0x00:
            for i, b in enumerate(data):
                mem[upper + addr + i] = b
        elif rtype == 0x02:
            upper = ((data[0] << 8) | data[1]) << 4
        elif rtype == 0x04:
            upper = ((data[0] << 8) | data[1]) << 16
        elif rtype == 0x01:
            break

    return mem


def memory_to_chunks(mem):
    """Group bytes into 256 B aligned chunks indexed by base address."""
    if not mem:
        return []
    addrs = sorted(mem)
    chunks = {}
    for a in addrs:
        base = a & ~(PAYLOAD_SIZE - 1)
        if base not in chunks:
            chunks[base] = bytearray(PAYLOAD_SIZE)
        chunks[base][a - base] = mem[a]
    return sorted(chunks.items())


def build_uf2(chunks, family=FAMILY_NRF52840):
    total = len(chunks)
    blocks = []
    for i, (addr, payload) in enumerate(chunks):
        block = bytearray(512)
        struct.pack_into("<IIIIIIII", block, 0,
                         UF2_MAGIC_START0, UF2_MAGIC_START1,
                         UF2_FLAG_FAMILYID,
                         addr, PAYLOAD_SIZE, i, total, family)
        block[32:32 + PAYLOAD_SIZE] = payload
        struct.pack_into("<I", block, 508, UF2_MAGIC_END)
        blocks.append(bytes(block))
    return b"".join(blocks)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="input .hex or .bin")
    ap.add_argument("-o", "--output", help="output .uf2 (default: stdout)")
    ap.add_argument("--base", type=lambda x: int(x, 0), default=0x27000,
                    help="base address for .bin input (default 0x27000)")
    ap.add_argument("--family", type=lambda x: int(x, 0), default=FAMILY_NRF52840)
    args = ap.parse_args()

    src = Path(args.input).read_bytes()
    if args.input.lower().endswith(".hex"):
        mem = parse_hex(src.decode())
    else:
        mem = {args.base + i: b for i, b in enumerate(src)}

    chunks = memory_to_chunks(mem)
    uf2 = build_uf2(chunks, family=args.family)

    if args.output:
        Path(args.output).write_bytes(uf2)
        print(f"wrote {len(chunks)} blocks → {args.output}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(uf2)


if __name__ == "__main__":
    main()
