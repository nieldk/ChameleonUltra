"""cli_hw_bl - update the bootloader from the running firmware (hw bl ...)."""

import argparse
import struct
import time
import zlib

from cli_core import ArgumentParserNoExit, DeviceRequiredUnit, hw

hw_bl = hw.subgroup("bl", "Bootloader update through the running firmware")

CHUNK = 256


BL_BASE = 0xF3000
BL_END = 0xFE000


def _read_hex(path):
    """Intel HEX -> bytes of [BL_BASE, BL_END); UICR records are skipped."""
    mem = {}
    upper = 0
    for line in open(path):
        line = line.strip()
        if not line.startswith(":"):
            continue
        raw = bytes.fromhex(line[1:])
        if sum(raw) & 0xFF:
            raise SystemExit("Bad Intel HEX checksum")
        n, addr, typ = raw[0], (raw[1] << 8) | raw[2], raw[3]
        if typ == 4:
            upper = ((raw[4] << 8) | raw[5]) << 16
        elif typ == 2:
            upper = ((raw[4] << 8) | raw[5]) << 4
        elif typ == 0:
            for i, b in enumerate(raw[4:4 + n]):
                a = upper + addr + i
                if BL_BASE <= a < BL_END:
                    mem[a] = b
    if not mem:
        raise SystemExit("No data in 0xF3000-0xFE000 in the hex file")
    size = max(mem) - BL_BASE + 1
    return bytes(mem.get(BL_BASE + i, 0xFF) for i in range(size))


def _load(path):
    if path.lower().endswith(".hex"):
        data = _read_hex(path)
    else:
        data = open(path, "rb").read()
    data += b"\xff" * (-len(data) % 4)
    return data


@hw_bl.command("push")
class HWBlPush(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = ("Write a bootloader image to 0xF3000 via the MBR, bypassing Secure DFU. "
                              "The device resets into the new bootloader.")
        parser.add_argument("file", help="bootloader .hex (UICR records are ignored) or raw .bin linked for 0xF3000")
        parser.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
        return parser

    def on_exec(self, args: argparse.Namespace):
        data = _load(args.file)
        crc = zlib.crc32(data) & 0xFFFFFFFF
        sp, rv = struct.unpack("<II", data[:8])
        print(f" - Image : {len(data):,} bytes, CRC32 0x{crc:08X}, SP 0x{sp:08X}, reset 0x{rv:08X}")
        if not args.yes:
            if input(" - Replace the bootloader now? [y/N] ").strip().lower() != "y":
                print(" - Aborted")
                return
        self.cmd.bl_stage_begin(len(data), crc)
        for off in range(0, len(data), CHUNK):
            self.cmd.bl_stage_data(off, data[off:off + CHUNK])
            print(f"\r - Staging {min(off + CHUNK, len(data)) * 100 // len(data)}%", end="", flush=True)
        print()
        self.cmd.bl_stage_commit()
        print(" - Verified. The device copies the image and resets; reconnect in a few seconds.")
        time.sleep(0.2)
