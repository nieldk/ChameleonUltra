"""cli_hw_bl - update the bootloader from the running firmware (hw bl ...)."""

import argparse
import struct
import time
import zlib

from cli_core import ArgumentParserNoExit, DeviceRequiredUnit, hw
from chameleon_enum import Status

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
        parser.add_argument("--raw", action="store_true",
                            help="install WITHOUT the MBR: NVMC-write 0xF3000 directly and convert UICR "
                                 "(NRFFW/REGOUT0). For a device whose bootloader was never MBR-registered, "
                                 "where normal push fails with 'MBR param page not set' / 'address not 0xF3000'. "
                                 "No journaling - a power loss mid-write bricks the device (SWD-only recovery).")
        return parser

    def on_exec(self, args: argparse.Namespace):
        data = _load(args.file)
        crc = zlib.crc32(data) & 0xFFFFFFFF
        sp, rv = struct.unpack("<II", data[:8])
        print(f" - Image : {len(data):,} bytes, CRC32 0x{crc:08X}, SP 0x{sp:08X}, reset 0x{rv:08X}")
        if args.raw:
            print(" - RAW install: bypasses the MBR, rewrites UICR, and has no power-loss safety net.")
        if not args.yes:
            prompt = " - RAW-replace the bootloader now? [y/N] " if args.raw else " - Replace the bootloader now? [y/N] "
            if input(prompt).strip().lower() != "y":
                print(" - Aborted")
                return
        self.cmd.bl_stage_begin(len(data), crc)
        for off in range(0, len(data), CHUNK):
            self.cmd.bl_stage_data(off, data[off:off + CHUNK])
            print(f"\r - Staging {min(off + CHUNK, len(data)) * 100 // len(data)}%", end="", flush=True)
        print()
        if args.raw:
            self.cmd.bl_stage_commit_raw()
            print(" - Verified. The device writes 0xF3000 via NVMC, converts UICR and resets; reconnect in a few seconds.")
        else:
            self.cmd.bl_stage_commit()
            print(" - Verified. The device copies the image and resets; reconnect in a few seconds.")
        time.sleep(0.2)


@hw_bl.command("info")
class HWBlInfo(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = ("Read-only bootloader-forwarding snapshot: where the MBR boots from "
                              "(UICR NRFFW / MBR flash words), REGOUT0, and the vector table at 0xF3000. "
                              "Does not write anything.")
        return parser

    def on_exec(self, args: argparse.Namespace):
        resp = self.cmd.bl_info()
        if resp.status != Status.SUCCESS or not resp.data or len(resp.data) < 28:
            print(" - bl info not supported by this app build (reflash the app)")
            return
        nrffw0, nrffw1, mbr_bl, mbr_pp, regout0, sp, rst = struct.unpack("<7I", resp.data[:28])

        def a(x):
            return "blank" if x == 0xFFFFFFFF else f"0x{x:08X}"

        vout = {0: "1.8V", 1: "2.1V", 2: "2.4V", 3: "2.7V", 4: "3.0V", 5: "3.3V", 7: "default 1.8V"}
        print(f" UICR NRFFW[0] bootloader addr : {a(nrffw0)}")
        print(f" UICR NRFFW[1] MBR param page  : {a(nrffw1)}")
        print(f" MBR flash 0xFF8 (bl addr)     : {a(mbr_bl)}")
        print(f" MBR flash 0xFFC (param page)  : {a(mbr_pp)}")
        rv = 7 if regout0 == 0xFFFFFFFF else (regout0 & 7)
        print(f" UICR REGOUT0                  : {a(regout0)}  (VOUT {vout.get(rv, rv)})")
        print(f" Vector @0xF3000  SP / reset   : 0x{sp:08X} / 0x{rst:08X}")
        boot = nrffw0 if nrffw0 != 0xFFFFFFFF else (mbr_bl if mbr_bl != 0xFFFFFFFF else None)
        if boot is None:
            print(" - MBR has no bootloader address: it boots the SoftDevice/app directly,")
            print("   so a bootloader at 0xF3000 is never entered via MBR forwarding.")
        else:
            print(f" - MBR boots the bootloader at {a(boot)}"
                  + ("  (matches 0xF3000)" if boot == 0xF3000 else "  (NOT 0xF3000)"))

        BL = 0x000F3000
        if len(resp.data) >= 7 * 4 + 8 * 3 * 4:
            acl = struct.unpack("<24I", resp.data[28:28 + 96])
            print(" ACL regions (flash write/erase lock):")
            any_region = False
            blocks_bl = False
            for i in range(8):
                addr, size, perm = acl[i * 3], acl[i * 3 + 1], acl[i * 3 + 2]
                if size == 0:
                    continue
                any_region = True
                w = "WRITE-BLOCKED" if (perm >> 1) & 1 else "write-ok"
                r = "read-blocked" if (perm >> 2) & 1 else "read-ok"
                covers = addr <= BL < addr + size
                flag = "  <-- covers 0xF3000" if covers else ""
                if covers and (perm >> 1) & 1:
                    blocks_bl = True
                print(f"   [{i}] 0x{addr:08X} +0x{size:X}  {w}, {r}{flag}")
            if not any_region:
                print("   (none set)")
            if blocks_bl:
                print(" - 0xF3000 is ACL write-locked: no app-side write (raw NVMC or COPY_BL)")
                print("   can change the bootloader. ACL is re-applied every boot and clears")
                print("   only on reset, so this needs SWD or the bootloader's own update path.")


@hw.command("version")
class HWVersion(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = ("Show or set the Secure-DFU version counters in the settings page. "
                              "These gate DFU updates (an image must be >= the stored counter); "
                              "set them at/below an image to let DFU accept it. hw bl push ignores them.")
        parser.add_argument("-a", "--app", type=int, help="set stored application version")
        parser.add_argument("-b", "--bl", type=int, help="set stored bootloader version")
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.app is None and args.bl is None:
            app_v, bl_v = self.cmd.get_dfu_settings_version()
            print(f" - Settings application version : {app_v}")
            print(f" - Settings bootloader version  : {bl_v}")
            return
        mask = (1 if args.app is not None else 0) | (2 if args.bl is not None else 0)
        app_v, bl_v = self.cmd.set_dfu_settings_version(mask, args.app or 0, args.bl or 0)
        print(f" - Updated settings versions: application {app_v}, bootloader {bl_v}")
