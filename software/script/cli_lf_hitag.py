"""cli_lf_hitag - Hitag2 password-mode read (lf hitag2 ...).

Reads an NXP/Philips Hitag2 tag in password mode: START_AUTH, UID, send a
reader password, and if the tag accepts it, dump every other page. Crypto
mode is not implemented -- a crypto-mode tag will not answer the plaintext
password frame and this will report no tag found, same as a password
mismatch.

Protocol constants (command codes, frame layout, password-mode sequence)
come from RfidResearchGroup/proxmark3's armsrc/hitag2.c and
include/protocols.h -- the working reference implementation PM3's "Aurora"
release ported from RFIDler -- not from a datasheet guess.
"""

import argparse

from cli_core import (
    ArgumentParserNoExit, ReaderRequiredUnit, SlotIndexArgsAndGoUnit,
    lf, CG, CY, CR, C0,
)
from chameleon_enum import SlotNumber, TagSpecificType

lf_hitag2 = lf.subgroup("hitag2", "Hitag2 password-mode commands (125 kHz)")

PAGE_NAMES = {
    0: "UID",
    1: "Password (reader's)",
    2: "Key, high bytes (crypto mode only)",
    3: "Config + tag password",
}


def _parse_hex4(s, label):
    s = s.strip()
    if len(s) != 8:
        raise ValueError(f"{label} must be 8 hex digits (4 bytes)")
    return bytes.fromhex(s)


@lf_hitag2.command("econfig")
class LFHitag2Econfig(SlotIndexArgsAndGoUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = (
            "Set or show the Hitag2 tag emulated by a slot (password mode only). "
            "With no options, shows the slot's current 8 pages. Any option given "
            "overlays onto the slot's current pages (read first) and writes the "
            "result back -- so setting --pwd alone, for instance, does not erase "
            "the UID or other pages already configured."
        )
        self.add_slot_args(p)
        p.add_argument("--uid", metavar="HEX8", help="page 0: UID, 4 bytes")
        p.add_argument("--pwd", metavar="HEX8", help="page 1: reader's password, 4 bytes")
        p.add_argument("--config", metavar="HEX2", help="page 3 byte 0: config (bit 3 set = crypto mode, unsupported for emulation)")
        p.add_argument("--tag-pwd", metavar="HEX6", help="page 3 bytes 1-3: tag's own password, 3 bytes")
        p.add_argument("--page", nargs=2, action="append", metavar=("N", "HEX8"),
                       help="set page N (0-7) to raw 4-byte hex; repeatable")
        return p

    def on_exec(self, args: argparse.Namespace):
        slotinfo = self.cmd.get_slot_info()
        selected = SlotNumber.from_fw(self.cmd.get_active_slot())
        lf_tag_type = TagSpecificType(slotinfo[selected - 1]["lf"])
        any_set = any([args.uid, args.pwd, args.config, args.tag_pwd, args.page])

        if not any_set:
            if lf_tag_type != TagSpecificType.HITAG2:
                print(f"{CR}Slot type is not Hitag2 -- nothing to show.{C0}")
                return
            pages = self.cmd.hitag2_get_emu_id()
            self._print_pages(pages)
            return

        if lf_tag_type != TagSpecificType.HITAG2:
            print(f"{CY}WARNING{C0}: Slot type not set to Hitag2.")
            pages = [bytearray(4) for _ in range(8)]
        else:
            pages = [bytearray(p) for p in self.cmd.hitag2_get_emu_id()]

        try:
            if args.uid:
                pages[0] = bytearray(_parse_hex4(args.uid, "--uid"))
            if args.pwd:
                pages[1] = bytearray(_parse_hex4(args.pwd, "--pwd"))
            if args.config or args.tag_pwd:
                config_byte = bytes.fromhex(args.config)[0] if args.config else pages[3][0]
                tag_pwd = bytes.fromhex(args.tag_pwd) if args.tag_pwd else bytes(pages[3][1:4])
                if len(tag_pwd) != 3:
                    raise ValueError("--tag-pwd must be 6 hex digits (3 bytes)")
                pages[3] = bytearray([config_byte]) + bytearray(tag_pwd)
            if args.page:
                for n_str, hex8 in args.page:
                    n = int(n_str)
                    if not (0 <= n <= 7):
                        raise ValueError("--page N must be 0-7")
                    pages[n] = bytearray(_parse_hex4(hex8, "--page"))
        except ValueError as e:
            print(f" {CR}{e}{C0}")
            return

        flat = b"".join(bytes(p) for p in pages)
        self.cmd.hitag2_set_emu_id(flat)
        print(f" {CG}Set Hitag2 emulated tag data success.{C0}")
        self._print_pages(pages)

    def _print_pages(self, pages):
        for i, page in enumerate(pages):
            label = PAGE_NAMES.get(i, "User")
            print(f"    {i}  {bytes(page).hex(' ').upper()}  {CG}{label}{C0}")


@lf_hitag2.command("read")
class LFHitag2Read(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = (
            "Read a Hitag2 tag in password mode. Sends START_AUTH, reads the "
            "UID, sends -k as the reader password, and on acceptance reads "
            "the remaining 7 pages."
        )
        p.add_argument("-k", "--pwd", required=True, metavar="HEX8",
                       help="4-byte reader password, 8 hex digits (e.g. 55667788)")
        return p

    def on_exec(self, args: argparse.Namespace):
        try:
            pwd = _parse_hex4(args.pwd, "--pwd")
        except ValueError as e:
            print(f" {CR}{e}{C0}")
            return

        status, pages = self.cmd.hitag2_read(pwd)
        if pages is None:
            print(f" {CR}No answer, or password rejected (wrong key, or tag is in crypto mode).{C0}")
            return

        for i, page in enumerate(pages):
            label = PAGE_NAMES.get(i, "User")
            print(f"    {i}  {page.hex(' ').upper()}  {CG}{label}{C0}")
