"""cli_lf_hitag - Hitag2 read, password mode and known-key crypto mode (lf hitag2 ...).

Reads an NXP/Philips Hitag2 tag: `read` for password mode (START_AUTH, UID,
send a reader password, and if accepted, dump every other page), `cread`
for crypto mode with an already-known key (START_AUTH, UID, send a Nr/Ar
challenge built from the key, and if accepted, dump every other page under
the resulting keystream). Neither does key recovery -- against the wrong
mode or an unknown key, both just get no answer, same as a wrong password.

Protocol constants (command codes, frame layout, password-mode and
crypto-mode sequence) come from RfidResearchGroup/proxmark3's
armsrc/hitag2.c, common/hitag2/hitag2_crypto.c and include/protocols.h --
the working reference implementation PM3's "Aurora" release ported from
RFIDler -- not from a datasheet guess.
"""

import argparse

from cli_core import (
    ArgumentParserNoExit, ReaderRequiredUnit, SlotIndexArgsAndGoUnit,
    lf, CG, CY, CR, C0,
)
from chameleon_enum import SlotNumber, TagSpecificType

lf_hitag2 = lf.subgroup("hitag2", "Hitag2 commands (125 kHz) -- password mode, and known-key crypto mode for emulation")

PAGE_NAMES = {
    0: "UID",
    1: "Password (password mode) / key bytes 2-5 (crypto mode)",
    2: "Key bytes 0-1 in bytes 2-3, rest reserved (crypto mode only)",
    3: "Config + tag password",
}


def _parse_hex4(s, label):
    s = s.strip()
    if len(s) != 8:
        raise ValueError(f"{label} must be 8 hex digits (4 bytes)")
    return bytes.fromhex(s)


def _parse_hex6(s, label):
    s = s.strip()
    if len(s) != 12:
        raise ValueError(f"{label} must be 12 hex digits (6 bytes)")
    return bytes.fromhex(s)


@lf_hitag2.command("econfig")
class LFHitag2Econfig(SlotIndexArgsAndGoUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = (
            "Set or show the Hitag2 tag emulated by a slot: password mode, or "
            "known-key crypto mode (page 3 byte 0 bit 3 set -- no key recovery, "
            "and no writes in either mode). With no options, shows the slot's "
            "current 8 pages. Any option given overlays onto the slot's current "
            "pages (read first) and writes the result back -- so setting --pwd "
            "alone, for instance, does not erase the UID or other pages already "
            "configured."
        )
        self.add_slot_args(p)
        p.add_argument("--uid", metavar="HEX8", help="page 0: UID, 4 bytes")
        p.add_argument("--pwd", metavar="HEX8",
                       help="page 1: reader's password (password mode) or key bytes 2-5 (crypto mode)")
        p.add_argument("--config", metavar="HEX2", help="page 3 byte 0: config (bit 3 set = crypto mode)")
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


@lf_hitag2.command("cread")
class LFHitag2CryptoRead(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = (
            "Read a Hitag2 tag in crypto mode with a known key (no key "
            "recovery). Sends START_AUTH, reads the UID, sends a Nr/Ar "
            "challenge built from -k, and on acceptance reads the "
            "remaining pages under the resulting keystream."
        )
        p.add_argument("-k", "--key", required=True, metavar="HEX12",
                       help="6-byte crypto-mode key, 12 hex digits "
                            "(same byte order as econfig's --pwd/--page 1-2)")
        return p

    def on_exec(self, args: argparse.Namespace):
        try:
            key = _parse_hex6(args.key, "--key")
        except ValueError as e:
            print(f" {CR}{e}{C0}")
            return

        status, pages = self.cmd.hitag2_crypto_read(key)
        if pages is None:
            print(f" {CR}No answer, or challenge rejected (wrong key, or tag is in password mode).{C0}")
            return

        for i, page in enumerate(pages):
            label = PAGE_NAMES.get(i, "User")
            print(f"    {i}  {page.hex(' ').upper()}  {CG}{label}{C0}")


@lf_hitag2.command("raw")
class LFHitag2RawCapture(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = (
            "Debug: send START_AUTH and print the raw GPIOTE edge intervals "
            "the device captured, in Tc units (1 Tc = 8us), instead of "
            "decoding them. Use this to see what the comparator actually "
            "produces on real hardware when `read`/`cread` report no "
            "answer."
        )
        p.add_argument("-b", "--both-edges", action="store_true",
                        help="dump the same both-edge, leveled runs read/cread's own "
                             "decode consumes, instead of the original rising-only "
                             "dump -- use this to see the actual decode input")
        return p

    def on_exec(self, args: argparse.Namespace):
        rx_arm_gap_us, hfclk_running, intervals = self.cmd.hitag2_raw_capture(args.both_edges)
        print(f" RX armed {rx_arm_gap_us} us after the last TX edge "
              f"(Hitag2's reply window is ~1600-1650 us after that edge).")
        if not hfclk_running:
            print(f" {CR}HFCLK was on the RC oscillator, not the crystal, "
                  f"during this TX burst -- bit timing was off nominal "
                  f"16 MHz (request_timeslot() does not guarantee the "
                  f"crystal).{C0}")
        if not intervals:
            print(f" {CR}No edges captured at all -- comparator saw nothing "
                  f"(check the tag is actually in the field).{C0}")
            return
        print(f" Captured {len(intervals)} interval(s), Tc units:")
        if args.both_edges:
            # Each byte: bit 7 = load level, bits 6..0 = length (clamped to
            # 0x7F) -- see hitag2_reader_raw_capture()'s both_edges doc.
            # Half-bit buckets (16/24/32 Tc), half of the rising-only ones,
            # since every run here is at most one bit wide.
            buckets = ((16, "0.5T "), (24, "0.75T"), (32, "1T   "))
            for i, b in enumerate(intervals):
                level = "H" if (b & 0x80) else "L"
                length = b & 0x7F
                tag = "?"
                for center, name in buckets:
                    if abs(length - center) <= 4:
                        tag = name
                        break
                print(f"    [{i:2}]  {level}  {length:3}  {tag}")
        else:
            buckets = ((32, "1T "), (48, "1.5T"), (64, "2T "))
            for i, v in enumerate(intervals):
                tag = "?"
                for center, name in buckets:
                    if abs(v - center) <= 8:
                        tag = name
                        break
                print(f"    [{i:2}]  {v:3}  {tag}")
