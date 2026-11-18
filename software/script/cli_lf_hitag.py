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
import time

from chameleon_com import NotOpenException, CMDInvalidException

from cli_core import (
    ArgumentParserNoExit, DeviceRequiredUnit, ReaderRequiredUnit, SlotIndexArgsAndGoUnit,
    lf, CG, CY, CR, CC, C0,
)
from chameleon_enum import SlotNumber, TagSpecificType

lf_hitag2 = lf.subgroup("hitag2", "Hitag2 commands (125 kHz) -- password mode, and known-key crypto mode for emulation")

PAGE_NAMES = {
    0: "UID",
    1: "Password (password mode) / key bytes 2-5 (crypto mode)",
    2: "Key bytes 0-1 in bytes 2-3, rest reserved (crypto mode only)",
    3: "Config + tag password",
}


# Tag information and page table as printed by RfidResearchGroup/proxmark3's
# `lf hitag read --ht2` (client/src/cmdlfhitag.c: getHitagTypeStr,
# print_hitag2_configuration, print_hitag2_blocks).
_HT2_TYPES = {
    1: "PCF 7936", 2: "PCF 7946", 3: "PCF 7947", 4: "PCF 7942/44", 5: "PCF 7943",
    6: "PCF 7941", 7: "PCF 7952", 8: "PCF 7961", 9: "PCF 7945",
}
_HT2_INFO = ["UID", "Pwd", "Key/Pwd", "Config", "User", "User", "User", "User"]


def _ht2_breakdown(bs, start, n, msg, color=""):
    end = C0 if color else ""
    return f"  {'.' * start}{color}{bs[start:start + n]}{end}{'.' * (8 - start - n)} - {color}{msg}{end}"


def _ht2_lock(page, config):
    if page == 0:
        return f"{CR}L {C0}"
    if page == 1:
        return f"{CR}L {C0}" if config & 0x80 else f"{CG}RW{C0}"
    if page == 2:
        if config & 0x80:
            return f"{CR}L {C0}" if config & 0x08 else f"{CR}R {C0}"
        return f"{CG}RW{C0}"
    if page == 3:
        return f"{CR}R {C0}" if config & 0x40 else f"{CG}RW{C0}"
    if page in (4, 5):
        return f"{CR}R {C0}" if config & 0x20 else f"{CG}RW{C0}"
    return f"{CR}R {C0}" if config & 0x10 else f"{CG}RW{C0}"


def _print_tag(pages):
    pages = [bytes(p) for p in pages]
    uid = int.from_bytes(pages[0], "big")
    config = pages[3][0]
    bs = f"{config:08b}"
    print()
    print(f" --- {CC}Tag Information{C0} ---------------------------")
    print(f" UID...... {CG}{uid:08X}{C0}")
    print(f" TYPE..... {CG}{_HT2_TYPES.get((uid >> 4) & 0xF, '')}{C0}")
    print(f" Config... {CY}0x{config:02X}{C0}")
    print(f"  {bs}")
    print(_ht2_breakdown(bs, 0, 4, "RFU"))
    if config & 0x08:
        print(_ht2_breakdown(bs, 4, 1, "Crypto mode", CY))
    else:
        print(_ht2_breakdown(bs, 4, 1, "Password mode"))
    print(_ht2_breakdown(bs, 5, 2, (
        "Public mode B, Coding: biphase",
        "Public mode A, Coding: manchester",
        "Public mode C, Coding: biphase",
        "Hitag 2",
    )[(config >> 1) & 3]))
    print(_ht2_breakdown(bs, 7, 1, "Biphase" if config & 0x01 else "Manchester"))
    print()
    print(" ----------------------------------------------")
    print("  #      | data        | ascii | lck | Info")
    print(" --------+-------------+-------+-----+---------")
    for i, page in enumerate(pages):
        ascii_ = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in page)
        info = _HT2_INFO[i] if i < len(_HT2_INFO) else "User"
        print(f" {i:2d}/0x{i:02X} | {page.hex(' ').upper()} | {ascii_}  | {_ht2_lock(i, config)}  | {info}")
    print(" --------+-------------+-------+-----+---------")
    print(f"  {CR}L{C0} = Locked, {CG}RW{C0} = Read Write, R = Read Only")
    print(" ----------------------------------------------")


def _fail_text(fail, rejected):
    """Message for a failed read/cread from the device's (stage, attempts, uid)."""
    if fail is None:
        return f"No answer, or {rejected}."
    stage, attempts, uid = fail
    if stage <= 1:
        return f"No usable answer to START_AUTH in {attempts} attempts (no tag, or the reply did not decode)."
    if stage == 2:
        return f"UID {uid.hex().upper()} read, then no answer: {rejected}."
    if stage == 3:
        return f"UID {uid.hex().upper()} read and authenticated, but a page read got no answer."
    return (f"UID {uid.hex().upper()} read, but no two reads in {attempts} attempts returned "
            f"the same data (link too noisy).")


# Published Hitag2 defaults. 8 hex digits = password mode, 12 = crypto mode.
# "ONMIKR"/"MIKR" is the transport default; BDF5E846 is Paxton's (PM3's
# ht2_default_keys). Add site defaults via `dict -f FILE`.
_DEFAULT_KEYS = [
    "4F4E4D494B52",  # crypto, "ONMIKR" (MIKRON)
    "4D494B52",      # password, "MIKR"
    "BDF5E846",      # password, Paxton
    "00000000",
    "FFFFFFFF",
]


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


def _parse_hex8(s, label):
    s = s.strip()
    if len(s) != 16:
        raise ValueError(f"{label} must be 16 hex digits (8 bytes)")
    return bytes.fromhex(s)


def _crack_fail_text(fail):
    """Message for a failed crack from the device's (crack_status, uid)."""
    if fail is None:
        return "No answer from the tag."
    status, uid = fail
    if status == 1:
        return "No usable answer to START_AUTH (no tag, or the reply did not decode)."
    if status == 2:
        return ("No encrypted command was answered: the tag is not in crypto mode, "
                "or this {nR}{aR} is not valid for it.")
    if status == 3:
        return (f"UID {uid.hex().upper()} authenticated, but the read-page-0 command "
                f"was not found (link too noisy).")
    return "Crack failed."


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

        status, pages, fail = self.cmd.hitag2_read(pwd)
        if pages is None:
            print(f" {CR}{_fail_text(fail, 'password rejected (wrong key, or tag is in crypto mode)')}{C0}")
            return

        _print_tag(pages)


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

        status, pages, fail = self.cmd.hitag2_crypto_read(key)
        if pages is None:
            print(f" {CR}{_fail_text(fail, 'challenge rejected (wrong key, or tag is in password mode)')}{C0}")
            return

        _print_tag(pages)


@lf_hitag2.command("crack")
class LFHitag2Crack(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = (
            "Recover a crypto-mode Hitag2's memory without its key, using the "
            "malleability attack from 'Gone in 360 Seconds' (sect. 5.1). "
            "Needs one valid {nR}{aR} pair eavesdropped from a genuine "
            "reader/tag authentication. The tag issues no challenge, so the "
            "pair is replayed to authenticate, the encrypted read command is "
            "brute-forced, and keystream is recovered from the known UID to "
            "dump all 8 pages, including the tag password."
        )
        p.add_argument("--nrar", required=True, metavar="HEX16",
                       help="8-byte {nR}{aR} pair, 16 hex digits")
        return p

    def on_exec(self, args: argparse.Namespace):
        try:
            nrar = _parse_hex8(args.nrar, "--nrar")
        except ValueError as e:
            print(f" {CR}{e}{C0}")
            return

        status, pages, fail = self.cmd.hitag2_crack(nrar)
        if pages is None:
            print(f" {CR}{_crack_fail_text(fail)}{C0}")
            return

        _print_tag(pages)


@lf_hitag2.command("nonces")
class LFHitag2Nonces(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = (
            "Show the {nR}{aR} reader auth attempts captured while this device "
            "emulates a Hitag2 tag (sect. 5.3 key recovery). Arm Hitag2 emulation, "
            "let a reader authenticate repeatedly, then read the pairs here and "
            "recover the key on a PC with proxmark3 tools/hitag2crack (ht2crack5)."
        )
        p.add_argument("-f", "--file", metavar="PATH",
                       help="write the UID and pairs to a file for ht2crack5")
        p.add_argument("--clear", action="store_true", help="clear the capture log")
        return p

    def on_exec(self, args: argparse.Namespace):
        if args.clear:
            self.cmd.hitag2_clear_nonces()
            print(f" {CG}cleared{C0}")
            return

        uid = bytes(self.cmd.hitag2_get_emu_id()[0])
        pairs = self.cmd.hitag2_get_nonces()
        if not pairs:
            print(f" {CY}no nonces captured (arm Hitag2 emulation and let a reader authenticate){C0}")
            return

        print(f" UID {CG}{uid.hex().upper()}{C0}, {CG}{len(pairs)}{C0} pair(s):")
        for p in pairs:
            print(f"   nR {p[:4].hex().upper()}  aR {p[4:].hex().upper()}")

        if args.file:
            with open(args.file, "w") as fh:
                fh.write(f"# UID {uid.hex().upper()}\n")
                for p in pairs:
                    fh.write(f"{p[:4].hex().upper()} {p[4:].hex().upper()}\n")
            print(f" {CG}wrote {args.file}{C0}")
        print(f" PC: proxmark3 tools/hitag2crack/ht2crack5 {uid.hex().upper()} "
              f"<nR0> <aR0> <nR1> <aR1>")


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


def _load_key_file(path):
    """Keys one per line, 8 or 12 hex digits; '#' and blank lines ignored."""
    keys = []
    with open(path) as f:
        for ln, raw in enumerate(f, 1):
            s = raw.split("#", 1)[0].strip().replace(" ", "")
            if not s:
                continue
            if len(s) not in (8, 12) or not all(c in "0123456789abcdefABCDEF" for c in s):
                raise ValueError(f"{path}:{ln}: not 8 or 12 hex digits: {raw.strip()!r}")
            keys.append(s.upper())
    return keys


@lf_hitag2.command("dict")
class LFHitag2Dict(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = (
            "Try a list of known keys against a Hitag2 tag. Each 8-hex-digit "
            "key is tried as a password-mode read, each 12-hex-digit key as a "
            "crypto-mode read; the first that authenticates is printed. With "
            "no -f, a short built-in list of published defaults is used. This "
            "only finds keys already in the list -- it is not key recovery."
        )
        p.add_argument("-f", "--file", metavar="FILE",
                       help="key list, one per line (8 or 12 hex digits; # comments ok)")
        p.add_argument("-k", "--key", metavar="HEX", action="append",
                       help="extra key to try, tried before the list (repeatable)")
        return p

    def on_exec(self, args: argparse.Namespace):
        keys = list(args.key or [])
        try:
            keys += _load_key_file(args.file) if args.file else list(_DEFAULT_KEYS)
        except (OSError, ValueError) as e:
            print(f" {CR}{e}{C0}")
            return

        seen, ordered = set(), []
        for k in keys:
            ku = k.strip().upper()
            if ku and ku not in seen:
                seen.add(ku)
                ordered.append(ku)
        if not ordered:
            print(f" {CR}No keys to try.{C0}")
            return

        print(f" Trying {len(ordered)} key(s). Ctrl-C to stop.")
        try:
            for i, k in enumerate(ordered):
                try:
                    kb = bytes.fromhex(k)
                except ValueError:
                    print(f" {CY}[{i + 1}/{len(ordered)}] {k}: not valid hex, skipped{C0}")
                    continue
                if len(kb) not in (4, 6):
                    print(f" {CY}[{i + 1}/{len(ordered)}] {k}: not 8 or 12 hex digits, skipped{C0}")
                    continue
                kind = "pwd" if len(kb) == 4 else "crypto"
                if i:
                    time.sleep(0.2)  # let the field and the tag settle between keys
                try:
                    pages = (self.cmd.hitag2_read(kb) if len(kb) == 4
                             else self.cmd.hitag2_crypto_read(kb))[1]
                except NotOpenException:
                    print(f" {CR}Device disconnected (it reset during the read). "
                          f"Reconnect with `hw connect` and retry.{C0}")
                    return
                except (TimeoutError, OSError, CMDInvalidException) as e:
                    print(f" {CY}[{i + 1}/{len(ordered)}] {k}: {e}{C0}")
                    pages = None
                if pages is not None:
                    print(f" {CG}[{i + 1}/{len(ordered)}] {k}: FOUND ({kind} mode){C0}")
                    _print_tag(pages)
                    return
                print(f" [{i + 1}/{len(ordered)}] {k}: no")
        except KeyboardInterrupt:
            print(f"\n {CY}Stopped.{C0}")
            return
        print(f" {CR}No key in the list worked.{C0}")
