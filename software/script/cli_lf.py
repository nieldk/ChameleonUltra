"""cli_lf — Low Frequency commands (lf ...).

EM410x/EM4x05, HID Prox, ioProx, PAC, Viking, IDTECK, Jablotron, FDX-B,
Indala, T55xx, and generic LF. Includes the LF *ArgsUnit base classes moved
out of cli_core. Split out of chameleon_cli_unit; foundation imported
explicitly from cli_core."""

import re
import struct
import argparse
import sys

from cli_core import (
    jablotron_card_id,
    pac_encode_raw,
    indala_encode_raw,
    indala_format_output,
    lf_indala,
    ArgsParserError,
    ArgumentParserNoExit,
    C0,
    CG,
    CR,
    CY,
    DeviceRequiredUnit,
    HIDFormat,
    IDTECK_PREAMBLE_HEX,
    ReaderRequiredUnit,
    SlotIndexArgsAndGoUnit,
    SlotNumber,
    Status,
    TagSpecificType,
    Union,
    _fdxb_build_frame,
    _fdxb_crc16,
    _fdxb_crc_ok,
    _fdxb_frame_ok,
    _idteck_frame_info,
    color_string,
    data,
    describe_country_code,
    hw,
    lf,
    lf_em_410x,
    lf_em_4x05,
    lf_fdxb,
    lf_generic,
    lf_hid_prox,
    lf_idteck,
    lf_ioprox,
    lf_jablotron,
    lf_pac,
    lf_t55xx,
    lf_viking,
)

# --- LF argument-unit base classes (moved from cli_core) ---


class LFEMIdArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_card_arg(parser: ArgumentParserNoExit, required=False):
        parser.add_argument(
            "--id", type=str, required=required, help="EM410x tag id", metavar="<hex>"
        )
        return parser

    def before_exec(self, args: argparse.Namespace):
        if not super().before_exec(args):
            return False
        if args.id is None or not re.match(
            r"^([a-fA-F0-9]{10}|[a-fA-F0-9]{26})$", args.id
        ):
            raise ArgsParserError("ID must include 10 or 26 HEX symbols")
        return True

    def args_parser(self) -> ArgumentParserNoExit:
        raise NotImplementedError("Please implement this")

    def on_exec(self, args: argparse.Namespace):
        raise NotImplementedError("Please implement this")


class LFHIDIdArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_card_arg(parser: ArgumentParserNoExit, required=False):
        formats = [x.name for x in HIDFormat]
        parser.add_argument(
            "-f",
            "--format",
            type=str,
            required=required,
            help="HIDProx card format",
            metavar="",
            choices=formats,
        )
        parser.add_argument(
            "--fc",
            type=int,
            required=False,
            help="HIDProx tag facility code",
            metavar="<int>",
        )
        parser.add_argument(
            "--cn",
            type=int,
            required=required,
            help="HIDProx tag card number",
            metavar="<int>",
        )
        parser.add_argument(
            "--il",
            type=int,
            required=False,
            help="HIDProx tag issue level",
            metavar="<int>",
        )
        parser.add_argument(
            "--oem", type=int, required=False, help="HIDProx tag OEM", metavar="<int>"
        )
        return parser

    @staticmethod
    def check_limits(
        format: int,
        fc: Union[int, None],
        cn: Union[int, None],
        il: Union[int, None],
        oem: Union[int, None],
    ):
        limits = {
            HIDFormat.H10301: [0xFF, 0xFFFF, 0, 0],
            HIDFormat.IND26: [0xFFF, 0xFFF, 0, 0],
            HIDFormat.IND27: [0x1FFF, 0x3FFF, 0, 0],
            HIDFormat.INDASC27: [0x1FFF, 0x3FFF, 0, 0],
            HIDFormat.TECOM27: [0x7FF, 0xFFFF, 0, 0],
            HIDFormat.W2804: [0xFF, 0x7FFF, 0, 0],
            HIDFormat.IND29: [0x1FFF, 0xFFFF, 0, 0],
            HIDFormat.ATSW30: [0xFFF, 0xFFFF, 0, 0],
            HIDFormat.ADT31: [0xF, 0x7FFFFF, 0, 0],
            HIDFormat.HCP32: [0, 0x3FFF, 0, 0],
            HIDFormat.HPP32: [0xFFF, 0x7FFFF, 0, 0],
            HIDFormat.KASTLE: [0xFF, 0xFFFF, 0x1F, 0],
            HIDFormat.KANTECH: [0xFF, 0xFFFF, 0, 0],
            HIDFormat.WIE32: [0xFFF, 0xFFFF, 0, 0],
            HIDFormat.D10202: [0x7F, 0xFFFFFF, 0, 0],
            HIDFormat.H10306: [0xFFFF, 0xFFFF, 0, 0],
            HIDFormat.N10002: [0xFFFF, 0xFFFF, 0, 0],
            HIDFormat.OPTUS34: [0x3FF, 0xFFFF, 0, 0],
            HIDFormat.SMP34: [0x3FF, 0xFFFF, 0x7, 0],
            HIDFormat.BQT34: [0xFF, 0xFFFFFF, 0, 0],
            HIDFormat.C1K35S: [0xFFF, 0xFFFFF, 0, 0],
            HIDFormat.C15001: [0xFF, 0xFFFF, 0, 0x3FF],
            HIDFormat.S12906: [0xFF, 0xFFFFFF, 0x3, 0],
            HIDFormat.ACTPHID: [0xFF, 0xFFFFFF, 0, 0x3FF],
            HIDFormat.SIE36: [0x3FFFF, 0xFFFF, 0, 0],
            HIDFormat.H10320: [0, 99999999, 0, 0],
            HIDFormat.H10302: [0, 0x7FFFFFFFF, 0, 0],
            HIDFormat.H10304: [0xFFFF, 0x7FFFF, 0, 0],
            HIDFormat.P10004: [0x1FFF, 0x3FFFF, 0, 0],
            HIDFormat.HGEN37: [0, 0xFFFFFFFF, 0, 0],
            HIDFormat.MDI37: [0xF, 0x1FFFFFFF, 0, 0],
        }
        limit = limits.get(HIDFormat(format))
        if limit is None:
            return True
        if fc is not None and fc > limit[0]:
            raise ArgsParserError(
                f"{HIDFormat(format)}: Facility Code must between 0 to {limit[0]}"
            )
        if cn is not None and cn > limit[1]:
            raise ArgsParserError(
                f"{HIDFormat(format)}: Card Number must between 0 to {limit[1]}"
            )
        if il is not None and il > limit[2]:
            raise ArgsParserError(
                f"{HIDFormat(format)}: Issue Level must between 0 to {limit[2]}"
            )
        if oem is not None and oem > limit[3]:
            raise ArgsParserError(
                f"{HIDFormat(format)}: OEM must between 0 to {limit[3]}"
            )

    def before_exec(self, args: argparse.Namespace):
        if super().before_exec(args):
            format = HIDFormat.H10301.value
            if args.format is not None:
                format = HIDFormat[args.format].value
            LFHIDIdArgsUnit.check_limits(format, args.fc, args.cn, args.il, args.oem)
            return True
        return False

    def args_parser(self) -> ArgumentParserNoExit:
        raise NotImplementedError()

    def on_exec(self, args: argparse.Namespace):
        raise NotImplementedError()


class LFHIDIdReadArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_card_arg(parser: ArgumentParserNoExit, required=False):
        formats = [x.name for x in HIDFormat]
        parser.add_argument(
            "-f",
            "--format",
            type=str,
            required=False,
            help="HIDProx card format hint",
            metavar="",
            choices=formats,
        )
        return parser

    def args_parser(self) -> ArgumentParserNoExit:
        raise NotImplementedError()

    def on_exec(self, args: argparse.Namespace):
        raise NotImplementedError()


class LFIOProxIdArgsUnit(DeviceRequiredUnit):
    """
    IOProx identity arguments:
      --ver <int>  version (0-255)
      --fc  <int>  facility (0-255)
      --cn  <int>  card number (0-65535)
      --raw8 <hex8> raw 8 bytes hex, e.g. 007854E03A5D65AB
    """

    @staticmethod
    def add_card_arg(parser: ArgumentParserNoExit, required=False):
        parser.add_argument(
            "--ver", type=int, required=False, help="ioProx version", metavar="<int>"
        )
        parser.add_argument(
            "--fc",
            type=str,
            required=False,
            help="ioProx facility code, e.g., 83 or 0x53",
            metavar="<str>",
        )
        parser.add_argument(
            "--cn",
            type=int,
            required=required,
            help="ioProx card number",
            metavar="<int>",
        )
        parser.add_argument(
            "--raw8",
            type=str,
            required=False,
            help="ioProx raw 8 bytes hex (e.g. 00AABBCCDDEEFF55)",
            metavar="<hex8>",
        )
        return parser

    @staticmethod
    def _check_u8(name: str, v: int):
        if v < 0 or v > 0xFF:
            raise ArgsParserError(f"{name} must be 0..255")

    @staticmethod
    def _check_u16(name: str, v: int):
        if v < 0 or v > 0xFFFF:
            raise ArgsParserError(f"{name} must be 0..65535")

    @staticmethod
    def parse_raw8(raw8: str) -> bytes:
        s = raw8.replace(" ", "").replace("0x", "").strip()
        b = bytes.fromhex(s)
        if len(b) != 8:
            raise ArgsParserError(
                "ioProx --raw must be exactly 8 bytes (16 hex chars), e.g. 007854E03A5D65AB"
            )
        return b

    @staticmethod
    def checksum5(b1, b2, b3, b4, b5) -> int:
        return (0xFF - ((b1 + b2 + b3 + b4 + b5) & 0xFF)) & 0xFF

    def before_exec(self, args: argparse.Namespace):
        if not super().before_exec(args):
            return False

        # validate if provided
        if args.ver is not None:
            self._check_u8("version", args.ver)
        if args.fc is not None:
            val = int(args.fc, 0)
            self._check_u8("facility", val)
            args.fc = val
        if args.cn is not None:
            self._check_u16("card number", args.cn)

        # if raw is present, validate it
        if args.raw8 is not None:
            self.parse_raw8(args.raw8)

        return True


class LFIOProxReadArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_card_arg(parser: ArgumentParserNoExit, required=False):
        parser.add_argument(
            "-v", "--verbose", action="store_true", help="Verbose output"
        )
        return parser


class LFVikingIdArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_card_arg(parser: ArgumentParserNoExit, required=False):
        parser.add_argument(
            "--id", type=str, required=required, help="Viking tag id", metavar="<hex>"
        )
        return parser

    def before_exec(self, args: argparse.Namespace):
        if not super().before_exec(args):
            return False
        if args.id is None or not re.match(r"^[a-fA-F0-9]{8}$", args.id):
            raise ArgsParserError("ID must include 8 HEX symbols")
        return True

    def args_parser(self) -> ArgumentParserNoExit:
        raise NotImplementedError("Please implement this")

    def on_exec(self, args: argparse.Namespace):
        raise NotImplementedError("Please implement this")


class LFJablotronIdArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_card_arg(parser: ArgumentParserNoExit, required=False):
        parser.add_argument(
            "--id",
            type=str,
            required=required,
            help="Jablotron tag id (5 bytes hex)",
            metavar="<hex>",
        )
        return parser

    def before_exec(self, args: argparse.Namespace):
        if not super().before_exec(args):
            return False
        if args.id is None or not re.match(r"^[a-fA-F0-9]{10}$", args.id):
            raise ArgsParserError("ID must include 10 HEX symbols (5 bytes)")
        return True

    def args_parser(self) -> ArgumentParserNoExit:
        raise NotImplementedError("Please implement this")

    def on_exec(self, args: argparse.Namespace):
        raise NotImplementedError("Please implement this")


class LFFdxbIdArgsUnit(DeviceRequiredUnit):
    """Argument parser for FDX-B: 26 hex chars = 13 bytes (destuffed frame)."""

    @staticmethod
    def add_card_arg(parser: ArgumentParserNoExit, required=False):
        parser.add_argument(
            "--id",
            type=str,
            required=required,
            help="FDX-B frame (13 bytes hex: national_id[5] + country[2] + crc[2] + reserved[4])",
            metavar="<hex>",
        )
        return parser

    def before_exec(self, args: argparse.Namespace):
        if not super().before_exec(args):
            return False
        if args.id is None or not re.match(r"^[a-fA-F0-9]{26}$", args.id):
            raise ArgsParserError("FDX-B ID must include 26 HEX symbols (13 bytes)")
        # Structural sanity: the CRC-16 in bytes 8-9 must cover bytes 0-7.
        # A hand-edited ID whose CRC no longer matches will not round-trip and
        # may be rejected by third-party readers.  Warn rather than block, so a
        # deliberately malformed frame can still be written for testing, unless
        # the frame is also unreadable by our own decoder (see _fdxb_frame_ok).
        frame = bytes.fromhex(args.id)
        ok, reason = _fdxb_frame_ok(frame)
        if not ok:
            raise ArgsParserError(f"FDX-B frame invalid: {reason}")
        return True

    def args_parser(self) -> ArgumentParserNoExit:
        raise NotImplementedError("Please implement this")

    def on_exec(self, args: argparse.Namespace):
        raise NotImplementedError("Please implement this")


class LFIdteckIdArgsUnit(DeviceRequiredUnit):
    """Argument parser for IDTECK: 16-hex = full 64-bit frame (preamble + payload)."""

    @staticmethod
    def add_card_arg(parser: ArgumentParserNoExit, required=False):
        parser.add_argument(
            "--id",
            type=str,
            required=required,
            help="IDTECK frame in hex: 16 chars for the full 64-bit frame, or "
            "8 chars for the 32-bit payload only (preamble 4944544B is auto-prepended).",
            metavar="<hex>",
        )
        return parser

    def before_exec(self, args: argparse.Namespace):
        if not super().before_exec(args):
            return False
        if args.id is None:
            # No id provided: the caller (e.g. econfig in readback form) is
            # allowed to proceed without one. Subcommands that require an id
            # declare it with required=True on the parser argument.
            return True
        if re.match(r"^[a-fA-F0-9]{16}$", args.id):
            pass
        elif re.match(r"^[a-fA-F0-9]{8}$", args.id):
            args.id = IDTECK_PREAMBLE_HEX + args.id
        else:
            raise ArgsParserError("ID must be 8 or 16 HEX symbols")

        # Informational checksum check: some readers validate a checksum on
        # the payload; emit a warning when it does not match the computed
        # value but do not block the operation, since not all IDTECK readers
        # enforce it.
        info = _idteck_frame_info(bytes.fromhex(args.id))
        if not info["preamble_valid"]:
            print(
                f"{color_string((CR, 'WARNING'))}: frame preamble {info['preamble_hex']} "
                f"is not the IDTECK {IDTECK_PREAMBLE_HEX} — reader will likely reject it"
            )
        if not info["checksum_valid"]:
            print(
                f"{color_string((CY, 'note'))}: payload checksum 0x{info['checksum']:02X} "
                f"does not match computed 0x{info['checksum_expected']:02X} "
                f"(some readers ignore this, some may reject)"
            )
        return True

    def args_parser(self) -> ArgumentParserNoExit:
        raise NotImplementedError("Please implement this")

    def on_exec(self, args: argparse.Namespace):
        raise NotImplementedError("Please implement this")


# --- LF helpers + command classes ---


@lf_fdxb.command("read")
class LFFdxbRead(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Scan FDX-B animal tag (134.2 kHz) and print id"
        parser.add_argument(
            "--raw", action="store_true", help="also print the raw 13-byte frame"
        )
        parser.add_argument(
            "-@",
            dest="continuous",
            action="store_true",
            help="continuous scan until a key is pressed (helps locate an implant)",
        )
        return parser

    def _print_result(self, resp, show_raw: bool) -> bool:
        if not resp or not hasattr(resp, "parsed") or resp.parsed is None:
            return False
        tag_type, frame = resp.parsed
        # Parse the 13-byte destuffed frame
        v = int.from_bytes(frame[0:8], "little")
        national = v & ((1 << 38) - 1)
        country = (v >> 38) & 0x3FF
        app_bit = (v >> 48) & 1
        animal = (v >> 63) & 1
        crc = int.from_bytes(frame[8:10], "little")

        print(" FDX-B (ISO 11784/11785)")
        print(f"  Country    : {describe_country_code(country)}")
        print(f"  National ID: {color_string((CG, str(national)))}")
        print(f"  Animal flag: {animal}")
        print(f"  App bit    : {app_bit}")
        print(f"  CRC-16     : 0x{crc:04x}")
        if show_raw:
            print(f"  Raw frame  : {frame.hex()}")
        return True

    def on_exec(self, args: argparse.Namespace):
        if not args.continuous:
            if not self._print_result(self.cmd.fdxb_scan(), args.raw):
                print(" No FDX-B tag found")
            return

        # Continuous mode: rescan until the user presses a key.  A hit does
        # not stop the loop -- sweeping past the implant should keep printing
        # so the strongest position is easy to find.
        print("[=] Press <Enter> to stop")
        try:
            while not self._key_pressed():
                if not self._print_result(self.cmd.fdxb_scan(), args.raw):
                    # brief spacer so the terminal shows scanning is live
                    print(" ...", end="\r")
        except KeyboardInterrupt:
            pass
        print()

    @staticmethod
    def _key_pressed() -> bool:
        """Non-blocking check for any keypress, portable across OSes."""
        if sys.platform == "win32":
            import msvcrt

            if msvcrt.kbhit():
                msvcrt.getch()
                return True
            return False
        import select

        dr, _, _ = select.select([sys.stdin], [], [], 0)
        if dr:
            sys.stdin.readline()
            return True
        return False


@lf_fdxb.command("write")
class LFFdxbWriteT55xx(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Write FDX-B frame to T55xx (by fields, or raw --id)"
        parser.add_argument(
            "--country",
            type=int,
            metavar="<0-1023>",
            help="country/manufacturer code (ISO 3166 numeric, e.g. 208 for Denmark)",
        )
        parser.add_argument(
            "--national",
            type=int,
            metavar="<id>",
            help="national ID, up to 274877906943 (38-bit)",
        )
        parser.add_argument(
            "--animal",
            type=int,
            default=1,
            choices=(0, 1),
            help="animal flag (default 1)",
        )
        parser.add_argument(
            "--extended",
            type=lambda x: int(x, 0),
            default=0,
            metavar="<0-0xFFFFFF>",
            help="optional 24-bit extended data (default 0)",
        )
        parser.add_argument(
            "--id",
            type=str,
            metavar="<hex>",
            help="raw 26-hex frame instead of fields (advanced; not validated for reserved bits)",
        )
        return parser

    def _resolve_frame(self, args) -> bytes:
        """Field args take priority; fall back to raw --id.  Returns 13 bytes."""
        if args.country is not None or args.national is not None:
            if args.country is None or args.national is None:
                raise ArgsParserError(
                    "both --country and --national are required when building by fields"
                )
            return _fdxb_build_frame(
                args.country, args.national, args.animal, args.extended
            )
        if args.id is not None:
            if not re.match(r"^[a-fA-F0-9]{26}$", args.id):
                raise ArgsParserError("FDX-B --id must be 26 HEX symbols (13 bytes)")
            frame = bytes.fromhex(args.id)
            ok, reason = _fdxb_frame_ok(frame)
            if not ok:
                raise ArgsParserError(f"FDX-B frame invalid: {reason}")
            return frame
        raise ArgsParserError("provide --country and --national, or a raw --id")

    def on_exec(self, args: argparse.Namespace):
        data_bytes = self._resolve_frame(args)
        if not _fdxb_crc_ok(data_bytes):
            calc = _fdxb_crc16(data_bytes[0:8])
            print(
                f" [!] CRC-16 in frame does not match data (expected 0x{calc:04x}); "
                f"writing anyway, but the tag may not verify on other readers"
            )
        self.cmd.fdxb_write_to_t55xx(data_bytes)
        print(f" - FDX-B frame: {data_bytes.hex().upper()} written to T55xx")


@lf_fdxb.command("clone")
class LFFdxbClone(LFFdxbWriteT55xx):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = "Clone FDX-B animal tag to T55xx (alias for 'write')"
        return parser

    def on_exec(self, args: argparse.Namespace):
        data_bytes = self._resolve_frame(args)
        if not _fdxb_crc_ok(data_bytes):
            calc = _fdxb_crc16(data_bytes[0:8])
            print(
                f" [!] CRC-16 in frame does not match data (expected 0x{calc:04x}); "
                f"cloning anyway, but the tag may not verify on other readers"
            )
        self.cmd.fdxb_write_to_t55xx(data_bytes)
        print(f" - FDX-B clone complete: {data_bytes.hex().upper()}")


@lf.command("search")
class LFSearch(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Search for any supported LF tag — tries every decoder in turn (PM3-style) and reports the first match"
        return parser

    def on_exec(self, args: argparse.Namespace):
        tag_type, id_bytes = self.cmd.lf_search()
        if tag_type is None:
            print(color_string((CR, "No known LF tag found")))
            return
        # HID Prox does not report a raw id: the firmware hands back the already
        # decoded wiegand card (see hidprox_get_data()), so print the same fields
        # as 'lf hid prox read' instead of hexdumping the struct.
        if tag_type == TagSpecificType.HIDProx:
            format, fc, cn1, cn2, il, oem = struct.unpack(">BIBIBH", id_bytes[:13])
            cn = (cn1 << 32) + cn2
            print(f"HIDProx/{HIDFormat(format)}")
            if fc > 0:
                print(f" FC: {color_string((CG, fc))}")
            if il > 0:
                print(f" IL: {color_string((CG, il))}")
            if oem > 0:
                print(f" OEM: {color_string((CG, oem))}")
            print(f" CN: {color_string((CG, cn))}")
            return
        # IDTECK hands back the whole 64-bit frame; show the decoded card id
        # alongside it rather than only the raw hex.
        if tag_type == TagSpecificType.IDTECK and len(id_bytes) == 8:
            info = _idteck_frame_info(bytes(id_bytes))
            cid = info["card_id"]
            chk = info["checksum"]
            print(f"IDTECK: {color_string((CG, id_bytes.hex().upper()))}")
            print(f" Card ID: {color_string((CG, f'{cid} [0x{cid:06X}]'))}")
            if not info["checksum_valid"]:
                print(f" Checksum: {color_string((CY, f'0x{chk:02X} mismatch'))}")
            return
        # PAC hands back the 8 ASCII characters of the card number, not a binary
        # id; hexdumping them prints the ASCII codes. Show the same fields as
        # 'lf pac read'.
        if tag_type == TagSpecificType.PAC and len(id_bytes) == 8:
            card_id_ascii = "".join(
                chr(b) if 0x20 <= b < 0x7F else "." for b in id_bytes
            )
            raw = pac_encode_raw(bytes(id_bytes))
            print(
                f" PAC/Stanley - CN: {color_string((CG, card_id_ascii))} | Raw: {raw.hex().upper()}"
            )
            return
        # Indala hands back the raw 64-bit frame; show the decoded FC/CN
        # alongside it rather than only the raw hex, same as 'lf indala read'.
        if tag_type == TagSpecificType.Indala and len(id_bytes) == 8:
            print(f" {indala_format_output(bytes(id_bytes[:8]))}")
            return
        print(
            f"{color_string((CG, str(tag_type)))}: {color_string((CG, id_bytes.hex()))}"
        )


@lf_em_410x.command("read")
class LFEMRead(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Scan em410x tag and print id"
        return parser

    def on_exec(self, args: argparse.Namespace):
        data = self.cmd.em410x_scan()
        print(f"{TagSpecificType(data[0])}: {color_string((CG, data[1].hex()))}")


@lf_em_410x.command("write")
class LFEM410xWriteT55xx(LFEMIdArgsUnit, ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Write em410x id to t55xx"
        return self.add_card_arg(parser, required=True)

    def on_exec(self, args: argparse.Namespace):
        id_hex = args.id
        if len(id_hex) not in (10, 26):
            raise ArgsParserError(
                "Writing to T55xx supports 5-byte EM410X (10 hex) or 13-byte Electra (26 hex) IDs."
            )
        id_bytes = bytes.fromhex(id_hex)
        self.cmd.em410x_write_to_t55xx(id_bytes)
        print(f" - EM410x ID write done: {id_hex}")


def _t55_hex4(s: str, name: str) -> bytes:
    """Parse exactly 4 hex bytes, or raise a clean ArgsParserError."""
    try:
        b = bytes.fromhex(s)
    except ValueError:
        raise ArgsParserError(f"{name} must be 8 hex digits (4 bytes)")
    if len(b) != 4:
        raise ArgsParserError(f"{name} must be 8 hex digits (4 bytes)")
    return b


def _t55_amplitude_halfbits(samples, rf_n):
    """Binarize a SAADC amplitude capture and recover the half-bit level stream
    with a phase-locked sampler. Half-cell = rf_n/2 samples (SAADC samples once
    per carrier cycle), known a priori. The half-bit level is a majority vote at
    the cell centre, and the clock re-anchors on the nearest real transition each
    cell, so run-length jitter and stretched/merged runs in the settling region
    don't slip Manchester phase (the RLE round(run/unit) approach did). Returns
    the half-bit list, or []."""
    n = len(samples)
    if n < 96:
        return []
    lo, hi = min(samples), max(samples)
    if hi - lo < 8:
        return []
    thr = (lo + hi) / 2.0
    b = [1 if s >= thr else 0 for s in samples]
    hb_len = max(2, rf_n // 2)
    edges = [i for i in range(1, n) if b[i] != b[i - 1]]
    if not edges:
        return []
    win = max(2, hb_len // 3)
    pos = edges[0]  # anchor phase on the first transition
    hb = []
    while pos + hb_len <= n:
        c = pos + hb_len // 2
        seg = b[max(0, c - win) : c + win + 1]
        hb.append(1 if sum(seg) * 2 >= len(seg) else 0)
        nb = pos + hb_len
        cand = [e for e in edges if abs(e - nb) <= hb_len // 3]
        pos = min(cand, key=lambda e: abs(e - nb)) if cand else nb
    return hb


def _t55_manchester_decode(hb, off):
    """Manchester-decode a half-bit stream from a start phase, with phase-slip
    resync. Returns (bitstring, violations)."""
    bits, viol, i = [], 0, off
    while i + 1 < len(hb):
        a, d = hb[i], hb[i + 1]
        if a == 1 and d == 0:
            bits.append(1)
            i += 2
        elif a == 0 and d == 1:
            bits.append(0)
            i += 2
        else:
            viol += 1
            i += 1  # slip one half-cell to resync
    return "".join(map(str, bits)), viol


def _t55_amplitude_bits(samples, rf_n):
    """Decode the amplitude capture to a bitstring (lower-violation phase)."""
    hb = _t55_amplitude_halfbits(samples, rf_n)
    if not hb:
        return ""
    s0, v0 = _t55_manchester_decode(hb, 0)
    s1, v1 = _t55_manchester_decode(hb, 1)
    return s0 if v0 <= v1 else s1


def _t55_find_word(samples, word_bytes, rf_n):
    """Search both half-bit phases and both Manchester polarities for a 32-bit
    word. Returns (polarity, bit_offset) or None."""
    hb = _t55_amplitude_halfbits(samples, rf_n)
    if not hb:
        return None
    target = "".join(f"{x:08b}" for x in word_bytes)
    for off in (0, 1):
        s, _ = _t55_manchester_decode(hb, off)
        if target in s:
            return ("normal", s.index(target))
        inv = "".join("1" if ch == "0" else "0" for ch in s)
        if target in inv:
            return ("inverted", inv.index(target))
    return None


def _t55_stream_block(bits):
    """A T55xx block is 32 bits and the tag streams it repeatedly, so a correct
    read is one 32-bit period — not the whole demodulated smear. Find the
    smallest repeating period in the bitstream and return (period_bits,
    period_bitstring). period_bits == 32 means a clean block; a proper divisor
    of 32 (e.g. 16) means the read-back collapsed to a shorter period (the known
    dense-word framing issue) and is NOT a trustworthy 32-bit value. Returns
    (None, None) if no stable period is found."""
    n = len(bits)
    if n < 16:
        return None, None
    # Skip a long constant settling lead-in (the field-on ramp demodulates as one
    # sustained level and otherwise dominates the period search).
    lead = 1
    while lead < n and bits[lead] == bits[0]:
        lead += 1
    if lead > 48:
        bits = bits[lead:]
        n = len(bits)
        if n < 16:
            return None, None
    for p in range(8, min(33, n // 2 + 1)):
        agree = sum(1 for i in range(n - p) if bits[i] == bits[i + p])
        if agree / (n - p) >= 0.92:
            return p, bits[:p]
    return None, None


# T5577 block-0 (configuration) decode, field layout per PM3 SetConfigWithBlock0Ex
# (RfidResearchGroup/proxmark3 client/src/cmdlft55xx.c). Verified against known
# configs 0x000880E0 (Manchester RF/32, maxblock 7) and 0x00148040 (em410x:
# Manchester RF/64, maxblock 2).
_T55_MOD = {
    0: "DIRECT (ASK/NRZ)",
    1: "PSK1",
    2: "PSK2",
    3: "PSK3",
    4: "FSK1",
    5: "FSK2",
    6: "FSK1a",
    7: "FSK2a",
    8: "Manchester",
    16: "Biphase",
    24: "Biphase-a (CDP)",
}
_T55_BITRATE = [8, 16, 32, 40, 50, 64, 100, 128]  # 3-bit non-extended dbr index

# Detected config from `lf t55xx detect`, used as the default RF for `read`.
_T55_DETECTED = {"rf": None, "mod": "manchester"}


def _t55_parse_block0(b0):
    """Decode a T5577 block-0 config word into its fields."""
    extend = (b0 >> 17) & 0x01  # X-mode / extended bit-rate
    if extend:
        dbr = (b0 >> 18) & 0x3F  # extended rate table differs
        rf = None
    else:
        dbr = (b0 >> 18) & 0x07
        rf = _T55_BITRATE[dbr]
    modulation = (b0 >> 12) & 0x1F
    return {
        "block0": b0,
        "extend": bool(extend),
        "rf": rf,
        "dbr": dbr,
        "modulation": modulation,
        "mod_name": _T55_MOD.get(modulation, f"0x{modulation:02X} (unknown)"),
        "maxblock": (b0 >> 5) & 0x07,
        "pwd": bool((b0 >> 4) & 1),
        "st": bool((b0 >> 3) & 1),
        "inverted": bool((b0 >> 1) & 1),
    }


def _t55_decode_bits(cmd, block, rf, pwd, page1, modulation):
    """Return the raw demodulated bit STRING for a block before any 32-bit framing
    (modulation 0 = Manchester via SAADC amplitude host decode; 1 = biphase via the
    firmware diphase_feed demod), or "" on failure."""
    if modulation == 1:
        n, items = cmd.lf_t55xx_read(block, rf, pwd, page1, modulation=1)
        return "".join("1" if b else "0" for b in items) if items else ""
    n, samples = cmd.lf_t55xx_read(block, rf, pwd, page1, adc=True)
    if n == 0:
        return ""
    return _t55_amplitude_bits(samples, rf) or ""


def _t55_lock_config(bits, rf, want_mods):
    """Slide a 32-bit window over the stream and return (block0, fields, inverted)
    for the first window that REPEATS (== the next 32 bits) AND parses to a config
    whose modulation is in want_mods, bitrate == rf, not extended. The repeat
    requirement skips the settling lead-in, tolerates block rotation, and rejects
    streaming tags (FDX-B) that never present a repeating 32-bit config block.
    Mirrors PM3's stride-locked framing. Returns None if nothing matches."""
    if not bits:
        return None
    n = len(bits)
    for i in range(n - 64):
        for inv in (0, 1):
            seg = bits[i : i + 32]
            nxt = bits[i + 32 : i + 64]
            if inv:
                seg = "".join("1" if c == "0" else "0" for c in seg)
                nxt = "".join("1" if c == "0" else "0" for c in nxt)
            if seg != nxt:
                continue
            f = _t55_parse_block0(int(seg, 2))
            if (
                f["modulation"] in want_mods
                and not f["extend"]
                and f["rf"] == rf
                and f["maxblock"] >= 1
            ):
                return int(seg, 2), f, inv
    return None


def _t55_detect_sources(cmd, rf, pwd, modcode):
    """Candidate demodulated bit strings for detecting block 0 at this rate. For
    Manchester, try the firmware EDGE decode first (block 0 is sparse, so the edge
    path is reliable and sidesteps the amplitude decoder's phase ambiguity on config
    words) plus the SAADC amplitude decode as a denser-config fallback. For biphase,
    the firmware diphase edge decode."""
    out = []
    if modcode == 0:
        n, items = cmd.lf_t55xx_read(0, rf, pwd, False, modulation=0)
        if items:
            out.append("".join("1" if b else "0" for b in items))
        n, samples = cmd.lf_t55xx_read(0, rf, pwd, False, adc=True)
        if n:
            b = _t55_amplitude_bits(samples, rf)
            if b:
                out.append(b)
    else:
        n, items = cmd.lf_t55xx_read(0, rf, pwd, False, modulation=1)
        if items:
            out.append("".join("1" if b else "0" for b in items))
    return out


def _t55_read_framed(cmd, block, rf, pwd, page1, modulation):
    """Read a block and frame it to its repeating unit -> (period, unit) or
    (None, None)."""
    bits = _t55_decode_bits(cmd, block, rf, pwd, page1, modulation)
    if not bits:
        return None, None
    return _t55_stream_block(bits)


def _t55_frame_block(bits):
    """Frame a demodulated stream to one 32-bit block: skip a long constant settling
    lead-in, then return (value, note) for the most common 32-bit window that repeats
    (== the next 32 bits) — any rotation of the true block, hence the caller's "may
    be rotated" note. Falls back to the shortest repeating period (flagging a
    collapse) when nothing repeats at 32; (None, None) if unusable."""
    n = len(bits)
    if n < 64:
        return None, None
    lead = 1
    while lead < n and bits[lead] == bits[0]:
        lead += 1
    if lead > 48:
        bits = bits[lead:]
        n = len(bits)
        if n < 64:
            return None, None
    reps = {}
    for i in range(n - 64):
        w = bits[i : i + 32]
        if w == bits[i + 32 : i + 64]:
            reps[w] = reps.get(w, 0) + 1
    if reps:
        return int(max(reps, key=reps.get), 2), "32-bit block"
    period, unit = _t55_stream_block(bits)
    if period is None:
        return None, None
    return (
        int((unit * (32 // period + 1))[:32], 2),
        f"{period}-bit period — repetitive value or dense-word collapse",
    )


def _t55_expect_match(bits, want):
    """True if the 32-bit `want` appears as a repeating window in any rotation or
    inverted polarity of the demodulated stream."""
    wb = format(want, "032b")
    cands = set()
    for base in (wb, "".join("1" if c == "0" else "0" for c in wb)):
        for r in range(32):
            cands.add(base[r:] + base[:r])
    n = len(bits)
    for i in range(n - 64):
        w = bits[i : i + 32]
        if w == bits[i + 32 : i + 64] and w in cands:
            return True
    return False


@lf_t55xx.command("write")
class LFT55xxWrite(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Write a raw 32-bit word to a T55xx block"
        parser.add_argument(
            "-b",
            "--block",
            type=int,
            required=True,
            metavar="<0-7>",
            help="Block number (0-7 on page 0, 0-3 on page 1)",
        )
        parser.add_argument(
            "-d",
            "--data",
            type=str,
            required=True,
            metavar="<hex>",
            help="32-bit data word, 4 hex bytes",
        )
        parser.add_argument(
            "-p",
            "--pwd",
            type=str,
            default=None,
            metavar="<hex>",
            help="Password, 4 hex bytes (password-protected write)",
        )
        parser.add_argument("--pg1", action="store_true", help="Target page 1")
        return parser

    def on_exec(self, args: argparse.Namespace):
        page1 = args.pg1
        max_block = 3 if page1 else 7
        if not (0 <= args.block <= max_block):
            raise ArgsParserError(
                f"block must be 0-{max_block} on page {'1' if page1 else '0'}"
            )
        word = _t55_hex4(args.data, "data")
        pwd = _t55_hex4(args.pwd, "pwd") if args.pwd is not None else None
        self.cmd.lf_t55xx_write(args.block, word, pwd, page1)
        print(
            f" - T55xx block {args.block}{' (pg1)' if page1 else ''} <- {word.hex().upper()}"
        )


@lf_t55xx.command("wipe")
class LFT55xxWipe(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Wipe a T55xx: default config to block 0, zeros to blocks 1-7"
        )
        parser.add_argument(
            "-c",
            "--cfg",
            type=str,
            default=None,
            metavar="<hex>",
            help="Override config block 0 (4 hex bytes)",
        )
        parser.add_argument(
            "-p",
            "--pwd",
            type=str,
            default=None,
            metavar="<hex>",
            help="Current password, 4 hex bytes (to auth the wipe)",
        )
        parser.add_argument(
            "--q5", action="store_true", help="Target Q5/T5555 (config 0x6001F004)"
        )
        parser.add_argument(
            "--extended",
            action="store_true",
            help="Also zero block 3 page 1 (extended-mode config)",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.cfg is not None:
            cfg = _t55_hex4(args.cfg, "cfg")
        else:
            cfg = bytes.fromhex("6001F004" if args.q5 else "000880E0")
        pwd = _t55_hex4(args.pwd, "pwd") if args.pwd is not None else None
        zero = b"\x00\x00\x00\x00"
        # Block 0 first, authenticated if a password was supplied. The default
        # config clears the pwd bit, so blocks 1-7 are then written open.
        self.cmd.lf_t55xx_write(0, cfg, pwd, page1=False)
        for blk in range(1, 8):
            self.cmd.lf_t55xx_write(blk, zero, None, page1=False)
        if args.extended:
            self.cmd.lf_t55xx_write(3, zero, None, page1=True)
        print(
            f" - T55xx wiped (block 0 = {cfg.hex().upper()}"
            f"{', Q5' if args.q5 else ''}{', +pg1 blk3' if args.extended else ''})"
        )


@lf_t55xx.command("detect")
class LFT55xxDetect(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Detect a T55xx tag by reading block 0 and stride-locking its config: "
            "slides a 32-bit window over the demodulated stream and accepts the first "
            "window that repeats and parses to a valid config at the read rate. Tries "
            "Manchester (amplitude path) and biphase (firmware diphase). FSK/PSK are not "
            "wired; streaming tags with no addressable config block (e.g. FDX-B) are "
            "reported as such. Sets the default RF/n for subsequent `read`."
        )
        parser.add_argument(
            "-p",
            "--pwd",
            type=str,
            default=None,
            metavar="<hex>",
            help="Password, 4 hex bytes (if block 0 is read-protected)",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        pwd = _t55_hex4(args.pwd, "pwd") if args.pwd else None
        # The winner is the rate+modulation whose block-0 decode is a clean 32-bit
        # word AND self-consistent: block 0 must say <that modulation> at the very
        # rate we read it at. That consistency check is what makes a hit trustworthy.
        # Manchester (8) uses the robust amplitude path; biphase (16/24) uses the
        # firmware diphase demod. FSK/PSK are not wired yet.
        for modname, modcode, want in (
            ("manchester", 0, (8,)),
            ("biphase", 1, (16, 24)),
        ):
            for rf in (32, 64, 16, 40, 50, 100, 128, 8):
                for bits in _t55_detect_sources(self.cmd, rf, pwd, modcode):
                    res = _t55_lock_config(bits, rf, want)
                    if not res:
                        continue
                    b0, f, inv = res
                    _T55_DETECTED["rf"] = rf
                    _T55_DETECTED["mod"] = modname
                    print(f" - T55xx detected  (block 0 = {f['block0']:08X})")
                    print(f"     modulation : {f['mod_name']}")
                    print(f"     bit rate   : RF/{f['rf']}")
                    print(f"     max block  : {f['maxblock']}")
                    print(f"     password   : {'yes' if f['pwd'] else 'no'}")
                    print(f"     seq term   : {'yes' if f['st'] else 'no'}")
                    print(f"     inverted   : {'yes' if f['inverted'] else 'no'}")
                    print(f"{CG} - read now defaults to RF/{rf} ({modname}).{C0}")
                    return
        print(f"{CR} - detect failed: no repeating 32-bit config block found.{C0}")
        print(
            f"{CY}   Likely a streaming tag with no addressable config block (e.g. FDX-B — "
            f"use `lf fdxb`), or FSK/PSK (not wired into t55xx read), or a rate not tried. "
            f"`lf t55xx read -b 0 --adc` shows the raw envelope.{C0}"
        )


@lf_t55xx.command("read")
class LFT55xxRead(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Read a T55xx block (Manchester) and dump the demodulated bitstream"
        )
        parser.add_argument("-b", "--block", type=int, required=True, metavar="<0-7>")
        parser.add_argument(
            "--rf",
            type=int,
            default=None,
            metavar="<n>",
            help="Bitrate divisor RF/n (default: from `detect`, else 32; em410x uses 64)",
        )
        parser.add_argument(
            "-p",
            "--pwd",
            type=str,
            default=None,
            metavar="<hex>",
            help="Password, 4 hex bytes",
        )
        parser.add_argument("--pg1", action="store_true", help="Target page 1")
        parser.add_argument(
            "--expect",
            type=str,
            default=None,
            metavar="<hex>",
            help="Verify: report whether this 32-bit word (4 hex bytes) is present",
        )
        parser.add_argument(
            "--raw",
            action="store_true",
            help="Diagnostic: dump raw edge intervals (carrier cycles) instead of decoding",
        )
        parser.add_argument(
            "--adc",
            action="store_true",
            help="Diagnostic: dump raw SAADC envelope amplitude (robust for dense data)",
        )
        parser.add_argument(
            "--regread",
            action="store_true",
            help="Diagnostic: skip the addressed downlink, capture the regular-read stream",
        )
        parser.add_argument(
            "--mod",
            choices=("auto", "manchester", "biphase"),
            default="auto",
            help="Demod: manchester (SAADC amplitude, robust) or biphase "
            "(firmware diphase_feed). auto = whatever `detect` found (else manchester).",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.rf is None:
            args.rf = _T55_DETECTED["rf"] or 32
        pwd = _t55_hex4(args.pwd, "pwd") if args.pwd else None
        downlink = not args.regread
        mode = "regular-read" if args.regread else "addressed"
        modname = _T55_DETECTED["mod"] if args.mod == "auto" else args.mod
        modulation = 1 if modname == "biphase" else 0

        # --raw: edge-interval diagnostic (fragile on dense data; see --adc).
        if args.raw:
            n, items = self.cmd.lf_t55xx_read(
                args.block, args.rf, pwd, args.pg1, raw=True, downlink=downlink
            )
            if n == 0:
                print(f"{CR} - no response ({mode}; try --adc to see the envelope){C0}")
                return
            print(f" - {n} edge intervals ({mode}):")
            for i in range(0, n, 20):
                print("   " + " ".join(f"{v:3d}" for v in items[i : i + 20]))
            nz = [v for v in items if v]
            if nz:
                hi = {}
                for v in nz:
                    hi[v] = hi.get(v, 0) + 1
                top = sorted(hi.items(), key=lambda kv: -kv[1])[:6]
                print("   most common: " + ", ".join(f"{v}({c})" for v, c in top))
                print(
                    f"   min={min(nz)} max={max(nz)}  (expect clusters near {args.rf}, "
                    f"{args.rf * 3 // 2}, {args.rf * 2} for RF/{args.rf} Manchester)"
                )
            return

        # Optional --adc: amplitude-envelope diagnostic dump (the block value itself
        # is decoded from the firmware demod below).
        if args.adc:
            n, samples = self.cmd.lf_t55xx_read(
                args.block, args.rf, pwd, args.pg1, adc=True, downlink=downlink
            )
            if n:
                mean = sum(samples) / n
                print(
                    f" - {n} amplitude samples ({mode}), mean={mean:.1f} "
                    f"min={min(samples)} max={max(samples)}:"
                )
                for i in range(0, n, 32):
                    print("   " + " ".join(f"{v:3d}" for v in samples[i : i + 32]))
                trace = "".join("1" if v >= mean else "0" for v in samples)
                print(" - threshold@mean:")
                for i in range(0, len(trace), 64):
                    print("   " + trace[i : i + 64])

        # Block value via the firmware demod (edge path — the proven decoder detect
        # uses; Manchester or biphase per --mod).
        n, items = self.cmd.lf_t55xx_read(
            args.block, args.rf, pwd, args.pg1, modulation=modulation, downlink=downlink
        )
        if not items:
            print(f"{CR} - no response ({mode}; check --rf / --mod){C0}")
            return
        bits = "".join("1" if b else "0" for b in items)
        label = "biphase" if modulation == 1 else "manchester"
        val, note = _t55_frame_block(bits)
        if val is None:
            print(
                f"{CY} - no stable block ({len(bits)} bits demodulated @ RF/{args.rf}, "
                f"{mode}, {label}):{C0}"
            )
            for i in range(0, len(bits), 64):
                print(f"   {bits[i:i + 64]}")
            return
        print(
            f" - block {args.block} @ RF/{args.rf} ({mode}, {label}): {val:08X}  "
            f"[{note}; may be inverted/rotated — use --expect to test a value]"
        )
        if args.expect is not None:
            want = int.from_bytes(_t55_hex4(args.expect, "expect"), "big")
            if _t55_expect_match(bits, want):
                print(
                    f"{CG} - verify OK: {args.expect.upper()} present "
                    f"(some rotation/polarity){C0}"
                )
            else:
                print(
                    f"{CR} - verify MISMATCH: {args.expect.upper()} not in stream{C0}"
                )


@lf_hid_prox.command("read")
class LFHIDProxRead(LFHIDIdReadArgsUnit, ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Scan hid prox tag and print card format, facility code, card number, issue level and OEM code"
        return self.add_card_arg(parser, required=True)

    def on_exec(self, args: argparse.Namespace):
        format = 0
        if args.format is not None:
            format = HIDFormat[args.format].value
        format, fc, cn1, cn2, il, oem = self.cmd.hidprox_scan(format)
        cn = (cn1 << 32) + cn2
        print(f"HIDProx/{HIDFormat(format)}")
        if fc > 0:
            print(f" FC: {color_string((CG, fc))}")
        if il > 0:
            print(f" IL: {color_string((CG, il))}")
        if oem > 0:
            print(f" OEM: {color_string((CG, oem))}")
        print(f" CN: {color_string((CG, cn))}")


@lf_hid_prox.command("write")
class LFHIDProxWriteT55xx(LFHIDIdArgsUnit, ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Write hidprox card data to t55xx"
        return self.add_card_arg(parser, required=True)

    def on_exec(self, args: argparse.Namespace):
        if args.fc is None:
            args.fc = 0
        if args.il is None:
            args.il = 0
        if args.oem is None:
            args.oem = 0
        format = HIDFormat[args.format]
        id = struct.pack(
            ">BIBIBH",
            format.value,
            args.fc,
            (args.cn >> 32),
            args.cn & 0xFFFFFFFF,
            args.il,
            args.oem,
        )
        self.cmd.hidprox_write_to_t55xx(id)
        print(f"HIDProx/{format}")
        if args.fc > 0:
            print(f" FC: {args.fc}")
        if args.il > 0:
            print(f" IL: {args.il}")
        if args.oem > 0:
            print(f" OEM: {args.oem}")
        print(f" CN: {args.cn}")
        print("write done.")


@lf_hid_prox.command("econfig")
class LFHIDProxEconfig(SlotIndexArgsAndGoUnit, LFHIDIdArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set emulated hidprox card id"
        self.add_slot_args(parser)
        self.add_card_arg(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.cn is not None:
            slotinfo = self.cmd.get_slot_info()
            selected = SlotNumber.from_fw(self.cmd.get_active_slot())
            lf_tag_type = TagSpecificType(slotinfo[selected - 1]["lf"])
            if lf_tag_type != TagSpecificType.HIDProx:
                print(f"{color_string((CR, 'WARNING'))}: Slot type not set to HIDProx.")
            if args.fc is None:
                args.fc = 0
            if args.il is None:
                args.il = 0
            if args.oem is None:
                args.oem = 0
            format = HIDFormat.H10301
            if args.format is not None:
                format = HIDFormat[args.format]
            id = struct.pack(
                ">BIBIBH",
                format.value,
                args.fc,
                (args.cn >> 32),
                args.cn & 0xFFFFFFFF,
                args.il,
                args.oem,
            )
            self.cmd.hidprox_set_emu_id(id)
            print(" - SET hidprox tag id success.")
        else:
            format, fc, cn1, cn2, il, oem = self.cmd.hidprox_get_emu_id()
            cn = (cn1 << 32) + cn2
            print(" - GET hidprox tag id success.")
            print(f" - HIDProx/{HIDFormat(format)}")
            if fc > 0:
                print(f"   FC: {color_string((CG, fc))}")
            if il > 0:
                print(f"   IL: {color_string((CG, il))}")
            if oem > 0:
                print(f"   OEM: {color_string((CG, oem))}")
            print(f"   CN: {color_string((CG, cn))}")


@lf_ioprox.command("read")
class LFIOProxRead(LFIOProxReadArgsUnit, ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Scan ioProx tag and print version, facility, card number and raw"
        )
        return self.add_card_arg(parser, required=False)

    def on_exec(self, args: argparse.Namespace):
        ver, fc, cn, raw8, *futureuse = self.cmd.ioprox_scan()
        print(f"ioProx XSF format")
        print(f"   Version: {color_string((CG, ver))}")
        print(f"   Facility: {color_string((CG, f'{fc} [0x{fc:02X}]'))}")
        print(f"   ID: {color_string((CY, cn))}")
        print(f"   Raw: {color_string((CY, raw8.hex().upper()))}")


@lf_ioprox.command("write")
class LFIOProxWriteT55xx(LFIOProxIdArgsUnit, ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Write ioProx card data to t55xx"
        return self.add_card_arg(parser, required=False)

    def on_exec(self, args: argparse.Namespace):
        # defaults
        ver = args.ver if args.ver is not None else 1
        fc = args.fc if args.fc is not None else 0
        cn = args.cn if args.cn is not None else 0

        # raw8 priority
        if args.raw8 is not None:
            raw8 = self.parse_raw8(args.raw8)
            ver, fc, cn, raw8, *futureuse = self.cmd.ioprox_decode_raw(raw8)
        else:
            res = self.cmd.ioprox_compose_id(args.ver, args.fc, args.cn)
            raw8 = res[3]

        payload16 = struct.pack(">BBH8s4x", ver & 0xFF, fc & 0xFF, cn & 0xFFFF, raw8)
        result = self.cmd.ioprox_write_to_t55xx(payload16)

        print(f"ioProx XSF format")
        print(f"   Version: {color_string((CG, ver))}")
        print(f"   Facility: {color_string((CG, f'{fc} [0x{fc:02X}]'))}")
        print(f"   ID: {color_string((CY, cn))}")
        print(f"   Raw: {color_string((CY, raw8.hex().upper()))}")
        print("Write done.")


@lf_ioprox.command("econfig")
class LFIOProxEconfig(SlotIndexArgsAndGoUnit, LFIOProxIdArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set/Get emulated ioProx card id (stored in slot)"
        self.add_slot_args(parser)
        self.add_card_arg(
            parser, required=False
        )  # SET when --cn or --raw present; GET otherwise
        return parser

    def on_exec(self, args: argparse.Namespace):
        do_set = (
            (args.cn is not None)
            or (args.raw8 is not None)
            or (args.fc is not None)
            or (args.ver is not None)
        )

        if do_set:
            # warn if slot isn't ioProx
            slotinfo = self.cmd.get_slot_info()
            selected = SlotNumber.from_fw(self.cmd.get_active_slot())
            lf_tag_type = TagSpecificType(slotinfo[selected - 1]["lf"])
            if lf_tag_type != TagSpecificType.ioProx:
                print(f"{color_string((CR, 'WARNING'))}: Slot type not set to IOProx.")

            # defaults
            ver = args.ver if args.ver is not None else 1
            fc = args.fc if args.fc is not None else 0
            cn = args.cn if args.cn is not None else 0

            # raw8 priority
            if args.raw8 is not None:
                raw8 = self.parse_raw8(args.raw8)
                ver, fc, cn, raw8, *futureuse = self.cmd.ioprox_decode_raw(raw8)
            else:
                res = self.cmd.ioprox_compose_id(args.ver, args.fc, args.cn)
                raw8 = res[3]

            payload16 = struct.pack(
                ">BBH8s4x", ver & 0xFF, fc & 0xFF, cn & 0xFFFF, raw8
            )

            result = self.cmd.ioprox_set_emu_id(payload16)

            print(f"ioProx XSF format")
            print(f"   Version: {color_string((CG, ver))}")
            print(f"   Facility: {color_string((CG, f'{fc} [0x{fc:02X}]'))}")
            print(f"   ID: {color_string((CY, cn))}")
            print(f"   Raw: {color_string((CY, raw8.hex().upper()))}")

        else:
            # GET
            ver, fc, cn, raw8, *futureuse = self.cmd.ioprox_get_emu_id()
            print(f"ioProx XSF format")
            print(f"   Version: {color_string((CG, ver))}")
            print(f"   Facility: {color_string((CG, f'{fc} [0x{fc:02X}]'))}")
            print(f"   ID: {color_string((CY, cn))}")
            print(f"   Raw: {color_string((CY, raw8.hex().upper()))}")


def pac_decode_raw(raw: bytes) -> bytes:
    """Decode 16-byte T55XX bitstream to 8-byte card ID.

    Validates sync, UART framing, header, and checksum.
    """
    if len(raw) != 16:
        raise ValueError("Raw data must be exactly 16 bytes (128 bits)")

    def get_bit(pos):
        return (raw[pos >> 3] >> (7 - (pos & 7))) & 1

    # Sync marker
    for i in range(8):
        if not get_bit(i):
            raise ValueError("Invalid sync marker (expected 0xFF)")

    decoded = []
    for f in range(12):
        start = 8 + f * 10
        if get_bit(start):
            raise ValueError(f"Invalid start bit in UART frame {f}")
        byte_val = 0
        ones = 0
        for i in range(7):
            if get_bit(start + 1 + i):
                byte_val |= 1 << i
                ones += 1
        if get_bit(start + 8):
            ones += 1
        if (ones & 1) == 0:
            raise ValueError(f"Parity error in UART frame {f}")
        if not get_bit(start + 9):
            raise ValueError(f"Invalid stop bit in UART frame {f}")
        decoded.append(byte_val)

    if decoded[0] != 0x02:
        raise ValueError(f"Invalid STX: 0x{decoded[0]:02X}")
    if decoded[1] != 0x32 or decoded[2] != 0x30:
        raise ValueError("Invalid header (expected '20')")

    card_id = bytes(decoded[3:11])
    xor_check = 0
    for b in card_id:
        xor_check ^= b
    if xor_check != decoded[11]:
        raise ValueError(
            f"Checksum error: expected 0x{xor_check:02X}, got 0x{decoded[11]:02X}"
        )

    return card_id


@lf_pac.command("read")
class LFPacRead(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Scan PAC/Stanley tag and print card ID"
        return parser

    def on_exec(self, args: argparse.Namespace):
        card_id = self.cmd.pac_scan()
        card_id_ascii = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in card_id)
        raw = pac_encode_raw(card_id)
        print(
            f" PAC/Stanley - CN: {color_string((CG, card_id_ascii))} | Raw: {raw.hex().upper()}"
        )


class LFPacIdArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_card_arg(parser: ArgumentParserNoExit, required=False):
        group = parser.add_mutually_exclusive_group(required=required)
        group.add_argument(
            "--cn",
            type=str,
            help="Card number (8 ASCII characters, e.g. CARD0001)",
            metavar="<ascii>",
        )
        group.add_argument(
            "--raw",
            type=str,
            help="T55XX bitstream (32 hex chars, PM3 raw format)",
            metavar="<hex>",
        )
        return parser

    def before_exec(self, args: argparse.Namespace):
        if not super().before_exec(args):
            return False
        if args.cn is not None:
            if len(args.cn) != 8:
                raise ArgsParserError("Card number must be exactly 8 characters")
            try:
                args.id = args.cn.encode("ascii").hex()
            except UnicodeEncodeError:
                raise ArgsParserError("Card number must be ASCII characters only")
        elif args.raw is not None:
            if not re.match(r"^[a-fA-F0-9]{32}$", args.raw):
                raise ArgsParserError(
                    "Raw must be exactly 32 hex characters (128-bit T55XX bitstream)"
                )
            try:
                card_id = pac_decode_raw(bytes.fromhex(args.raw))
            except ValueError as e:
                raise ArgsParserError(f"Invalid PAC raw data: {e}")
            args.id = card_id.hex()
        else:
            args.id = None
            return True
        # PAC uses 7-bit UART frames; MSB of each byte is not encoded
        id_bytes = bytes.fromhex(args.id)
        if any(b > 0x7F for b in id_bytes):
            raise ArgsParserError(
                "PAC card IDs are 7-bit only (each byte must be 0x00-0x7F)"
            )
        return True

    def args_parser(self) -> ArgumentParserNoExit:
        raise NotImplementedError("Please implement this")

    def on_exec(self, args: argparse.Namespace):
        raise NotImplementedError("Please implement this")


@lf_pac.command("write")
class LFPacWriteT55xx(LFPacIdArgsUnit, ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Write PAC/Stanley id to T55xx"
        return self.add_card_arg(parser, required=True)

    def on_exec(self, args: argparse.Namespace):
        id_bytes = bytes.fromhex(args.id)
        self.cmd.pac_write_to_t55xx(id_bytes)
        id_ascii = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in id_bytes)
        raw = pac_encode_raw(id_bytes)
        print(f" - PAC/Stanley write done - CN: {id_ascii} | Raw: {raw.hex().upper()}")


@lf_pac.command("econfig")
class LFPacEconfig(SlotIndexArgsAndGoUnit, LFPacIdArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set emulated PAC/Stanley card ID"
        self.add_slot_args(parser)
        self.add_card_arg(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.id is not None:
            slotinfo = self.cmd.get_slot_info()
            selected = SlotNumber.from_fw(self.cmd.get_active_slot())
            lf_tag_type = TagSpecificType(slotinfo[selected - 1]["lf"])
            if lf_tag_type != TagSpecificType.PAC:
                print(f"{color_string((CR, 'WARNING'))}: Slot type not set to PAC.")
            self.cmd.pac_set_emu_id(bytes.fromhex(args.id))
            print(" - Set PAC/Stanley tag id success.")
        else:
            response = self.cmd.pac_get_emu_id()
            card_id_ascii = "".join(
                chr(b) if 0x20 <= b < 0x7F else "." for b in response
            )
            raw = pac_encode_raw(response)
            print(" - Get PAC/Stanley tag id success.")
            print(f"CN: {card_id_ascii} | Raw: {raw.hex().upper()}")


@lf_viking.command("read")
class LFVikingRead(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Scan Viking tag and print id"
        return parser

    def on_exec(self, args: argparse.Namespace):
        id = self.cmd.viking_scan()
        print(f" Viking: {color_string((CG, id.hex()))}")


@lf_viking.command("write")
class LFVikingWriteT55xx(LFVikingIdArgsUnit, ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Write Viking id to t55xx"
        return self.add_card_arg(parser, required=True)

    def on_exec(self, args: argparse.Namespace):
        id_hex = args.id
        id_bytes = bytes.fromhex(id_hex)
        self.cmd.viking_write_to_t55xx(id_bytes)
        print(f" - Viking ID(8H): {id_hex} write done.")


@lf_idteck.command("write")
class LFIdteckWriteT55xx(LFIdteckIdArgsUnit, ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Clone an IDTECK PSK1 frame onto a T55xx tag."
        return self.add_card_arg(parser, required=True)

    def on_exec(self, args: argparse.Namespace):
        id_hex = args.id
        id_bytes = bytes.fromhex(id_hex)
        self.cmd.idteck_write_to_t55xx(id_bytes)
        print(f" - IDTECK frame {id_hex} written to T55xx.")


@lf_idteck.command("econfig")
class LFIdteckEconfig(SlotIndexArgsAndGoUnit, LFIdteckIdArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Get or set the IDTECK emulated id on a slot. "
            "Provide --id to set; omit it to read back the current value."
        )
        self.add_slot_args(parser)
        self.add_card_arg(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.id is not None:
            slotinfo = self.cmd.get_slot_info()
            selected = SlotNumber.from_fw(self.cmd.get_active_slot())
            lf_tag_type = TagSpecificType(slotinfo[selected - 1]["lf"])
            if lf_tag_type != TagSpecificType.IDTECK:
                print(
                    f"{color_string((CR, 'WARNING'))}: Slot LF type is not IDTECK. "
                    f"Set it with: hw slot type -s <n> -t IDTECK"
                )
            self.cmd.idteck_set_emu_id(bytes.fromhex(args.id))
            print(f" - IDTECK emu id set to {args.id.upper()}.")
        else:
            response = self.cmd.idteck_get_emu_id()
            info = _idteck_frame_info(response)
            print(f" - IDTECK emu id: {response.hex().upper()}")
            print(
                f"   Preamble : {info['preamble_hex']}"
                + (
                    ""
                    if info["preamble_valid"]
                    else f"  {color_string((CR, '(not IDTK)'))}"
                )
            )
            print(f"   Payload  : {info['payload_hex']}")
            print(f"   Card ID  : {info['card_id']} (0x{info['card_id']:06X})")
            chk_tag = (
                color_string((CG, "ok"))
                if info["checksum_valid"]
                else color_string((CY, "mismatch"))
            )
            print(
                f"   Checksum : 0x{info['checksum']:02X} (expected 0x{info['checksum_expected']:02X}, {chk_tag})"
            )


@lf.command("clone")
class LFT55xxClone(ReaderRequiredUnit):
    """
    Clone a scanned or manually-specified LF card ID onto a blank T55xx tag.

    Supported types and their required arguments:

      em410x   --id <10 hex>         e.g. --id DEADBEEF88
      electra  --id <26 hex>         e.g. --id DEADBEEF880102030405060708
      hid      -f <format> --cn <n>  e.g. -f H10301 --fc 10 --cn 1234
      ioprox   --ver <n> --fc <n> --cn <n>   OR   --raw8 <16 hex>
      pac      --id <8 ASCII>        e.g. --id 11223344
      viking   --id <8 hex>          e.g. --id DEADBEEF
      idteck   --id <16 hex>         e.g. --id 4944544BDEADBEEF
                                      (or 8 hex for payload only; preamble auto-prepended)

    Only supported on Chameleon Ultra (Lite has no LF writer).
    """

    TYPES = ["em410x", "electra", "hid", "ioprox", "pac", "viking", "idteck"]

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Clone a LF card ID onto a blank T55xx tag.\n"
            "Supported types: em410x, electra, hid, ioprox, pac, viking, idteck.\n"
            "Only supported on Chameleon Ultra (Lite has no LF writer)."
        )
        parser.add_argument(
            "-t",
            "--type",
            type=str,
            required=True,
            choices=self.TYPES,
            metavar="TYPE",
            help="Card type: " + ", ".join(self.TYPES),
        )
        # EM410x / Electra / Viking
        parser.add_argument(
            "--id",
            type=str,
            required=False,
            metavar="HEX",
            help="Card ID in hex: 10 for em410x, 26 for electra, 8 for viking, 8 or 16 for idteck; 8 ASCII chars for pac",
        )
        # HID Prox
        parser.add_argument(
            "-f",
            "--format",
            type=str,
            required=False,
            choices=[x.name for x in HIDFormat],
            metavar="FORMAT",
            help="HID Prox format, e.g. H10301 (required for hid type)",
        )
        parser.add_argument(
            "--fc",
            type=int,
            required=False,
            metavar="INT",
            help="Facility code (HID / ioProx)",
        )
        parser.add_argument(
            "--cn",
            type=int,
            required=False,
            metavar="INT",
            help="Card number (HID / ioProx)",
        )
        parser.add_argument(
            "--il",
            type=int,
            required=False,
            metavar="INT",
            help="Issue level (HID, optional)",
        )
        parser.add_argument(
            "--oem",
            type=int,
            required=False,
            metavar="INT",
            help="OEM code (HID, optional)",
        )
        # ioProx
        parser.add_argument(
            "--ver",
            type=int,
            required=False,
            metavar="INT",
            help="Version byte (ioProx)",
        )
        parser.add_argument(
            "--raw8",
            type=str,
            required=False,
            metavar="HEX",
            help="ioProx raw 8 bytes in hex, e.g. 007854E03A5D65AB",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        # Clone requires LF writer — only available on Chameleon Ultra (not Lite)
        if self.cmd.get_device_model() != 0:
            print(
                f" - Error: LF clone requires Chameleon Ultra. Lite has no LF writer."
            )
            return
        t = args.type

        if t in ("em410x", "electra"):
            if args.id is None:
                raise ArgsParserError("--id is required for em410x / electra")
            expected = 10 if t == "em410x" else 26
            if not re.match(r"^[a-fA-F0-9]{" + str(expected) + r"}$", args.id):
                raise ArgsParserError(
                    f"--id must be exactly {expected} hex characters for {t}"
                )
            id_bytes = bytes.fromhex(args.id)
            self.cmd.em410x_write_to_t55xx(id_bytes)
            label = "EM410x Electra" if t == "electra" else "EM410x"
            print(f" - {label} ID cloned to T55xx: {args.id.upper()}")

        elif t == "hid":
            if args.format is None:
                raise ArgsParserError("-f/--format is required for hid")
            if args.cn is None:
                raise ArgsParserError("--cn is required for hid")
            fmt = HIDFormat[args.format]
            fc = args.fc if args.fc is not None else 0
            il = args.il if args.il is not None else 0
            oem = args.oem if args.oem is not None else 0
            LFHIDIdArgsUnit.check_limits(fmt.value, fc, args.cn, il, oem)
            cn = args.cn
            id_bytes = struct.pack(
                ">BIBIBH",
                fmt.value,
                fc,
                (cn >> 32),
                cn & 0xFFFFFFFF,
                il,
                oem,
            )
            self.cmd.hidprox_write_to_t55xx(id_bytes)
            print(f" - HID Prox cloned to T55xx")
            print(f"   Format : {fmt.name}")
            if fc:
                print(f"   FC     : {fc}")
            if il:
                print(f"   IL     : {il}")
            if oem:
                print(f"   OEM    : {oem}")
            print(f"   CN     : {cn}")

        elif t == "ioprox":
            ver = args.ver if args.ver is not None else 1
            fc = int(args.fc) if args.fc is not None else 0
            cn = args.cn if args.cn is not None else 0
            if args.raw8 is not None:
                raw8 = LFIOProxIdArgsUnit.parse_raw8(args.raw8)
                ver, fc, cn, raw8, *_ = self.cmd.ioprox_decode_raw(raw8)
            else:
                res = self.cmd.ioprox_compose_id(ver, fc, cn)
                raw8 = res[3]
            payload16 = struct.pack(
                ">BBH8s4x", ver & 0xFF, fc & 0xFF, cn & 0xFFFF, raw8
            )
            self.cmd.ioprox_write_to_t55xx(payload16)
            print(f" - ioProx cloned to T55xx")
            print(f"   Ver    : {ver}")
            print(f"   FC     : {fc} [0x{fc:02X}]")
            print(f"   CN     : {cn}")
            print(f"   Raw8   : {raw8.hex().upper()}")

        elif t == "pac":
            if args.id is None:
                raise ArgsParserError("--id is required for pac (8 ASCII characters)")
            if len(args.id) != 8:
                raise ArgsParserError("--id must be exactly 8 ASCII characters for pac")
            id_bytes = args.id.encode("ascii")
            self.cmd.pac_write_to_t55xx(id_bytes)
            print(f" - PAC/Stanley ID cloned to T55xx: {args.id}")

        elif t == "viking":
            if args.id is None:
                raise ArgsParserError("--id is required for viking")
            if not re.match(r"^[a-fA-F0-9]{8}$", args.id):
                raise ArgsParserError(
                    "--id must be exactly 8 hex characters for viking"
                )
            id_bytes = bytes.fromhex(args.id)
            self.cmd.viking_write_to_t55xx(id_bytes)
            print(f" - Viking ID cloned to T55xx: {args.id.upper()}")

        elif t == "idteck":
            if args.id is None:
                raise ArgsParserError("--id is required for idteck (8 or 16 hex)")
            if re.match(r"^[a-fA-F0-9]{16}$", args.id):
                id_hex = args.id
            elif re.match(r"^[a-fA-F0-9]{8}$", args.id):
                id_hex = "4944544B" + args.id  # prepend "IDTK" preamble
            else:
                raise ArgsParserError("--id must be 8 or 16 hex characters for idteck")
            id_bytes = bytes.fromhex(id_hex)
            self.cmd.idteck_write_to_t55xx(id_bytes)
            print(f" - IDTECK frame cloned to T55xx: {id_hex.upper()}")


@lf_generic.command("adcread")
class LFADCGenericRead(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Read ADC and return the array"
        return parser

    def on_exec(self, args: argparse.Namespace):
        resp = self.cmd.adc_generic_read()

        if resp is not None:
            print(f"generic read data[{len(resp)}]:")
            width = 50
            for i in range(0, len(resp), width):
                chunk = resp[i : i + width]
                hexpart = " ".join(f"{b:02x}" for b in chunk)
                binpart = "".join("1" if b >= 0xBF else "0" for b in chunk)
                print(f"{i:04x} {hexpart:<{width * 3}} {binpart}")

            avg = 0
            for val in resp:
                avg += val
            print(f"avg: {hex(round(avg / len(resp)))}")
        else:
            print("generic read error")


@lf_em_410x.command("econfig")
class LFEM410xEconfig(SlotIndexArgsAndGoUnit, LFEMIdArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set emulated em410x card id"
        self.add_slot_args(parser)
        self.add_card_arg(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.id is not None:
            self.cmd.em410x_set_emu_id(bytes.fromhex(args.id))
            print(" - Set em410x tag id success.")
        else:
            response = self.cmd.em410x_get_emu_id()
            print(" - Get em410x tag id success.")
            print(f"ID: {response.hex()}")


@lf_viking.command("econfig")
class LFVikingEconfig(SlotIndexArgsAndGoUnit, LFVikingIdArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set emulated Viking card id"
        self.add_slot_args(parser)
        self.add_card_arg(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.id is not None:
            slotinfo = self.cmd.get_slot_info()
            selected = SlotNumber.from_fw(self.cmd.get_active_slot())
            lf_tag_type = TagSpecificType(slotinfo[selected - 1]["lf"])
            if lf_tag_type != TagSpecificType.Viking:
                print(f"{color_string((CR, 'WARNING'))}: Slot type not set to Viking.")
            self.cmd.viking_set_emu_id(bytes.fromhex(args.id))
            print(" - Set Viking tag id success.")
        else:
            response = self.cmd.viking_get_emu_id()
            print(" - Get Viking tag id success.")
            print(f"ID: {response.hex().upper()}")


@lf_jablotron.command("read")
class LFJablotronRead(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Scan Jablotron tag and print id"
        return parser

    def on_exec(self, args: argparse.Namespace):
        id = self.cmd.jablotron_scan()
        card_id = jablotron_card_id(id)
        print(f" Jablotron ID: {color_string((CG, id.hex().upper()))}")
        print(f" Card number:  {color_string((CY, str(card_id)))}")


@lf_jablotron.command("write")
class LFJablotronWriteT55xx(LFJablotronIdArgsUnit, ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Write Jablotron id to t55xx"
        return self.add_card_arg(parser, required=True)

    def on_exec(self, args: argparse.Namespace):
        id_hex = args.id
        id_bytes = bytes.fromhex(id_hex)
        self.cmd.jablotron_write_to_t55xx(id_bytes)
        print(f" - Jablotron ID: {id_hex.upper()} write done.")


@lf_jablotron.command("econfig")
class LFJablotronEconfig(SlotIndexArgsAndGoUnit, LFJablotronIdArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set emulated Jablotron card id"
        self.add_slot_args(parser)
        self.add_card_arg(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.id is not None:
            slotinfo = self.cmd.get_slot_info()
            selected = SlotNumber.from_fw(self.cmd.get_active_slot())
            lf_tag_type = TagSpecificType(slotinfo[selected - 1]["lf"])
            if lf_tag_type != TagSpecificType.Jablotron:
                print(
                    f"{color_string((CR, 'WARNING'))}: Slot type not set to Jablotron."
                )
            self.cmd.jablotron_set_emu_id(bytes.fromhex(args.id))
            print(" - Set Jablotron tag id success.")
        else:
            response = self.cmd.jablotron_get_emu_id()
            card_id = jablotron_card_id(response)
            print(" - Get Jablotron tag id success.")
            print(f"ID: {response.hex().upper()}")
            print(f"Card: {card_id}")


@lf_em_4x05.command("read")
class LFEm4x05Read(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Scan EM4x05 or EM4x69 tag (reader-talk-first) and print config, UID"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            pwd = int(args.pwd, 16) if hasattr(args, "pwd") and args.pwd else 0
        except ValueError:
            print(f"{CR}Invalid password, expected hex{C0}")
            return
        config, uid, uid_hi, is_em4x69, uid_block = self.cmd.em4x05_scan(pwd=pwd)
        tag_label = "EM4x69" if is_em4x69 else "EM4x05"
        rl = bool((config >> 6) & 1)
        print(f" Tag type : {CG}{tag_label}{C0}")
        print(f" Config   : {CG}{config:#010x}{C0}")
        print(f" UID block: {CG}{uid_block}{C0}")
        if rl:
            print(
                f" Auth     : {CG}LOGIN used (pwd={args.pwd.upper() if hasattr(args, 'pwd') and args.pwd else '00000000'}){C0}"
            )
        if is_em4x69:
            uid64 = (uid_hi << 32) | uid
            print(f" UID (64) : {CG}{uid64:016x}{C0}")
        else:
            print(f" UID      : {CG}{uid:08x}{C0}")


@lf.command("sniff")
class LFSniff(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Capture raw LF field ADC samples (125kHz, 8µs/sample). "
            "~0x80 = field on, lower values = gap or no field."
        )
        parser.add_argument(
            "--timeout",
            type=int,
            default=2000,
            metavar="MS",
            help="Capture duration in milliseconds (default: 2000, max: 10000, firmware blocks for full duration)",
        )
        parser.add_argument(
            "--out",
            type=str,
            default=None,
            metavar="FILE",
            help="Save raw samples to binary file (for offline analysis)",
        )
        parser.add_argument(
            "--hex", action="store_true", help="Print hex dump of samples to screen"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        timeout = max(1, min(10000, args.timeout))
        print(f" Capturing LF field for {timeout}ms at 125kHz (8µs/sample)...")
        resp = self.cmd.lf_sniff(timeout_ms=timeout)

        if resp.status != Status.LF_TAG_OK or not resp.data:
            print(f"{CR}No samples captured{C0}")
            return

        import chameleon_cli_unit as _self_mod

        data = bytes(resp.data)
        _self_mod._last_capture = data

        n = len(data)
        duration_ms = n * 8 / 1000
        print(f" Captured : {CG}{n}{C0} bytes ({duration_ms:.1f}ms)")

        mn = min(data)
        mx = max(data)
        mean = sum(data) // len(data)
        print(
            f" Range    : {CG}0x{mn:02x}{C0} – {CG}0x{mx:02x}{C0}  mean: {CG}0x{mean:02x}{C0}"
        )

        # Detect real field gaps — they drop to near zero (0x00-0x40),
        # well below the steady carrier (~0xb0). Use half of mean as threshold
        # to avoid false positives from the antenna startup transient.
        gap_threshold = mean // 2
        # Skip first 200 samples (1.6ms) to ignore startup ringing
        steady_data = data[200:]
        gap_count = sum(1 for b in steady_data if b < gap_threshold)
        if gap_count > 0:
            print(
                f" Gaps     : {CG}{gap_count}{C0} samples below 0x{gap_threshold:02x} (real field drops)"
            )
        else:
            print(
                f" Gaps     : {CR}none detected — flat carrier (no gap commands sent){C0}"
            )

        if args.hex:
            print()
            print(f"  addr  {'hex bytes':47s}  level")
            print(f"  ----  {'-'*47}  ----------------")
            for i in range(0, min(n, 256), 16):
                row = data[i : i + 16]
                hex_part = " ".join(f"{b:02x}" for b in row)
                bar = ""
                for b in row:
                    if b < 0x10:
                        bar += "_"  # gap / field off
                    elif b < 0x40:
                        bar += "."  # ringing decay
                    elif b < 0x80:
                        bar += "-"  # low
                    elif b < 0xA0:
                        bar += "+"  # mid
                    elif b < 0xC0:
                        bar += "o"  # steady carrier
                    elif b < 0xE0:
                        bar += "O"  # high
                    else:
                        bar += "#"  # clipped 0xff
                print(f"  {i:04x}  {hex_part:<47s}  {bar}")
            if n > 256:
                print(f"  ... ({n - 256} more bytes, use --out to save all)")
            print()
            print("  _ gap  . ringing  - low  + mid  o carrier  O high  # clipped")

        if args.out:
            try:
                with open(args.out, "wb") as f:
                    f.write(data)
                print(f" Saved    : {CG}{args.out}{C0} ({n} bytes)")
            except Exception as e:
                print(f"{CR}Failed to save: {e}{C0}")


class LFIndalaIdArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_card_arg(parser: ArgumentParserNoExit, required=False):
        group = parser.add_mutually_exclusive_group(required=required)
        group.add_argument(
            "-r",
            "--raw",
            type=str,
            help="Raw 64-bit frame (16 hex chars)",
            metavar="<hex>",
        )
        group.add_argument(
            "--fc",
            type=int,
            dest="_indala_fc",
            help="Facility code (26-bit format, use with --cn)",
            metavar="<dec>",
        )
        parser.add_argument(
            "--cn",
            type=int,
            dest="_indala_cn",
            help="Card number (26-bit format, use with --fc)",
            metavar="<dec>",
        )
        return parser

    def before_exec(self, args: argparse.Namespace):
        if not super().before_exec(args):
            return False
        fc = getattr(args, "_indala_fc", None)
        cn = getattr(args, "_indala_cn", None)
        if fc is not None or cn is not None:
            if fc is None or cn is None:
                raise ArgsParserError("--fc and --cn must be used together")
            if not (0 <= fc <= 255):
                raise ArgsParserError("FC must be 0-255")
            if not (0 <= cn <= 65535):
                raise ArgsParserError("CN must be 0-65535")
            args.raw = indala_encode_raw(fc, cn).hex()
        if args.raw is not None and not re.match(r"^[a-fA-F0-9]{16}$", args.raw):
            raise ArgsParserError("Raw must be exactly 16 hex characters")
        return True

    def args_parser(self) -> ArgumentParserNoExit:
        raise NotImplementedError("Please implement this")

    def on_exec(self, args: argparse.Namespace):
        raise NotImplementedError("Please implement this")


@lf_indala.command("read")
class LFIndalaRead(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Scan for an Indala tag"
        return parser

    def on_exec(self, args: argparse.Namespace):
        resp = self.cmd.indala_scan()
        if resp.status != Status.LF_TAG_OK:
            print(f" Indala scan failed: {resp.status}")
            return
        print(f" {indala_format_output(resp.data[:8])}")


@lf_indala.command("write")
class LFIndalaWriteT55xx(LFIndalaIdArgsUnit, ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Clone Indala tag to T55XX (use -r <hex>, or --fc <n> --cn <n>)"
        )
        parser = self.add_card_arg(parser, required=True)
        return parser

    def on_exec(self, args: argparse.Namespace):
        id_bytes = bytes.fromhex(args.raw)
        self.cmd.indala_write_to_t55xx(id_bytes)
        print(f" {indala_format_output(id_bytes)}")
        print(" Write done. Verify with 'lf indala read'.")


@lf_indala.command("econfig")
class LFIndalaEconfig(SlotIndexArgsAndGoUnit, LFIndalaIdArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Get or set the Indala emulated frame on a slot. "
            "Provide -r <hex> or --fc/--cn to set; omit to read back the current value."
        )
        self.add_slot_args(parser)
        self.add_card_arg(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.raw is not None:
            slotinfo = self.cmd.get_slot_info()
            selected = SlotNumber.from_fw(self.cmd.get_active_slot())
            lf_tag_type = TagSpecificType(slotinfo[selected - 1]["lf"])
            if lf_tag_type != TagSpecificType.Indala:
                print(
                    f"{color_string((CR, 'WARNING'))}: Slot LF type is not Indala. "
                    f"Set it with: hw slot type -s <n> -t Indala"
                )
            self.cmd.indala_set_emu_id(bytes.fromhex(args.raw))
            print(f" - Indala emu frame set to {args.raw.upper()}.")
        else:
            response = self.cmd.indala_get_emu_id()
            print(" - Get Indala emu frame success.")
            print(f" {indala_format_output(response)}")
