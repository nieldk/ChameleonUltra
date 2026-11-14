"""cli_hf_mfu — MIFARE Ultralight / NTAG commands (hf mfu ...).

Read/write pages, counters, signatures, NDEF, NFC import, UL-C gen, dump,
emulation slot load/save/config/detect, and the MFUAuthArgsUnit base (moved
from cli_core). Foundation imported explicitly from cli_core."""

import re
import sys
import os
import threading
import subprocess
import struct
import argparse

from cli_core import (
    CrackEffect,
    ArgumentParserNoExit,
    CG,
    CR,
    CY,
    ClassVar,
    DeviceRequiredUnit,
    HF14AAntiCollArgsUnit,
    MifareUltralightWriteMode,
    ReaderRequiredUnit,
    SlotIndexArgsAndGoUnit,
    SlotNumber,
    Status,
    TagSenseType,
    TagSpecificType,
    UnexpectedResponseError,
    chameleon_com,
    color_string,
    data,
    default_cwd,
    hf,
    hf_mfu,
    ndef,
)

# --- MFU auth-args base (moved from cli_core) ---


class MFUAuthArgsUnit(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()

        def key_parser(key: str) -> bytes:
            try:
                key = bytes.fromhex(key)
            except ValueError:
                raise ValueError("Key should be a hex string")

            if len(key) not in [4, 16]:
                raise ValueError("Key should either be 4 or 16 bytes long")

            return key

        parser.add_argument(
            "-k",
            "--key",
            type=key_parser,
            metavar="<hex>",
            help="Authentication key: 4 bytes (UL EV1/NTAG password) "
                 "or 16 bytes (Ultralight-C 3DES key, cipher order).",
        )
        parser.add_argument(
            "-l",
            action="store_true",
            dest="swap_endian",
            help="Swap endianness of the key.",
        )

        return parser

    def get_param(self, args):
        key = args.key

        if key is not None and args.swap_endian:
            key = bytearray(key)
            for i in range(len(key)):
                key[i] = key[len(key) - 1 - i]
            key = bytes(key)

        class Param:
            def __init__(self, key):
                self.key = key

        return Param(key)

    def on_exec(self, args: argparse.Namespace):
        raise NotImplementedError("Please implement this")


# --- MFU helpers + command classes ---


def detect_mfu_page_count(cmd):
    """
    Scan for a single MIFARE Ultralight / NTAG compatible tag and try to
    auto-detect its total page count, using the same GET_VERSION /
    AUTHENTICATE fingerprinting `hf mfu dump` uses.

    Returns a (tag_name, stop_page) tuple:
     - tag_name is a human readable model name, or None if it couldn't be
       pinned down exactly.
     - stop_page is the number of pages on the tag (exclusive upper bound),
       or None if the size is unknown and the caller should either read
       until the first error or ask the user for --qty.

    Raises RuntimeError with a human readable message if no single
    compatible tag could be found.
    """
    tags = cmd.hf14a_scan()
    if len(tags) > 1:
        raise RuntimeError("Collision detected, leave only one tag.")
    elif len(tags) == 0:
        raise RuntimeError("No tag detected.")
    elif tags[0]["atqa"] != b"\x44\x00" or tags[0]["sak"] != b"\x00":
        raise RuntimeError(
            f"Tag is not Mifare Ultralight compatible "
            f"(ATQA {tags[0]['atqa'].hex()} SAK {tags[0]['sak'].hex()})."
        )

    options = {
        "activate_rf_field": 0,
        "wait_response": 1,
        "append_crc": 1,
        "auto_select": 1,
        "keep_rf_field": 1,
        "check_response_crc": 1,
    }

    tag_name = None
    stop_page = None

    # first try sending the GET_VERSION command
    try:
        version = cmd.hf14a_raw(
            options=options, resp_timeout_ms=100, data=struct.pack("!B", 0x60)
        )
        if len(version) == 0:
            version = None
    except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
        version = None

    # try sending AUTHENTICATE command and observe the result
    try:
        supports_auth = (
            len(
                cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=100,
                    data=struct.pack("!B", 0x1A),
                )
            )
            != 0
        )
    except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
        supports_auth = False

    if version is not None and not supports_auth:
        # either ULEV1 or NTAG
        assert len(version) == 8

        is_mikron_ulev1 = version[1] == 0x34 and version[2] == 0x21
        if (version[2] == 3 or is_mikron_ulev1) and version[4] == 1 and version[5] == 0:
            # Ultralight EV1 V0
            size_map = {
                0x0B: ("Mifare Ultralight EV1 48b", 20),
                0x0E: ("Mifare Ultralight EV1 128b", 41),
            }
        elif version[2] == 4 and version[4] == 1 and version[5] == 0:
            # NTAG 210/212/213/215/216 V0
            size_map = {
                0x0B: ("NTAG 210", 20),
                0x0E: ("NTAG 212", 41),
                0x0F: ("NTAG 213", 45),
                0x11: ("NTAG 215", 135),
                0x13: ("NTAG 216", 231),
            }
        else:
            size_map = {}

        if version[6] in size_map:
            tag_name, stop_page = size_map[version[6]]
    elif version is None and supports_auth:
        # Ultralight C
        tag_name = "Mifare Ultralight C"
        stop_page = 48
    elif version is None and not supports_auth:
        try:
            # Invalid command returning a NAK means that's some old type of NTAG.
            cmd.hf14a_raw(
                options=options, resp_timeout_ms=100, data=struct.pack("!B", 0xFF)
            )
            tag_name = "NTAG 20x"
            # exact size isn't knowable this way
        except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
            # Regular Ultralight
            tag_name = "Mifare Ultralight"
            stop_page = 16
    # else: probably Ultralight AES, which isn't supported yet - leave both None

    # release the RF field, callers will reselect properly for the actual operation
    try:
        cmd.hf14a_raw(
            options={**options, "keep_rf_field": 0},
            resp_timeout_ms=100,
            data=struct.pack("!BB", 0x30, 0),
        )
    except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
        pass

    return tag_name, stop_page


@hf_mfu.command("ercnt")
class HFMFUERCNT(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Read MIFARE Ultralight / NTAG counter value."
        parser.add_argument(
            "-c", "--counter", type=int, required=True, help="Counter index."
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        value, no_tearing = self.cmd.mfu_read_emu_counter_data(args.counter)
        print(f" - Value: {value:06x} ({value})")
        if no_tearing:
            print(f" - Tearing: {color_string((CG, 'not set'))}")
        else:
            print(f" - Tearing: {color_string((CR, 'set'))}")


@hf_mfu.command("ewcnt")
class HFMFUEWCNT(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Write MIFARE Ultralight / NTAG counter value."
        parser.add_argument(
            "-c", "--counter", type=int, required=True, help="Counter index."
        )
        parser.add_argument(
            "-v", "--value", type=int, required=True, help="Counter value (24-bit)."
        )
        parser.add_argument(
            "-t",
            "--reset-tearing",
            action="store_true",
            help="Reset tearing event flag.",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.value > 0xFFFFFF:
            print(color_string((CR, f"Counter value {args.value:#x} is too large.")))
            return

        self.cmd.mfu_write_emu_counter_data(
            args.counter, args.value, args.reset_tearing
        )

        print("- Ok")


@hf_mfu.command("rdpg")
class HFMFURDPG(MFUAuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = "MIFARE Ultralight / NTAG read one page"
        parser.add_argument(
            "-p",
            "--page",
            type=int,
            required=True,
            metavar="<dec>",
            help="The page where the key will be used against",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)

        if param.key is not None and len(param.key) == 16:
            try:
                data = self.cmd.mf0_ulc_read(param.key, args.page, 1)
                print(f" - Data: {bytes(data[:4]).hex()}")
            except UnexpectedResponseError:
                print(color_string((CR, " - Auth failed")))
            return

        options = {
            "activate_rf_field": 0,
            "wait_response": 1,
            "append_crc": 1,
            "auto_select": 1,
            "keep_rf_field": 0,
            "check_response_crc": 1,
        }

        if param.key is not None:
            options["keep_rf_field"] = 1
            try:
                resp = self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!B", 0x1B) + param.key,
                )

                failed_auth = len(resp) < 2
                if not failed_auth:
                    print(f" - PACK: {resp[:2].hex()}")
            except Exception:
                # failed auth may cause tags to be lost
                failed_auth = True

            options["keep_rf_field"] = 0
            options["auto_select"] = 0
        else:
            failed_auth = False

        if not failed_auth:
            resp = self.cmd.hf14a_raw(
                options=options,
                resp_timeout_ms=200,
                data=struct.pack("!BB", 0x30, args.page),
            )
            print(f" - Data: {resp[:4].hex()}")
        else:
            try:
                self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!BB", 0x30, args.page),
                )
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                # we may lose the tag again here
                pass
            print(color_string((CR, " - Auth failed")))


@hf_mfu.command("wrpg")
class HFMFUWRPG(MFUAuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = "MIFARE Ultralight / NTAG write one page"
        parser.add_argument(
            "-p",
            "--page",
            type=int,
            required=True,
            metavar="<dec>",
            help="The index of the page to write to.",
        )
        parser.add_argument(
            "-d",
            "--data",
            type=bytes.fromhex,
            required=True,
            metavar="<hex>",
            help="Your page data, as a 4 byte (8 character) hex string.",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)

        data = args.data
        if len(data) != 4:
            print(
                color_string(
                    (CR, "Page data should be a 4 byte (8 character) hex string")
                )
            )
            return

        if param.key is not None and len(param.key) == 16:
            try:
                self.cmd.mf0_ulc_write(param.key, args.page, data)
                print(" - Ok")
            except UnexpectedResponseError:
                print(color_string((CR, "Write failed.")))
            return

        options = {
            "activate_rf_field": 0,
            "wait_response": 1,
            "append_crc": 1,
            "auto_select": 1,
            "keep_rf_field": 0,
            "check_response_crc": 0,
        }

        if param.key is not None:
            options["keep_rf_field"] = 1
            options["check_response_crc"] = 1
            try:
                resp = self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!B", 0x1B) + param.key,
                )

                failed_auth = len(resp) < 2
                if not failed_auth:
                    print(f" - PACK: {resp[:2].hex()}")
            except Exception:
                # failed auth may cause tags to be lost
                failed_auth = True

            options["keep_rf_field"] = 0
            options["auto_select"] = 0
            options["check_response_crc"] = 0
        else:
            failed_auth = False

        if not failed_auth:
            resp = self.cmd.hf14a_raw(
                options=options,
                resp_timeout_ms=200,
                data=struct.pack("!BB", 0xA2, args.page) + data,
            )

            if resp[0] == 0x0A:
                print(" - Ok")
            else:
                print(color_string((CR, f"Write failed ({resp[0]:#04x}).")))
        else:
            # send a command just to disable the field. use read to avoid corrupting the data
            try:
                self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!BB", 0x30, args.page),
                )
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                # we may lose the tag again here
                pass
            print(color_string((CR, " - Auth failed")))


@hf_mfu.command("ndefread")
class HFMFUNDEFREAD(MFUAuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = (
            "Read an NDEF message from a MIFARE Ultralight / NTAG tag "
            "(Type 2 Tag TLV area, starting at the first user memory page)."
        )
        parser.add_argument(
            "-p",
            "--page",
            type=int,
            required=False,
            default=4,
            metavar="<dec>",
            help="First page to start scanning the TLV area from (default: 4).",
        )
        parser.add_argument(
            "-q",
            "--qty",
            type=int,
            required=False,
            default=None,
            metavar="<dec>",
            help="Number of pages to read before giving up (default: read until "
            "an empty response or a Terminator TLV is found).",
        )
        parser.add_argument(
            "-f",
            "--file",
            type=str,
            required=False,
            default="",
            help="Save the raw NDEF message bytes to this file.",
        )
        parser.add_argument(
            "--raw",
            action="store_true",
            help="Only print the raw NDEF message hex, skip record decoding.",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)

        if args.qty is not None:
            max_pages = args.qty
        else:
            try:
                tag_name, stop_page = detect_mfu_page_count(self.cmd)
            except RuntimeError as e:
                print(color_string((CR, f"- {e}")))
                return

            if tag_name is not None:
                print(f" - Detected tag type as {tag_name}.")

            if stop_page is not None:
                max_pages = stop_page - args.page
                if max_pages <= 0:
                    print(
                        color_string(
                            (
                                CR,
                                f"- Start page {args.page} is beyond the tag's "
                                f"{stop_page} pages.",
                            )
                        )
                    )
                    return
            else:
                print(
                    color_string(
                        (
                            CY,
                            "- Couldn't auto-detect tag size, reading until first error.",
                        )
                    )
                )
                max_pages = 256

        options = {
            "activate_rf_field": 0,
            "wait_response": 1,
            "append_crc": 1,
            "auto_select": 1,
            "keep_rf_field": 1,
            "check_response_crc": 1,
        }

        if param.key is not None:
            try:
                resp = self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!B", 0x1B) + param.key,
                )
                failed_auth = len(resp) < 2
                if not failed_auth:
                    print(f" - PACK: {resp[:2].hex()}")
            except Exception:
                failed_auth = True
            options["auto_select"] = 0
        else:
            failed_auth = False

        if failed_auth:
            options["keep_rf_field"] = 0
            try:
                self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!BB", 0x30, args.page),
                )
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                pass
            print(color_string((CR, " - Auth failed")))
            return

        area = bytearray()
        stopped_early = False

        for offset in range(max_pages):
            page = args.page + offset
            is_last_attempt = offset == max_pages - 1
            options["keep_rf_field"] = 0 if is_last_attempt else 1
            try:
                resp = self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!BB", 0x30, page),
                )
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                resp = None

            if resp is None or len(resp) < 4:
                stopped_early = True
                break

            area += resp[:4]

            # stop early once we've seen a Terminator TLV, no need to keep reading
            if ndef.TLV_TERMINATOR in area:
                options["keep_rf_field"] = 0
                try:
                    self.cmd.hf14a_raw(
                        options=options,
                        resp_timeout_ms=200,
                        data=struct.pack("!BB", 0x30, page),
                    )
                except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                    pass
                break

        if not area:
            print(color_string((CR, "- No data read from tag.")))
            return
        if stopped_early and args.qty is None:
            print(color_string((CY, "- Stopped at first unreadable page.")))

        message = ndef.find_ndef_message(bytes(area))
        if message is None:
            print(
                color_string((CR, "- No NDEF Message TLV found in the scanned area."))
            )
            print(f" - Raw area: {bytes(area).hex()}")
            return

        print(f" - NDEF message: {len(message)} bytes")
        if args.file != "":
            with open(args.file, "wb") as fd:
                fd.write(message)
            print(f" - Saved to {args.file}")

        if args.raw:
            print(f" - Raw: {message.hex()}")
            return

        try:
            records = ndef.decode_message(message)
        except ndef.NdefError as e:
            print(color_string((CR, f"- Failed to decode records: {e}")))
            print(f" - Raw: {message.hex()}")
            return

        for i, rec in enumerate(records):
            print(f" - Record {i}: {rec.describe()}")


@hf_mfu.command("ndefwrite")
class HFMFUNDEFWRITE(MFUAuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = (
            "Write an NDEF message to a MIFARE Ultralight / NTAG tag "
            "(Type 2 Tag TLV area, starting at the first user memory page)."
        )
        record_group = parser.add_mutually_exclusive_group(required=True)
        record_group.add_argument(
            "-u",
            "--uri",
            type=str,
            metavar="<uri>",
            help="Write a URI record, e.g. a URL.",
        )
        record_group.add_argument(
            "-t", "--text", type=str, metavar="<text>", help="Write a Text record."
        )
        record_group.add_argument(
            "-m",
            "--mime",
            type=str,
            metavar="<hex>",
            help="Write a MIME record payload as hex, requires --mime-type.",
        )
        record_group.add_argument(
            "-r",
            "--raw",
            type=str,
            metavar="<hex>",
            help="Write a complete, already-encoded raw NDEF message as hex "
            "(will still be TLV-wrapped).",
        )
        parser.add_argument(
            "--lang",
            type=str,
            default="en",
            metavar="<lang>",
            help="Text record language code (default: en).",
        )
        parser.add_argument(
            "--mime-type",
            type=str,
            default=None,
            metavar="<type>",
            help="MIME type for --mime, e.g. text/plain.",
        )
        parser.add_argument(
            "-p",
            "--page",
            type=int,
            required=False,
            default=4,
            metavar="<dec>",
            help="First page to write the TLV area at (default: 4).",
        )
        parser.add_argument(
            "-q",
            "--qty",
            type=int,
            required=False,
            default=None,
            metavar="<dec>",
            help="Number of available user pages on the tag, used as a safety "
            "check before writing (default: no check).",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)

        if args.mime is not None and args.mime_type is None:
            print(color_string((CR, "- --mime requires --mime-type")))
            return

        try:
            if args.uri is not None:
                message = ndef.encode_message([ndef.NdefRecord.uri(args.uri)])
            elif args.text is not None:
                message = ndef.encode_message(
                    [ndef.NdefRecord.text(args.text, lang=args.lang)]
                )
            elif args.mime is not None:
                message = ndef.encode_message(
                    [ndef.NdefRecord.mime(args.mime_type, bytes.fromhex(args.mime))]
                )
            else:
                message = bytes.fromhex(args.raw)
        except (ndef.NdefError, ValueError) as e:
            print(color_string((CR, f"- Failed to build NDEF message: {e}")))
            return

        wrapped = ndef.wrap_ndef_message(message)
        pages = ndef.pages_from_message(wrapped)

        if args.qty is not None:
            available = args.qty
        else:
            try:
                tag_name, stop_page = detect_mfu_page_count(self.cmd)
            except RuntimeError as e:
                print(color_string((CR, f"- {e}")))
                return

            if tag_name is not None:
                print(f" - Detected tag type as {tag_name}.")

            if stop_page is not None:
                available = stop_page - args.page
            else:
                available = None
                print(
                    color_string(
                        (
                            CY,
                            "- Couldn't auto-detect tag size, writing without a "
                            "capacity check.",
                        )
                    )
                )

        if available is not None and len(pages) > available:
            print(
                color_string(
                    (
                        CR,
                        f"- NDEF message needs {len(pages)} pages but only "
                        f"{available} are available.",
                    )
                )
            )
            return

        print(
            f" - NDEF message: {len(message)} bytes ({len(pages)} pages incl. TLV wrapper)"
        )

        options = {
            "activate_rf_field": 0,
            "wait_response": 1,
            "append_crc": 1,
            "auto_select": 1,
            "keep_rf_field": 0,
            "check_response_crc": 0,
        }

        if param.key is not None:
            options["keep_rf_field"] = 1
            options["check_response_crc"] = 1
            try:
                resp = self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!B", 0x1B) + param.key,
                )
                failed_auth = len(resp) < 2
                if not failed_auth:
                    print(f" - PACK: {resp[:2].hex()}")
            except Exception:
                failed_auth = True
            options["keep_rf_field"] = 0
            options["auto_select"] = 0
            options["check_response_crc"] = 0
        else:
            failed_auth = False

        if failed_auth:
            options["keep_rf_field"] = 0
            try:
                self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!BB", 0x30, args.page),
                )
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                pass
            print(color_string((CR, " - Auth failed")))
            return

        for offset, page_data in enumerate(pages):
            page = args.page + offset
            is_last = offset == len(pages) - 1
            options["keep_rf_field"] = 0 if is_last else 1
            try:
                resp = self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!BB", 0xA2, page) + page_data,
                )
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                print(color_string((CR, f"- Write failed at page {page} (tag lost).")))
                return

            options["auto_select"] = 0

            if len(resp) == 0 or resp[0] != 0x0A:
                code = resp[0] if len(resp) else None
                print(color_string((CR, f"- Write failed at page {page} ({code}).")))
                return

        print(color_string((CG, "- Ok, NDEF message written.")))


@hf_mfu.command("setkey")
class HFMFUSETKEY(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Change the MIFARE Ultralight C 3DES key (authenticate with the current key, then write the new key)"

        def key16(key: str) -> bytes:
            try:
                key = bytes.fromhex(key)
            except ValueError:
                raise ValueError("Key should be a hex string")
            if len(key) != 16:
                raise ValueError("Ultralight-C 3DES key must be 16 bytes")
            return key

        parser.add_argument(
            "-k",
            "--key",
            type=key16,
            required=True,
            metavar="<hex>",
            help="Current 16-byte 3DES key (cipher order).",
        )
        parser.add_argument(
            "-n",
            "--new-key",
            type=key16,
            required=True,
            metavar="<hex>",
            help="New 16-byte 3DES key (cipher order).",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            self.cmd.mf0_ulc_set_key(args.key, args.new_key)
            print(" - Ok")
        except UnexpectedResponseError:
            print(color_string((CR, " - Failed (wrong current key or key page locked)")))


@hf_mfu.command("eview")
class HFMFUEVIEW(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "MIFARE Ultralight / NTAG view emulator data"
        return parser

    def on_exec(self, args: argparse.Namespace):
        nr_pages = self.cmd.mfu_get_emu_pages_count()
        page = 0
        while page < nr_pages:
            count = min(nr_pages - page, 16)
            data = self.cmd.mfu_read_emu_page_data(page, count)
            for i in range(0, len(data), 4):
                print(f"#{page+(i >> 2):02x}: {data[i:i+4].hex()}")
            page += count


@hf_mfu.command("eload")
class HFMFUELOAD(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "MIFARE Ultralight / NTAG load emulator data"
        parser.add_argument(
            "-f", "--file", required=True, type=str, help="File to load data from."
        )
        parser.add_argument(
            "-t",
            "--type",
            type=str,
            required=False,
            help="Force writing as either raw binary or hex.",
            choices=["bin", "hex"],
        )
        return parser

    def get_param(self, args):
        class Param:
            def __init__(self):
                pass

        return Param()

    def on_exec(self, args: argparse.Namespace):
        file_type = args.type
        if file_type is None:
            if args.file.endswith(".eml") or args.file.endswith(".txt"):
                file_type = "hex"
            else:
                file_type = "bin"

        if file_type == "hex":
            with open(args.file, "r") as f:
                data = f.read()
            data = re.sub("#.*$", "", data, flags=re.MULTILINE)
            data = bytes.fromhex(data)
        else:
            with open(args.file, "rb") as f:
                data = f.read()

        # this will throw an exception on incorrect slot type
        nr_pages = self.cmd.mfu_get_emu_pages_count()
        size = nr_pages * 4
        if len(data) > size:
            print(
                color_string(
                    (
                        CR,
                        f"Dump file is too large for the current slot (expected {size} bytes).",
                    )
                )
            )
            return
        elif (len(data) % 4) > 0:
            print(
                color_string((CR, "Dump file's length is not a multiple of 4 bytes."))
            )
            return
        elif len(data) < size:
            print(
                color_string(
                    (
                        CY,
                        f"Dump file is smaller than the current slot's memory ({len(data)} < {size}).",
                    )
                )
            )

        nr_pages = len(data) >> 2
        page = 0
        while page < nr_pages:
            offset = page * 4
            cur_count = min(16, nr_pages - page)

            if offset >= len(data):
                page_data = bytes.fromhex("00000000") * cur_count
            else:
                page_data = data[offset : offset + 4 * cur_count]

            self.cmd.mfu_write_emu_page_data(page, page_data)
            page += cur_count

        print(" - Ok")


@hf_mfu.command("esave")
class HFMFUESAVE(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "MIFARE Ultralight / NTAG save emulator data"
        parser.add_argument(
            "-f", "--file", required=True, type=str, help="File to save data to."
        )
        parser.add_argument(
            "-t",
            "--type",
            type=str,
            required=False,
            help="Force writing as either raw binary or hex.",
            choices=["bin", "hex"],
        )
        return parser

    def get_param(self, args):
        class Param:
            def __init__(self):
                pass

        return Param()

    def on_exec(self, args: argparse.Namespace):
        file_type = args.type
        fd = None
        save_as_eml = False

        if file_type is None:
            if args.file.endswith(".eml") or args.file.endswith(".txt"):
                file_type = "hex"
            else:
                file_type = "bin"

        if file_type == "hex":
            fd = open(args.file, "w+")
            save_as_eml = True
        else:
            fd = open(args.file, "wb+")

        with fd:
            # this will throw an exception on incorrect slot type
            nr_pages = self.cmd.mfu_get_emu_pages_count()

            fd.truncate(0)

            # write version and signature as comments if saving as .eml
            if save_as_eml:
                try:
                    version = self.cmd.mf0_ntag_get_version_data()

                    fd.write(f"# Version: {version.hex()}\n")
                except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                    pass  # slot does not have version data

                try:
                    signature = self.cmd.mf0_ntag_get_signature_data()

                    if signature != b"\x00" * 32:
                        fd.write(f"# Signature: {signature.hex()}\n")
                except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                    pass  # slot does not have signature data

            page = 0
            while page < nr_pages:
                cur_count = min(32, nr_pages - page)

                data = self.cmd.mfu_read_emu_page_data(page, cur_count)
                if save_as_eml:
                    for i in range(0, len(data), 4):
                        fd.write(data[i : i + 4].hex() + "\n")
                else:
                    fd.write(data)

                page += cur_count

        print(" - Ok")


@hf_mfu.command("rcnt")
class HFMFURCNT(MFUAuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = "MIFARE Ultralight / NTAG read counter"
        parser.add_argument(
            "-c",
            "--counter",
            type=int,
            required=True,
            metavar="<dec>",
            help="Index of the counter to read (always 0 for NTAG, 0-2 for Ultralight EV1).",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)

        if param.key is not None and len(param.key) == 16:
            print(color_string((CR, "rcnt is not available for Ultralight-C (3DES) tags.")))
            return

        options = {
            "activate_rf_field": 0,
            "wait_response": 1,
            "append_crc": 1,
            "auto_select": 1,
            "keep_rf_field": 0,
            "check_response_crc": 1,
        }

        if param.key is not None:
            options["keep_rf_field"] = 1
            try:
                resp = self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!B", 0x1B) + param.key,
                )

                failed_auth = len(resp) < 2
                if not failed_auth:
                    print(f" - PACK: {resp[:2].hex()}")
            except Exception:
                # failed auth may cause tags to be lost
                failed_auth = True

            options["keep_rf_field"] = 0
            options["auto_select"] = 0
        else:
            failed_auth = False

        if not failed_auth:
            resp = self.cmd.hf14a_raw(
                options=options,
                resp_timeout_ms=200,
                data=struct.pack("!BB", 0x39, args.counter),
            )
            print(f" - Data: {resp[:3].hex()}")
        else:
            try:
                self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!BB", 0x39, args.counter),
                )
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                # we may lose the tag again here
                pass
            print(color_string((CR, " - Auth failed")))


@hf_mfu.command("dump")
class HFMFUDUMP(MFUAuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = "MIFARE Ultralight dump pages"
        parser.add_argument(
            "-p",
            "--page",
            type=int,
            required=False,
            metavar="<dec>",
            default=0,
            help="Manually set number of pages to dump",
        )
        parser.add_argument(
            "-q",
            "--qty",
            type=int,
            required=False,
            metavar="<dec>",
            help="Manually set number of pages to dump",
        )
        parser.add_argument(
            "-f",
            "--file",
            type=str,
            required=False,
            default="",
            help="Specify a filename for dump file",
        )
        parser.add_argument(
            "-t",
            "--type",
            type=str,
            required=False,
            choices=["bin", "hex"],
            help="Force writing as either raw binary or hex.",
        )
        return parser

    def do_dump(self, args: argparse.Namespace, param, fd, save_as_eml):
        if args.qty is not None:
            stop_page = min(args.page + args.qty, 256)
        else:
            stop_page = None

        tags = self.cmd.hf14a_scan()
        if len(tags) > 1:
            print(f"- {color_string((CR, 'Collision detected, leave only one tag.'))}")
            return
        elif len(tags) == 0:
            print(f"- {color_string((CR, 'No tag detected.'))}")
            return
        elif tags[0]["atqa"] != b"\x44\x00" or tags[0]["sak"] != b"\x00":
            err = color_string(
                (
                    CR,
                    f"Tag is not Mifare Ultralight compatible (ATQA {tags[0]['atqa'].hex()} SAK {tags[0]['sak'].hex()}).",
                )
            )
            print(f"- {err}")
            return

        if param.key is not None and len(param.key) == 16:
            print(" - Detected tag type as Mifare Ultralight C.")
            ulc_stop = stop_page if stop_page is not None else 0x2C
            count = min(ulc_stop - args.page, 48)
            if count > 0:
                try:
                    data = bytes(self.cmd.mf0_ulc_read(param.key, args.page, count))
                except UnexpectedResponseError:
                    print(color_string((CR, " - Auth failed")))
                    data = b""
                pages_read = len(data) // 4
                for idx in range(pages_read):
                    page_data = data[idx * 4: idx * 4 + 4]
                    print(f" - Page {args.page + idx:2}: {page_data.hex()}")
                    if fd is not None:
                        if save_as_eml:
                            fd.write(page_data.hex() + "\n")
                        else:
                            fd.write(page_data)
                if 0 < pages_read < count:
                    print(f"- {color_string((CY, 'Dump stopped early (page not readable without/again auth).'))}")
                if fd is not None and args.file != "":
                    print(f"- {color_string((CG, f'Dump written in {args.file}.'))}")
            return

        options = {
            "activate_rf_field": 0,
            "wait_response": 1,
            "append_crc": 1,
            "auto_select": 1,
            "keep_rf_field": 1,
            "check_response_crc": 1,
        }

        # if stop page isn't set manually, try autodetection
        if stop_page is None:
            tag_name = None

            # first try sending the GET_VERSION command
            try:
                version = self.cmd.hf14a_raw(
                    options=options, resp_timeout_ms=100, data=struct.pack("!B", 0x60)
                )
                if len(version) == 0:
                    version = None
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                version = None

            # try sending AUTHENTICATE command and observe the result
            try:
                supports_auth = (
                    len(
                        self.cmd.hf14a_raw(
                            options=options,
                            resp_timeout_ms=100,
                            data=struct.pack("!B", 0x1A),
                        )
                    )
                    != 0
                )
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                supports_auth = False

            if version is not None and not supports_auth:
                # either ULEV1 or NTAG
                assert len(version) == 8

                is_mikron_ulev1 = version[1] == 0x34 and version[2] == 0x21
                if (
                    (version[2] == 3 or is_mikron_ulev1)
                    and version[4] == 1
                    and version[5] == 0
                ):
                    # Ultralight EV1 V0
                    size_map = {
                        0x0B: ("Mifare Ultralight EV1 48b", 20),
                        0x0E: ("Mifare Ultralight EV1 128b", 41),
                    }
                elif version[2] == 4 and version[4] == 1 and version[5] == 0:
                    # NTAG 210/212/213/215/216 V0
                    size_map = {
                        0x0B: ("NTAG 210", 20),
                        0x0E: ("NTAG 212", 41),
                        0x0F: ("NTAG 213", 45),
                        0x11: ("NTAG 215", 135),
                        0x13: ("NTAG 216", 231),
                    }
                else:
                    size_map = {}

                if version[6] in size_map:
                    tag_name, stop_page = size_map[version[6]]
            elif version is None and supports_auth:
                # Ultralight C
                tag_name = "Mifare Ultralight C"
                stop_page = 48
            elif version is None and not supports_auth:
                try:
                    # Invalid command returning a NAK means that's some old type of NTAG.
                    self.cmd.hf14a_raw(
                        options=options,
                        resp_timeout_ms=100,
                        data=struct.pack("!B", 0xFF),
                    )

                    print(
                        color_string(
                            (CY, "Tag is likely NTAG 20x, reading until first error.")
                        )
                    )
                    stop_page = 256
                except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                    # Regular Ultralight
                    tag_name = "Mifare Ultralight"
                    stop_page = 16
            else:
                # This is probably Ultralight AES, but we don't support this one yet.
                pass

            if tag_name is not None:
                print(f" - Detected tag type as {tag_name}.")

            if stop_page is None:
                err_str = "Couldn't autodetect the expected card size, reading until first error."
                print(f"- {color_string((CY, err_str))}")
                stop_page = 256

        needs_stop = False

        if param.key is not None:
            try:
                resp = self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!B", 0x1B) + param.key,
                )

                needs_stop = len(resp) < 2
                if not needs_stop:
                    print(f" - PACK: {resp[:2].hex()}")
            except Exception:
                # failed auth may cause tags to be lost
                needs_stop = True

            options["auto_select"] = 0

        # this handles auth failure
        if needs_stop:
            print(color_string((CR, " - Auth failed")))
            if fd is not None:
                fd.close()
                fd = None

        for i in range(args.page, stop_page):
            # this could be done once in theory but the command would need to be optimized properly
            if param.key is not None and not needs_stop:
                resp = self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!B", 0x1B) + param.key,
                )
                options["auto_select"] = 0  # prevent resets

            # disable the rf field after the last command
            if i == (stop_page - 1) or needs_stop:
                options["keep_rf_field"] = 0

            try:
                resp = self.cmd.hf14a_raw(
                    options=options,
                    resp_timeout_ms=200,
                    data=struct.pack("!BB", 0x30, i),
                )
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                # probably lost tag, but we still need to disable rf field
                resp = None

            if needs_stop:
                # break if this command was sent just to disable RF field
                break
            elif resp is None or len(resp) == 0:
                # we need to disable RF field if we reached the last valid page so send one more read command
                needs_stop = True
                continue

            # after the read we are sure we no longer need to select again
            options["auto_select"] = 0

            # TODO: can be optimized as we get 4 pages at once but beware of wrapping
            # in case of end of memory or LOCK on ULC and no key provided
            data = resp[:4]
            print(f" - Page {i:2}: {data.hex()}")
            if fd is not None:
                if save_as_eml:
                    fd.write(data.hex() + "\n")
                else:
                    fd.write(data)

        if needs_stop and stop_page != 256:
            print(f"- {color_string((CY, 'Dump is shorter than expected.'))}")
        if args.file != "":
            print(f"- {color_string((CG, f'Dump written in {args.file}.'))}")

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)

        file_type = args.type
        fd = None
        save_as_eml = False

        if args.file != "":
            if file_type is None:
                if args.file.endswith(".eml") or args.file.endswith(".txt"):
                    file_type = "hex"
                else:
                    file_type = "bin"

            if file_type == "hex":
                fd = open(args.file, "w+")
                save_as_eml = True
            else:
                fd = open(args.file, "wb+")

        if fd is not None:
            with fd:
                fd.truncate(0)
                self.do_dump(args, param, fd, save_as_eml)
        else:
            self.do_dump(args, param, fd, save_as_eml)


@hf_mfu.command("version")
class HFMFUVERSION(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Request MIFARE Ultralight / NTAG version data."
        return parser

    def on_exec(self, args: argparse.Namespace):
        options = {
            "activate_rf_field": 0,
            "wait_response": 1,
            "append_crc": 1,
            "auto_select": 1,
            "keep_rf_field": 0,
            "check_response_crc": 1,
        }

        resp = self.cmd.hf14a_raw(
            options=options, resp_timeout_ms=200, data=struct.pack("!B", 0x60)
        )
        print(f" - Data: {resp[:8].hex()}")


@hf_mfu.command("signature")
class HFMFUSIGNATURE(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Request MIFARE Ultralight / NTAG ECC signature data."
        return parser

    def on_exec(self, args: argparse.Namespace):
        options = {
            "activate_rf_field": 0,
            "wait_response": 1,
            "append_crc": 1,
            "auto_select": 1,
            "keep_rf_field": 0,
            "check_response_crc": 1,
        }

        resp = self.cmd.hf14a_raw(
            options=options, resp_timeout_ms=200, data=struct.pack("!BB", 0x3C, 0x00)
        )
        print(f" - Data: {resp[:32].hex()}")


@hf_mfu.command("authnonce")
class HFMFUAUTHNONCE(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get authentication nonce from MIFARE Ultralight C tag."
        return parser

    def on_exec(self, args: argparse.Namespace):
        options = {
            "activate_rf_field": 0,
            "wait_response": 1,
            "append_crc": 1,
            "auto_select": 1,
            "keep_rf_field": 0,
            "check_response_crc": 1,
        }

        resp = self.cmd.hf14a_raw(
            options=options, resp_timeout_ms=200, data=struct.pack("!BB", 0x1A, 0x00)
        )
        # Response is 0xAF + 8 bytes nonce + 2 bytes CRC = 11 bytes
        # We want to display just the 8-byte nonce (skip 0xAF prefix)
        if len(resp) >= 9 and resp[0] == 0xAF:
            print(f" - Nonce: {resp[1:9].hex()}")
        else:
            print(f" - Error: Unexpected response: {resp.hex()}")


@hf_mfu.command("ulcg")
class HFMFUULCG(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Key recovery for Giantec ULCG and USCUID-UL cards (won't work on NXP cards!)"
        parser.add_argument(
            "-c",
            "--challenges",
            type=int,
            default=1000,
            help="Number of challenges to collect (default: 1000)",
        )
        parser.add_argument(
            "-t",
            "--threads",
            type=int,
            default=1,
            help="Number of threads for key recovery (default: 1)",
        )
        parser.add_argument(
            "-j",
            "--json",
            type=str,
            help="Path to JSON file to load or save challenges",
        )
        parser.add_argument(
            "-o",
            "--offline",
            action="store_true",
            help="Use offline mode with pre-collected challenges",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        import json

        if not args.offline:
            challenges = self.collect_challenges(args.challenges)
            if challenges is None:
                return
            if args.json:
                with open(args.json, "w") as f:
                    json.dump(challenges, f)
                print(f"[+] Challenges saved to {args.json}.")
                print("[!] Beware that the card key is now erased!")
                return
        else:
            if not args.json:
                print("[-] Error: --json required for offline mode")
                return
            with open(args.json, "r") as f:
                challenges = json.load(f)

        self.crack_key(challenges, args.threads, args.offline)

    def collect_challenges(self, num_challenges):
        """Collect challenges from the card and check if it is vulnerable."""
        # Sanity check: make sure an Ultralight C is detected
        resp = self.cmd.hf14a_scan()
        if resp is None or len(resp) == 0:
            print("[-] Error: No tag detected")
            return None

        # Check SAK for Ultralight C (SAK should be 0x00)
        print("[+] Checking for Ultralight C...")

        # Check AUTH0 configuration
        options = {
            "activate_rf_field": 0,
            "wait_response": 1,
            "append_crc": 1,
            "auto_select": 1,
            "keep_rf_field": 0,
            "check_response_crc": 1,
        }

        # Read page 40-43 (config pages)
        resp = self.cmd.hf14a_raw(
            options=options, resp_timeout_ms=200, data=struct.pack("!BB", 0x30, 0x28)
        )  # READ page 40

        if len(resp) < 16:
            print(
                "[-] Error: Card not unlocked. Run relay attack in UNLOCK mode first."
            )
            return None

        # Check AUTH0 (should be >= 0x30)
        minimum_auth_page = resp[8]
        if minimum_auth_page < 48:
            print(
                "[-] Error: Card not unlocked. Run relay attack in UNLOCK mode first."
            )
            return None

        # Check lock bit
        is_locked_key = ((resp[1] & 0x80) >> 7) == 1
        if is_locked_key:
            print("[-] Error: Card is not vulnerable (key is locked)")
            return None

        print(
            "[+] All sanity checks \033[1;32mpassed\033[0m. Checking if card is vulnerable.\033[?25l"
        )

        # Collect 100 challenges to check for collision
        challenges_collected = 0
        challenges_100 = set()
        challenges = {}
        collision = False

        while challenges_collected < num_challenges:
            resp = self.cmd.hf14a_raw(
                options=options,
                resp_timeout_ms=200,
                data=struct.pack("!BB", 0x1A, 0x00),
            )
            if len(resp) >= 9 and resp[0] == 0xAF:
                hex_challenge = resp[1:9].hex().upper()
                if hex_challenge in challenges_100:
                    collision = True
                    challenges["challenge_100"] = hex_challenge
                    break
                else:
                    challenges_100.add(hex_challenge)
                challenges_collected += 1

        print(f"\r[+] Challenges collected: \033[96m{challenges_collected}\033[0m")
        if collision:
            print("[+] Status: \033[1;31mVulnerable\033[0m\033[?25h")
        else:
            print("[+] Status: \033[1;32mNot vulnerable\033[0m\033[?25h")
            return None

        # Card is vulnerable, proceed with attack
        print("[+] Collecting key-specific challenges...")

        # Overwrite block 47 and collect challenge_75
        self.write_block(47, b"\x00\x00\x00\x00")
        resp = self.cmd.hf14a_raw(
            options=options, resp_timeout_ms=200, data=struct.pack("!BB", 0x1A, 0x00)
        )
        if len(resp) >= 9 and resp[0] == 0xAF:
            challenges["challenge_75"] = resp[1:9].hex().upper()
        print("[+] 75 collection complete")

        # Overwrite block 46 and collect challenge_50
        self.write_block(46, b"\x00\x00\x00\x00")
        resp = self.cmd.hf14a_raw(
            options=options, resp_timeout_ms=200, data=struct.pack("!BB", 0x1A, 0x00)
        )
        if len(resp) >= 9 and resp[0] == 0xAF:
            challenges["challenge_50"] = resp[1:9].hex().upper()
        print("[+] 50 collection complete")

        # Overwrite block 45 and collect challenge_25
        self.write_block(45, b"\x00\x00\x00\x00")
        resp = self.cmd.hf14a_raw(
            options=options, resp_timeout_ms=200, data=struct.pack("!BB", 0x1A, 0x00)
        )
        if len(resp) >= 9 and resp[0] == 0xAF:
            challenges["challenge_25"] = resp[1:9].hex().upper()
        print("[+] 25 collection complete")

        # Overwrite block 44 and collect challenge_0
        self.write_block(44, b"\x00\x00\x00\x00")
        resp = self.cmd.hf14a_raw(
            options=options, resp_timeout_ms=200, data=struct.pack("!BB", 0x1A, 0x00)
        )
        if len(resp) >= 9 and resp[0] == 0xAF:
            challenges["challenge_0"] = resp[1:9].hex().upper()
        print("[+] 0 collection complete")

        return challenges

    def write_block(self, block, data):
        """Write a block using hf14a_raw"""
        options = {
            "activate_rf_field": 0,
            "wait_response": 1,
            "append_crc": 1,
            "auto_select": 1,
            "keep_rf_field": 0,
            "check_response_crc": 1,
        }
        # WRITE command (0xA2) + block number + 4 bytes of data
        cmd_data = struct.pack("!BB4s", 0xA2, block, data)
        self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=cmd_data)

    def crack_key(self, challenges, num_threads, offline):
        """Crack the key using collected challenges"""
        import signal
        import traceback

        key_segment_values = {0: "00" * 4, 1: "00" * 4, 2: "00" * 4, 3: "00" * 4}
        key_found = False

        print("[+] Cracking in progress...\033[?25l")

        # Create and start the cracking effect
        crack_effect = CrackEffect()
        effect_thread = threading.Thread(target=crack_effect.start)
        effect_thread.start()

        def signal_handler(sig, frame):
            print("\n\n\n[!] Interrupt received, stopping...\033[?25h")
            crack_effect.stop_event.set()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        ciphertexts = {
            1: challenges["challenge_25"],
            0: challenges["challenge_50"],
            3: challenges["challenge_75"],
            2: challenges["challenge_100"],
        }

        try:
            for key_segment_idx in [1, 0, 3, 2]:
                ciphertext = ciphertexts[key_segment_idx]

                cmd = [
                    str(default_cwd / "mfulc_des_brute"),
                    "-c",
                    challenges["challenge_0"],
                    ciphertext,
                    "".join(key_segment_values.values()),
                    str(key_segment_idx + 1),
                    str(num_threads),
                ]

                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=3600
                    )

                    if "Could not detect LFSR" in result.stderr:
                        key_found = False
                        crack_effect.stop_event.set()
                        crack_effect.erase_key()
                        print(f"\n\n\n[-] Error: {result.stderr}\033[?25h")
                        break

                    if "No matching key was found" in result.stdout:
                        key_found = False
                        crack_effect.stop_event.set()
                        crack_effect.erase_key()
                        print(
                            f"\n\n\n[-] Error: No matching key found for segment {key_segment_idx + 1}\033[?25h"
                        )
                        break

                    if "Full key (hex): " not in result.stdout:
                        key_found = False
                        crack_effect.stop_event.set()
                        crack_effect.erase_key()
                        print(
                            "\n\n\n[-] Error: Unexpected output from mfulc_des_brute\033[?25h"
                        )
                        break

                    # Extract the key segment from output
                    full_key_line = [
                        line
                        for line in result.stdout.split("\n")
                        if "Full key (hex):" in line
                    ][0]
                    full_key = full_key_line.split("Full key (hex): ")[1].strip()
                    key_segment_values[key_segment_idx] = full_key[
                        (8 * key_segment_idx) :
                    ][:8]
                    key_found = True
                    crack_effect.add_cracked_block(
                        key_segment_idx, key_segment_values[key_segment_idx]
                    )

                except subprocess.TimeoutExpired:
                    key_found = False
                    crack_effect.stop_event.set()
                    crack_effect.erase_key()
                    print(
                        f"\n\n\n[-] Error: Timeout cracking segment {key_segment_idx + 1}\033[?25h"
                    )
                    break
                except Exception as e:
                    key_found = False
                    crack_effect.stop_event.set()
                    crack_effect.erase_key()
                    print(f"\n\n\n[-] Error: {e}\033[?25h")
                    break
        except Exception as e:
            crack_effect.stop_event.set()
            print(f"\n\n\nAn error occurred: {e}\033[?25h")
            traceback.print_exc()
        finally:
            effect_thread.join()

        if key_found:
            result_key = "".join(key_segment_values.values())
            formatted_key = f"\033[1;34m{result_key}\033[0m"
            print(f"[+] Found key: {formatted_key}\033[?25h")
            if offline:
                print(
                    "You can restore found key on the card with appropriate write commands"
                )
            else:
                # Restore the key on the card
                print("[+] Restoring key to card...")
                key_bytes = bytes.fromhex(result_key)

                # Need to swap endianness in 8-byte chunks before writing
                # UL-C stores key with swapped endianness
                key_swapped = bytearray(16)
                # Swap first 8 bytes
                for i in range(8):
                    key_swapped[i] = key_bytes[7 - i]
                # Swap second 8 bytes
                for i in range(8):
                    key_swapped[8 + i] = key_bytes[15 - i]

                # Write 4 blocks of 4 bytes each
                for i in range(4):
                    block = 44 + i
                    data = bytes(key_swapped[i * 4 : (i + 1) * 4])
                    self.write_block(block, data)
                print("[+] Key restored on the card")


@hf_mfu.command("nfcimport")
class HFMFUNfcImport(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    FLIPPER_TYPE_MAP: ClassVar[dict[str, TagSpecificType]] = {
        "NTAG203": TagSpecificType.NTAG_215,  # best-effort: no native NTAG203 support
        "NTAG210": TagSpecificType.NTAG_210,
        "NTAG212": TagSpecificType.NTAG_212,
        "NTAG213": TagSpecificType.NTAG_213,
        "NTAG215": TagSpecificType.NTAG_215,
        "NTAG216": TagSpecificType.NTAG_216,
        "NTAGI2C1K": TagSpecificType.NTAG_216,  # best-effort
        "NTAGI2C2K": TagSpecificType.NTAG_216,  # best-effort
        "NTAGI2CPlus1K": TagSpecificType.NTAG_216,  # best-effort
        "NTAGI2CPlus2K": TagSpecificType.NTAG_216,  # best-effort
        "Mifare Ultralight": TagSpecificType.MF0ICU1,
        "Mifare Ultralight C": TagSpecificType.MF0ICU2,
        "Mifare Ultralight 11": TagSpecificType.MF0UL11,
        "Mifare Ultralight 21": TagSpecificType.MF0UL21,
    }

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Import a Flipper Zero .nfc file into a MIFARE Ultralight / NTAG "
            "emulator slot"
        )
        self.add_slot_args(parser)
        parser.add_argument(
            "-f",
            "--file",
            required=True,
            type=str,
            help="Path to Flipper Zero .nfc file",
        )
        parser.add_argument(
            "--amiibo",
            action="store_true",
            default=False,
            help="Derive and write correct PWD/PACK for amiibo (NTAG215)",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        file_path = args.file
        file_name = os.path.basename(file_path)

        try:
            with open(file_path, "r") as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(color_string((CR, f"File not found: {file_path}")))
            return
        except OSError as e:
            print(color_string((CR, f"Error reading file: {e}")))
            return

        device_type = None
        uid = None
        atqa = None
        sak = None
        signature = None
        version = None
        counters = {}
        tearing = {}
        pages_total = None
        pages = {}

        for line in lines:
            line = line.strip()
            if line.startswith("#") or not line:
                continue

            if line.startswith("Device type:"):
                device_type = line.split(":", 1)[1].strip()
            elif line.startswith("UID:"):
                uid = bytes.fromhex(line.split(":", 1)[1].strip().replace(" ", ""))
            elif line.startswith("ATQA:"):
                atqa = bytes.fromhex(line.split(":", 1)[1].strip().replace(" ", ""))
            elif line.startswith("SAK:"):
                sak = bytes.fromhex(line.split(":", 1)[1].strip().replace(" ", ""))
            elif line.startswith("Signature:"):
                signature = bytes.fromhex(
                    line.split(":", 1)[1].strip().replace(" ", "")
                )
            elif line.startswith("Mifare version:"):
                version = bytes.fromhex(line.split(":", 1)[1].strip().replace(" ", ""))
            elif line.startswith("Counter "):
                match = re.match(r"Counter\s+(\d+):\s+(\d+)", line)
                if match:
                    counters[int(match.group(1))] = int(match.group(2))
            elif line.startswith("Tearing "):
                match = re.match(r"Tearing\s+(\d+):\s+([0-9A-Fa-f]+)", line)
                if match:
                    tearing[int(match.group(1))] = int(match.group(2), 16)
            elif line.startswith("Pages total:"):
                pages_total = int(line.split(":", 1)[1].strip())
            elif line.startswith("Page "):
                match = re.match(r"Page\s+(\d+):\s+(.*)", line)
                if match:
                    page_num = int(match.group(1))
                    page_data = bytes.fromhex(match.group(2).strip().replace(" ", ""))
                    pages[page_num] = page_data

        if device_type is None:
            print(color_string((CR, "No 'Device type' found in .nfc file.")))
            return
        if uid is None:
            print(color_string((CR, "No 'UID' found in .nfc file.")))
            return
        if atqa is None:
            print(color_string((CR, "No 'ATQA' found in .nfc file.")))
            return
        if sak is None:
            print(color_string((CR, "No 'SAK' found in .nfc file.")))
            return

        tag_type = self.FLIPPER_TYPE_MAP.get(device_type)

        if tag_type is None and device_type.startswith("Mifare Ultralight EV1"):
            nr = pages_total if pages_total else len(pages)
            tag_type = TagSpecificType.MF0UL11 if nr <= 20 else TagSpecificType.MF0UL21

        if tag_type is None:
            print(
                color_string((CR, f"Unsupported Flipper device type: '{device_type}'"))
            )
            print(
                "  Supported types: "
                f"{', '.join(sorted(self.FLIPPER_TYPE_MAP.keys()))}, "
                "Mifare Ultralight EV1"
            )
            return

        print(f"Importing Flipper NFC file: {file_name}")
        print(f"  Device type: {device_type} -> {tag_type}")
        print(f"  UID: {uid.hex(' ').upper()}")
        print(f"  ATQA: {atqa.hex(' ').upper()}  SAK: {sak.hex().upper()}")
        if version:
            print(f"  Version: {version.hex(' ').upper()}")
        if signature:
            print(f"  Signature: {signature.hex(' ').upper()}")
        if counters:
            counter_values = ", ".join(
                str(counters.get(i, 0)) for i in range(max(counters.keys()) + 1)
            )
            print(f"  Counters: {counter_values}")
        nr_pages = pages_total if pages_total else len(pages)
        print(f"  Pages: {nr_pages}")
        print()

        print(f"Setting slot {self.slot_num} tag type to {tag_type}...")
        self.cmd.set_slot_tag_type(self.slot_num, tag_type)
        self.cmd.set_slot_data_default(self.slot_num, tag_type)
        self.cmd.set_active_slot(self.slot_num)

        print("Setting anti-collision data...")
        self.cmd.hf14a_set_anti_coll_data(uid, atqa, sak)

        if version and len(version) == 8:
            print("Setting version data...")
            try:
                self.cmd.mf0_ntag_set_version_data(version)
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                print(
                    color_string(
                        (CY, "  Warning: tag type does not support GET_VERSION.")
                    )
                )

        if signature and len(signature) == 32:
            print("Setting signature data...")
            try:
                self.cmd.mf0_ntag_set_signature_data(signature)
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                print(
                    color_string((CY, "  Warning: tag type does not support READ_SIG."))
                )

        if counters:
            print("Setting counter data...")
            ntag_types = {
                TagSpecificType.NTAG_210,
                TagSpecificType.NTAG_212,
                TagSpecificType.NTAG_213,
                TagSpecificType.NTAG_215,
                TagSpecificType.NTAG_216,
            }
            for i in sorted(counters.keys()):
                value = counters[i]
                if value > 0xFFFFFF:
                    print(
                        color_string(
                            (
                                CY,
                                f"  Warning: counter {i} value {value:#x} exceeds 24-bit, skipping.",
                            )
                        )
                    )
                    continue
                if tag_type in ntag_types:
                    if i != 2:
                        continue
                    fw_index = 0
                else:
                    fw_index = i
                tearing_val = tearing.get(i, 0x00)
                reset_tearing = tearing_val == 0xBD or tearing_val == 0x00
                try:
                    self.cmd.mfu_write_emu_counter_data(fw_index, value, reset_tearing)
                except (
                    ValueError,
                    chameleon_com.CMDInvalidException,
                    UnexpectedResponseError,
                    TimeoutError,
                ):
                    print(color_string((CY, f"  Warning: could not set counter {i}.")))

        if pages:
            slot_pages = self.cmd.mfu_get_emu_pages_count()
            max_page = max(pages.keys())
            write_pages = min(max_page + 1, slot_pages)

            print(f"Writing {write_pages} pages...", end=" ", flush=True)

            page = 0
            while page < write_pages:
                cur_count = min(16, write_pages - page)
                batch = bytearray()
                for p in range(page, page + cur_count):
                    batch.extend(pages.get(p, b"\x00\x00\x00\x00"))
                self.cmd.mfu_write_emu_page_data(page, bytes(batch))
                page += cur_count

            print("done")

        if args.amiibo:
            if tag_type != TagSpecificType.NTAG_215:
                print(
                    color_string(
                        (
                            CY,
                            f"  Warning: --amiibo flag ignored (tag type is {tag_type}, not NTAG 215).",
                        )
                    )
                )
            elif uid is None or len(uid) != 7:
                print(
                    color_string(
                        (CY, "  Warning: --amiibo flag ignored (UID is not 7 bytes).")
                    )
                )
            else:
                pwd = bytes(
                    [
                        0xAA ^ uid[1] ^ uid[3],
                        0x55 ^ uid[2] ^ uid[4],
                        0xAA ^ uid[3] ^ uid[5],
                        0x55 ^ uid[4] ^ uid[6],
                    ]
                )
                pack = bytes([0x80, 0x80, 0x00, 0x00])
                print(
                    f"Setting amiibo PWD: {pwd.hex(' ').upper()}, "
                    f"PACK: {pack[:2].hex(' ').upper()}..."
                )
                self.cmd.mfu_write_emu_page_data(133, pwd)
                self.cmd.mfu_write_emu_page_data(134, pack)

        self.cmd.set_slot_enable(self.slot_num, TagSenseType.HF, True)

        print()
        print(
            f" - Import complete. Slot {self.slot_num} is now emulating "
            f"{device_type} ({file_name})"
        )


@hf_mfu.command("econfig")
class HFMFUEConfig(SlotIndexArgsAndGoUnit, HF14AAntiCollArgsUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Settings of Mifare Ultralight / NTAG emulator"
        self.add_slot_args(parser)
        self.add_hf14a_anticoll_args(parser)
        uid_magic_group = parser.add_mutually_exclusive_group()
        uid_magic_group.add_argument(
            "--enable-uid-magic", action="store_true", help="Enable UID magic mode"
        )
        uid_magic_group.add_argument(
            "--disable-uid-magic", action="store_true", help="Disable UID magic mode"
        )

        # Add this new write mode parameter
        write_names = [w.name for w in MifareUltralightWriteMode.list()]
        help_str = "Write Mode: " + ", ".join(write_names)
        parser.add_argument(
            "--write", type=str, help=help_str, metavar="MODE", choices=write_names
        )

        parser.add_argument(
            "--set-version",
            type=bytes.fromhex,
            help="Set data to be returned by the GET_VERSION command.",
        )
        parser.add_argument(
            "--set-signature",
            type=bytes.fromhex,
            help="Set data to be returned by the READ_SIG command.",
        )
        parser.add_argument(
            "--reset-auth-cnt",
            action="store_true",
            help="Resets the counter of unsuccessful authentication attempts.",
        )

        detection_group = parser.add_mutually_exclusive_group()
        detection_group.add_argument(
            "--enable-log",
            action="store_true",
            help="Enable password authentication logging",
        )
        detection_group.add_argument(
            "--disable-log",
            action="store_true",
            help="Disable password authentication logging",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        aux_data_changed = False
        aux_data_change_requested = False

        if args.set_version is not None:
            aux_data_change_requested = True
            aux_data_changed = True

            if len(args.set_version) != 8:
                print(color_string((CR, "Version data should be 8 bytes long.")))
                return

            try:
                self.cmd.mf0_ntag_set_version_data(args.set_version)
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                print(
                    color_string((CR, "Tag type does not support GET_VERSION command."))
                )
                return

        if args.set_signature is not None:
            aux_data_change_requested = True
            aux_data_changed = True

            if len(args.set_signature) != 32:
                print(color_string((CR, "Signature data should be 32 bytes long.")))
                return

            try:
                self.cmd.mf0_ntag_set_signature_data(args.set_signature)
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                print(color_string((CR, "Tag type does not support READ_SIG command.")))
                return

        if args.reset_auth_cnt:
            aux_data_change_requested = True
            old_value = self.cmd.mfu_reset_auth_cnt()
            if old_value != 0:
                aux_data_changed = True
                print(
                    f"- Unsuccessful auth counter has been reset from {old_value} to 0."
                )

        # collect current settings
        anti_coll_data = self.cmd.hf14a_get_anti_coll_data()
        if len(anti_coll_data) == 0:
            print(
                color_string(
                    (CR, f"Slot {self.slot_num} does not contain any HF 14A config")
                )
            )
            return
        uid = anti_coll_data["uid"]
        atqa = anti_coll_data["atqa"]
        sak = anti_coll_data["sak"]
        ats = anti_coll_data["ats"]
        slotinfo = self.cmd.get_slot_info()
        fwslot = SlotNumber.to_fw(self.slot_num)
        hf_tag_type = TagSpecificType(slotinfo[fwslot]["hf"])
        if hf_tag_type not in [
            TagSpecificType.MF0ICU1,
            TagSpecificType.MF0ICU2,
            TagSpecificType.MF0UL11,
            TagSpecificType.MF0UL21,
            TagSpecificType.NTAG_210,
            TagSpecificType.NTAG_212,
            TagSpecificType.NTAG_213,
            TagSpecificType.NTAG_215,
            TagSpecificType.NTAG_216,
        ]:
            print(
                color_string(
                    (
                        CR,
                        f"Slot {self.slot_num} not configured as MIFARE Ultralight / NTAG",
                    )
                )
            )
            return
        change_requested, change_done, uid, atqa, sak, ats = self.update_hf14a_anticoll(
            args, uid, atqa, sak, ats
        )

        if args.enable_uid_magic:
            change_requested = True
            self.cmd.mf0_ntag_set_uid_magic_mode(True)
            magic_mode = True
        elif args.disable_uid_magic:
            change_requested = True
            self.cmd.mf0_ntag_set_uid_magic_mode(False)
            magic_mode = False
        else:
            magic_mode = self.cmd.mf0_ntag_get_uid_magic_mode()

        # Add this new write mode handling
        write_mode = None
        if args.write is not None:
            change_requested = True
            new_write_mode = MifareUltralightWriteMode[args.write]
            try:
                current_write_mode = self.cmd.mf0_ntag_get_write_mode()
                if new_write_mode != current_write_mode:
                    self.cmd.mf0_ntag_set_write_mode(new_write_mode)
                    change_done = True
                    write_mode = new_write_mode
                else:
                    print(color_string((CY, "Requested write mode already set")))
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                print(
                    color_string(
                        (
                            CR,
                            "Failed to set write mode. Check if device firmware supports this feature.",
                        )
                    )
                )

        detection = self.cmd.mf0_ntag_get_detection_enable()
        if args.enable_log:
            change_requested = True
            if detection is not None:
                if not detection:
                    detection = True
                    self.cmd.mf0_ntag_set_detection_enable(detection)
                    change_done = True
                else:
                    print(
                        color_string(
                            (
                                CY,
                                "Requested logging of MFU authentication data already enabled",
                            )
                        )
                    )
            else:
                print(
                    color_string(
                        (CR, "Detection functionality not available in this firmware")
                    )
                )
        elif args.disable_log:
            change_requested = True
            if detection is not None:
                if detection:
                    detection = False
                    self.cmd.mf0_ntag_set_detection_enable(detection)
                    change_done = True
                else:
                    print(
                        color_string(
                            (
                                CY,
                                "Requested logging of MFU authentication data already disabled",
                            )
                        )
                    )
            else:
                print(
                    color_string(
                        (CR, "Detection functionality not available in this firmware")
                    )
                )

        if change_done or aux_data_changed:
            print(" - MFU/NTAG Emulator settings updated")
        if not (change_requested or aux_data_change_requested):
            atqa_string = f"{atqa.hex().upper()} (0x{int.from_bytes(atqa, byteorder='little'):04x})"
            print(f'- {"Type:":40}{color_string((CY, hf_tag_type))}')
            print(f'- {"UID:":40}{color_string((CY, uid.hex().upper()))}')
            print(f'- {"ATQA:":40}{color_string((CY, atqa_string))}')
            print(f'- {"SAK:":40}{color_string((CY, sak.hex().upper()))}')
            if len(ats) > 0:
                print(f'- {"ATS:":40}{color_string((CY, ats.hex().upper()))}')

            # Display UID Magic status
            magic_status = "enabled" if magic_mode else "disabled"
            print(f'- {"UID Magic:":40}{color_string((CY, magic_status))}')

            # Add this to display write mode if available
            try:
                write_mode = MifareUltralightWriteMode(
                    self.cmd.mf0_ntag_get_write_mode()
                )
                print(f'- {"Write mode:":40}{color_string((CY, write_mode))}')
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                # Write mode not supported in current firmware
                pass

            # Existing version/signature display code
            try:
                version = self.cmd.mf0_ntag_get_version_data().hex().upper()
                print(f'- {"Version:":40}{color_string((CY, version))}')
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                pass

            try:
                signature = self.cmd.mf0_ntag_get_signature_data().hex().upper()
                print(f'- {"Signature:":40}{color_string((CY, signature))}')
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                pass

            try:
                detection = (
                    color_string((CG, "enabled"))
                    if self.cmd.mf0_ntag_get_detection_enable()
                    else color_string((CR, "disabled"))
                )
                print(f'- {"Log (password) mode:":40}{f"{detection}"}')
            except (ValueError, chameleon_com.CMDInvalidException, TimeoutError):
                pass


@hf_mfu.command("edetect")
class HFMFUEDetect(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get Mifare Ultralight / NTAG emulator detection logs"
        self.add_slot_args(parser)
        parser.add_argument(
            "--count",
            type=int,
            help="Number of log entries to retrieve",
            metavar="COUNT",
        )
        parser.add_argument(
            "--index",
            type=int,
            default=0,
            help="Starting index (default: 0)",
            metavar="INDEX",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        detection_enabled = self.cmd.mf0_ntag_get_detection_enable()
        if not detection_enabled:
            print(color_string((CY, "Detection logging is disabled for this slot")))
            return

        total_count = self.cmd.mf0_ntag_get_detection_count()
        print(f"Total detection log entries: {total_count}")

        if total_count == 0:
            print(color_string((CY, "No detection logs available")))
            return

        if args.count is not None:
            entries_to_get = min(args.count, total_count - args.index)
        else:
            entries_to_get = total_count - args.index

        if entries_to_get <= 0:
            print(color_string((CY, f"No entries available from index {args.index}")))
            return

        logs = self.cmd.mf0_ntag_get_detection_log(args.index)

        print(
            f"\nPassword detection logs (showing {len(logs)} entries from index {args.index}):"
        )
        print("-" * 50)

        for i, log_entry in enumerate(logs):
            actual_index = args.index + i
            password = log_entry["password"]
            print(f"{actual_index:3d}: {color_string((CY, password.upper()))}")
