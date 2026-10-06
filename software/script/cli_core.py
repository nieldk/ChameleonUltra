"""cli_core — shared foundation for the Chameleon CLI command modules.

Imports, module-level helpers, base *Unit classes, and the CLITree group
definitions (root, hw, hf, hf_mf, ...). Every cli_* command module imports
the groups and bases from here and registers its commands by decorator side
effect. Split out of the former monolithic chameleon_cli_unit.py."""

import binascii
import glob
import math
import os
import tempfile
import re
import subprocess
import argparse
import timeit
import sys
import time
import serial.tools.list_ports
import threading
import random
import struct
import queue
import pm3_trace
import chameleon_ndef as ndef
from enum import Enum
from multiprocessing import Pool, cpu_count
from typing import ClassVar, Union
from pathlib import Path
from platform import uname
from datetime import datetime
import hardnested_utils
from fdxb_country import describe_country_code

from chameleon_dfc import DfcCredential, DfcError
import chameleon_pm3
import chameleon_com
import chameleon_cmd
import chameleon_dfu
from chameleon_utils import (
    ArgumentParserNoExit,
    ArgsParserError,
    UnexpectedResponseError,
    execute_tool,
    tqdm_if_exists,
    print_key_table,
    odd_parity_byte,
    default_cwd,
)

from chameleon_utils import CLITree
from chameleon_utils import CR, CG, CB, CC, CY, C0, color_string
from chameleon_utils import print_mem_dump
from chameleon_enum import Command, Status, SlotNumber, TagSenseType, TagSpecificType
from chameleon_enum import (
    MifareClassicWriteMode,
    MifareClassicPrngType,
    MifareClassicDarksideStatus,
    MfcKeyType,
)
from chameleon_enum import MifareUltralightWriteMode
from chameleon_enum import (
    AnimationMode,
    ButtonPressFunction,
    ButtonType,
    MfcValueBlockOperator,
)
from chameleon_enum import HIDFormat
from chameleon_enum import StandaloneMode, StandaloneState, StandaloneFlag
from crypto1 import Crypto1

# NXP IDs based on https://www.nxp.com/docs/en/application-note/AN10833.pdf
type_id_SAK_dict = {
    0x00: "MIFARE Ultralight Classic/C/EV1/Nano | NTAG 2xx",
    0x08: "MIFARE Classic 1K | Plus SE 1K | Plug S 2K | Plus X 2K",
    0x09: "MIFARE Mini 0.3k",
    0x10: "MIFARE Plus 2K",
    0x11: "MIFARE Plus 4K",
    0x18: "MIFARE Classic 4K | Plus S 4K | Plus X 4K",
    0x19: "MIFARE Classic 2K",
    0x20: "MIFARE Plus EV1/EV2 | DESFire EV1/EV2/EV3 | DESFire Light | NTAG 4xx | "
    "MIFARE Plus S 2/4K | MIFARE Plus X 2/4K | MIFARE Plus SE 1K",
    0x28: "SmartMX with MIFARE Classic 1K",
    0x38: "SmartMX with MIFARE Classic 4K",
}


def load_key_file(import_key, keys):
    """
    Load binary key file and append its content to the provided set of keys.
    Each key is 6 bytes concatenated.
    """
    with open(import_key.name, "rb") as file:
        data = file.read()
    for i in range(0, len(data), 6):
        key = data[i : i + 6]
        if len(key) == 6:
            keys.add(key)
    return keys


def load_dic_file(import_dic, keys):
    """
    Load dictionary file and append its content to the provided set of keys.
    Each key is a 12-char hex string on a new line.
    """
    with open(import_dic.name, "r") as file:
        for line in file:
            line = line.strip()
            if line:
                keys.add(bytes.fromhex(line))
    return keys


def check_tools():
    missing_tools = []

    for tool in (
        "staticnested",
        "nested",
        "darkside",
        "mfkey32v2",
        "mfkey64",
        "staticnested_1nt",
        "staticnested_2x1nt_rf08s",
        "staticnested_2x1nt_rf08s_1key",
    ):
        if any(default_cwd.glob(f"{tool}*")):
            continue
        else:
            missing_tools.append(tool)

    if missing_tools:
        missing_tool_str = ", ".join(missing_tools)
        warn_str = f"Note: optional Mifare tools not found: {missing_tool_str}. Mifare attack commands will not work."
        print(color_string((CY, warn_str)))


class BaseCLIUnit:
    def __init__(self):
        # new a device command transfer and receiver instance(Send cmd and receive response)
        self._device_com: Union[chameleon_com.ChameleonCom, None] = None
        self._device_cmd: Union[chameleon_cmd.ChameleonCMD, None] = None

    @property
    def device_com(self) -> chameleon_com.ChameleonCom:
        assert self._device_com is not None
        return self._device_com

    @device_com.setter
    def device_com(self, com):
        self._device_com = com
        self._device_cmd = chameleon_cmd.ChameleonCMD(self._device_com)

    @property
    def cmd(self) -> chameleon_cmd.ChameleonCMD:
        assert self._device_cmd is not None
        return self._device_cmd

    def args_parser(self) -> ArgumentParserNoExit:
        """
            CMD unit args.

        :return:
        """
        raise NotImplementedError("Please implement this")

    def before_exec(self, args: argparse.Namespace):
        """
            Call a function before exec cmd.

        :return: function references
        """
        return True

    def on_exec(self, args: argparse.Namespace):
        """
            Call a function on cmd match.

        :return: function references
        """
        raise NotImplementedError("Please implement this")

    def after_exec(self, args: argparse.Namespace):
        """
            Call a function after exec cmd.

        :return: function references
        """
        return True

    @staticmethod
    def sub_process(cmd, cwd=default_cwd):
        class ShadowProcess:
            def __init__(self):
                self.output = ""
                self.time_start = timeit.default_timer()
                self._process = subprocess.Popen(
                    cmd,
                    cwd=cwd,
                    shell=True,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                )
                threading.Thread(target=self.thread_read_output).start()

            def thread_read_output(self):
                while self._process.poll() is None:
                    assert self._process.stdout is not None
                    data = self._process.stdout.read(1024)
                    if len(data) > 0:
                        self.output += data.decode(encoding="utf-8")

            def get_time_distance(self, ms=True):
                if ms:
                    return round((timeit.default_timer() - self.time_start) * 1000, 2)
                else:
                    return round(timeit.default_timer() - self.time_start, 2)

            def is_running(self):
                return self._process.poll() is None

            def is_timeout(self, timeout_ms):
                time_distance = self.get_time_distance()
                if time_distance > timeout_ms:
                    return True
                return False

            def get_output_sync(self):
                return self.output

            def get_ret_code(self):
                return self._process.poll()

            def stop_process(self):
                # noinspection PyBroadException
                try:
                    self._process.kill()
                except Exception:
                    pass

            def get_process(self):
                return self._process

            def wait_process(self):
                return self._process.wait()

        return ShadowProcess()


class DeviceRequiredUnit(BaseCLIUnit):
    """
    Make sure of device online
    """

    def before_exec(self, args: argparse.Namespace):
        ret = self.device_com.isOpen()
        if ret:
            return True
        else:
            print("Please connect to chameleon device first (use 'hw connect').")
            return False


class ReaderRequiredUnit(DeviceRequiredUnit):
    """
    Make sure of device enter to reader mode.
    """

    def before_exec(self, args: argparse.Namespace):
        if not super().before_exec(args):
            return False

        if self.cmd.is_device_reader_mode():
            return True

        self.cmd.set_device_reader_mode(True)
        print("Switch to {  Tag Reader  } mode successfully.")
        return True


class SlotIndexArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_slot_args(parser: ArgumentParserNoExit, mandatory=False):
        slot_choices = [x.value for x in SlotNumber]
        help_str = f"Slot Index: {slot_choices} Default: active slot"

        parser.add_argument(
            "-s",
            "--slot",
            type=int,
            required=mandatory,
            help=help_str,
            metavar="<1-8>",
            choices=slot_choices,
        )
        return parser


class SlotIndexArgsAndGoUnit(SlotIndexArgsUnit):
    def before_exec(self, args: argparse.Namespace):
        if super().before_exec(args):
            self.prev_slot_num = SlotNumber.from_fw(self.cmd.get_active_slot())
            if args.slot is not None:
                self.slot_num = args.slot
                if self.slot_num != self.prev_slot_num:
                    self.cmd.set_active_slot(self.slot_num)
            else:
                self.slot_num = self.prev_slot_num
            return True
        return False

    def after_exec(self, args: argparse.Namespace):
        if self.prev_slot_num != self.slot_num:
            self.cmd.set_active_slot(self.prev_slot_num)


class SenseTypeArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_sense_type_args(parser: ArgumentParserNoExit):
        sense_group = parser.add_mutually_exclusive_group(required=True)
        sense_group.add_argument("--hf", action="store_true", help="HF type")
        sense_group.add_argument("--lf", action="store_true", help="LF type")
        return parser


class MF1AuthArgsUnit(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.add_argument(
            "--blk",
            "--block",
            type=int,
            required=True,
            metavar="<dec>",
            help="The block where the key of the card is known",
        )
        type_group = parser.add_mutually_exclusive_group()
        type_group.add_argument(
            "-a", "-A", action="store_true", help="Known key is A key (default)"
        )
        type_group.add_argument(
            "-b", "-B", action="store_true", help="Known key is B key"
        )
        parser.add_argument(
            "-k",
            "--key",
            type=str,
            required=True,
            metavar="<hex>",
            help="tag sector key",
        )
        return parser

    def get_param(self, args):
        class Param:
            def __init__(self):
                self.block = args.blk
                self.type = MfcKeyType.B if args.b else MfcKeyType.A
                key: str = args.key
                if not re.match(r"^[a-fA-F0-9]{12}$", key):
                    raise ArgsParserError("key must include 12 HEX symbols")
                self.key: bytearray = bytearray.fromhex(key)

        return Param()


class HF14AAntiCollArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_hf14a_anticoll_args(parser: ArgumentParserNoExit):
        parser.add_argument("--uid", type=str, metavar="<hex>", help="Unique ID")
        parser.add_argument(
            "--atqa", type=str, metavar="<hex>", help="Answer To Request"
        )
        parser.add_argument(
            "--sak", type=str, metavar="<hex>", help="Select AcKnowledge"
        )
        ats_group = parser.add_mutually_exclusive_group()
        ats_group.add_argument(
            "--ats", type=str, metavar="<hex>", help="Answer To Select"
        )
        ats_group.add_argument(
            "--delete-ats", action="store_true", help="Delete Answer To Select"
        )
        return parser

    def update_hf14a_anticoll(self, args, uid, atqa, sak, ats):
        anti_coll_data_changed = False
        change_requested = False
        if args.uid is not None:
            change_requested = True
            uid_str: str = args.uid.strip()
            if re.match(r"[a-fA-F0-9]+", uid_str) is not None:
                new_uid = bytes.fromhex(uid_str)
                if len(new_uid) not in [4, 7, 10]:
                    raise Exception("UID length error")
            else:
                raise Exception("UID must be hex")
            if new_uid != uid:
                uid = new_uid
                anti_coll_data_changed = True
            else:
                print(color_string((CY, "Requested UID already set")))
        if args.atqa is not None:
            change_requested = True
            atqa_str: str = args.atqa.strip()
            if re.match(r"[a-fA-F0-9]{4}", atqa_str) is not None:
                new_atqa = bytes.fromhex(atqa_str)
            else:
                raise Exception("ATQA must be 4-byte hex")
            if new_atqa != atqa:
                atqa = new_atqa
                anti_coll_data_changed = True
            else:
                print(color_string((CY, "Requested ATQA already set")))
        if args.sak is not None:
            change_requested = True
            sak_str: str = args.sak.strip()
            if re.match(r"[a-fA-F0-9]{2}", sak_str) is not None:
                new_sak = bytes.fromhex(sak_str)
            else:
                raise Exception("SAK must be 2-byte hex")
            if new_sak != sak:
                sak = new_sak
                anti_coll_data_changed = True
            else:
                print(color_string((CY, "Requested SAK already set")))
        if (args.ats is not None) or args.delete_ats:
            change_requested = True
            if args.delete_ats:
                new_ats = b""
            else:
                ats_str: str = args.ats.strip()
                if re.match(r"[a-fA-F0-9]+", ats_str) is not None:
                    new_ats = bytes.fromhex(ats_str)
                else:
                    raise Exception("ATS must be hex")
            if new_ats != ats:
                ats = new_ats
                anti_coll_data_changed = True
            else:
                print(color_string((CY, "Requested ATS already set")))
        if anti_coll_data_changed:
            self.cmd.hf14a_set_anti_coll_data(uid, atqa, sak, ats)
        return change_requested, anti_coll_data_changed, uid, atqa, sak, ats


IDTECK_PREAMBLE_HEX = "4944544B"
IDTECK_PREAMBLE_INT = 0x4944544B


def _idteck_compute_checksum(payload_lo3: int) -> int:
    """Compute the IDTECK checksum byte from the low 3 bytes of the 4-byte payload.

    Matches the formula used by Proxmark3 (cmdlfidteck.c): the checksum is the
    sum of the three non-checksum payload bytes, taken modulo 256.
    """
    return ((payload_lo3 >> 16) + (payload_lo3 >> 8) + payload_lo3) & 0xFF


def _idteck_compose_frame(card_id: int) -> bytes:
    """Compose an 8-byte IDTECK frame from a 24-bit card ID.

    The frame is preamble + [checksum][card_id bytes reversed] where the
    reversal and checksum placement match the layout observed on real IDTECK
    cards (see cmdlfidteck.c in the Proxmark3 client). This helper is exposed
    for future CLI use (e.g. `lf idteck compose --cn`); it is not wired into
    any command yet.
    """
    card_id &= 0xFFFFFF
    # The card ID is stored with bytes reversed in the payload; mirror PM3.
    reversed_id = (
        ((card_id & 0xFF) << 16)
        | ((card_id >> 8) & 0xFF) << 8
        | ((card_id >> 16) & 0xFF)
    )
    chksum = _idteck_compute_checksum(reversed_id)
    payload = (chksum << 24) | reversed_id
    return bytes.fromhex(IDTECK_PREAMBLE_HEX) + payload.to_bytes(4, "big")


def _idteck_frame_info(frame: bytes) -> dict:
    """Parse an 8-byte IDTECK frame into its components.

    Returns a dict with: preamble_hex, preamble_valid, payload_hex, checksum,
    checksum_expected, checksum_valid, card_id (24-bit extracted from payload
    bytes 1-3 with the byte-reversal convention used by PM3).
    """
    if len(frame) != 8:
        raise ValueError("IDTECK frame must be exactly 8 bytes")
    preamble = int.from_bytes(frame[:4], "big")
    payload = int.from_bytes(frame[4:], "big")
    chksum = (payload >> 24) & 0xFF
    lo3 = payload & 0xFFFFFF
    expected = _idteck_compute_checksum(lo3)
    card_id = ((lo3 >> 16) & 0xFF) | ((lo3 >> 8) & 0xFF) << 8 | (lo3 & 0xFF) << 16
    return {
        "preamble_hex": f"{preamble:08X}",
        "preamble_valid": preamble == IDTECK_PREAMBLE_INT,
        "payload_hex": f"{payload:08X}",
        "checksum": chksum,
        "checksum_expected": expected,
        "checksum_valid": chksum == expected,
        "card_id": card_id,
    }


def _fdxb_crc16(data: bytes) -> int:
    """CRC-16 as computed by the firmware's fdxb_crc16 (reflected 0x8408)."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def _fdxb_frame_ok(frame: bytes) -> "tuple[bool, str]":
    """
    Validate a 13-byte destuffed FDX-B frame for writability.

    Returns (True, "") if structurally sound, else (False, reason).

    The 64-bit block in bytes 0-7 is laid out (LSB first):
        bits  0-37  national ID
        bits 38-47  country code
        bit  48     extended-data flag (a.k.a. data-block / application bit)
        bits 49-62  reserved -- MUST be zero on a conformant tag
        bit  63     animal flag

    A frame with nonzero reserved bits is emitted fine by the T55xx but
    rejected as malformed by conformant readers, so the written tag reads
    back as "not found".  That is the hard failure we block here.
    """
    if len(frame) != 13:
        return False, f"expected 13 bytes, got {len(frame)}"

    v = int.from_bytes(frame[0:8], "little")
    reserved = (v >> 49) & ((1 << 14) - 1)
    if reserved != 0:
        return False, (
            f"reserved bits 49-62 are nonzero (0x{reserved:04x}); "
            f"a conformant reader will reject this frame as malformed "
            f"and the written tag will read back as not found"
        )
    return True, ""


def _fdxb_crc16(data: bytes) -> int:
    """CRC-16 as computed by the firmware's fdxb_crc16 (reflected 0x8408)."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def _fdxb_crc_ok(frame: bytes) -> bool:
    """True if bytes 8-9 match the CRC-16 over bytes 0-7."""
    stored = int.from_bytes(frame[8:10], "little")
    return stored == _fdxb_crc16(frame[0:8])


def _fdxb_build_frame(
    country: int, national: int, animal: int = 1, extended: int = 0
) -> bytes:
    """
    Build a 13-byte destuffed FDX-B frame from logical fields.

    Reserved bits 49-62 are left zero by construction, so a frame built this
    way can never hit the "reserved bits nonzero -> unreadable" footgun.

        bits  0-37  national ID     (<= 274877906943)
        bits 38-47  country code    (<= 1023)
        bit  48     extended flag   (set iff extended != 0)
        bits 49-62  reserved        (always 0 here)
        bit  63     animal flag
        bytes 8-9   CRC-16 over bytes 0-7
        bytes 10-12 extended data   (24 bits, 0 if unused)
    """
    if not 0 <= country <= 0x3FF:
        raise ArgsParserError("country must be 0-1023")
    if not 0 <= national <= ((1 << 38) - 1):
        raise ArgsParserError("national ID must be 0-274877906943 (38-bit field)")
    if not 0 <= extended <= 0xFFFFFF:
        raise ArgsParserError("extended data must be 0-16777215 (24-bit field)")

    v = national & ((1 << 38) - 1)
    v |= (country & 0x3FF) << 38
    v |= (1 if extended else 0) << 48
    v |= (animal & 1) << 63

    head = v.to_bytes(8, "little")
    crc = _fdxb_crc16(head).to_bytes(2, "little")
    ext = (extended & 0xFFFFFF).to_bytes(3, "little")
    return head + crc + ext


class TagTypeArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_type_args(parser: ArgumentParserNoExit):
        type_names = [t.name for t in TagSpecificType.list()]
        help_str = "Tag Type: " + ", ".join(type_names)
        parser.add_argument(
            "-t",
            "--type",
            type=str,
            required=True,
            metavar="TAG_TYPE",
            help=help_str,
            choices=type_names,
        )
        return parser

    def args_parser(self) -> ArgumentParserNoExit:
        raise NotImplementedError()

    def on_exec(self, args: argparse.Namespace):
        raise NotImplementedError()


root = CLITree(root=True)
hw = root.subgroup("hw", "Hardware-related commands")
hw_slot = hw.subgroup("slot", "Emulation slots commands")
hw_settings = hw.subgroup("settings", "Chameleon settings commands")

hf = root.subgroup("hf", "High Frequency commands")
hf_14a = hf.subgroup("14a", "ISO14443-a commands")
hf_mf = hf.subgroup("mf", "MIFARE Classic commands")
hf_mfu = hf.subgroup("mfu", "MIFARE Ultralight / NTAG commands")
hf_des = hf.subgroup("des", "MIFARE DESFire commands")
hf_seos = hf.subgroup("seos", "SEOS commands")
hf_st25ta = hf.subgroup("st25ta", "ST25TA (NFC Forum Type 4) commands")
hf_mfplus = hf.subgroup("mfplus", "MIFARE Plus SL3 (AES) commands")

lf = root.subgroup("lf", "Low Frequency commands")
lf_em = lf.subgroup("em", "EM commands")
lf_em_4x05 = lf_em.subgroup("4x05", "EM4x05/EM4x69 commands")
lf_indala = lf.subgroup("indala", "Indala commands")
data = root.subgroup("data", "Data analysis and visualization commands")
emv = root.subgroup("emv", "EMV contactless payment card commands")
standalone = root.subgroup("standalone", "Host-less standalone modes")


lf_em_410x = lf_em.subgroup("410x", "EM410x commands")
lf_hid = lf.subgroup("hid", "HID commands")
lf_hid_prox = lf_hid.subgroup("prox", "HID Prox commands")
lf_ioprox = lf.subgroup("ioprox", "ioProx commands")
lf_pac = lf.subgroup("pac", "PAC/Stanley commands")
lf_viking = lf.subgroup("viking", "Viking commands")
lf_jablotron = lf.subgroup("jablotron", "Jablotron commands")
lf_fdxb = lf.subgroup("fdxb", "FDX-B animal tag commands (134.2 kHz)")
lf_generic = lf.subgroup("generic", "Generic commands")
lf_idteck = lf.subgroup("idteck", "IDTECK commands")
lf_t55xx = lf.subgroup("t55xx", "T55xx/T5577 raw block commands")


# --- shared helpers relocated from chameleon_cli_unit during the split ---
# (used by cli_hf_mfu/cli_hf_des/cli_lf and the monolith; must live in the
#  foundation so every module can import them.)


class CrackEffect:
    """
    A class to create a visual effect of cracking blocks of data.
    """

    def __init__(
        self, num_blocks: int = 4, block_size: int = 8, scramble_delay: float = 0.01
    ):
        """
        Initialize the CrackEffect class with the given parameters.

        Args:
            num_blocks (int): Number of blocks to display. Default is 4.
            block_size (int): Size of each block in characters. Default is 8.
            scramble_delay (float): Delay between each scramble update in seconds. Default is 0.01.
        """
        self.num_blocks = num_blocks
        self.block_size = block_size
        self.scramble_delay = scramble_delay
        self.message_queue = queue.Queue()
        self.revealed = [""] * num_blocks
        self.stop_event = threading.Event()
        self.cracked_blocks = set()
        self.display_lock = threading.Lock()
        self.output_enabled = True

    def generate_random_hex(self) -> str:
        """Generate a random hex string of block_size length."""
        import random

        hex_chars = "0123456789ABCDEF"
        return "".join(random.choice(hex_chars) for _ in range(self.block_size))

    def format_block(self, block: str, is_cracked: bool) -> str:
        """Format a block with appropriate color based on its state."""
        if is_cracked:
            return f"\033[1;34m{block}\033[0m"  # Bold blue
        return f"\033[96m{block}\033[0m"  # Bright cyan

    def draw_static_box(self):
        """Draw the initial static box."""
        if not self.output_enabled:
            return
        width = (self.block_size + 1) * self.num_blocks + 4
        print("")  # Add some padding above
        print("╔" + "═" * width + "╗")
        print("║" + " " * width + "║")
        print("║" + " " * width + "║")
        print("║" + " " * width + "║")
        print("╚" + "═" * width + "╝")
        # Move cursor to the middle line
        sys.stdout.write("\033[3A")  # Move up 3 lines to middle row
        sys.stdout.flush()

    def print_above(self, data):
        """Print the given data above the box and redraws the box."""
        if not self.output_enabled:
            print(data)
            return
        with self.display_lock:
            # Move cursor above the box and clean the line
            sys.stdout.write("\033[2A\033[1G\033[K" + data)
            self.draw_static_box()

    def display_current_state(self):
        """Display the current state of all blocks."""
        if not self.output_enabled:
            return
        with self.display_lock:
            formatted_blocks = [
                self.format_block(block, i in self.cracked_blocks)
                for i, block in enumerate(self.revealed)
            ]
            display_text = " ".join(formatted_blocks)

            # Update only the middle line
            sys.stdout.write(f"\r║  {display_text}   ║")
            sys.stdout.flush()

    def scramble_effect(self):
        """Run the main loop for the scrambling effect."""
        if not self.output_enabled:
            return
        while not self.stop_event.is_set():
            # Update all non-cracked blocks with random values
            for block in range(self.num_blocks):
                if block not in self.cracked_blocks:
                    self.revealed[block] = self.generate_random_hex()

            self.display_current_state()
            time.sleep(self.scramble_delay)

    def erase_key(self):
        """Erase random parts of the key."""
        if not self.output_enabled:
            return
        for block in range(self.num_blocks):
            if block not in self.cracked_blocks:
                self.revealed[block] = "." * self.block_size
        self.display_current_state()

    def process_message_queue(self):
        """Process incoming cracked blocks from the queue."""
        if not self.output_enabled:
            return
        while not self.stop_event.is_set():
            try:
                block_idx, cracked_text = self.message_queue.get(timeout=0.1)
                self.revealed[block_idx] = cracked_text
                self.cracked_blocks.add(block_idx)
                self.display_current_state()

                # Check if all blocks are cracked
                if len(self.cracked_blocks) == self.num_blocks:
                    self.stop_event.set()
                    print("\n" * 3)  # Add newlines after completion
                    break
            except queue.Empty:
                continue
            except Exception as e:
                print(f"\nError processing message: {e}")
                break

    def add_cracked_block(self, block_idx: int, text: str):
        """Add a cracked block to the message queue."""
        if not 0 <= block_idx < self.num_blocks:
            raise ValueError(f"Block index {block_idx} out of range")
        if len(text) != self.block_size:
            raise ValueError(f"Block text must be {self.block_size} characters")
        self.message_queue.put((block_idx, text))

    def start(self):
        """Start the cracking effect."""
        self.draw_static_box()

        # Create and start the worker threads
        scramble_thread = threading.Thread(target=self.scramble_effect)
        process_thread = threading.Thread(target=self.process_message_queue)

        scramble_thread.daemon = True
        process_thread.daemon = True

        scramble_thread.start()
        process_thread.start()

        # Wait for both threads to complete
        process_thread.join()
        self.stop_event.set()
        scramble_thread.join()


def _decode_14a_frame_col(
    data: bytes, szBits: int, is_tx: bool = False, prev_cmd=None, iso_dep: bool = False
):
    """Return (description, colour, cmd_tag) for a 14A frame.

    Direction- and context-gated so demod garbage is not dressed up as protocol:
      * is_tx False (reader->card) is decoded as a COMMAND, is_tx True
        (card->reader) as a RESPONSE.
      * a response is only NAMED when the preceding reader command makes it
        plausible -- ATQA after REQA/WUPA, SAK after SELECT, UID after ANTICOLL
        -- and it passes its integrity check (BCC / length).
      * APDUs are only decoded inside an established ISO-DEP (RATS/ATS) channel.
    Anything that fails is shown raw, not mislabelled.

    cmd_tag (3rd value) is this frame's reader-command class ('reqa','anticoll1',
    'select1','auth','rats','halt','deselect',...) or None, so the caller can
    feed it as prev_cmd to the next frame and track ISO-DEP state.
    """
    if not data:
        return "", C0, None
    b0 = data[0]

    def raw(reason=""):
        body = f"raw {data.hex()}"
        return (f"{body}  ({reason})" if reason else body), _CD, None

    # ===================== READER -> CARD : commands =====================
    if not is_tx:
        if szBits == 7:
            if b0 == 0x26:
                return "REQA", CG, "reqa"
            if b0 == 0x52:
                return "WUPA", CG, "wupa"
            return f"short(0x{b0:02x})", CC, None
        if b0 in (0x93, 0x95, 0x97):
            lvl = {0x93: "1", 0x95: "2", 0x97: "3"}[b0]
            if len(data) > 1 and data[1] == 0x70:
                uid = " ".join(f"{b:02x}" for b in data[2:6]) if len(data) >= 6 else ""
                return f"SELECT CL{lvl}  UID={uid}", CB, f"select{lvl}"
            nvb = f"NVB={data[1]:02x}" if len(data) > 1 else ""
            return f"ANTICOLL CL{lvl}  {nvb}", CB, f"anticoll{lvl}"
        if b0 == 0x50:
            return "HALT", CC, "halt"
        if b0 == 0xC2:
            return "S-DESELECT", CC, "deselect"
        if b0 == 0xD0:
            return (f"PPS  PPS1={data[1]:02x}" if len(data) > 1 else "PPS"), CC, None
        if b0 == 0xE0:
            fsdi = (data[1] >> 4) if len(data) > 1 else 0
            cid = (data[1] & 0xF) if len(data) > 1 else 0
            return f"RATS  FSDI={fsdi} CID={cid}", CC, "rats"
        if b0 == 0x60:
            return (
                (f"AUTH KeyA  block={data[1]}" if len(data) > 1 else "AUTH KeyA"),
                CR,
                "auth",
            )
        if b0 == 0x61:
            return (
                (f"AUTH KeyB  block={data[1]}" if len(data) > 1 else "AUTH KeyB"),
                CR,
                "auth",
            )
        if b0 == 0x30:
            return (f"READ  block={data[1]}" if len(data) > 1 else "READ"), CC, "read"
        if b0 == 0xA0:
            return (f"WRITE block={data[1]}" if len(data) > 1 else "WRITE"), CY, "write"
        if b0 == 0x40:
            return "MAGIC WUPC1", CY, None
        if b0 == 0x43:
            return "MAGIC WUPC2", CY, None
        if b0 == 0x41:
            return "MAGIC WIPE", CR, None
        # ISO 7816-4 APDU -- only inside an established ISO-DEP channel
        if iso_dep and len(data) >= 4 and b0 in (0x00, 0x80, 0x90, 0xA0):
            cla, ins = data[0], data[1]
            p1 = data[2] if len(data) > 2 else 0
            p2 = data[3] if len(data) > 3 else 0
            if cla == 0x00 and ins == 0xA4:
                if len(data) > 5:
                    aid = " ".join(f"{b:02x}" for b in data[5 : 5 + data[4]])
                    name = _known_aid(bytes(data[5 : 5 + data[4]]))
                    label = f"SELECT AID  {aid.upper()}" + (
                        f"  ({name})" if name else ""
                    )
                    return label, CY, None
                return "SELECT", CY, None
            if cla == 0x00 and ins == 0xB0:
                return (
                    f"READ BINARY  off={p1 << 8 | p2} len={data[4] if len(data) > 4 else 0}",
                    CC,
                    None,
                )
            if cla == 0x00 and ins == 0xB2:
                return f"READ RECORD  SFI={p2 >> 3} rec={p1}", CC, None
            if cla == 0x80 and ins == 0xCA:
                name = _known_bertag((p1 << 8) | p2)
                return (
                    f"GET DATA  {p1:02x}{p2:02x}" + (f"  ({name})" if name else ""),
                    CC,
                    None,
                )
            if cla == 0x80 and ins == 0xA8:
                return "GPO  (Get Processing Options)", CY, None
            if cla == 0x80 and ins == 0xAE:
                actype = {0x00: "AAC", 0x40: "TC", 0x80: "ARQC"}.get(
                    p1 & 0xC0, f"AC/{p1:02x}"
                )
                return f"GENERATE AC  requesting {actype}", CR, None
            if cla == 0x00 and ins == 0x20:
                return "VERIFY PIN", CY, None
            if cla == 0x00 and ins == 0x88:
                return "INTERNAL AUTH", CR, None
            if cla == 0x00 and ins == 0x82:
                return "EXTERNAL AUTH", CR, None
            if cla == 0x00 and ins == 0x70:
                return "MANAGE CHANNEL", CC, None
            return (
                f"APDU  CLA={cla:02x} INS={ins:02x} P1={p1:02x} P2={p2:02x}",
                CY,
                None,
            )
        if szBits >= 64:
            return "(encrypted / data)", CC, None
        return f"unknown cmd (0x{b0:02x})", CC, None

    # ===================== CARD -> READER : responses =====================
    # ATQA -- 2 bytes, only right after REQA/WUPA
    if (
        szBits == 16
        and len(data) == 2
        and prev_cmd in ("reqa", "wupa")
        and (data[0] & 0x20) == 0  # byte0 bit5 is RFU (0)
        and (data[0] & 0x1F) != 0  # byte0 must carry a bit-frame SDD bit
        and (data[1] & 0xF0) == 0
    ):  # byte1 high nibble is RFU (0)
        atqa = data[0] | (data[1] << 8)
        return f"ATQA (Answer To Request, Type A) = 0x{atqa:04X}", CG, None
    # UID/anticoll response -- 5 bytes with VALID BCC, only after ANTICOLL
    if (
        szBits == 40
        and len(data) == 5
        and prev_cmd in ("anticoll1", "anticoll2", "anticoll3")
    ):
        u0, u1, u2, u3, bcc = data
        if (u0 ^ u1 ^ u2 ^ u3) == bcc:
            return (
                f"ANTICOLL response: UID={bytes(data[:4]).hex()}  BCC=0x{bcc:02X} (OK)",
                CG,
                None,
            )
        return raw("BCC fail")
    # SAK -- 1 byte (or 3 on the wire incl. CRC-A), only after a SELECT
    if prev_cmd in ("select1", "select2", "select3") and (
        (szBits == 8 and len(data) == 1) or (szBits == 24 and len(data) == 3)
    ):
        return _sak_desc(data[0]), CG, None
    # ISO-DEP response -- ISO 7816 status word at the tail
    if iso_dep and len(data) >= 2:
        for off in (-2, -4):
            if len(data) >= abs(off):
                lbl = _decode_sw(data[off], data[off + 1])
                if lbl:
                    return f"SW {data[off]:02X} {data[off + 1]:02X}  {lbl}", CY, None
    # large blob (the caller's auth tracker names the specific NT/NR||AR/AT)
    if szBits >= 64:
        return "(encrypted / data)", CC, None
    # nothing matched a plausible response -> show raw, do not invent a label
    return raw()

    # Short frames (7-bit)
    if szBits == 7:
        if b0 == 0x26:
            return "REQA", CG
        if b0 == 0x52:
            return "WUPA", CG
        return f"short(0x{b0:02x})", CC

    # Sub-byte noise frames (< 7 bits) — field activation artefacts
    if szBits < 7:
        return f"field noise ({szBits} bit)", CC

    # Anti-collision / Select
    if b0 == 0x93:
        if len(data) > 1 and data[1] == 0x70:
            uid = " ".join(f"{b:02x}" for b in data[2:6]) if len(data) >= 6 else ""
            return f"SELECT CL1  UID={uid}", CB
        nvb = f"NVB={data[1]:02x}" if len(data) > 1 else ""
        return f"ANTICOLL CL1  {nvb}", CB
    if b0 == 0x95:
        if len(data) > 1 and data[1] == 0x70:
            uid = " ".join(f"{b:02x}" for b in data[2:6]) if len(data) >= 6 else ""
            return f"SELECT CL2  UID={uid}", CB
        nvb = f"NVB={data[1]:02x}" if len(data) > 1 else ""
        return f"ANTICOLL CL2  {nvb}", CB
    if b0 == 0x97:
        if len(data) > 1 and data[1] == 0x70:
            uid = " ".join(f"{b:02x}" for b in data[2:6]) if len(data) >= 6 else ""
            return f"SELECT CL3  UID={uid}", CB
        nvb = f"NVB={data[1]:02x}" if len(data) > 1 else ""
        return f"ANTICOLL CL3  {nvb}", CB

    # HALT (0x50 0x00 + CRC — b1 may vary after parity strip)
    if b0 == 0x50:
        return "HALT", CC

    # S-DESELECT (ISO14443-4 block)
    if b0 == 0xC2:
        return "S-DESELECT", CC

    # PPS
    if b0 == 0xD0:
        return f"PPS  PPS1={data[1]:02x}" if len(data) > 1 else "PPS", CC

    # RATS
    if b0 == 0xE0:
        fsdi = (data[1] >> 4) if len(data) > 1 else 0
        cid = (data[1] & 0xF) if len(data) > 1 else 0
        return f"RATS  FSDI={fsdi} CID={cid}", CC

    # MIFARE Classic commands
    if b0 == 0x60:
        return (
            f"AUTH KeyA  block=0x{data[1]:02X} ({data[1]})"
            if len(data) > 1
            else "AUTH KeyA"
        ), CR
    if b0 == 0x61:
        return (
            f"AUTH KeyB  block=0x{data[1]:02X} ({data[1]})"
            if len(data) > 1
            else "AUTH KeyB"
        ), CR
    # Encrypted nonce / auth response (follows AUTH, first byte varies)
    if szBits == 72:
        return "(encrypted nonce — auth challenge/response)", CC

    if b0 == 0x30:
        return f"READ  block={data[1]}" if len(data) > 1 else "READ", CC
    if b0 == 0xA0:
        return f"WRITE block={data[1]}" if len(data) > 1 else "WRITE", CY
    if b0 == 0x40:
        return "MAGIC WUPC1", CY
    if b0 == 0x43:
        return "MAGIC WUPC2", CY
    if b0 == 0x41:
        return "MAGIC WIPE", CR

    # ISO 7816-4 APDUs
    if len(data) >= 2 and b0 in (0x00, 0x80, 0x90, 0xA0):
        cla, ins = data[0], data[1]
        p1 = data[2] if len(data) > 2 else 0
        p2 = data[3] if len(data) > 3 else 0
        # SELECT FILE / AID
        if cla == 0x00 and ins == 0xA4:
            if len(data) > 5:
                aid = " ".join(f"{b:02x}" for b in data[5 : 5 + data[4]])
                # Identify known AIDs
                aid_raw = bytes(data[5 : 5 + data[4]])
                name = _known_aid(aid_raw)
                label = f"SELECT AID  {aid.upper()}"
                if name:
                    label += f"  ({name})"
                return label, CY
            return "SELECT", CY
        # READ BINARY
        if cla == 0x00 and ins == 0xB0:
            return (
                f"READ BINARY  off={p1 << 8 | p2} len={data[4] if len(data) > 4 else 0}",
                CC,
            )
        # READ RECORD
        if cla == 0x00 and ins == 0xB2:
            sfi = p2 >> 3
            return f"READ RECORD  SFI={sfi} rec={p1}", CC
        # GET DATA
        if cla == 0x80 and ins == 0xCA:
            tag = (p1 << 8) | p2
            name = _known_bertag(tag)
            return f"GET DATA  {p1:02x}{p2:02x}" + (f"  ({name})" if name else ""), CC
        # GET PROCESSING OPTIONS
        if cla == 0x80 and ins == 0xA8:
            return "GPO  (Get Processing Options)", CY
        # GENERATE AC
        if cla == 0x80 and ins == 0xAE:
            actype = {0x00: "AAC", 0x40: "TC", 0x80: "ARQC"}.get(
                p1 & 0xC0, f"AC/{p1:02x}"
            )
            return f"GENERATE AC  requesting {actype}", CR
        # VERIFY
        if cla == 0x00 and ins == 0x20:
            return "VERIFY PIN", CY
        # INTERNAL AUTHENTICATE
        if cla == 0x00 and ins == 0x88:
            return "INTERNAL AUTH", CR
        # EXTERNAL AUTHENTICATE
        if cla == 0x00 and ins == 0x82:
            return "EXTERNAL AUTH", CR
        # MANAGE CHANNEL
        if cla == 0x00 and ins == 0x70:
            return "MANAGE CHANNEL", CC
        return f"APDU  CLA={cla:02x} INS={ins:02x} P1={p1:02x} P2={p2:02x}", CY

    # ISO 7816-4 status word — scan last 2 bytes (and last 4 if CRC present)
    sw_label = ""
    for sw_offset in (-2, -4):
        if len(data) >= abs(sw_offset):
            s1, s2 = data[sw_offset], data[sw_offset + 1]
            lbl = _decode_sw(s1, s2)
            if lbl:
                sw_label = f"SW {s1:02X} {s2:02X}  {lbl}"
                break
    if sw_label:
        return sw_label, CY

    # Unknown — show first byte
    return f"unknown (0x{b0:02x})", CC


def indala_encode_raw(fc: int, cn: int) -> bytes:
    """Encode FC/CN into 8-byte Indala 26-bit raw frame (PM3-compatible bit mapping)."""
    bits = [0] * 64

    # preamble
    bits[0] = 1
    bits[2] = 1
    bits[32] = 1

    # fc
    bits[57] = (fc >> 7) & 1
    bits[49] = (fc >> 6) & 1
    bits[44] = (fc >> 5) & 1
    bits[47] = (fc >> 4) & 1
    bits[48] = (fc >> 3) & 1
    bits[53] = (fc >> 2) & 1
    bits[39] = (fc >> 1) & 1
    bits[58] = fc & 1

    # cn
    bits[42] = (cn >> 15) & 1
    bits[45] = (cn >> 14) & 1
    bits[43] = (cn >> 13) & 1
    bits[40] = (cn >> 12) & 1
    bits[52] = (cn >> 11) & 1
    bits[36] = (cn >> 10) & 1
    bits[35] = (cn >> 9) & 1
    bits[51] = (cn >> 8) & 1
    bits[46] = (cn >> 7) & 1
    bits[33] = (cn >> 6) & 1
    bits[37] = (cn >> 5) & 1
    bits[54] = (cn >> 4) & 1
    bits[56] = (cn >> 3) & 1
    bits[59] = (cn >> 2) & 1
    bits[50] = (cn >> 1) & 1
    bits[41] = cn & 1

    # checksum (sum of specific cn bits)
    chk = sum(
        [
            (cn >> 14) & 1,
            (cn >> 12) & 1,
            (cn >> 9) & 1,
            (cn >> 8) & 1,
            (cn >> 6) & 1,
            (cn >> 5) & 1,
            (cn >> 2) & 1,
            cn & 1,
        ]
    )
    if chk % 2 == 0:
        bits[62], bits[63] = 1, 0
    else:
        bits[62], bits[63] = 0, 1

    # parity
    p1, p2 = 1, 1
    for i in range(33, 64):
        if i % 2:
            p1 ^= bits[i]
        else:
            p2 ^= bits[i]
    bits[34] = p1
    bits[38] = p2

    raw = bytearray(8)
    for i in range(64):
        if bits[i]:
            raw[i // 8] |= 1 << (7 - (i % 8))
    return bytes(raw)


def indala_format_output(raw: bytes) -> str:
    """Format Indala raw bytes as PM3-style output string."""
    fc, cn = indala_decode_raw(raw)
    lines = [f"Indala (len 64)  Raw: {raw.hex().upper()}"]
    lines.append(f"   Fmt 26  FC: {fc}  Card: {cn}")
    return "\n".join(lines)


# --- shared decode/table helpers relocated during the split ---


def _decode_sw(sw1: int, sw2: int) -> str:
    """Decode an ISO 7816-4 status word pair."""
    exact = {
        0x9000: "OK",
        0x6100: "Response bytes available",
        0x6283: "File deactivated",
        0x6300: "Auth failed",
        0x6400: "No changes",
        0x6581: "Memory failure",
        0x6700: "Wrong length",
        0x6881: "Logical channel not supported",
        0x6882: "Secure messaging not supported",
        0x6900: "Command not allowed",
        0x6981: "Command incompatible with file structure",
        0x6982: "Security status not satisfied",
        0x6983: "Auth method blocked",
        0x6984: "Referenced data invalidated",
        0x6985: "Conditions of use not satisfied",
        0x6986: "Command not allowed — no EF selected",
        0x6A00: "Wrong parameters P1-P2",
        0x6A80: "Incorrect data in command",
        0x6A81: "Function not supported",
        0x6A82: "File not found",
        0x6A83: "Record not found",
        0x6A84: "Not enough memory",
        0x6A85: "Lc inconsistent with TLV",
        0x6A86: "Incorrect parameters P1-P2",
        0x6A87: "Lc inconsistent with P1-P2",
        0x6A88: "Referenced data not found",
        0x6B00: "Wrong parameters P1-P2",
        0x6D00: "Instruction not supported",
        0x6E00: "Class not supported",
        0x6F00: "Unknown error",
    }
    key = (sw1 << 8) | sw2
    if key in exact:
        return exact[key]
    if sw1 == 0x61:
        return f"Response bytes available: {sw2}"
    if sw1 == 0x62:
        return f"Warning — no info change: {sw2:02X}"
    if sw1 == 0x63:
        return f"Warning — state changed: {sw2:02X}"
    if sw1 == 0x6C:
        return f"Wrong Le — use {sw2}"
    if sw1 == 0x90:
        return "OK"
    if sw1 == 0x91:
        return "Proprietary OK"
    return ""


_CD = "\033[90m"  # dim grey: raw/garbled frames that fail validation


def _sak_desc(sak: int):
    try:
        sak_type = type_id_SAK_dict.get(sak, "")
    except Exception:
        sak_type = ""
    if sak_type:
        return f"SAK (Select Acknowledge) = 0x{sak:02X}  [{sak_type}]"
    return f"SAK (Select Acknowledge) = 0x{sak:02X}"


def _known_aid(aid: bytes) -> str:
    table = {
        bytes.fromhex("a0000000031010"): "Visa Credit/Debit",
        bytes.fromhex("a0000000032010"): "Visa Electron",
        bytes.fromhex("a0000000033010"): "Visa Classic",
        bytes.fromhex("a0000000038010"): "Visa Plus",
        bytes.fromhex("a0000000041010"): "Mastercard",
        bytes.fromhex("a0000000043060"): "Maestro",
        bytes.fromhex("a000000025010801"): "AmEx",
        bytes.fromhex("a0000000181002"): "Mastercard Debit",
        bytes.fromhex("d2760000850101"): "NDEF (NFC Forum)",
        bytes.fromhex("d27600002545"): "NDEF Type 4",
        bytes.fromhex("315041592e5359532e4444463031"): "PPSE (2PAY.SYS.DDF01)",
    }
    return table.get(aid, "")


def _known_bertag(tag: int) -> str:
    table = {
        0x9F36: "ATC",
        0x9F13: "Last Online ATC",
        0x9F17: "PIN Try Counter",
        0x9F4F: "Log Format",
        0x9F4E: "Merchant Name",
    }
    return table.get(tag, "")


def indala_decode_raw(raw: bytes):
    """Decode Indala 26-bit FC/CN from 8-byte raw frame (PM3-compatible bit mapping)."""
    bits = []
    for b in raw:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)

    fc = 0
    fc |= bits[57] << 7
    fc |= bits[49] << 6
    fc |= bits[44] << 5
    fc |= bits[47] << 4
    fc |= bits[48] << 3
    fc |= bits[53] << 2
    fc |= bits[39] << 1
    fc |= bits[58] << 0

    cn = 0
    cn |= bits[42] << 15
    cn |= bits[45] << 14
    cn |= bits[43] << 13
    cn |= bits[40] << 12
    cn |= bits[52] << 11
    cn |= bits[36] << 10
    cn |= bits[35] << 9
    cn |= bits[51] << 8
    cn |= bits[46] << 7
    cn |= bits[33] << 6
    cn |= bits[37] << 5
    cn |= bits[54] << 4
    cn |= bits[56] << 3
    cn |= bits[59] << 2
    cn |= bits[50] << 1
    cn |= bits[41] << 0

    return fc, cn


# --- shared helpers relocated from cli_lf (used by the monolith too) ---


def jablotron_card_id(raw_bytes: bytes) -> int:
    """Convert 5 raw Jablotron bytes to decimal card number via BCD."""
    card_id = 0
    for b in raw_bytes:
        card_id = card_id * 100 + ((b >> 4) * 10) + (b & 0x0F)
    return card_id


def pac_encode_raw(card_id: bytes) -> bytes:
    """Encode 8-byte card ID to 16-byte T55XX bitstream (128 bits).

    Frame: 0xFF sync (8 bits) + 12 × 10-bit UART frames.
    UART frame: start(0) + 7 data bits LSB-first + odd parity + stop(1).
    Payload: STX(0x02), '2', '0', card_id[0..7], XOR checksum.
    """
    payload = [0x02, 0x32, 0x30] + list(card_id)
    xor_check = 0
    for b in card_id:
        xor_check ^= b
    payload.append(xor_check)

    bits = [1] * 8  # sync marker 0xFF
    for byte_val in payload:
        bits.append(0)  # start bit
        ones = 0
        for i in range(7):
            bit = (byte_val >> i) & 1
            bits.append(bit)
            ones += bit
        bits.append(0 if (ones & 1) else 1)  # odd parity
        bits.append(1)  # stop bit

    raw = bytearray(16)
    for i in range(128):
        if bits[i]:
            raw[i >> 3] |= 1 << (7 - (i & 7))
    return bytes(raw)


# --- shared helpers relocated from cli_hf_mf (used by the monolith too) ---

_TOOL_MISSING = "MISSING"  # binary not found on disk

_TOOL_BLOCKED = "BLOCKED"  # binary exists but OS/AV prevented execution

_TOOL_NO_KEY = "NO_KEY"  # binary ran cleanly, no key found for these nonces


def _sniff_tool_path(name):
    """Return the Path to a cracking binary, or None if not present."""
    suffix = ".exe" if sys.platform == "win32" else ""
    p = default_cwd / (name + suffix)
    return p if p.exists() else None


def _run_mfkey64(uid, nt, nr, ar, at):
    """
    Run mfkey64 and return the recovered key string (12 hex chars), or one of
    _TOOL_MISSING / _TOOL_BLOCKED / _TOOL_NO_KEY.

    mfkey64 requires 5 args: uid nt {nr} {ar} {at}
    When cracking a sniff pair (both at==\'\'):
        at = nonce[1].nt  (the CU sent this as {at} after nonce[0]; the reader
                           treated it as a fresh nt for the next auth round)
    When cracking a single complete auth:
        at = the directly captured {at} frame
    """
    path = _sniff_tool_path("mfkey64")
    if path is None:
        return _TOOL_MISSING
    try:
        result = subprocess.run(
            [str(path), uid, nt, nr, ar, at],
            capture_output=True,
            timeout=30,
            encoding="ascii",
        )
    except FileNotFoundError:
        return _TOOL_MISSING
    except PermissionError:
        return _TOOL_BLOCKED
    except OSError:
        # Covers antivirus quarantine, wrong arch, etc.
        return _TOOL_BLOCKED
    except subprocess.TimeoutExpired:
        return _TOOL_BLOCKED
    if result.returncode not in (0, 1):
        # Non-zero exit other than 1 (usage error) usually means OS blocked it
        return _TOOL_BLOCKED
    sea_obj = _KEY.search(result.stdout)
    return sea_obj[0] if sea_obj is not None else _TOOL_NO_KEY


def _run_mfkey32v2(items):
    """
    Used by HFMFELog (detection-log path) via multiprocessing Pool.
    Returns (key_str, items) on success, None if not found, raises on binary errors
    so the pool can propagate them.
    """
    output_str = subprocess.run(
        [
            default_cwd / ("mfkey32v2.exe" if sys.platform == "win32" else "mfkey32v2"),
            items[0]["uid"],
            items[0]["nt"],
            items[0]["nr"],
            items[0]["ar"],
            items[1]["nt"],
            items[1]["nr"],
            items[1]["ar"],
        ],
        capture_output=True,
        check=True,
        encoding="ascii",
    ).stdout
    sea_obj = _KEY.search(output_str)
    if sea_obj is not None:
        return sea_obj[0], items
    return None


def _run_mfkey32v2_sniff(n0, n1):
    """
    Sniff-path wrapper for mfkey32v2.  Returns a key string, or one of
    _TOOL_MISSING / _TOOL_BLOCKED / _TOOL_NO_KEY — never raises.
    """
    path = _sniff_tool_path("mfkey32v2")
    if path is None:
        return _TOOL_MISSING
    try:
        result = subprocess.run(
            [
                str(path),
                n0["uid"],
                n0["nt"],
                n0["nr"],
                n0["ar"],
                n1["nt"],
                n1["nr"],
                n1["ar"],
            ],
            capture_output=True,
            timeout=30,
            encoding="ascii",
        )
    except FileNotFoundError:
        return _TOOL_MISSING
    except PermissionError:
        return _TOOL_BLOCKED
    except OSError:
        return _TOOL_BLOCKED
    except subprocess.TimeoutExpired:
        return _TOOL_BLOCKED
    if result.returncode not in (0, 1):
        return _TOOL_BLOCKED
    sea_obj = _KEY.search(result.stdout)
    return sea_obj[0] if sea_obj is not None else _TOOL_NO_KEY


# --- shared helpers relocated from cli_hf_des (used by the monolith too) ---

AUTHTRACE_STATUS_NAMES = {
    0x00: "ok",
    0x01: "no_tag",
    0x02: "err_stat",
    0x06: "auth_fail",
    0x60: "par_err",
    0x68: "success",
}

# --- default MFC key (used by relocated mfkey helpers) ---
_KEY = re.compile("[a-fA-F0-9]{12}", flags=re.MULTILINE)
