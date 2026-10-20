"""cli_hf_mfplus - MIFARE Plus SL0/SL3 (AES) emulation commands (hf mfplus ...).

Scope, matching the firmware: real SL0 personalization (WritePerso/
CommitPerso) with per-sector Key A/B plus the three mandatory admin keys
(CardMasterKey 0x9000, CardConfigKey 0x9001, L3SwitchKey 0x9003),
AuthenticateFirst and AuthenticateNonFirst, CMAC'd and AES-CBC encrypted
ReadBlock/WriteBlock, GetVersion. A freshly factory-reset slot starts in
SL0 (transport configuration) and only reaches SL3 once CommitPerso
succeeds -- there is no SL0->SL1 personalization path.
"""

import argparse

from cli_core import (
    ArgumentParserNoExit,
    CG,
    CR,
    CY,
    DeviceRequiredUnit,
    SlotIndexArgsAndGoUnit,
    TagSpecificType,
    color_string,
    hf_mfplus,
)

MFPLUS_LEVEL_SL0 = 0
MFPLUS_LEVEL_SL3 = 3

# CardMasterKey / CardConfigKey / L3SwitchKey -- the three admin keys that
# must be written before CommitPerso will switch SL0 -> SL3.
KEY_ADDR_ALIASES = {
    "master": (0x90, 0x00),
    "config": (0x90, 0x01),
    "l3switch": (0x90, 0x03),
}


def _require_mfplus_slot(cmd):
    active = cmd.get_active_slot()
    slot_info = cmd.get_slot_info()
    hf_type = TagSpecificType(slot_info[active]["hf"])
    if hf_type not in (TagSpecificType.MIFARE_PLUS_S2K_SL3, TagSpecificType.MIFARE_PLUS_S4K_SL3):
        raise Exception("Card in current slot is not MIFARE Plus")


def _parse_addr(addr_str: str):
    """Accepts an alias (master/config/l3switch), a sector/keytype pair
    like '1:A', or a raw 4-hex-digit key number like '4002'."""
    addr_str = addr_str.strip()
    if addr_str.lower() in KEY_ADDR_ALIASES:
        return KEY_ADDR_ALIASES[addr_str.lower()]
    if ":" in addr_str:
        sector_str, keytype_str = addr_str.split(":", 1)
        sector = int(sector_str)
        keytype = 0 if keytype_str.strip().upper() == "A" else 1
        key_num = 0x4000 + sector * 2 + keytype
        return (key_num >> 8) & 0xFF, key_num & 0xFF
    key_num = int(addr_str, 16)
    return (key_num >> 8) & 0xFF, key_num & 0xFF


@hf_mfplus.command("info")
class HFMfPlusInfo(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Show MIFARE Plus emulator state (security level, block count)"
        self.add_slot_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        _require_mfplus_slot(self.cmd)
        info = self.cmd.mfplus_get_info()
        anti = self.cmd.hf14a_get_anti_coll_data()

        if anti:
            print(f"{'UID:':20}{color_string((CY, anti['uid'].hex().upper()))}")
            print(f"{'ATQA:':20}{color_string((CY, anti['atqa'].hex().upper()))}")
            print(f"{'SAK:':20}{color_string((CY, anti['sak'].hex().upper()))}")
            print(f"{'ATS:':20}{color_string((CY, anti['ats'].hex().upper()))}")
        level = info["level"]
        level_str = {MFPLUS_LEVEL_SL0: "SL0 (not personalized)",
                     MFPLUS_LEVEL_SL3: "SL3 (AES)"}.get(level, f"unknown ({level})")
        print(f"{'Security level:':20}{color_string((CY, level_str))}")
        print(f"{'Blocks:':20}{info['block_max']}")
        if level == MFPLUS_LEVEL_SL0:
            print()
            print(color_string((CY,
                "Card is in SL0 (transport configuration). Use 'hf mfplus wrp' "
                "to write the mandatory admin keys and any per-sector keys, "
                "then 'hf mfplus commitp' to switch to SL3.")))


@hf_mfplus.command("wrp")
class HFMfPlusWritePerso(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "WritePerso: write one AES key into the MIFARE Plus key table. "
            "Only valid while the card is in SL0."
        )
        self.add_slot_args(parser)
        parser.add_argument(
            "-a", "--addr", type=str, required=True, metavar="<addr>",
            help="Key slot: 'master', 'config', 'l3switch' (the three mandatory "
                 "admin keys), '<sector>:A' / '<sector>:B' for a per-sector key, "
                 "or a raw 4-hex-digit key number (e.g. 4002)")
        parser.add_argument(
            "-k", "--key", type=str, required=True, metavar="<hex32>",
            help="16-byte AES key (32 hex chars)")
        return parser

    def on_exec(self, args: argparse.Namespace):
        _require_mfplus_slot(self.cmd)
        key = bytes.fromhex(args.key.strip())
        if len(key) != 16:
            print(color_string((CR, "Error: key must be 16 bytes (32 hex chars)")))
            return
        addr_hi, addr_lo = _parse_addr(args.addr)
        self.cmd.mfplus_write_perso(addr_hi, addr_lo, key)
        self.cmd.slot_data_config_save()
        print(color_string((CG, f"WritePerso 0x{addr_hi:02X}{addr_lo:02X} OK")))


@hf_mfplus.command("commitp")
class HFMfPlusCommitPerso(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "CommitPerso: switch SL0 -> SL3. Requires the three mandatory "
            "admin keys (master/config/l3switch) to have been written first."
        )
        self.add_slot_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        _require_mfplus_slot(self.cmd)
        self.cmd.mfplus_commit_perso()
        self.cmd.slot_data_config_save()
        print(color_string((CG, "CommitPerso OK -- card is now SL3")))
