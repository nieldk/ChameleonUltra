"""cli_hf_mfplus - MIFARE Plus SL3 (AES) emulation commands (hf mfplus ...).

v1 scope, matching the firmware: AuthenticateFirst only (no non-first
auth), ReadBlock/WriteBlock, GetVersion. All sectors share one configurable
AES key for both Key A and Key B -- real MIFARE Plus has an independent key
per sector/keytype; this is a deliberate simplification, not yet supported.
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


def _require_mfplus_sl3(cmd):
    active = cmd.get_active_slot()
    slot_info = cmd.get_slot_info()
    hf_type = TagSpecificType(slot_info[active]["hf"])
    if hf_type not in (TagSpecificType.MIFARE_PLUS_S2K_SL3, TagSpecificType.MIFARE_PLUS_S4K_SL3):
        raise Exception("Card in current slot is not MIFARE Plus SL3")


@hf_mfplus.command("info")
class HFMfPlusInfo(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Show MIFARE Plus SL3 emulator configuration"
        self.add_slot_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        _require_mfplus_sl3(self.cmd)
        info = self.cmd.mfplus_get_info()
        anti = self.cmd.hf14a_get_anti_coll_data()

        if anti:
            print(f"{'UID:':20}{color_string((CY, anti['uid'].hex().upper()))}")
            print(f"{'ATQA:':20}{color_string((CY, anti['atqa'].hex().upper()))}")
            print(f"{'SAK:':20}{color_string((CY, anti['sak'].hex().upper()))}")
            print(f"{'ATS:':20}{color_string((CY, anti['ats'].hex().upper()))}")
        print(f"{'Blocks:':20}{info['block_max']}")
        print(f"{'AES key (A & B):':20}{info['default_key'].hex().upper()}")
        print()
        print(color_string((CY,
            "v1: AuthenticateFirst only, one shared key for all sectors, "
            "no SL0 personalization protocol.")))


@hf_mfplus.command("econfig")
class HFMfPlusEConfig(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set the shared AES key MIFARE Plus SL3 emulation uses"
        self.add_slot_args(parser)
        parser.add_argument("-k", "--key", type=str, required=True, metavar="<hex32>",
                            help="16-byte AES key (32 hex chars), used as Key A and Key B "
                                 "for every sector")
        return parser

    def on_exec(self, args: argparse.Namespace):
        _require_mfplus_sl3(self.cmd)
        key = bytes.fromhex(args.key.strip())
        if len(key) != 16:
            print(color_string((CR, "Error: key must be 16 bytes (32 hex chars)")))
            return
        self.cmd.mfplus_set_key(key)
        self.cmd.slot_data_config_save()
        print(color_string((CG, "MIFARE Plus SL3 key updated")))
