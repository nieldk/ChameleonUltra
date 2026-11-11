"""cli_hf_st25ta - ST25TA (NFC Forum Type 4) emulation commands (hf st25ta ...)."""

import argparse

from cli_core import (
    ArgumentParserNoExit,
    CG,
    CR,
    CY,
    DeviceRequiredUnit,
    HF14AAntiCollArgsUnit,
    SlotIndexArgsAndGoUnit,
    TagSpecificType,
    _box,
    color_string,
    hf_st25ta,
)

CC_READ_ACCESS = 13
CC_WRITE_ACCESS = 14
READ_ACCESS = {"free": 0x00, "locked": 0x80, "forbidden": 0xFE}
WRITE_ACCESS = {"free": 0x00, "locked": 0x80, "forbidden": 0xFF}


def _require_st25ta(cmd):
    active = cmd.get_active_slot()
    slot_info = cmd.get_slot_info()
    if TagSpecificType(slot_info[active]["hf"]) != TagSpecificType.ST25TA:
        raise Exception("Card in current slot is not ST25TA")


def _access_str(value: int, table: dict) -> str:
    for name, v in table.items():
        if v == value:
            return name
    return f"unknown (0x{value:02X})"


def _parse_pwd(text: str) -> bytes:
    pwd = bytes.fromhex(text.strip())
    if len(pwd) != 16:
        raise Exception("Password must be 16 bytes (32 hex chars)")
    return pwd


@hf_st25ta.command("info")
class HFSt25taInfo(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Show ST25TA emulator configuration"
        self.add_slot_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        _require_st25ta(self.cmd)
        info = self.cmd.st25ta_get_info()
        anti = self.cmd.hf14a_get_anti_coll_data()
        cc = info["cc"]
        msg_len = int.from_bytes(self.cmd.st25ta_read_ndef(0, 2), "big")

        lw = 14   # longest label: "Write password"
        lines = []
        if anti:
            lines.append(f"{'UID':<{lw}} {color_string((CY, anti['uid'].hex().upper()))}")
            lines.append(f"{'ATQA':<{lw}} {color_string((CY, anti['atqa'].hex().upper()))}")
            lines.append(f"{'SAK':<{lw}} {color_string((CY, anti['sak'].hex().upper()))}")
            lines.append(f"{'ATS':<{lw}} {color_string((CY, anti['ats'].hex().upper()))}")
        lines.append(f"{'NDEF file size':<{lw}} {info['ndef_size']} bytes")
        lines.append(f"{'NDEF message':<{lw}} {msg_len} bytes")
        lines.append(f"{'File type':<{lw}} 0x{cc[7]:02X}")
        lines.append(f"{'Read access':<{lw}} {_access_str(cc[CC_READ_ACCESS], READ_ACCESS)}")
        lines.append(f"{'Write access':<{lw}} {_access_str(cc[CC_WRITE_ACCESS], WRITE_ACCESS)}")
        lines.append(f"{'Read password':<{lw}} {info['pwd_read'].hex().upper()}")
        lines.append(f"{'Write password':<{lw}} {info['pwd_write'].hex().upper()}")
        for line in _box("ST25TA", lines, color=CG, min_width=38):
            print(line)


@hf_st25ta.command("eview")
class HFSt25taEView(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "View NDEF data from emulator memory"
        self.add_slot_args(parser)
        parser.add_argument("--full", action="store_true",
                            help="Dump the whole NDEF file, not only the message")
        parser.add_argument("-o", "--output", type=str, default=None, metavar="<file>",
                            help="Write the data to a binary file")
        return parser

    def on_exec(self, args: argparse.Namespace):
        _require_st25ta(self.cmd)
        info = self.cmd.st25ta_get_info()
        if args.full:
            data = self.cmd.st25ta_read_ndef(0, info["ndef_size"])
        else:
            msg_len = int.from_bytes(self.cmd.st25ta_read_ndef(0, 2), "big")
            msg_len = min(msg_len, info["ndef_size"] - 2)
            data = self.cmd.st25ta_read_ndef(2, msg_len) if msg_len else b""

        print(f"[=] {len(data)} bytes")
        if data:
            print(data.hex().upper())
        if args.output:
            with open(args.output, "wb") as f:
                f.write(data)
            print(f"[=] Saved to {args.output}")


@hf_st25ta.command("eload")
class HFSt25taELoad(SlotIndexArgsAndGoUnit, HF14AAntiCollArgsUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Load NDEF message and anti-collision data into emulator memory"
        self.add_slot_args(parser)
        self.add_hf14a_anticoll_args(parser)
        src = parser.add_mutually_exclusive_group()
        src.add_argument("-d", "--data", type=str, default=None, metavar="<hex>",
                         help="NDEF message (hex)")
        src.add_argument("-f", "--file", type=str, default=None, metavar="<file>",
                         help="NDEF message (binary file)")
        return parser

    def on_exec(self, args: argparse.Namespace):
        _require_st25ta(self.cmd)

        anti = self.cmd.hf14a_get_anti_coll_data()
        if not anti:
            print(color_string((CR, "Slot does not contain any HF 14A config")))
            return
        change_requested, _, _, _, _, _ = self.update_hf14a_anticoll(
            args, anti["uid"], anti["atqa"], anti["sak"], anti["ats"]
        )

        msg = None
        if args.data is not None:
            msg = bytes.fromhex(args.data.strip())
        elif args.file is not None:
            with open(args.file, "rb") as f:
                msg = f.read()

        if msg is None and not change_requested:
            print(color_string((CR, "Error: No changes were requested.")))
            return

        if msg is not None:
            info = self.cmd.st25ta_get_info()
            if len(msg) + 2 > info["ndef_size"]:
                print(color_string((CR,
                    f"Error: message needs {len(msg) + 2} bytes, NDEF file is "
                    f"{info['ndef_size']}. Use econfig --size.")))
                return
            # Body first, length last
            if msg:
                self.cmd.st25ta_write_ndef(2, msg)
            self.cmd.st25ta_write_ndef(0, len(msg).to_bytes(2, "big"))
            print(color_string((CG, f"NDEF message loaded ({len(msg)} bytes)")))

        self.cmd.slot_data_config_save()


@hf_st25ta.command("econfig")
class HFSt25taEConfig(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Configure ST25TA emulator size, access rights and passwords"
        self.add_slot_args(parser)
        parser.add_argument("--size", type=int, default=None, metavar="<bytes>",
                            help="NDEF file size incl. 2-byte length (2-7680)")
        parser.add_argument("--read-access", choices=list(READ_ACCESS), default=None)
        parser.add_argument("--write-access", choices=list(WRITE_ACCESS), default=None)
        parser.add_argument("--read-pwd", type=str, default=None, metavar="<hex16>")
        parser.add_argument("--write-pwd", type=str, default=None, metavar="<hex16>")
        return parser

    def on_exec(self, args: argparse.Namespace):
        _require_st25ta(self.cmd)
        if all(v is None for v in (args.size, args.read_access, args.write_access,
                                   args.read_pwd, args.write_pwd)):
            print(color_string((CR, "Error: No changes were requested.")))
            return

        info = self.cmd.st25ta_get_info()
        cc = info["cc"]
        size = args.size if args.size is not None else info["ndef_size"]
        if not 2 <= size <= 7680:
            raise Exception("Size must be 2-7680")
        read_acc = READ_ACCESS[args.read_access] if args.read_access else cc[CC_READ_ACCESS]
        write_acc = WRITE_ACCESS[args.write_access] if args.write_access else cc[CC_WRITE_ACCESS]
        pwd_read = _parse_pwd(args.read_pwd) if args.read_pwd else info["pwd_read"]
        pwd_write = _parse_pwd(args.write_pwd) if args.write_pwd else info["pwd_write"]

        self.cmd.st25ta_set_config(size, read_acc, write_acc, pwd_read, pwd_write)
        self.cmd.slot_data_config_save()
        print(color_string((CG, "ST25TA config updated")))
