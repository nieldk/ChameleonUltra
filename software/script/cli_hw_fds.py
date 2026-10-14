"""cli_hw_fds - inspect the on-device FDS flash store (hw fds ...)."""

import argparse

from cli_core import ArgumentParserNoExit, DeviceRequiredUnit, hw

hw_fds = hw.subgroup("fds", "Inspect the device FDS flash store")


# FDS record key for slot records is the tag_sense_type_t (1 = LF, 2 = HF).
_SENSE = {1: "LF", 2: "HF"}


def _kind(file_id: int, key: int) -> str:
    if file_id == 0x1000:
        return "emulation config"
    if file_id == 0x1001:
        return "settings"
    if file_id == 0x1010:
        return "standalone modes"
    # Slot records: file_id = base + fw slot index (0-7); UI slot is index + 1.
    if 0x1100 <= file_id <= 0x1107:
        return f"slot {file_id - 0x1100 + 1} ({_SENSE.get(key, '?')}) tag dump"
    if 0x1200 <= file_id <= 0x1207:
        return f"slot {file_id - 0x1200 + 1} ({_SENSE.get(key, '?')}) nickname"
    if file_id >= 0xC000:
        return "BLE bond (peer manager)"
    return ""


@hw_fds.command("ls")
class HWFdsList(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "List FDS records: file_id, key, size and kind."
        return parser

    def on_exec(self, args: argparse.Namespace):
        recs = self.cmd.get_fds_list()
        if not recs:
            print(" - No FDS records.")
            return
        total = sum(r[2] for r in recs)
        print(f" - {len(recs)} record(s), {total} bytes")
        print("   file_id  key     size  kind")
        for file_id, key, ln in sorted(recs):
            print(f"   0x{file_id:04X}   0x{key:04X}  {ln:5d}  {_kind(file_id, key)}")


@hw_fds.command("dump")
class HWFdsDump(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Hex-dump one FDS record by file_id and key."
        parser.add_argument("-f", "--file-id", required=True, help="FDS file id, e.g. 0x1001")
        parser.add_argument("-k", "--key", default="0x1", help="FDS record key (default 0x1)")
        return parser

    def on_exec(self, args: argparse.Namespace):
        file_id = int(args.file_id, 0)
        key = int(args.key, 0)
        try:
            data = self.cmd.get_fds_record(file_id, key)
        except Exception:
            print(f" - No record for file 0x{file_id:04X} key 0x{key:04X}.")
            return
        if not data:
            print(" - Record is empty.")
            return
        print(f" - file 0x{file_id:04X} key 0x{key:04X} ({_kind(file_id, key)}): {len(data)} bytes")
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            hexs = ' '.join(f"{b:02x}" for b in chunk)
            text = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
            print(f"   {off:04x}  {hexs:<47}  {text}")
