"""cli_hw_log - persistent debug log commands (hw log ...)."""

import argparse
import sys
import time

from cli_core import ArgumentParserNoExit, DeviceRequiredUnit, hw

hw_log = hw.subgroup("log", "Persistent debug log (kept in flash, readable as LOG.TXT in UF2 mode)")

LEVELS = ["off", "error", "warning", "info", "debug"]
CHUNK = 480


def _status(cmd):
    return cmd.log_get_status()


@hw_log.command("status")
class HWLogStatus(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Show debug log level and storage"
        return parser

    def on_exec(self, args: argparse.Namespace):
        st = _status(self.cmd)
        print(f" - Level   : {st['level']} ({LEVELS[st['level']]})")
        print(f" - Stored  : {st['stored']:,} bytes in flash ({st['pages']} pages)")
        print(f" - Pending : {st['pending']:,} bytes in RAM, not yet in flash")
        print(f" - Dropped : {st['dropped']:,} bytes (RAM buffer was full)")
        print(f" - Boots   : {st['boots']}")
        if st['failed']:
            print(" - Flash writes FAILED, logging to RAM only until reboot")
            err = st.get('err', 0)
            if err:
                print(f" - Error   : stage {err >> 24} (1 call, 2 event, 3 init), op {(err >> 16) & 0xFF}"
                      f" (1 erase, 2 hdr, 3 data, 4 clear), code 0x{err & 0xFFFF:04X}")


@hw_log.command("level")
class HWLogLevel(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get or set the debug log level (persisted)"
        parser.add_argument("level", nargs="?", choices=LEVELS + ["0", "1", "2", "3", "4"],
                            help="off, error, warning, info or debug (0-4); omit to show")
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.level is None:
            level = _status(self.cmd)['level']
        else:
            level = LEVELS.index(args.level) if args.level in LEVELS else int(args.level)
            self.cmd.log_set_level(level)
        print(f" - Log level: {level} ({LEVELS[level]})")


@hw_log.command("dump")
class HWLogDump(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Read the stored debug log"
        parser.add_argument("-o", "--output", help="write to a file instead of the screen")
        return parser

    def on_exec(self, args: argparse.Namespace):
        _status(self.cmd)          # asks the device to flush its RAM tail
        time.sleep(0.5)            # flash writes are asynchronous
        total = _status(self.cmd)['stored']
        out = open(args.output, "wb") if args.output else None
        offset = 0
        try:
            while offset < total:
                data = self.cmd.log_read(offset, min(CHUNK, total - offset))
                if not data:
                    break
                offset += len(data)
                if out:
                    out.write(data)
                else:
                    sys.stdout.write(data.decode("utf-8", errors="replace"))
        finally:
            if out:
                out.close()
        if out:
            print(f" - Wrote {offset:,} bytes to {args.output}")
        elif offset == 0:
            print(" - Log is empty (is the level above 0?)")


@hw_log.command("clear")
class HWLogClear(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Erase the stored debug log"
        return parser

    def on_exec(self, args: argparse.Namespace):
        self.cmd.log_clear()
        print(" - Log clear requested")
