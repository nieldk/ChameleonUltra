"""cli_hw_log - persistent debug log commands (hw log ...)."""

import argparse
import os
import sys
import time


def _stop_pressed() -> bool:
    """Non-blocking: True if the user pressed Enter (tty only). Drains the input
    so it doesn't leak into the next prompt. Returns False on non-tty stdin."""
    try:
        if not sys.stdin.isatty():
            return False
        if os.name == "nt":
            import msvcrt
            hit = False
            while msvcrt.kbhit():
                msvcrt.getwch()
                hit = True
            return hit
        import select
        if select.select([sys.stdin], [], [], 0)[0]:
            sys.stdin.readline()
            return True
        return False
    except Exception:
        return False

from cli_core import ArgumentParserNoExit, CG, CR, C0, DeviceRequiredUnit, _box, hw

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
        lw = 8   # longest label: "Dropped"
        lines = [
            f"{'Level':<{lw}} {st['level']} ({LEVELS[st['level']]})",
            f"{'Stored':<{lw}} {st['stored']:,} bytes in flash ({st['pages']} pages)",
            f"{'Pending':<{lw}} {st['pending']:,} bytes in RAM, not yet in flash",
            f"{'Dropped':<{lw}} {st['dropped']:,} bytes (RAM buffer was full)",
            f"{'Boots':<{lw}} {st['boots']}",
        ]
        color = CG
        if st['failed']:
            color = CR
            lines.append(f"{CR}Flash writes FAILED, logging to RAM only until reboot{C0}")
            err = st.get('err', 0)
            if err:
                lines.append(f"{'Error':<{lw}} stage {err >> 24} (1 call, 2 event, 3 init), op "
                              f"{(err >> 16) & 0xFF} (1 erase, 2 hdr, 3 data, 4 clear), "
                              f"code 0x{err & 0xFFFF:04X}")
        for line in _box("Debug Log", lines, color=color, min_width=46):
            print(line)


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


@hw_log.command("stream")
class HWLogStream(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = ("Live-tail the debug log over the current link (RTT-like, no J-Link). "
                              "Each poll flushes the device's RAM tail to flash, then prints new "
                              "entries until Ctrl-C.")
        parser.add_argument("-i", "--interval", type=float, default=0.3,
                            help="poll interval in seconds (default 0.3)")
        parser.add_argument("--from-start", action="store_true",
                            help="print the existing log first, then follow")
        return parser

    def on_exec(self, args: argparse.Namespace):
        st = _status(self.cmd)
        if st['level'] == 0:
            print(" - Note: log level is off; enable it with 'hw log level info'")
        offset = 0 if args.from_start else st['stored']
        how = "press Enter to stop" if sys.stdin.isatty() else "Ctrl-C to stop"
        print(f" - Streaming from offset {offset:,} ({how})")
        try:
            while True:
                total = _status(self.cmd)['stored']   # flushes RAM -> flash
                if total < offset:                    # cleared or wrapped: resync
                    offset = 0
                while offset < total:
                    data = self.cmd.log_read(offset, min(CHUNK, total - offset))
                    if not data:
                        break
                    offset += len(data)
                    sys.stdout.write(data.decode("utf-8", errors="replace"))
                    sys.stdout.flush()
                # Stop only between polls (never mid-command, which would desync
                # the link). Poll stdin in small slices across the interval.
                end = time.time() + args.interval
                stop = False
                while time.time() < end:
                    if _stop_pressed():
                        stop = True
                        break
                    time.sleep(0.03)
                if stop:
                    break
        except KeyboardInterrupt:
            # A Ctrl-C can land mid-command; let the RX thread drain so the next
            # command isn't matched to a stale response.
            time.sleep(0.2)
        print("\n - stopped")


@hw_log.command("clear")
class HWLogClear(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Erase the stored debug log"
        return parser

    def on_exec(self, args: argparse.Namespace):
        self.cmd.log_clear()
        print(" - Log clear requested")
