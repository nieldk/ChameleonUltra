#!/usr/bin/env python3
import argparse
import random
import shutil
import sys
import time
import traceback
import chameleon_com
import colorama
import chameleon_cli_unit
import chameleon_utils
import pathlib
import prompt_toolkit
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.history import FileHistory
from chameleon_utils import CR, CG, CY, color_string

# Chameleon silhouette traced from a hand-drawn reference (coiled tail,
# crested head, small reader board: a nod to the pm3 mini). The CHAMELEON
# wordmark overlaps the body, same as the reference.
CHAMELEON_ART = [
    "          ▄█            █",
    "         ▄███          ██▄▄██▄▄",
    "   ▄▄█████████▄▄▄▄     ▄██▀▀███",
    "  ▄██▀██████████████▄▄███  █ ██",
    " █████████████████████████  ██",
    "█████████▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀",
    "█████████",
    "████ ████",
    "██ ██ ███",
    "▀██ █████▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄",
    " ▀███▀█████████████████████",
    "  ▀███████████████  ██████",
    "    ▀▀▀█▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀",
    "    ▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄",
    "   ▄███████████▄▄▄██████",
    "   ▀███████████  ▄██████",
]

# Big block wordmark (figlet "ANSI Shadow"), pasted overlapping the art.
BLOCK_TEXT = [
    "██████╗██╗  ██╗ █████╗ ███╗   ███╗███████╗██╗     ███████╗ ██████╗ ███╗   ██╗",
    "██╔════╝██║  ██║██╔══██╗████╗ ████║██╔════╝██║     ██╔════╝██╔═══██╗████╗  ██║",
    "██║     ███████║███████║██╔████╔██║█████╗  ██║     █████╗  ██║   ██║██╔██╗ ██║",
    "██║     ██╔══██║██╔══██║██║╚██╔╝██║██╔══╝  ██║     ██╔══╝  ██║   ██║██║╚██╗██║",
    "╚██████╗██║  ██║██║  ██║██║ ╚═╝ ██║███████╗███████╗███████╗╚██████╔╝██║ ╚████║",
    " ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝",
]

# Small badge naming the device variant, pasted right under the wordmark.
# Column offsets below are relative to the badge's own left edge.
ULTRA_BADGE = [
    "                                                       ╦ ╦╦ ╔╦╗╦═╗╔═╗",
    "                                          ███████      ║ ║║  ║ ╠╦╝╠═╣",
    "                                                       ╚═╝╩═╝╩ ╩╚═╩ ╩",
]
LITE_BADGE = [
    "                                                       ╦  ╦╔╦╗╔═╗",
    "                                          ███████      ║  ║ ║ ║╣",
    "                                                       ╩═╝╩ ╩ ╚═╝",
]
TAGLINE = "P H R E A K B Y T E   E D I T I O N"

# Where the wordmark starts overlapping the art (row/col, in characters).
_TEXT_COL = 9
_TEXT_ROW = 6

# Glyph pool for the matrix-style reveal below -- half-width katakana (the
# classic "Matrix rain" look) plus alnum/punctuation so it still reads fine
# on a console whose font is missing the katakana glyphs.
_MATRIX_GLYPHS = "日ﾊﾉﾎﾓﾖﾄｲｸｺｼﾇﾔ" + "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ+-*/<>|=!?"

_BANNER_COLOR_MAP = {"G": CG, "Y": CY}


def _banner_grid(badge):
    """Raw (width-padded, not rstripped) char/color grid for the banner --
    shared by the static print and the matrix-reveal animation below."""
    art_w = max(len(l) for l in CHAMELEON_ART)
    txt_w = max(len(l) for l in BLOCK_TEXT)
    badge_row = _TEXT_ROW + len(BLOCK_TEXT)
    tag_row = badge_row + len(badge) + 1
    h = max(tag_row + 1, len(CHAMELEON_ART))
    w = max(art_w, _TEXT_COL + txt_w) + 1
    chars = [[" "] * w for _ in range(h)]
    colors = [["G"] * w for _ in range(h)]

    def paste(lines, row0, col0, color):
        for k, line in enumerate(lines):
            r = row0 + k
            if not (0 <= r < h):
                continue
            for c, ch in enumerate(line):
                if ch == " ":
                    continue
                col = col0 + c
                if not (0 <= col < w):
                    continue
                chars[r][col] = ch
                colors[r][col] = color

    paste(CHAMELEON_ART, 0, 0, "G")
    paste(BLOCK_TEXT, _TEXT_ROW, _TEXT_COL, "Y")
    paste(badge, badge_row, _TEXT_COL, "Y")
    tagline_col = max(0, (w - len(TAGLINE)) // 2)
    paste([TAGLINE], tag_row, tagline_col, "Y")

    return chars, colors, h, w


def _compose_banner(badge):
    chars, colors, h, w = _banner_grid(badge)
    return [("".join(row).rstrip(), col_row) for row, col_row in zip(chars, colors)]


def _color_banner(rows):
    lines = []
    for text, colors in rows:
        segments = []
        start = 0
        cur = colors[0] if text else "G"
        for i in range(1, len(text)):
            if colors[i] != cur:
                segments.append((cur, text[start:i]))
                start = i
                cur = colors[i]
        if text:
            segments.append((cur, text[start:]))
        lines.append(
            color_string(*[(_BANNER_COLOR_MAP[c], s) for c, s in segments]) if segments else ""
        )
    return "\n".join(lines)


def _render_banner_frame(chars, colors, h, w, front, band):
    """One animation frame: columns left of front-band are the real glyph in
    its real color, columns inside the band flicker a random matrix glyph in
    green, columns not yet reached are blank. Cells that are blank in the
    final banner stay blank the whole time -- only the art/text itself
    flickers, not the background."""
    rows = []
    for r in range(h):
        segments = []
        start = 0
        cur = None
        line = []
        for c in range(w):
            ch = chars[r][c]
            if ch == " ":
                disp, col = " ", cur if cur is not None else "G"
            elif c < front - band:
                disp, col = ch, colors[r][c]
            elif c < front:
                disp, col = random.choice(_MATRIX_GLYPHS), "G"
            else:
                disp, col = " ", cur if cur is not None else "G"
            line.append(disp)
            if col != cur:
                if line[:-1]:
                    segments.append((cur, "".join(line[start:-1])))
                start = len(line) - 1
                cur = col
        if line:
            segments.append((cur, "".join(line[start:])))
        rows.append(
            color_string(*[(_BANNER_COLOR_MAP[c], s) for c, s in segments]) if segments else ""
        )
    return rows


def _animate_banner_reveal(badge):
    """Matrix-style cascading build-up for the startup banner: a scrambled
    glyph band sweeps left to right and settles into the real banner behind
    it. Falls back to the plain static banner when stdout isn't a real
    terminal (piped output, logs, CI) since cursor-repositioning escapes
    would just corrupt that output."""
    chars, colors, h, w = _banner_grid(badge)

    # Cursor-up-and-overwrite only works if every line fits on one terminal
    # row. A redirected/non-tty stream, or a terminal narrower than the
    # banner (lines would wrap and the overwrite would leave garbage above),
    # both fall back to the plain static banner.
    if not sys.stdout.isatty() or shutil.get_terminal_size().columns < w:
        print(_color_banner(_compose_banner(badge)))
        return

    band = 6
    step_cols = 1
    frame_delay = 0.012

    sys.stdout.write("\n" * h)
    sys.stdout.flush()
    front = 0
    while front < w + band:
        front += step_cols
        frame = _render_banner_frame(chars, colors, h, w, front, band)
        sys.stdout.write(f"\x1b[{h}A")
        sys.stdout.write("\n".join(frame) + "\n")
        sys.stdout.flush()
        time.sleep(frame_delay)

    # Final frame: the exact static banner, so the settled result (and
    # anything that scrapes it) matches print_banner()'s non-animated output.
    sys.stdout.write(f"\x1b[{h}A")
    print(_color_banner(_compose_banner(badge)))


ICEMAN = r"""
██╗ ██████╗███████╗███╗   ███╗ █████╗ ███╗   ██╗
██║██╔════╝██╔════╝████╗ ████║██╔══██╗████╗  ██║
██║██║     █████╗  ██╔████╔██║███████║██╔██╗ ██║
██║██║     ██╔══╝  ██║╚██╔╝██║██╔══██║██║╚██╗██║
██║╚██████╗███████╗██║ ╚═╝ ██║██║  ██║██║ ╚████║
╚═╝ ╚═════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""


class ChameleonCLI:
    """
    CLI for chameleon
    """

    def __init__(self):
        # new a device communication instance(only communication)
        self.device_com = chameleon_com.ChameleonCom()

    def get_cmd_node(
        self, node: chameleon_utils.CLITree, cmdline: list[str]
    ) -> tuple[chameleon_utils.CLITree, list[str]]:
        """
        Recursively traverse the command line tree to get to the matching node

        :return: last matching CLITree node, remaining tokens
        """
        # No more subcommands to parse, return node
        if cmdline == []:
            return node, []

        for child in node.children:
            if cmdline[0] == child.name:
                return self.get_cmd_node(child, cmdline[1:])

        # No matching child node
        return node, cmdline[:]

    def get_prompt(self):
        """
        Retrieve the cli prompt
        :return: current cmd prompt
        """
        if self.device_com.isOpen():
            ttype = getattr(self.device_com, "transport_type", None)
            label = {"SERIAL": "USB", "BLE": "BLE", "SOCKET": "TCP"}.get(
                getattr(ttype, "name", ""), "USB"
            )
            status = color_string((CG, label))
        else:
            status = color_string((CR, "Offline"))
        return ANSI(f"[{status}] phreakbyte --> ")

    @staticmethod
    def print_iceman_tribute():
        print(color_string((CY, ICEMAN)))
        print(color_string((CG, "        Phreakbyte tips its hat to Iceman.")))
        print("        Years of RFID research, the Proxmark3 iceman fork, and the")
        print("        generosity and encouragement that made this independent fork")
        print("        possible. Standing on the shoulders of giants.")
        print(color_string((CY, "        Thank you.")))

    def print_banner(self):
        model = None
        try:
            if self.device_com.isOpen():
                model = self.cmd.get_device_model()  # 0 = Ultra, 1 = Lite
        except Exception:
            pass
        badge = LITE_BADGE if model == 1 else ULTRA_BADGE
        _animate_banner_reveal(badge)

    def exec_cmd(self, cmd_str):
        if cmd_str == "":
            return

        # look for alternate exit
        if cmd_str in ["quit", "q", "e"]:
            cmd_str = "exit"
        if cmd_str.strip().lower() in ("iceman", "credits"):
            self.print_iceman_tribute()
            return

        # look for alternate comments
        if cmd_str[0] in ";#%":
            cmd_str = "rem " + cmd_str[1:].lstrip()

        # parse cmd
        argv = cmd_str.split()

        tree_node, arg_list = self.get_cmd_node(chameleon_cli_unit.root, argv)
        if not tree_node.cls:
            # Found tree node is a group without an implementation, print children
            print("".ljust(18, "-") + "".ljust(10) + "".ljust(30, "-"))
            for child in tree_node.children:
                cmd_title = color_string((CG, child.name))
                if not child.cls:
                    help_line = (
                        f" - {cmd_title}".ljust(37)
                    ) + f"{{ {child.help_text}... }}"
                else:
                    help_line = (f" - {cmd_title}".ljust(37)) + f"{child.help_text}"
                print(help_line)
            return

        unit: chameleon_cli_unit.BaseCLIUnit = tree_node.cls()
        unit.device_com = self.device_com
        args_parse_result = unit.args_parser()

        assert args_parse_result is not None
        args: argparse.ArgumentParser = args_parse_result
        args.prog = tree_node.fullname
        try:
            args_parse_result = args.parse_args(arg_list)
            if args.help_requested:
                return
        except chameleon_utils.ArgsParserError as e:
            args.print_help()
            print(color_string((CY, str(e).strip())))
            return
        except chameleon_utils.ParserExitIntercept:
            # don't exit process.
            return

        try:
            # before process cmd, we need to do something...
            if not unit.before_exec(args_parse_result):
                return

            # start process cmd, delay error to call after_exec firstly
            error = None
            try:
                unit.on_exec(args_parse_result)
            except Exception as e:
                error = e
            unit.after_exec(args_parse_result)
            if error is not None:
                raise error

        except (
            chameleon_utils.UnexpectedResponseError,
            chameleon_utils.ArgsParserError,
            chameleon_com.CMDInvalidException,
            TimeoutError,
        ) as e:
            print(color_string((CR, str(e))))
        except Exception:
            print(f"CLI exception: {color_string((CR, traceback.format_exc()))}")

    @staticmethod
    def _split_commands(line):
        """Split one input line into commands. Newlines always separate; ';'
        separates too, except a line that itself starts with a ';'/'#'/'%'
        comment is kept whole so it stays a single rem."""
        out = []
        for part in line.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            s = part.strip()
            if s[:1] in (";", "#", "%"):
                out.append(s)
            else:
                out.extend(p.strip() for p in s.split(";"))
        return [c for c in out if c != ""]

    def startCLI(self, startup_port=None, auto_connect=True):
        """
            start listen input.

        :return:
        """
        self.completer = chameleon_utils.CustomNestedCompleter.from_clitree(
            chameleon_cli_unit.root
        )
        # Cap the completion dropdown's reserved rows to terminal height so a
        # short window keeps most of its space; the default 8 halves a ~25-row
        # terminal. Scales back up to 8 on taller terminals.
        menu_rows = max(3, min(8, shutil.get_terminal_size().lines // 5))
        self.session = prompt_toolkit.PromptSession(
            completer=self.completer,
            reserve_space_for_menu=menu_rows,
            history=FileHistory(str(pathlib.Path.home() / ".chameleon_history")),
        )

        self.print_banner()
        if auto_connect:
            # same path as 'hw connect'; no port -> USB serial auto-detect
            self.exec_cmd("hw connect" + (f" -p {startup_port}" if startup_port else ""))
        cmd_strs = []
        while True:
            if cmd_strs:
                cmd_str = cmd_strs.pop(0)
            else:
                # wait user input
                try:
                    cmd_strs = self._split_commands(self.session.prompt(self.get_prompt()))
                    cmd_str = cmd_strs.pop(0) if cmd_strs else ""
                except EOFError:
                    cmd_str = "exit"
                except KeyboardInterrupt:
                    cmd_str = "exit"
            self.exec_cmd(cmd_str)


if __name__ == "__main__":
    if sys.version_info < (3, 9):
        raise Exception("This script requires at least Python 3.9")
    colorama.init(autoreset=True)
    chameleon_cli_unit.check_tools()
    ap = argparse.ArgumentParser(description="ChameleonUltra CLI")
    ap.add_argument(
        "-p", "--port", default=None,
        help="Connect at startup to this port/transport (e.g. /dev/ttyACM0, ble, "
             "tcp:host:port); omit to auto-detect a USB serial Chameleon",
    )
    ap.add_argument("--no-connect", action="store_true", help="Skip auto-connect at startup")
    cli_args = ap.parse_args()
    ChameleonCLI().startCLI(startup_port=cli_args.port, auto_connect=not cli_args.no_connect)
