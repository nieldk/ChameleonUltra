#!/usr/bin/env python3
"""
read_uid.py — Show the UID a ChameleonUltra relay has captured, displayed large.

Connects to one of the two relay CUs and reads the relay's diagnostic state
(STANDALONE_RELAY_DIAG) over USB/BLE. It does NOT scan RF and does NOT switch
the device into reader mode, so it is safe to run against a live RELAY_CARD or
RELAY_READER CU without disturbing the relay.

Usage:
    py read_uid.py [--port COM3] [--ble] [--watch]

Requirements:
    py -m pip install pyfiglet
    Place this script alongside chameleon_com.py etc.
"""

import argparse
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── pretty output ────────────────────────────────────────────────────────────
try:
    import pyfiglet
    def big(text: str, font: str = "big") -> str:
        return pyfiglet.figlet_format(text, font=font)
except ImportError:
    print("[!] pyfiglet not found – falling back to plain text. "
          "Run: py -m pip install pyfiglet", file=sys.stderr)
    def big(text: str, font: str = "big") -> str:
        return f"\n  {text}\n"

import serial.tools.list_ports

import chameleon_com
import chameleon_cmd

# ── ansi ──────────────────────────────────────────────────────────────────────
ANSI_GREEN  = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_RED    = "\033[91m"
ANSI_RESET  = "\033[0m"
ANSI_CYAN   = "\033[96m"
ANSI_BOLD   = "\033[1m"

_ROLE = {0: "RELAY_CARD (faces reader)", 1: "RELAY_READER (faces real card)"}


def format_uid(uid_bytes: bytes) -> str:
    return " ".join(f"{b:02X}" for b in uid_bytes)


def format_uid_compact(uid_bytes: bytes) -> str:
    return "".join(f"{b:02X}" for b in uid_bytes)


def uid_length_name(n: int) -> str:
    return {4: "Single (4B)", 7: "Double (7B)", 10: "Triple (10B)"}.get(n, f"{n}B")


_last_line_count = 0

def clear_last_output():
    global _last_line_count
    if _last_line_count > 0:
        sys.stdout.write(f"\033[{_last_line_count}A")
        sys.stdout.write("\033[J")
        sys.stdout.flush()
    _last_line_count = 0


def print_uid(uid_bytes: bytes, role: int) -> None:
    global _last_line_count
    uid_spaced  = format_uid(uid_bytes)
    uid_compact = format_uid_compact(uid_bytes)
    uid_len     = uid_length_name(len(uid_bytes))

    clear_last_output()

    lines = [""]
    lines.append("─" * 40)
    for l in big(uid_compact).splitlines():
        lines.append(ANSI_GREEN + l + ANSI_RESET)
    lines.append(f"  UID (hex)  :  {uid_spaced}")
    lines.append(f"  Length     :  {uid_len}")
    lines.append(f"  Source     :  {_ROLE.get(role, f'role {role}')}")
    lines.append("─" * 40)

    output = "\n".join(lines) + "\n"
    sys.stdout.write(output)
    sys.stdout.flush()
    _last_line_count = len(lines)


# ── device ──────────────────────────────────────────────────────────────────
def find_port():
    """Auto-detect a ChameleonUltra by USB VID (0x6868), as the CLI does."""
    for p in serial.tools.list_ports.comports():
        if p.vid == 0x6868:
            return p.device
    return None


def open_device(port, use_ble):
    dev = chameleon_com.ChameleonCom()
    if use_ble:
        dev.open("ble")            # or "ble:AA:BB:CC:DD:EE:FF" to target a MAC
    else:
        target = port or find_port()
        if target is None:
            print(f"{ANSI_RED}[!] No ChameleonUltra serial port found.{ANSI_RESET}\n"
                  "    Connect the device or pass --port COM3", file=sys.stderr)
            sys.exit(1)
        dev.open(target)
    return dev


def relay_uid(cmd):
    """Return (uid_bytes, role) the relay has captured, or (None, None).

    Reads STANDALONE_RELAY_DIAG — relay state only, no RF, no mode change. A
    UID is present once identity_rx (CARD side) or card_found (READER side) and
    uid_len is set.
    """
    try:
        d = cmd.relay_get_diag()
    except Exception:
        return None, None
    if not d:
        return None, None
    uid_len = d.get("uid_len", 0)
    have    = d.get("identity_rx", 0) or d.get("card_found", 0)
    if not have or not uid_len:
        return None, None
    uid = bytes(d.get("uid", [])[:uid_len])
    return (uid if uid else None), d.get("ble_role", 0)


# ── main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Show the UID a ChameleonUltra relay has captured, displayed large."
    )
    parser.add_argument("--port", "-p", metavar="DEV",
                        help="Serial port (e.g. COM3). Auto-detected if omitted.")
    parser.add_argument("--ble", action="store_true",
                        help="Connect via BLE instead of USB serial.")
    parser.add_argument("--watch", "-w", action="store_true",
                        help="Poll continuously until Ctrl-C.")
    parser.add_argument("--interval", "-i", type=float, default=0.5,
                        help="Poll interval in seconds for --watch mode (default: 0.5).")
    parser.add_argument("--font", default="standard",
                        help="pyfiglet font name (default: 'standard').")
    args = parser.parse_args()

    print(f"{ANSI_BOLD}ChameleonUltra Relay UID{ANSI_RESET}")
    print(f"Connecting {'via BLE' if args.ble else 'via USB'} …")

    try:
        dev = open_device(args.port, args.ble)
    except Exception as e:
        print(f"{ANSI_RED}[!] Could not open ChameleonUltra: {e}{ANSI_RESET}", file=sys.stderr)
        sys.exit(1)

    cmd = chameleon_cmd.ChameleonCMD(dev)

    if args.font:
        try:
            pyfiglet.figlet_format("0", font=args.font)  # probe
            _font = args.font
            global big
            big = lambda text, font=_font: pyfiglet.figlet_format(text, font=_font)
        except Exception:
            print(f"{ANSI_YELLOW}[!] Font '{args.font}' not found, using default.{ANSI_RESET}",
                  file=sys.stderr)

    print(f"{ANSI_GREEN}Connected.{ANSI_RESET}  Reading relay state "
          "(arm RELAY on both CUs, present the card to the READER CU) …\n")

    last_uid = None
    try:
        while True:
            uid, role = relay_uid(cmd)

            if uid is None:
                last_uid = None
                if args.watch:
                    print(".", end="", flush=True)
                else:
                    print(f"{ANSI_YELLOW}[!] No UID yet — relay not linked or no card "
                          f"on the READER CU.{ANSI_RESET}")
            else:
                if uid != last_uid:
                    if args.watch:
                        print()
                    print_uid(uid, role)
                    last_uid = uid

            if not args.watch:
                break
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\n{ANSI_YELLOW}Stopped.{ANSI_RESET}")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
