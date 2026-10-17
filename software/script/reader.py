#!/usr/bin/env python3
"""
read_uid.py — Monitor a ChameleonUltra relay: show the captured UID, and when
there isn't one yet, show *why* (BLE/role/sub state), so a stalled relay is
visible instead of a blind row of dots.

Reads STANDALONE_RELAY_DIAG only — no RF, no mode change — so it is safe to run
against a live RELAY_CARD or RELAY_READER CU.

Usage:
    read_uid.py [--port COM3] [--ble] [--watch]

Requirements:
    pip install pyfiglet          # optional, for the large UID banner
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
          "Run: pip install pyfiglet", file=sys.stderr)
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

# decode maps mirror `standalone status` in chameleon_cli_unit.py
_ROLE  = {0: "RELAY_CARD (faces reader)", 1: "RELAY_READER (faces real card)"}
_STATE = {0: "IDLE", 1: "STARTING", 2: "CONNECTING", 3: "DISCOVERING",
          4: "NEGOTIATING", 5: "READY", 6: "ACTIVE", 7: "ERROR"}
_SUB   = {0: "INIT", 1: "LINKING", 2: "CARD_AWAIT_IDENTITY", 3: "CARD_READY",
          4: "CARD_AWAIT_RESPONSE", 5: "READER_SCAN", 6: "READER_READY",
          7: "READER_RELAY", 8: "ERROR"}


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


def _emit(lines):
    global _last_line_count
    clear_last_output()
    output = "\n".join(lines) + "\n"
    sys.stdout.write(output)
    sys.stdout.flush()
    _last_line_count = len(lines)


def print_uid(uid_bytes: bytes, role: int) -> None:
    uid_spaced  = format_uid(uid_bytes)
    uid_compact = format_uid_compact(uid_bytes)
    lines = [""]
    lines.append("─" * 40)
    for l in big(uid_compact).splitlines():
        lines.append(ANSI_GREEN + l + ANSI_RESET)
    lines.append(f"  UID (hex)  :  {uid_spaced}")
    lines.append(f"  Length     :  {uid_length_name(len(uid_bytes))}")
    lines.append(f"  Source     :  {_ROLE.get(role, f'role {role}')}")
    lines.append("─" * 40)
    _emit(lines)


def _hint(d: dict) -> str:
    """One line saying where a UID-less relay is stuck (mirrors `standalone status`)."""
    reports = d.get("adv_reports", 0)
    hits    = d.get("relay_hits", 0)
    state   = d.get("ble_state", 0)
    role    = d.get("ble_role", 0)
    if reports == 0:
        return f"{ANSI_RED}scanning not working (RC522/scan side){ANSI_RESET}"
    if hits == 0:
        return f"{ANSI_YELLOW}no relay HELLO seen — other CU not armed or out of range{ANSI_RESET}"
    if state < 5:
        return f"{ANSI_YELLOW}HELLO seen but not connected — check both CUs armed{ANSI_RESET}"
    if role == 1:
        return f"{ANSI_YELLOW}no card on the READER (green) CU — present one{ANSI_RESET}"
    return f"{ANSI_YELLOW}waiting for card identity from RELAY_READER{ANSI_RESET}"


def print_state(d: dict) -> None:
    role  = d.get("ble_role", 0)
    state = d.get("ble_state", 0)
    sub   = d.get("sub_state", 0)
    lines = [""]
    lines.append("─" * 40)
    lines.append(f"  {ANSI_YELLOW}no UID captured yet{ANSI_RESET}")
    lines.append(f"  role   :  {_ROLE.get(role, f'role {role}')}")
    lines.append(f"  ble    :  {_STATE.get(state, f'UNKNOWN({state})')}"
                 f"   sub={_SUB.get(sub, f'UNKNOWN({sub})')}")
    lines.append(f"  counts :  {d.get('adv_reports', 0)} scan reports  "
                 f"{d.get('relay_hits', 0)} relay hits")
    lines.append(f"  -> {_hint(d)}")
    lines.append("─" * 40)
    _emit(lines)


def print_unavailable() -> None:
    lines = [""]
    lines.append("─" * 40)
    lines.append(f"  {ANSI_RED}relay diag unavailable{ANSI_RESET}")
    lines.append("  The CU didn't answer STANDALONE_RELAY_DIAG. Either this")
    lines.append("  firmware was built without STANDALONE_RELAY=1, or the CU")
    lines.append("  is not in relay mode (standalone set-mode relay).")
    lines.append("─" * 40)
    _emit(lines)


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


def relay_diag(cmd):
    """Return the relay diag dict, or None if the command isn't available."""
    try:
        d = cmd.relay_get_diag()
    except Exception:
        return None
    return d or None


def diag_uid(d: dict):
    """(uid_bytes, role) if the relay has captured a UID, else (None, role)."""
    role    = d.get("ble_role", 0)
    uid_len = d.get("uid_len", 0)
    have    = d.get("identity_rx", 0) or d.get("card_found", 0)
    if not have or not uid_len:
        return None, role
    uid = bytes(d.get("uid", [])[:uid_len])
    return (uid if uid else None), role


# ── main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Monitor a ChameleonUltra relay: captured UID, or why there isn't one."
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
          "(arm RELAY on both CUs, present the card to the READER CU) …")

    last_sig = object()
    try:
        while True:
            d = relay_diag(cmd)
            if d is None:
                sig = "unavailable"
                if sig != last_sig:
                    print_unavailable()
                    last_sig = sig
            else:
                uid, role = diag_uid(d)
                if uid is not None:
                    sig = ("uid", uid)
                    if sig != last_sig:
                        print_uid(uid, role)
                        last_sig = sig
                else:
                    # re-render state each poll so counts/sub update live
                    print_state(d)
                    last_sig = ("state",)

            if not args.watch:
                break
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\n{ANSI_YELLOW}Stopped.{ANSI_RESET}")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
