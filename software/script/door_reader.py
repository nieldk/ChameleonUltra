#!/usr/bin/env python3
"""
door_reader.py — drive a THIRD ChameleonUltra as a door reader, to exercise a
two-CU relay end to end with no real reader.

Topology:
    [real card] -- green RELAY_READER  ~BLE~  blue RELAY_CARD -- THIS CU (reader)

This CU is put in reader mode and does what a door does: scan the (relayed) UID,
optionally check it against an allow-list (grant/deny), and optionally run a
MIFARE Classic auth + block read. Every step is timed — the auth time is the
number that tells you whether the relay's BLE round-trip keeps inside Crypto1's
window.

    ./door_reader.py --port /dev/ttyACM2            # scan + grant/deny
    ./door_reader.py --port /dev/ttyACM2 --auth     # + Crypto1 auth/read block 0
    ./door_reader.py --port /dev/ttyACM2 --auth --block 4 --key FFFFFFFFFFFF --watch
    ./door_reader.py --list                         # list CUs, pick the right port

On Linux the port is NOT auto-safe: with several CUs connected, auto-pick grabs
the first by USB VID, which may be a relay CU. Pass --port, or use --list.
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import serial.tools.list_ports
import chameleon_com
import chameleon_cmd
from chameleon_enum import MfcKeyType

CG, CY, CR, CC, C0 = "\033[92m", "\033[93m", "\033[91m", "\033[96m", "\033[0m"
CU_VID = 0x6868


def list_ports():
    rows = [p for p in serial.tools.list_ports.comports() if p.vid == CU_VID]
    if not rows:
        print("No ChameleonUltra (VID 0x6868) found.")
        return
    print("ChameleonUltra devices:")
    for p in rows:
        print(f"  {p.device:16}  serial={p.serial_number}")


def pick_port(explicit):
    if explicit:
        return explicit
    rows = [p.device for p in serial.tools.list_ports.comports() if p.vid == CU_VID]
    if not rows:
        sys.exit("No ChameleonUltra serial port found; pass --port")
    if len(rows) > 1:
        print(f"{CY}[!] {len(rows)} CUs found ({', '.join(rows)}); using {rows[0]}. "
              f"Pass --port to choose.{C0}", file=sys.stderr)
    return rows[0]


def hx(b) -> str:
    return "".join(f"{x:02X}" for x in b)


def scan(cmd):
    """Return the first tag dict, or None. Times the exchange."""
    t0 = time.perf_counter()
    try:
        tags = cmd.hf14a_scan()
    except Exception:
        tags = None
    dt = (time.perf_counter() - t0) * 1000
    return (tags[0] if tags else None), dt


_last_n = 0

def render_inplace(lines):
    """Redraw `lines` over the previous block (no scrolling). \033[J after the
    cursor-up clears to end of screen, so a shorter block erases the old one."""
    global _last_n
    out = (f"\033[{_last_n}A\033[J" if _last_n else "") + "\n".join(lines) + "\n"
    sys.stdout.write(out)
    sys.stdout.flush()
    _last_n = len(lines)


def door_once(cmd, args, allow):
    """Scan once; return the display lines (no printing)."""
    tag, dt = scan(cmd)
    if not tag:
        return [f"{CY}… no card ({dt:.0f} ms){C0}"]

    uid = hx(tag['uid'])
    sak = hx(tag['sak'])
    lines = [f"{CC}card{C0}  UID={uid}  SAK={sak}  ATQA={hx(tag['atqa'])}  "
             f"(scan {dt:.0f} ms)"]

    # Door decision by UID allow-list (UID-only access systems).
    if allow is not None:
        ok = uid.upper() in allow
        lines.append(f"  access: {CG+'GRANTED' if ok else CR+'DENIED'}{C0}  (UID {uid})")

    if not args.auth:
        return lines

    # MIFARE Classic auth + read — the relay-timing stress test.
    key = bytes.fromhex(args.key)
    ktype = MfcKeyType.A if args.key_type.upper() == 'A' else MfcKeyType.B
    t0 = time.perf_counter()
    err = None
    try:
        ok = cmd.mf1_auth_one_key_block(args.block, ktype, key)
    except Exception as e:
        ok = False
        err = e
    dt = (time.perf_counter() - t0) * 1000
    if err is not None:
        lines.append(f"  {CR}auth error: {err}{C0}")
    lines.append(f"  auth blk {args.block} key{args.key_type.upper()} {args.key}: "
                 f"{CG+'OK' if ok else CR+'FAIL'}{C0}  ({dt:.0f} ms)")
    if ok:
        t0 = time.perf_counter()
        try:
            data = cmd.mf1_read_one_block(args.block, ktype, key)
            dt = (time.perf_counter() - t0) * 1000
            lines.append(f"  read blk {args.block}: {hx(data)}  ({dt:.0f} ms)")
        except Exception as e:
            lines.append(f"  {CR}read failed: {e}{C0}")
    return lines


def main():
    ap = argparse.ArgumentParser(description="Drive a third CU as a door reader against a relay.")
    ap.add_argument("--port", "-p", help="serial port of the READER CU (pass this on Linux)")
    ap.add_argument("--ble", action="store_true", help="connect the reader CU over BLE")
    ap.add_argument("--list", action="store_true", help="list connected CUs and exit")
    ap.add_argument("--auth", action="store_true", help="also do a MIFARE Classic auth + read")
    ap.add_argument("--block", type=int, default=0, help="block to auth/read (default 0)")
    ap.add_argument("--key", default="FFFFFFFFFFFF", help="6-byte key hex (default FFFFFFFFFFFF)")
    ap.add_argument("--key-type", default="A", choices=["A", "B", "a", "b"], help="key type (default A)")
    ap.add_argument("--allow", help="comma-separated UID allow-list (hex) for grant/deny")
    ap.add_argument("--once", action="store_true", help="scan once and exit (default: continuous)")
    ap.add_argument("--interval", "-i", type=float, default=0.4, help="scan interval s (default 0.4)")
    args = ap.parse_args()

    if args.list:
        list_ports()
        return

    allow = None
    if args.allow:
        allow = {u.strip().upper().replace(" ", "") for u in args.allow.split(",") if u.strip()}

    dev = chameleon_com.ChameleonCom()
    dev.open("ble" if args.ble else pick_port(args.port))
    cmd = chameleon_cmd.ChameleonCMD(dev)
    cmd.set_device_reader_mode(True)
    print(f"{CG}Reader ready.{C0}  Present the relay's CARD (blue) CU to this one.")

    try:
        while True:
            lines = door_once(cmd, args, allow)
            if args.once:
                print("\n".join(lines))
                break
            render_inplace(lines)          # redraw in place, no scrolling
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n{CY}Stopped.{C0}")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
