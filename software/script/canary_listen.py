#!/usr/bin/env python3
"""
canary_listen.py - print nfc_canary BLE notifications from a ChameleonUltra/Lite.

    pip install bleak
    python canary_listen.py                  # scan for a device named Chameleon*
    python canary_listen.py AA:BB:CC:DD:EE:FF
    python canary_listen.py chameleon        # match part of the BLE name (also finds a custom name via the UART service)
    python canary_listen.py --list           # show every BLE device seen (debug "not found")
    python canary_listen.py --pair           # pair first (if BLE pairing is enabled on the device)
    python canary_listen.py --reconnect      # keep retrying after a drop
    python canary_listen.py --selftest       # check the frame decoder, no hardware

Notifications are standard Chameleon data frames (cmd 7010, 10-byte payload):
  SOF(0x11) LRC1 | cmd(u16 BE) status(u16 BE) len(u16 BE) LRC2 | data | LRC3
The 10-byte payload is little-endian, see nfc_canary_core.h.
"""
import asyncio
import sys
import time

from canary_cmd import canary_cmd_name

NUS_TX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"   # device -> host (notify)
CMD_CANARY_EVENT = 7010
LEVELS = ("field", "poll", "select", "engage")
TYPES = {1: "ALERT", 2: "END", 3: "TEST"}
FLAGS = {0x01: "forced-close", 0x02: "disarmed"}


def lrc(b: bytes) -> int:
    return (0x100 - sum(b)) & 0xFF


class FrameParser:
    """Reassembles frames from arbitrarily chunked notification bytes."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data: bytes):
        self.buf += data
        while True:
            # resync on SOF
            while self.buf and self.buf[0] != 0x11:
                del self.buf[0]
            if len(self.buf) < 9:
                return
            if self.buf[1] != lrc(self.buf[0:1]) or self.buf[8] != lrc(self.buf[0:8]):
                del self.buf[0]          # bad header, resync
                continue
            n = int.from_bytes(self.buf[6:8], "big")
            total = 9 + n + 1
            if len(self.buf) < total:
                return
            frame = bytes(self.buf[:total])
            del self.buf[:total]
            data = frame[9:9 + n]
            if frame[9 + n] != lrc(data):
                continue                  # bad payload checksum, drop
            yield (int.from_bytes(frame[2:4], "big"),
                   int.from_bytes(frame[4:6], "big"), data)


def decode(p: bytes) -> str:
    if len(p) != 10:
        return f"unexpected payload length {len(p)}: {p.hex()}"
    typ = TYPES.get(p[0], f"type?{p[0]}")
    lvl = LEVELS[p[1]] if p[1] < 4 else f"level?{p[1]}"
    seq = p[3]
    if typ == "TEST":
        return f"TEST        seq={seq}"
    dur = int.from_bytes(p[4:6], "little")
    frames = int.from_bytes(p[8:10], "little")
    flags = ",".join(n for b, n in FLAGS.items() if p[7] & b) or "-"
    cmd = f"0x{p[2]:02x} ({canary_cmd_name(lvl, p[2])})" if p[1] > 0 else "--"
    base = f"{typ:<5} {lvl:<6} cmd={cmd} seq={seq} dur={dur}s"
    if typ == "END":
        base += f" field_ons={p[6]} frames={frames} flags={flags}"
    return base


class Tracker:
    def __init__(self):
        self.last_seq = None

    def gap(self, seq: int) -> int:
        missed = 0 if self.last_seq is None else (seq - self.last_seq - 1) & 0xFF
        self.last_seq = seq
        return missed


def handle(parser, tracker, data: bytes):
    for cmd, status, payload in parser.feed(data):
        if cmd != CMD_CANARY_EVENT:
            continue
        line = decode(payload)
        if len(payload) == 10:
            missed = tracker.gap(payload[3])
            if missed:
                line += f"   [!] {missed} event(s) missed before this one"
        print(time.strftime("%H:%M:%S"), line, flush=True)


def selftest():
    def frame(cmd, payload):
        h = bytes([0x11, lrc(b"\x11")]) + cmd.to_bytes(2, "big") + \
            (0x68).to_bytes(2, "big") + len(payload).to_bytes(2, "big")
        return h + bytes([lrc(h)]) + payload + bytes([lrc(payload)])

    evts = [bytes([1, 2, 0x93, 0, 5, 0, 1, 0, 3, 0]),
            bytes([2, 3, 0x60, 1, 42, 0, 2, 0x01, 17, 0]),
            bytes([3, 0, 0, 3, 0, 0, 0, 0, 0, 0])]      # seq 2 missing
    stream = b"\xff\x00" + b"".join(frame(CMD_CANARY_EVENT, e) for e in evts)
    parser, tracker = FrameParser(), Tracker()
    for i in range(0, len(stream), 7):                   # awkward chunking
        handle(parser, tracker, stream[i:i + 7])


NUS_SERVICE = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"


async def find_device(target, timeout=10.0):
    """Same matching rules as the CLI (chameleon_ble.py): an address connects
    directly; otherwise match the target (default "chameleon") as a
    case-insensitive substring of the advertised name, falling back to any
    device advertising the Nordic UART service (covers a custom BLE name)."""
    from bleak import BleakScanner
    if target and (target.count(":") >= 5 or "-" in target):
        return target
    want = (target or "chameleon").lower()
    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    by_nus = None
    for dev, adv in found.values():
        name = adv.local_name or dev.name or ""
        if want in name.lower():
            return dev
        if NUS_SERVICE in [u.lower() for u in (adv.service_uuids or [])] and by_nus is None:
            by_nus = dev
    return by_nus


async def list_devices(timeout=10.0):
    from bleak import BleakScanner
    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    for dev, adv in sorted(found.values(), key=lambda t: -(t[1].rssi or -999)):
        nus = "  [NUS]" if NUS_SERVICE in [u.lower() for u in (adv.service_uuids or [])] else ""
        print(f"{dev.address}  rssi={adv.rssi}  {adv.local_name or dev.name or '(no name)'}{nus}")


async def listen_once(target, pair):
    from bleak import BleakClient
    print("scanning...")
    dev = await find_device(target)
    if dev is None:
        raise RuntimeError("no Chameleon found. Is it advertising (BLE on, not already "
                           "connected to the phone/CLI)? Try --list to see what is visible, "
                           "then pass the address (or part of the name) explicitly.")
    print(f"connecting to {getattr(dev, 'address', dev)} ...")
    parser, tracker = FrameParser(), Tracker()
    done = asyncio.Event()
    async with BleakClient(dev, timeout=20.0,
                           disconnected_callback=lambda c: done.set()) as c:
        if pair:
            print("pairing (enter the device BLE pairing key when asked) ...")
            await c.pair()
        await c.start_notify(NUS_TX, lambda _, d: handle(parser, tracker, bytes(d)))
        print("listening (Ctrl-C to quit); press the STANDALONE_ACTION button on the device for a TEST event")
        await done.wait()
        print("device disconnected")


async def run(target, pair, reconnect):
    while True:
        try:
            await listen_once(target, pair)
        except Exception as e:           # show the real reason instead of dying silently
            print(f"error: {type(e).__name__}: {e}")
            if "uthenticat" in str(e) or "ncryption" in str(e) or "ecurity" in str(e):
                print("hint: BLE pairing is probably enabled on the device. Pair/bond it "
                      "first in your OS Bluetooth settings (key from `hw settings blepair`), "
                      "or re-run with --pair.")
        if not reconnect:
            return
        print("retrying in 5 s ...")
        await asyncio.sleep(5)


if __name__ == "__main__":
    flags = {a for a in sys.argv[1:] if a.startswith("-")}
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if "--selftest" in flags:
        selftest()
    elif "--list" in flags:
        asyncio.run(list_devices())
    else:
        try:
            asyncio.run(run(args[0] if args else None, "--pair" in flags,
                            "--reconnect" in flags))
        except KeyboardInterrupt:
            pass
