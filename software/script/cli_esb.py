"""cli_esb - host-side parsing of captures from the `esb` standalone mode.

Pure functions, no device access. Frames are raw ESB payloads (the radio's own
16-bit CRC already stripped); nothing about the higher-layer protocol is
assumed beyond what's documented for Logitech Unifying specifically. Anything
not understood is reported as-is (raw hex) rather than guessed.
"""

import struct

# Logitech Unifying payload shapes, from Bastille Research's MouseJack
# disclosure and SensePost's Logitacker writeup: 5, 10 or 22-byte payload,
# plus a 1-byte vendor checksum on top of ESB's own CRC -- so 6, 11 or 23
# bytes as captured here. What each shape actually carries (HID++ short vs.
# long report, encrypted keyboard frame, etc.) is Logitacker-specific
# protocol detail that hasn't been looked into yet; this only reports shape,
# checksum validity and raw bytes.
UNIFYING_LENS = {6: "short(5)", 11: "short(10)", 23: "long(22)"}


def parse_records(blob: bytes):
    """Split the firmware log into (channel, frame) tuples. Stops at a truncated record."""
    out, i = [], 0
    while i + 2 <= len(blob):
        ch, ln = blob[i], blob[i + 1]
        if i + 2 + ln > len(blob):
            break
        out.append((ch, bytes(blob[i + 2:i + 2 + ln])))
        i += 2 + ln
    return out


def unifying_checksum_ok(f: bytes) -> bool:
    """Logitech Unifying's documented vendor checksum: byte-wise sum of the
    whole frame (payload + checksum byte) is 0 mod 256. Documented in the
    Bastille/MouseJack and Logitacker write-ups; not Nordic/ESB's own CRC,
    which the radio has already checked and stripped before this."""
    if not f:
        return False
    return (sum(f) & 0xFF) == 0


def describe_frame(ch: int, f: bytes) -> str:
    shape = UNIFYING_LENS.get(len(f), f"len={len(f)}")
    ok = "ok" if unifying_checksum_ok(f) else "BAD"
    return f"ch={ch:3d} {shape:<10s} checksum={ok}  {f.hex()}"


def summarize(recs) -> str:
    if not recs:
        return "no frames"
    by_shape = {}
    for _ch, f in recs:
        shape = UNIFYING_LENS.get(len(f), f"len={len(f)}")
        by_shape[shape] = by_shape.get(shape, 0) + 1
    parts = ", ".join(f"{n} {s}" for s, n in sorted(by_shape.items()))
    return f"{len(recs)} frame(s): {parts}"


# --- esb-promisc: brute-force partial-address captures -------------------
#
# Every record here is a CANDIDATE, not a confirmed frame -- the firmware
# runs with CRC off (there's nothing to validate an unknown address
# against), so isolated hits on noise are expected. See
# esb_promisc_radio.h/mode_esb_promisc.c for exactly what's grounded
# (the BALEN-shrink partial-match technique, confirmed on this RADIO
# family for BLE) vs. unverified (that it ports to ESB/Unifying, and the
# exact byte order of the leaked remainder). This module does NOT attempt
# address reconstruction -- that needs a real capture to pin the byte
# order down first; it only groups and dumps candidates so that can be
# done by hand against a capture with a partially-known address.

def parse_promisc_records(blob: bytes):
    """Split the firmware log into (channel, prefix_guess, base_guess, raw) tuples."""
    out, i = [], 0
    while i + 4 <= len(blob):
        ch, prefix, base, ln = blob[i], blob[i + 1], blob[i + 2], blob[i + 3]
        if i + 4 + ln > len(blob):
            break
        out.append((ch, prefix, base, bytes(blob[i + 4:i + 4 + ln])))
        i += 4 + ln
    return out


def describe_promisc_hit(ch: int, prefix: int, base: int, raw: bytes) -> str:
    return f"ch={ch:3d} prefix={prefix:#04x} base={base:#04x}  {raw.hex()}"


def promisc_hit_counts(recs):
    """(prefix, base) -> hit count. A guess with many hits is a real
    candidate; a guess with one or two is likely noise (CRC is off)."""
    counts = {}
    for _ch, prefix, base, _raw in recs:
        counts[(prefix, base)] = counts.get((prefix, base), 0) + 1
    return counts


def summarize_promisc(recs) -> str:
    if not recs:
        return "no hits"
    counts = promisc_hit_counts(recs)
    top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
    top_str = ", ".join(f"prefix={p:#04x}/base={b:#04x}:{n}" for (p, b), n in top)
    return f"{len(recs)} hit(s) across {len(counts)} guess(es); top: {top_str}"
