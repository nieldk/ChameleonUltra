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
    line = f"ch={ch:3d} prefix={prefix:#04x} base={base:#04x}  {raw.hex()}"
    c = esb_crc_best(prefix, base, raw)
    if c is None:
        return line + "  crc:noise"
    tag = f"CRC-OK({c['order']}) pl={c['payload_len']} pay={c['payload'].hex()}"
    if c['unifying']:
        tag += f" unifying {UNIFYING_LENS[c['payload_len']]} cksum={'ok' if c['cksum_ok'] else 'BAD'}"
    return line + "  " + tag


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
    valid = sum(1 for ch, p, b, raw in recs if esb_crc_best(p, b, raw))
    unif = sum(1 for ch, p, b, raw in recs
               if (c := esb_crc_best(p, b, raw)) and c['unifying'])
    head = f"{len(recs)} hit(s) across {len(counts)} guess(es)"
    if valid:
        return (f"{head}; {valid} CRC-valid ({unif} Unifying) -- these are real frames, "
                f"the rest are noise; top guesses: {top_str}")
    return f"{head}; 0 CRC-valid (all noise so far); top: {top_str}"


# --- ESB CRC-16 validation of promisc captures ---------------------------
#
# A promisc hit is raw bits with CRC off (see esb_promisc_radio.h), so real
# frames and noise matches look alike. nRF24/Nordic ESB appends a 2-byte
# CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) computed MSB-first over the
# contiguous on-air bitstream {address, 9-bit PCF, payload}. Prepending the
# two matched address bytes to raw[] reconstructs that bitstream from its
# start, so sliding the CRC boundary and checking for a match tells a real
# frame from noise -- a false match is ~1/65536 per boundary. A match also
# fixes the address byte order the capture leaves open (header unknown #1):
# whichever prepend order validates is the on-air order.

def _bits_msb(data: bytes):
    out = []
    for byte in data:
        for i in range(7, -1, -1):
            out.append((byte >> i) & 1)
    return out


def _crc16_ccitt(bits) -> int:
    crc = 0xFFFF
    for b in bits:
        crc ^= (b & 1) << 15
        crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def _bits_to_int(bits) -> int:
    v = 0
    for b in bits:
        v = (v << 1) | b
    return v


def esb_crc_candidates(prefix: int, base: int, raw: bytes, addr_bytes: int = 5,
                       max_payload: int = 23):
    """CRC-valid ESB framings in one promisc hit. Fixes the address at
    addr_bytes (5 for Unifying); a 3/4-byte-address frame still validates,
    just read as a longer payload. Tries both prepend orders; for each,
    slides the 2-byte CRC boundary over payload lengths and keeps the ones
    where CRC-16 over the leading bits equals the next 16. Shortest payload
    first -- longer matches reuse real bytes plus trailing noise."""
    out = []
    hdr = addr_bytes * 8 + 9          # address + 9-bit PCF, before payload
    for order in ("pb", "bp"):
        buf = (bytes([prefix, base]) if order == "pb" else bytes([base, prefix])) + bytes(raw)
        bits = _bits_msb(buf)
        n = len(bits)
        for plen in range(0, max_payload + 1):
            k = hdr + 8 * plen
            if k + 16 > n:
                break
            if _crc16_ccitt(bits[:k]) == _bits_to_int(bits[k:k + 16]):
                payload = bytes(_bits_to_int(bits[hdr + 8 * i:hdr + 8 * i + 8]) for i in range(plen))
                out.append({
                    'order': order,
                    'payload_len': plen,
                    'payload': payload,
                    'crc': _bits_to_int(bits[k:k + 16]),
                    'unifying': plen in UNIFYING_LENS,
                    'cksum_ok': plen in UNIFYING_LENS and unifying_checksum_ok(payload),
                })
    out.sort(key=lambda c: (c['payload_len'], c['order'] != "pb"))
    return out


def esb_crc_best(prefix: int, base: int, raw: bytes):
    """Best CRC-valid framing for a hit, or None. Prefers a Unifying-shaped
    payload whose vendor checksum also passes, else the shortest valid one."""
    cands = esb_crc_candidates(prefix, base, raw)
    if not cands:
        return None
    for c in cands:
        if c['cksum_ok']:
            return c
    for c in cands:
        if c['unifying']:
            return c
    return cands[0]
