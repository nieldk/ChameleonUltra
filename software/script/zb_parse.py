"""zb_parse - host-side parsing of 802.15.4 / Zigbee frames from the `zigbee` standalone mode.

Pure functions, no device access. Frames are MPDUs without the FCS. Layouts follow
IEEE 802.15.4 (MAC FCF) and the Zigbee NWK header; the NWK header is cleartext even
when the payload is secured. Anything not understood is reported as None/"unparsed"
instead of guessed.
"""

import struct

FRAME_TYPES = {0: "beacon", 1: "data", 2: "ack", 3: "command"}


def parse_records(blob: bytes):
    """Split the firmware log into (channel, lqi_raw, frame) tuples. Stops at a truncated record."""
    out, i = [], 0
    while i + 3 <= len(blob):
        ch, lqi, ln = blob[i], blob[i + 1], blob[i + 2]
        if i + 3 + ln > len(blob):
            break
        out.append((ch, lqi, bytes(blob[i + 3:i + 3 + ln])))
        i += 3 + ln
    return out


def _addr(buf, off, mode):
    """Return (value, new_off) or (None, off) on short buffer. mode 2 = short, 3 = extended."""
    n = 2 if mode == 2 else 8
    if off + n > len(buf):
        return None, off
    v = int.from_bytes(buf[off:off + n], "little")
    return v, off + n


def parse_mac(f: bytes):
    """Parse the MAC header. Returns a dict, or None if too short. Key 'payload_off' marks the payload start."""
    if len(f) < 2:
        return None
    fcf = f[0] | (f[1] << 8)
    m = {
        "type": fcf & 7, "security": bool(fcf & 8), "ack_req": bool(fcf & 0x20),
        "panid_comp": bool(fcf & 0x40), "seq_suppr": bool(fcf & 0x100),
        "ie": bool(fcf & 0x200), "dst_mode": (fcf >> 10) & 3,
        "version": (fcf >> 12) & 3, "src_mode": (fcf >> 14) & 3,
        "seq": None, "dst_pan": None, "dst": None, "src_pan": None, "src": None,
        "payload_off": None, "ok": False,
    }
    off = 2
    if not m["seq_suppr"]:
        if len(f) < 3:
            return m
        m["seq"] = f[2]
        off = 3
    if m["dst_mode"] == 1 or m["src_mode"] == 1:
        return m                                    # reserved address mode
    if m["dst_mode"]:
        if off + 2 > len(f):
            return m
        m["dst_pan"] = f[off] | (f[off + 1] << 8)
        off += 2
        m["dst"], off2 = _addr(f, off, m["dst_mode"])
        if m["dst"] is None:
            return m
        off = off2
    if m["src_mode"]:
        if not (m["panid_comp"] and m["dst_mode"]):
            if off + 2 > len(f):
                return m
            m["src_pan"] = f[off] | (f[off + 1] << 8)
            off += 2
        else:
            m["src_pan"] = m["dst_pan"]
        m["src"], off2 = _addr(f, off, m["src_mode"])
        if m["src"] is None:
            return m
        off = off2
    m["payload_off"] = off
    m["ok"] = True
    return m


def parse_beacon(f: bytes, m):
    """Zigbee beacon payload (15 bytes), only for plain beacons (no GTS, no pending addresses)."""
    if not m or not m["ok"] or m["type"] != 0 or m["security"] or m["ie"]:
        return None
    o = m["payload_off"]
    if o + 4 > len(f):
        return None
    sf = f[o] | (f[o + 1] << 8)
    gts, pend = f[o + 2], f[o + 3]
    if (gts & 7) or pend:                           # GTS descriptors / pending addresses present
        return None
    p = f[o + 4:]
    if len(p) < 15 or p[0] != 0:
        return None
    return {
        "coordinator": bool(sf & 0x4000), "permit_join": bool(sf & 0x8000),
        "stack_profile": p[1] & 0xF, "nwk_ver": p[1] >> 4,
        "router_cap": bool(p[2] & 4), "depth": (p[2] >> 3) & 0xF, "ed_cap": bool(p[2] & 0x80),
        "epid": int.from_bytes(p[3:11], "little"),
        "nwk_update_id": p[14],
    }


def parse_nwk(f: bytes, m):
    """Zigbee NWK header of a data frame (MAC payload). Unsecured MAC frames only."""
    if not m or not m["ok"] or m["type"] != 1 or m["security"]:
        return None
    p = f[m["payload_off"]:]
    if len(p) < 8:
        return None
    fcf = p[0] | (p[1] << 8)
    n = {
        "ftype": fcf & 3, "proto": (fcf >> 2) & 0xF, "security": bool(fcf & 0x200),
        "dst": p[2] | (p[3] << 8), "src": p[4] | (p[5] << 8), "radius": p[6], "seq": p[7],
        "dst_ieee": None, "src_ieee": None,
    }
    o = 8
    if fcf & 0x800:
        if o + 8 > len(p):
            return None
        n["dst_ieee"] = int.from_bytes(p[o:o + 8], "little")
        o += 8
    if fcf & 0x1000:
        if o + 8 > len(p):
            return None
        n["src_ieee"] = int.from_bytes(p[o:o + 8], "little")
        o += 8
    if fcf & 0x400 or fcf & 0x100:                  # source route / multicast: header not walked
        n["hdr_len"] = None
        return n
    n["hdr_len"] = o
    n["aux"] = None
    if n["security"]:
        a = parse_aux(p, o)
        n["aux"] = a
    return n


def parse_aux(p: bytes, o: int):
    """NWK auxiliary header at p[o:]: ctrl, counter, [ext nonce: src IEEE], [key id 1: key seq]."""
    if o + 5 > len(p):
        return None
    ctrl = p[o]
    a = {"ctrl": ctrl, "key_id": (ctrl >> 3) & 3, "counter": int.from_bytes(p[o + 1:o + 5], "little"),
         "src_ieee": None, "key_seq": None}
    e = o + 5
    if ctrl & 0x20:
        if e + 8 > len(p):
            return None
        a["src_ieee"] = int.from_bytes(p[e:e + 8], "little")
        e += 8
    if a["key_id"] == 1:
        if e + 1 > len(p):
            return None
        a["key_seq"] = p[e]
        e += 1
    a["end"] = e
    return a


def nwk_decrypt(f: bytes, m, n, key: bytes):
    """Verify the 32-bit MIC and decrypt a NWK payload (security level 5, ENC-MIC-32).

    a = NWK header || aux header, nonce = src IEEE || counter || security control, with the
    level bits forced to 5 as Wireshark does (the level is not carried on the air).
    Returns (plaintext, mic_ok), or None (no aux/src IEEE, bad key length). Plaintext is
    returned even when the MIC fails, so a wrong key shows as garbage + mic_ok False.
    """
    if not n or not n.get("aux") or n.get("hdr_len") is None:
        return None
    a = n["aux"]
    src = a["src_ieee"] if a["src_ieee"] is not None else n["src_ieee"]
    if src is None or len(key) != 16:
        return None
    p = f[m["payload_off"]:]
    ctrl = (a["ctrl"] & ~7) | 5
    nonce = src.to_bytes(8, "little") + a["counter"].to_bytes(4, "little") + bytes([ctrl])
    hdr = p[:n["hdr_len"]] + bytes([ctrl]) + p[n["hdr_len"] + 1:a["end"]]
    body = p[a["end"]:]
    if len(body) < 4:
        return None
    return ccm_decrypt(key, nonce, hdr, body[:-4], body[-4:])


def ccm_decrypt(key: bytes, nonce: bytes, aad: bytes, ct: bytes, mic: bytes):
    """AES-CCM, 13-byte nonce, 4-byte MIC (RFC 3610, L=2). Returns (plaintext, mic_ok)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    blk = lambda b: enc.update(b)
    xor = lambda x, y: bytes(i ^ j for i, j in zip(x, y))
    ctr = lambda i: blk(bytes([1]) + nonce + i.to_bytes(2, "big"))
    pt = b"".join(xor(ct[i:i + 16], ctr(i // 16 + 1)) for i in range(0, len(ct), 16))
    flags = (0x40 if aad else 0) | (((len(mic) - 2) // 2) << 3) | 1
    x = blk(bytes([flags]) + nonce + len(pt).to_bytes(2, "big"))
    data = (len(aad).to_bytes(2, "big") + aad) if aad else b""
    data += b"\0" * (-len(data) % 16)
    data += pt + b"\0" * (-len(pt) % 16)
    for i in range(0, len(data), 16):
        x = blk(xor(x, data[i:i + 16]))
    tag = xor(x[:len(mic)], ctr(0)[:len(mic)])
    return pt, tag == mic


APS_FRAME_TYPES = {0: "data", 1: "command", 2: "ack", 3: "interpan"}

# APS Transport-Key command (command ID 0x05), key-type byte -> name.
# Source: ZigBee spec (05-3474) section 4.4.1.1 "Transport-Key command" and its
# key-descriptor table; cross-checked against Microchip's APS_TransportKeyType_t /
# APS_ReqTransportKeyData_t docs and Wireshark's packet-zbee-aps.c field names
# (hf_zbee_aps_cmd_key_type/_key/_seqno/_dst/_src). We could not fetch the dissector's
# C source itself (gitea.osmocom.org blocks automated fetches; raw.githubusercontent.com
# isn't on this tool's allowlist), so the *byte order* below is reconstructed from the
# spec's field list, not read off the dissector line-by-line -- only the Standard
# Network Key layout is decoded; others are reported but not parsed further.
APS_CMD_TRANSPORT_KEY = 0x05
TRANSPORT_KEY_TYPES = {
    0x00: "trust-center master key", 0x01: "standard network key",
    0x02: "application master key", 0x03: "application link key",
    0x04: "trust-center link key", 0x05: "high-security network key",
}


APS_FRAME_TYPES_COMMAND = 1


def parse_aps(p: bytes):
    """APS frame header at p[0:]. Only Command-type frames are decoded in full (no
    endpoint/cluster/profile fields -- those exist only for Data/Ack frames and aren't
    needed for Transport-Key capture); Data/Ack/interpan frames are reported as such but
    not walked further."""
    if len(p) < 2:
        return None
    fcf = p[0]
    a = {
        "ftype": fcf & 3, "delivery": (fcf >> 2) & 3, "ack_format": bool(fcf & 0x10),
        "security": bool(fcf & 0x20), "ack_req": bool(fcf & 0x40),
        "ext_header": bool(fcf & 0x80), "counter": p[1],
        "aux": None, "hdr_len": None,
    }
    if a["ext_header"]:
        return a                                    # fragmentation framing, not handled
    if a["ftype"] != APS_FRAME_TYPES_COMMAND:
        return a                                    # data/ack/interpan: fields not parsed
    o = 2
    if a["security"]:
        aux = parse_aux(p, o)
        if aux is None:
            return a
        a["aux"] = aux
        o = aux["end"]
    a["hdr_len"] = o
    return a


def aps_decrypt(p: bytes, a, key: bytes):
    """Decrypt an APS Command frame's payload (security level 5, ENC-MIC-32), the same
    CCM* construction as NWK security but keyed/nonced from the APS aux header. Returns
    (plaintext, mic_ok), or None if there's no aux header / extended source address."""
    if not a or not a.get("aux") or a.get("hdr_len") is None:
        return None
    aux = a["aux"]
    if aux["src_ieee"] is None or len(key) != 16:
        return None
    ctrl = (aux["ctrl"] & ~7) | 5
    nonce = aux["src_ieee"].to_bytes(8, "little") + aux["counter"].to_bytes(4, "little") + bytes([ctrl])
    hdr = p[:2] + p[2:a["hdr_len"]]
    hdr = hdr[:2] + bytes([ctrl]) + hdr[3:]          # force level bits in aux ctrl byte
    body = p[a["hdr_len"]:]
    if len(body) < 4:
        return None
    return ccm_decrypt(key, nonce, hdr, body[:-4], body[-4:])


def parse_transport_key(plain: bytes):
    """Decode an APS Transport-Key command payload. Only the Standard Network Key case
    (key type 0x01) is decoded: Key Type(1) + Key(16) + Sequence Number(1) +
    Destination Address(8, EUI64) + Source Address(8, EUI64), per the spec's network-key
    descriptor fields. Not verified against a real captured join -- see module docstring
    on parse_aps/APS_CMD_TRANSPORT_KEY above."""
    if len(plain) < 2 or plain[0] != APS_CMD_TRANSPORT_KEY:
        return None
    key_type = plain[1]
    r = {"key_type": key_type, "key_type_name": TRANSPORT_KEY_TYPES.get(key_type, f"type {key_type}")}
    if key_type == 0x01 and len(plain) >= 2 + 16 + 1 + 8 + 8:
        o = 2
        r["key"] = plain[o:o + 16]
        r["seq"] = plain[o + 16]
        r["dst_ieee"] = int.from_bytes(plain[o + 17:o + 25], "little")
        r["src_ieee"] = int.from_bytes(plain[o + 25:o + 33], "little")
        r["decoded"] = True
    else:
        r["decoded"] = False
        r["raw"] = plain[2:]
    return r


def fmt_ieee(v):
    return ":".join(f"{b:02x}" for b in v.to_bytes(8, "big"))


def describe_frame(ch: int, lqi: int, f: bytes) -> str:
    """One-line decode of a single frame: type, addressing, and NWK/beacon summary
    where parseable. Shared by `cli_zigbee.py` (dump) and the generic
    `standalone zigbee get-result` renderer in chameleon_cli_unit.py."""
    m = parse_mac(f)
    line = f"ch{ch:<2} lqi={lqi:<3} len={len(f):<3} "
    if not m:
        return line + "short: " + f.hex()
    line += FRAME_TYPES.get(m["type"], f"type{m['type']}")
    if not m["ok"]:
        return line + " (header not parsed)"
    if m["seq"] is not None:
        line += f" seq={m['seq']}"
    if m["dst"] is not None:
        line += f" dst={m['dst_pan']:#06x}:{m['dst']:#x}"
    if m["src"] is not None:
        line += f" src={m['src_pan']:#06x}:{m['src']:#x}"
    if m["security"]:
        line += " [mac-secured]"
    b = parse_beacon(f, m)
    n = parse_nwk(f, m)
    if b:
        line += (f" EPID={fmt_ieee(b['epid'])} profile={b['stack_profile']} "
                 f"depth={b['depth']} join={'y' if b['permit_join'] else 'n'}")
    elif n:
        line += (f" nwk[{['data', 'cmd', '?', 'interpan'][n['ftype']]} "
                 f"{n['src']:#06x}->{n['dst']:#06x} r={n['radius']} s={n['seq']}"
                 f"{' nwk-secured' if n['security'] else ''}]")
    return line
