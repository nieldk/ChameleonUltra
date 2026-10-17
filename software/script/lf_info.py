"""pm3-style LF output helpers (ported from Proxmark3 client/src/cmdlf*.c).
Pure functions, no device access."""


def em410x_lines(idb, hl=lambda s: s, hd=lambda s: s):
    """Short EM410x ID block as printed by pm3 printEM410x(verbose).
    idb: 5 ID bytes. hl: highlight, hd: header highlight."""
    i = int.from_bytes(idb, "big")
    # reverse the bits of every byte, byte order kept
    u = 0
    for m in range(5, 0, -1):
        for b in range(8):
            u = (u << 1) | ((i >> (b + (m - 1) * 8)) & 1)
    zk = "".join(f"{(u >> s) & 0xF:02d}" for s in range(36, -1, -4))
    paxton = (((i >> 32) << 24) | (i & 0xFFFFFF)) + 0x143E00
    a = [(i & 0xFFFFFF) >> k & 1 for k in range(24)]
    p1 = 0
    for src, dst in ((23, 21), (22, 23), (21, 20), (20, 22), (19, 18), (18, 16),
                     (17, 19), (16, 17), (15, 13), (14, 15), (13, 12), (12, 14),
                     (11, 6), (10, 2), (9, 7), (8, 1), (7, 0), (6, 8), (5, 11),
                     (4, 3), (3, 10), (2, 4), (1, 5), (0, 9)):
        p1 |= a[src] << dst
    s1, s2, s3 = i & 0xFFFF, (i >> 16) & 0x7F, i & 0x7FFFFF
    return [
        f"EM 410x ID {hl(f'{i:010X}')}",
        f"-------- {hd('Possible de-scramble patterns')} ---------",
        f"Unique TAG ID      : {u:010X}",
        "HoneyWell IdentKey",
        f"    DEZ 8          : {i & 0xFFFFFF:08d}",
        f"    DEZ 10         : {i & 0xFFFFFFFF:010d}",
        f"    DEZ 5.5        : {(i >> 16) & 0xFFFF:05d}.{i & 0xFFFF:05d}",
        f"    DEZ 3.5A       : {i >> 32:03d}.{i & 0xFFFF:05d}",
        f"    DEZ 3.5B       : {(i & 0xFF000000) >> 24:03d}.{i & 0xFFFF:05d}",
        f"    DEZ 3.5C       : {(i & 0xFF0000) >> 16:03d}.{i & 0xFFFF:05d}",
        f"    DEZ 14/IK2     : {i:014d}",
        f"    DEZ 15/IK3     : {u:015d}",
        f"    DEZ 20/ZK      : {zk}",
        "",
        f"Other              : {i & 0xFFFF:05d}_{(i >> 16) & 0xFF:03d}_{i & 0xFFFFFF:08d}",
        f"Pattern Paxton     : {paxton} [0x{paxton:X}]",
        f"Pattern 1          : {p1} [0x{p1:X}]",
        f"Pattern Sebury     : {s1} {s2} {s3}  [0x{s1:X} 0x{s2:X} 0x{s3:X}]",
        f"VD / ID            : {(i >> 32) & 0xFFFF:03d} / {i & 0xFFFFFFFF:010d}",
        f"Pattern ELECTRA    : {(i >> 24) & 0xFFFF} {i & 0xFFFFFF}",
        "------------------------------------------------",
    ]


def viking_raw(idb):
    """pm3 getVikingBits(): F2 00 00 <id32> <chk>."""
    chk = idb[0] ^ idb[1] ^ idb[2] ^ idb[3] ^ 0xF2 ^ 0xA8
    return bytes([0xF2, 0, 0]) + bytes(idb[:4]) + bytes([chk])


def jablotron_raw(full):
    """pm3 getJablotronBits(): FFFF <5 byte code> <chk>."""
    chk = (sum(full[:5]) & 0xFF) ^ 0x3A
    return b"\xFF\xFF" + bytes(full[:5]) + bytes([chk])


def jablotron_printed(full):
    """Printed card number: 1410-nn-nnnn-nnnn (BCD nibbles of the code)."""
    h = bytes(full[:5]).hex().upper()
    return f"1410-{h[0:2]}-{h[2:6]}-{h[6:10]}"


def ioprox_line(ver, fc, cn, raw8, hl=lambda s: s, ok=lambda s: s, bad=lambda s: s):
    """pm3 'IO Prox - XSF(vv)ff:nnnnn, Raw: ... ( ok )' line, CRC recomputed
    from the frame: 9-bit groups (8 data + stop), 0xFF - sum(groups 1..5)."""
    v = int.from_bytes(raw8, "big")
    bits = [(v >> (63 - k)) & 1 for k in range(64)]
    grp = lambda g: int("".join(map(str, bits[9 * g:9 * g + 8])), 2)
    calc = 0xFF - (sum(grp(g) for g in range(1, 6)) & 0xFF)
    crc = int("".join(map(str, bits[54:62])), 2)
    st = ok("( ok )") if crc == calc else bad(f"( fail ) 0x{crc:02X} != 0x{calc:02X}")
    return f"IO Prox - {hl(f'XSF({ver:02d}){fc:02x}:{cn:05d}')}, Raw: {raw8.hex()} {st}"


def indala_lines(raw, fc, cn, hl=lambda s: s):
    """pm3 demodIndala() 64-bit block. raw: 8-byte frame, fc/cn: Fmt 26 fields."""
    bit = lambda n: (raw[n // 8] >> (7 - n % 8)) & 1
    uid1 = int.from_bytes(raw[:4], "big")
    uid2 = int.from_bytes(raw[4:], "big")
    par = (bit(34) << 1) | bit(38)
    p1 = 0
    for n, sh in ((3, 8), (6, 5), (8, 4), (9, 3), (11, 1), (16, 6), (19, 7),
                  (20, 10), (21, 2), (22, 0), (24, 9)):
        p1 |= bit(32 + n) << sh
    heden = 0
    for n, w in ((8, 1), (10, 2), (14, 4), (15, 8), (12, 16), (28, 32), (3, 64),
                 (11, 128), (19, 256), (26, 512), (17, 1024), (18, 2048),
                 (20, 4096), (13, 8192), (7, 16384), (23, 32768)):
        if bit(31 + n):
            heden += w
    return [
        f"Indala (len 64)  Raw: {hl(raw.hex().upper())}",
        f"Fmt {hl('26')} FC: {hl(fc)} Card: {hl(cn)} Parity: {hl(f'{par >> 1}{par & 1}')}",
        "",
        "Possible de-scramble patterns",
        f"  Printed....... __{p1:04d}__  ( 0x{p1:X} )",
        f"  Internal ID... {uid2 & 0x7FFFFFFF}",
        f"  Heden-2L...... {heden}",
    ]


def fdxb_lines(frame, country, country_name, crc_ok, hl=lambda s: s,
               ok=lambda s: s, bad=lambda s: s):
    """pm3 'lf fdxb reader' verbose block. frame: 13-byte frame (LSB-first
    fields, CRC-16 at 8..9, 24-bit extended data at 10..12)."""
    v = int.from_bytes(frame[0:8], "little")
    national = v & ((1 << 38) - 1)
    data_blk = (v >> 48) & 1
    rudi = (v >> 49) & 1
    reserved = (v >> 50) & 0x1F
    user = (v >> 55) & 0x1F
    repl = (v >> 60) & 0x7
    animal = (v >> 63) & 1
    crc = int.from_bytes(frame[8:10], "little")
    ext = int.from_bytes(frame[10:13], "little")
    yes = lambda b, s="": hl("True") + s if b else "False"
    out = [
        "FDX-B / ISO 11784/5 Animal",
        f"Animal ID......... {hl(f'{country:03d}-{national:012d}')}",
        f"National Code..... {hl(f'{national:012d}')} ( 0x{national:X} )",
        f"Country Code...... {hl(f'{country:03d}')} - {country_name}",
        f"Reserved/RFU...... {reserved} (0x{reserved:04X})",
        f"Animal bit set?... {yes(animal)}",
        f"Data block?....... {yes(data_blk)}  ( 0x{ext:X} )",
        f"RUDI bit?......... {yes(rudi, ' ( advanced transponder )')}",
        f"User Info?........ {user} {'( RFU )' if user == 0 else ''}".rstrip(),
        f"Replacement No?... {repl} {'( RFU )' if repl == 0 else ''}".rstrip(),
        f"CRC-16............ 0x{crc:04X} ( {ok('ok') if crc_ok else bad('fail')} )",
        f"Raw............... {hl(bytes(frame[:13]).hex())}",
    ]
    temp = ext & 0xFF
    par = (ext >> 8) & 1
    if par == (0 if bin(temp).count("1") & 1 else 1) and not ext & 0xE00:
        f = 74 + temp * 0.2
        out += ["", "Bio-Thermo detected",
                f"  temperature... {hl(f'{f:.1f}')} F / {hl(f'{(f - 32) / 1.8:.1f}')} C"]
    return out


def idteck_line(frame, info, hl=lambda s: s, ok=lambda s: s, bad=lambda s: s):
    """pm3 'IDTECK Tag Found' line. info: _idteck_frame_info() result."""
    cid = info["card_id"]
    st = ok("ok") if info["checksum_valid"] else bad("fail")
    return (f"IDTECK Tag Found: Card ID {hl(cid)} ( 0x{cid:06X} ) "
            f"Raw: {bytes(frame).hex().upper()}  chksum 0x{info['checksum']:02X} ( {st} )")
