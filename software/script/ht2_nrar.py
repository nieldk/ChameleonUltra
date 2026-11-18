#!/usr/bin/env python3
"""Compute a valid {nR}{aR} for a CU Hitag2 crypto-mode emulator (bench use).

The CU emulator reads the 4 Nr bytes as the plaintext cipher IV, so a valid
bench pair is 00000000 || Ar, where Ar is 0xFFFFFFFF encrypted under the
emulator's key+UID. Ported from firmware hitag2_crypto.c; Nr fixed to 0.

Usage: ht2_nrar.py <key-12-hex> <uid-8-hex>
  key/uid byte order matches `lf hitag2 econfig` / cread -k.
Against a REAL tag use a sniffed pair instead: real Nr is encrypted.
"""
import sys

_F4A = 0x2C79
_F4B = 0x6671
_F5C = 0x7907287B


def _rev8(b):
    return int(f"{b:08b}"[::-1], 2)


def _i4(x, a, b, c, d):
    return ((x >> a) & 1) + (((x >> b) & 1) << 1) + (((x >> c) & 1) << 2) + (((x >> d) & 1) << 3)


def _f20(x):
    i5 = ((_F4A >> _i4(x, 1, 2, 4, 5)) & 1) \
        | (((_F4B >> _i4(x, 7, 11, 13, 14)) & 1) << 1) \
        | (((_F4B >> _i4(x, 16, 20, 22, 25)) & 1) << 2) \
        | (((_F4B >> _i4(x, 27, 28, 30, 32)) & 1) << 3) \
        | (((_F4A >> _i4(x, 33, 42, 43, 45)) & 1) << 4)
    return (_F5C >> i5) & 1


def _rev32(x):
    return _rev8(x & 0xFF) | (_rev8((x >> 8) & 0xFF) << 8) \
        | (_rev8((x >> 16) & 0xFF) << 16) | (_rev8((x >> 24) & 0xFF) << 24)


def _rev64(x):
    r = 0
    for i in range(8):
        r |= _rev8((x >> (8 * i)) & 0xFF) << (8 * i)
    return r


def _init(key, uid, iv):
    x = ((key & 0xFFFF) << 32) + uid
    for i in range(32):
        x >>= 1
        x += (_f20(x) ^ (((iv >> i) ^ (key >> (i + 16))) & 1)) << 47
    return x & 0xFFFFFFFFFFFF


def _bit(state):
    x = state[0]
    fb = (x ^ (x >> 2) ^ (x >> 3) ^ (x >> 6) ^ (x >> 7) ^ (x >> 8)
          ^ (x >> 16) ^ (x >> 22) ^ (x >> 23) ^ (x >> 26) ^ (x >> 30)
          ^ (x >> 41) ^ (x >> 42) ^ (x >> 43) ^ (x >> 46) ^ (x >> 47)) & 1
    x = (x >> 1) | (fb << 47)
    state[0] = x
    return _f20(x)


def _byte(state):
    c = 0
    for i in range(7, -1, -1):
        c |= _bit(state) << i
    return c


def nrar(key_bytes, uid_bytes):
    key_raw = int.from_bytes(key_bytes, "little")
    cs = [_init(_rev64(key_raw), _rev32(int.from_bytes(uid_bytes, "little")), 0)]
    ar = bytes((~_byte(cs)) & 0xFF for _ in range(4))
    return "00000000" + ar.hex().upper()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    k = bytes.fromhex(sys.argv[1])
    u = bytes.fromhex(sys.argv[2])
    if len(k) != 6 or len(u) != 4:
        print("key must be 6 bytes (12 hex), uid 4 bytes (8 hex)")
        sys.exit(1)
    print(nrar(k, u))
