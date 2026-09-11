"""
pm3_trace.py — convert ChameleonUltra HF-14A sniff captures into
Proxmark3 ``.trace`` files.

Both the live ``hf 14a sniff`` response and the standalone
``hf14a_tap_sniff`` stored sessions use the same on-wire record stream
produced by ``hf14a_sniff_finalize()`` in the firmware:

    per record:  [hdr_be16][data...]
        hdr  : big-endian u16.  bit15 = direction (0 reader->card,
               1 card->reader),  low 15 bits = frame length in *bits*.
        data : ceil(bits/8) bytes.

Reader-side frames arrive as 9-bits-per-byte (8 data + 1 parity), so the
real parity is recovered.  Card-side frames are byte-granular with no
parity captured, so odd parity is computed (clean in PM3, but a genuine
card-side parity error won't be surfaced — the RC522 path doesn't capture
sub-byte/parity).  Timestamps are stripped by the firmware, so PM3 timing
is synthetic-but-monotonic; frame order and protocol decode are correct.

Proxmark3 record layout (verified against RfidResearchGroup/proxmark3
include/pm3_cmd.h ``tracelog_hdr_t`` and client/src/cmdtrace.c):

    u32  timestamp            (little-endian)
    u16  duration             (little-endian)
    u16  data_len:15 | isResponse<<15   (little-endian)
    u8   data[data_len]
    u8   parity[ceil(data_len/8)]        bit (7-(j&7)) of byte j>>3 = parity of data byte j

A ``.trace`` file is just these records concatenated — no header/magic.
Load in PM3 with:  ``trace load -f FILE`` then ``trace list -t 14a``.
"""

import struct
import sys
import argparse


# --- ISO14443-A odd parity -------------------------------------------------
# Parity bit P is set so the count of 1s in (8 data bits + P) is odd.
# Matches PM3 oddparity8():  e.g. REQA 0x26 (three 1s) -> P = 0.
def odd_parity_byte(b: int) -> int:
    return (bin(b & 0xFF).count("1") & 1) ^ 1


# --- Parse the CU sniff record stream into frames --------------------------
# Mirrors the inline parser in chameleon_cli_unit.py exactly, including the
# 9-bit-per-byte parity extraction and short-frame (REQA/WUPA) handling.
def parse_14a_sniff_buf(buf: bytes):
    """Return a list of (szBits, data, is_tx, parity_bits).

    szBits      : data length in bits after any parity strip (bytes*8, or the
                  raw short-frame bit count e.g. 7 for REQA).
    data        : bytes, parity removed.
    is_tx       : True => card->reader (PM3 isResponse=1).
    parity_bits : list of captured parity bits (len==len(data)) for reader-side
                  9-bit frames, else [] (compute odd parity at emit time).
    """
    frames = []
    i = 0
    n = len(buf)
    while i + 2 <= n:
        hdr = (buf[i] << 8) | buf[i + 1]
        i += 2
        is_tx = bool(hdr & 0x8000)
        szBits = hdr & 0x7FFF
        if szBits == 0:
            break
        szBytes = (szBits + 7) // 8
        if i + szBytes > n:
            break
        raw = buf[i:i + szBytes]
        i += szBytes

        parity_bits = []
        if szBits >= 8 and szBits % 9 == 0:
            # 9 bits per byte: 8 data (LSB first) + 1 parity
            n_bytes = szBits // 9
            all_bits = []
            for byte in raw:
                for b in range(8):
                    all_bits.append((byte >> b) & 1)
            stripped = []
            for nb in range(n_bytes):
                val = 0
                for b in range(8):
                    val |= all_bits[nb * 9 + b] << b
                stripped.append(val)
                parity_bits.append(all_bits[nb * 9 + 8])
            data = bytes(stripped)
            szBits = n_bytes * 8
        else:
            data = raw

        frames.append((szBits, data, is_tx, parity_bits))
    return frames


# --- Frames -> Proxmark3 .trace blob ---------------------------------------
_CYCLES_PER_BIT = 128     # ~13.56 MHz / 106 kbps
_SYNTH_GAP = 256          # synthetic inter-frame spacing (carrier cycles)


def frames_to_pm3_trace(frames) -> bytes:
    """Convert parsed frames to a Proxmark3 ``.trace`` byte blob."""
    out = bytearray()
    ts = 0
    for szBits, data, is_tx, parity_bits in frames:
        data_len = len(data)
        if data_len == 0:
            continue
        duration = min((szBits or data_len * 8) * _CYCLES_PER_BIT, 0xFFFF)

        pbytes = bytearray((data_len + 7) // 8)
        for j in range(data_len):
            if parity_bits and j < len(parity_bits):
                p = parity_bits[j] & 1
            else:
                p = odd_parity_byte(data[j])
            pbytes[j >> 3] |= (p & 1) << (7 - (j & 7))    # MSB-first (cmdtrace.c:669)

        meta = (data_len & 0x7FFF) | ((1 if is_tx else 0) << 15)
        out += struct.pack("<IHH", ts & 0xFFFFFFFF, duration, meta)
        out += data
        out += bytes(pbytes)
        ts += duration + _SYNTH_GAP
    return bytes(out)


def sniff_buf_to_pm3_trace(buf: bytes) -> bytes:
    """One-shot: raw CU sniff record stream -> PM3 .trace blob."""
    return frames_to_pm3_trace(parse_14a_sniff_buf(buf))


# --- Standalone tap-sniff session buffer -----------------------------------
# Drained result buffer is a run of session records:
#   u8 session_num, u8 status, u16 trace_len (LE), u8 trace[trace_len]
def iter_tap_sniff_sessions(result_buf: bytes):
    """Yield (session_num, status, trace_bytes) for each stored session."""
    off = 0
    n = len(result_buf)
    while off + 4 <= n:
        num = result_buf[off]
        status = result_buf[off + 1]
        tlen = result_buf[off + 2] | (result_buf[off + 3] << 8)
        off += 4
        trace = result_buf[off:off + tlen]
        off += tlen
        yield num, status, trace


def export_tap_sniff_sessions_to_pm3(result_buf: bytes, prefix: str = "sniff-session"):
    """Write one ``<prefix>-NN.trace`` per stored standalone session.

    Returns a list of (filename, frame_count, status) for what was written.
    """
    written = []
    for num, status, trace in iter_tap_sniff_sessions(result_buf):
        if not trace:
            continue
        frames = parse_14a_sniff_buf(trace)
        blob = frames_to_pm3_trace(frames)
        fn = f"{prefix}-{num:02d}.trace"
        with open(fn, "wb") as f:
            f.write(blob)
        written.append((fn, len(frames), status))
    return written


# --- CLI: convert a dumped buffer without the full client ------------------
def _main(argv=None):
    ap = argparse.ArgumentParser(
        description="Convert a ChameleonUltra HF-14A sniff dump to Proxmark3 .trace")
    ap.add_argument("infile", help="binary dump: a single sniff record stream, "
                                   "or (with --sessions) a standalone result buffer")
    ap.add_argument("-o", "--out", default=None,
                    help="output .trace file (single-stream mode; default infile+'.trace')")
    ap.add_argument("--sessions", action="store_true",
                    help="treat infile as a standalone tap-sniff result buffer "
                         "and write one .trace per session")
    ap.add_argument("--prefix", default="sniff-session",
                    help="output filename prefix in --sessions mode")
    args = ap.parse_args(argv)

    with open(args.infile, "rb") as f:
        buf = f.read()

    if args.sessions:
        written = export_tap_sniff_sessions_to_pm3(buf, args.prefix)
        if not written:
            print("No sessions found.")
            return 1
        for fn, nframes, status in written:
            print(f"  {fn}  ({nframes} frame(s), status 0x{status:02x})")
        return 0

    out = args.out or (args.infile + ".trace")
    blob = sniff_buf_to_pm3_trace(buf)
    with open(out, "wb") as f:
        f.write(blob)
    nframes = len(parse_14a_sniff_buf(buf))
    print(f"  {out}  ({len(blob)} bytes, {nframes} frame(s))")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
