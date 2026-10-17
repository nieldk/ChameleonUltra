#!/usr/bin/env python3
"""
u2f_cu_reader_test.py — test the U2F standalone mode with a SECOND ChameleonUltra
as the NFC reader (no PC/SC reader or phone needed).

  CU #1: arm the u2f mode    ->  standalone set-mode u2f   (then both-long to arm)
  CU #2: run this script, antennas held together.

This drives CU #2's reader as an ISO14443-4 T=CL initiator: anticollision +
SELECT + RATS, then U2F APDUs in I-blocks, following S(WTX) and ISO7816 61xx
chaining. It verifies the AUTHENTICATE signature against the REGISTER public key,
so a green run proves key-wrap + ECDSA + chaining end to end over real RF.

    pip install cryptography        # optional, only for the signature check
    python3 u2f_cu_reader_test.py [--port COM4] [--ble]
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chameleon_com
import chameleon_cmd

AID = bytes.fromhex("A0000006472F0001")

# hf14a_raw option sets
OPT_SELECT = {'activate_rf_field': 1, 'wait_response': 1, 'append_crc': 1,
              'auto_select': 1, 'keep_rf_field': 1, 'check_response_crc': 0}
OPT_IBLOCK = {'activate_rf_field': 0, 'wait_response': 1, 'append_crc': 1,
              'auto_select': 0, 'keep_rf_field': 1, 'check_response_crc': 1}


class Tcl:
    """Minimal ISO14443-4 initiator over a ChameleonUltra reader."""

    def __init__(self, cmd, dbg=False):
        self.cmd = cmd
        self.blk = 0
        self.dbg = dbg

    def open(self):
        # auto_select does anticollision+SELECT (SAK), then E080 is the RATS.
        # raw_cmd's autoSelect is SELECT-only, so this is the single RATS.
        ats = self.cmd.hf14a_raw(OPT_SELECT, 300, bytes.fromhex("E080"))
        if not ats:
            raise RuntimeError("no ATS — card not selected (is u2f armed, antennas aligned?)")
        return bytes(ats)

    # A CU reader has a 64-byte RC522 FIFO, so one on-air block is PCB + frag +
    # 2 CRC <= 64 -> at most 61 APDU bytes; 55 keeps margin. Larger APDUs
    # (REGISTER, AUTHENTICATE) are split across chained I-blocks.
    FRAG = 55

    def _xcv(self, frame: bytes) -> bytes:
        """Transmit one on-air block (PCB+payload); return the response block,
        transparently granting S(WTX) requests while the token computes."""
        if self.dbg:
            print(f"      -> {frame.hex()}")
        resp = bytes(self.cmd.hf14a_raw(OPT_IBLOCK, 3000, frame))
        if self.dbg:
            print(f"      <- {resp.hex()}")
        guard = 0
        while resp and (resp[0] & 0xC0) == 0xC0 and (resp[0] & 0x30) == 0x30:
            guard += 1
            if guard > 60:
                raise RuntimeError("stuck in WTX")
            resp = bytes(self.cmd.hf14a_raw(OPT_IBLOCK, 3000, resp))
            if self.dbg:
                print(f"      <- {resp.hex()}")
        if not resp:
            raise RuntimeError("no response to I-block")
        return resp

    def _send_iblock(self, apdu: bytes) -> bytes:
        """Send one APDU, chaining it across I-blocks when it exceeds the
        reader's single-frame limit. Returns the response APDU (PCB stripped)."""
        off = 0
        while len(apdu) - off > self.FRAG:
            pcb = 0x02 | 0x10 | (self.blk & 1)          # I-block + chaining bit
            resp = self._xcv(bytes([pcb]) + apdu[off:off + self.FRAG])
            if (resp[0] & 0xE6) != 0xA2:                # expect R(ACK)
                raise RuntimeError(f"expected R(ACK) mid-chain, got {resp.hex()}")
            self.blk ^= 1
            off += self.FRAG
        pcb = 0x02 | (self.blk & 1)                     # final (or only) block
        resp = self._xcv(bytes([pcb]) + apdu[off:])
        self.blk ^= 1
        return resp[1:]            # strip I-block PCB (no CID/NAD — we send none)

    def apdu(self, body: bytes):
        """Send one APDU; follow 61xx GET RESPONSE chaining. Returns (data, sw)."""
        out = self._send_iblock(body)
        data, sw = out[:-2], (out[-2] << 8) | out[-1]
        while (sw >> 8) == 0x61:
            out = self._send_iblock(bytes([0x00, 0xC0, 0x00, 0x00, sw & 0xFF]))
            data += out[:-2]
            sw = (out[-2] << 8) | out[-1]
        return data, sw


def ext_apdu(cla, ins, p1, p2, body=b"") -> bytes:
    if not body:
        return bytes([cla, ins, p1, p2])
    return bytes([cla, ins, p1, p2, 0x00]) + struct.pack(">H", len(body)) + body + b"\x00\x00"


def need(cond, msg):
    print(("  OK  " if cond else " FAIL ") + msg)
    if not cond:
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="Test U2F mode via a second ChameleonUltra reader.")
    ap.add_argument("--port", "-p", help="serial port of the READER CU (auto if omitted)")
    ap.add_argument("--ble", action="store_true", help="connect the reader CU over BLE")
    ap.add_argument("--debug", action="store_true", help="dump raw TX/RX frames")
    args = ap.parse_args()

    dev = chameleon_com.ChameleonCom()
    if args.ble:
        dev.open("ble")
    else:
        import serial.tools.list_ports
        port = args.port or next((p.device for p in serial.tools.list_ports.comports()
                                  if p.vid == 0x6868), None)
        if not port:
            sys.exit("No ChameleonUltra serial port found; pass --port")
        dev.open(port)
    cmd = chameleon_cmd.ChameleonCMD(dev)
    cmd.set_device_reader_mode(True)
    print("Reader ready. Hold the two CU antennas together (u2f armed on the other).")

    t = Tcl(cmd, dbg=args.debug)
    ats = t.open()
    print(f"  ATS: {ats.hex().upper()}")

    data, sw = t.apdu(bytes([0x00, 0xA4, 0x04, 0x00, len(AID)]) + AID + b"\x00")
    need(sw == 0x9000 and data == b"U2F_V2", f"SELECT -> {data!r} sw={sw:04X}")

    # VERSION is optional (browsers don't use it); send with an Le, don't fail on it.
    data, sw = t.apdu(bytes([0x00, 0x03, 0x00, 0x00, 0x00]))
    ok = (sw == 0x9000 and data == b"U2F_V2")
    print(("  OK  " if ok else "  ..  ") + f"VERSION -> {data!r} sw={sw:04X}"
          + ("" if ok else "  (non-fatal)"))

    challenge, app = os.urandom(32), os.urandom(32)
    data, sw = t.apdu(ext_apdu(0x00, 0x01, 0x00, 0x00, challenge + app))
    need(sw == 0x9000 and len(data) > 67 and data[0] == 0x05, f"REGISTER sw={sw:04X} len={len(data)}")
    pub = data[1:66]
    khlen = data[66]
    kh = data[67:67 + khlen]
    print(f"      pubkey={pub[:8].hex()}…  keyHandle({khlen})={kh[:8].hex()}…")

    body = challenge + app + bytes([khlen]) + kh
    _, sw = t.apdu(ext_apdu(0x00, 0x02, 0x07, 0x00, body))
    need(sw == 0x6985, f"AUTH check-only -> sw={sw:04X} (expect 6985)")

    data, sw = t.apdu(ext_apdu(0x00, 0x02, 0x03, 0x00, body))
    need(sw == 0x9000 and len(data) >= 7, f"AUTH sign sw={sw:04X} len={len(data)}")
    up = data[0]
    counter = struct.unpack(">I", data[1:5])[0]
    sig_der = data[5:]
    print(f"      userPresence={up} counter={counter}")

    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)
        msg = app + bytes([up]) + struct.pack(">I", counter) + challenge
        pk.verify(sig_der, msg, ec.ECDSA(hashes.SHA256()))
        need(True, "signature verifies against the REGISTER public key")
    except ImportError:
        print("  ..  signature check skipped (pip install cryptography)")

    print("\n[OK] U2F register + authenticate round-trip verified over RF.")
    dev.close()


if __name__ == "__main__":
    main()
