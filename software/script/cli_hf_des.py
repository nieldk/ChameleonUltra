"""cli_hf_des — MIFARE DESFire commands (hf des ...).

Live DES/2TDEA/3TDEA/AES auth + APDU helpers, PM3 mfdes-v1 / .dfc credential
load/save, and the `hf des` command classes. Split out of chameleon_cli_unit;
foundation imported explicitly from cli_core."""

import re
import argparse
import time

from cli_core import (
    _decode_14a_frame_col,
    ArgumentParserNoExit,
    BaseCLIUnit,
    C0,
    CC,
    CG,
    CR,
    CY,
    Crypto1,
    DeviceRequiredUnit,
    DfcCredential,
    DfcError,
    ReaderRequiredUnit,
    SlotIndexArgsAndGoUnit,
    Status,
    TagSpecificType,
    UnexpectedResponseError,
    chameleon_pm3,
    hf_des,
)


def _des_raw(
    cmd,
    keep_field=True,
    activate=False,
    wait_resp=True,
    append_crc=False,
    data=b"",
    timeout_ms=200,
):
    """Helper used inside HfDes* commands — wraps cmd.hf14a_raw options."""
    options = {
        "activate_rf_field": 1 if activate else 0,
        "wait_response": 1 if wait_resp else 0,
        "append_crc": 1 if append_crc else 0,
        "auto_select": 0,
        "keep_rf_field": 1 if keep_field else 0,
        "check_response_crc": 0,
    }
    return cmd.hf14a_raw(options=options, resp_timeout_ms=timeout_ms, data=list(data))


def _des_select(cmd):
    """
    Field-on + ISO14443-A select via hf14a_scan.
    Returns (uid_bytes, sak, ats).
    hf14a_scan returns a list of tag dicts (via @expect_response which unwraps .parsed).
    """
    tags = cmd.hf14a_scan()
    if not tags:
        raise RuntimeError("No 14443A tag in field")
    tag = tags[0]
    uid_bytes = tag["uid"]
    sak = tag["sak"][0]  # sak is a 1-byte bytes object
    ats = tag["ats"]
    return uid_bytes, sak, ats


def _des_wrap(cmd_byte: int, data: bytes = b"") -> bytes:
    """
    Wrap a native DESFire command in an ISO 7816-4 envelope:
        CLA=90  INS=cmd  P1=00  P2=00  [Lc data]  Le=00
    This is the 'native ISO' framing DESFire EV1+ accepts over T=CL.
    """
    if data:
        return bytes([0x90, cmd_byte, 0x00, 0x00, len(data)]) + data + bytes([0x00])
    else:
        return bytes([0x90, cmd_byte, 0x00, 0x00, 0x00])


def _des_transceive(cmd, des_cmd: int, data: bytes = b"", timeout_ms=500) -> bytes:
    """
    Send one native DESFire command via ISO-wrapped APDU over T=CL.
    Uses hf14a_4_reader_apdu which handles RATS, CRC32, and PCB framing in firmware.
    Returns payload bytes with the DESFire status byte appended:
        [...payload..., status]
    where status 0x00=OK, 0xAF=more data, other=error.
    Raises RuntimeError on comms failure.
    """
    apdu = _des_wrap(des_cmd, data)
    resp = cmd.hf14a_4_reader_apdu(apdu)
    if resp.status not in (Status.SUCCESS, Status.HF_TAG_OK):
        raise RuntimeError(f"No response to command 0x{des_cmd:02X}")
    rdata = resp.data
    if not rdata or len(rdata) < 2:
        raise RuntimeError(f"Empty response to command 0x{des_cmd:02X}")
    # ISO response: [...payload...] SW1 SW2
    # DESFire status is in SW2 (SW1=0x91 for native wrapped)
    sw1, sw2 = rdata[-2], rdata[-1]
    if sw1 != 0x91:
        raise RuntimeError(f"Unexpected SW1=0x{sw1:02X} SW2=0x{sw2:02X}")
    payload = rdata[:-2]
    # Return payload + DESFire status byte so callers can check for 0xAF (more frames)
    return payload + bytes([sw2])


def _desfire_auth_des(cmd, key: bytes, key_no: int = 0) -> bool:
    """
    DESFire native D40 authentication (DES/2TDEA, command 0x0A).
    Returns True on success, False on wrong key.
    Raises RuntimeError on comms failure.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import os

    if len(key) == 8:
        key2tdea = key + key
    elif len(key) == 16:
        key2tdea = key
    else:
        raise ValueError(f"DES key must be 8 or 16 bytes, got {len(key)}")

    # Step 1: send Authenticate command (0x0A + key_no)
    resp = _des_transceive(cmd, 0x0A, bytes([key_no]))
    status = resp[-1]
    if status != 0xAF:
        return False
    enc_rnd_b = resp[:-1]
    if len(enc_rnd_b) != 8:
        raise RuntimeError(f"Expected 8-byte encRndB, got {len(enc_rnd_b)}")

    # Step 2: decrypt RndB with IV=0
    iv = bytes(8)
    cipher = Cipher(
        algorithms.TripleDES(key2tdea), modes.CBC(iv), backend=default_backend()
    )
    dec = cipher.decryptor()
    rnd_b = dec.update(enc_rnd_b) + dec.finalize()

    # Step 3: rotate RndB left by 1 byte
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]

    # Step 4: generate RndA and encrypt RndA || RndB' in CBC (IV = encRndB)
    rnd_a = os.urandom(8)
    cipher2 = Cipher(
        algorithms.TripleDES(key2tdea), modes.CBC(enc_rnd_b), backend=default_backend()
    )
    enc2 = cipher2.encryptor()
    enc_both = enc2.update(rnd_a + rnd_b_rot) + enc2.finalize()

    # Step 5: send AF + enc(RndA || RndB') as additional frame
    resp2 = _des_transceive(cmd, 0xAF, enc_both)
    status2 = resp2[-1]
    if status2 != 0x00:
        return False

    # Step 6: verify enc(RndA')
    enc_rnd_a_card = resp2[:-1]
    if len(enc_rnd_a_card) != 8:
        raise RuntimeError(f"Expected 8-byte encRndA', got {len(enc_rnd_a_card)}")
    iv3 = enc_both[-8:]
    cipher3 = Cipher(
        algorithms.TripleDES(key2tdea), modes.CBC(iv3), backend=default_backend()
    )
    dec3 = cipher3.decryptor()
    rnd_a_card = dec3.update(enc_rnd_a_card) + dec3.finalize()
    rnd_a_rot = rnd_a[1:] + rnd_a[:1]
    return rnd_a_card == rnd_a_rot


def _desfire_auth_aes(cmd, key: bytes, key_no: int = 0) -> bool:
    """
    DESFire EV1 AES authentication (command 0xAA).
    Returns True on success, False on wrong key.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import os

    if len(key) != 16:
        raise ValueError(f"AES key must be 16 bytes, got {len(key)}")

    # Step 1: send AuthenticateAES (0xAA + key_no)
    resp = _des_transceive(cmd, 0xAA, bytes([key_no]))
    status = resp[-1]
    if status != 0xAF:
        return False
    enc_rnd_b = resp[:-1]
    if len(enc_rnd_b) != 16:
        raise RuntimeError(f"Expected 16-byte encRndB, got {len(enc_rnd_b)}")

    # Step 2: decrypt RndB with IV=0
    iv = bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    rnd_b = dec.update(enc_rnd_b) + dec.finalize()

    # Step 3: rotate RndB left 1
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]

    # Step 4: generate RndA, encrypt RndA || RndB' with IV = encRndB
    rnd_a = os.urandom(16)
    cipher2 = Cipher(
        algorithms.AES(key), modes.CBC(enc_rnd_b), backend=default_backend()
    )
    enc2 = cipher2.encryptor()
    enc_both = enc2.update(rnd_a + rnd_b_rot) + enc2.finalize()

    # Step 5: send AF + enc(RndA || RndB')
    resp2 = _des_transceive(cmd, 0xAF, enc_both)
    status2 = resp2[-1]
    if status2 != 0x00:
        return False

    # Step 6: verify enc(RndA')
    enc_rnd_a_card = resp2[:-1]
    if len(enc_rnd_a_card) != 16:
        raise RuntimeError(f"Expected 16-byte encRndA', got {len(enc_rnd_a_card)}")
    iv3 = enc_both[-16:]
    cipher3 = Cipher(algorithms.AES(key), modes.CBC(iv3), backend=default_backend())
    dec3 = cipher3.decryptor()
    rnd_a_card = dec3.update(enc_rnd_a_card) + dec3.finalize()
    rnd_a_rot = rnd_a[1:] + rnd_a[:1]
    return rnd_a_card == rnd_a_rot


def _desfire_auth_3k3des(cmd, key: bytes, key_no: int = 0) -> bool:
    """
    DESFire EV1 3K3DES (3-key Triple-DES) authentication (command 0x1A).
    Key must be 24 bytes. Returns True on success, False on wrong key.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import os

    if len(key) != 24:
        raise ValueError(f"3K3DES key must be 24 bytes, got {len(key)}")

    # Step 1: send Authenticate3K3DES (0x1A + key_no)
    resp = _des_transceive(cmd, 0x1A, bytes([key_no]))
    status = resp[-1]
    if status != 0xAF:
        return False
    enc_rnd_b = resp[:-1]
    if len(enc_rnd_b) != 8:
        raise RuntimeError(f"Expected 8-byte encRndB, got {len(enc_rnd_b)}")

    # Step 2: decrypt RndB with IV=0 using 3K3DES (EDE3)
    iv = bytes(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    rnd_b = dec.update(enc_rnd_b) + dec.finalize()

    # Step 3: rotate RndB left by 1 byte
    rnd_b_rot = rnd_b[1:] + rnd_b[:1]

    # Step 4: generate RndA, encrypt RndA || RndB' with IV = encRndB
    rnd_a = os.urandom(8)
    cipher2 = Cipher(
        algorithms.TripleDES(key), modes.CBC(enc_rnd_b), backend=default_backend()
    )
    enc2 = cipher2.encryptor()
    enc_both = enc2.update(rnd_a + rnd_b_rot) + enc2.finalize()

    # Step 5: send AF + enc(RndA || RndB')
    resp2 = _des_transceive(cmd, 0xAF, enc_both)
    status2 = resp2[-1]
    if status2 != 0x00:
        return False

    # Step 6: verify enc(RndA')
    enc_rnd_a_card = resp2[:-1]
    if len(enc_rnd_a_card) != 8:
        raise RuntimeError(f"Expected 8-byte encRndA', got {len(enc_rnd_a_card)}")
    iv3 = enc_both[-8:]
    cipher3 = Cipher(
        algorithms.TripleDES(key), modes.CBC(iv3), backend=default_backend()
    )
    dec3 = cipher3.decryptor()
    rnd_a_card = dec3.update(enc_rnd_a_card) + dec3.finalize()
    rnd_a_rot = rnd_a[1:] + rnd_a[:1]
    return rnd_a_card == rnd_a_rot


def _desfire_get_app_ids(cmd) -> list:
    """Send GetApplicationIDs (0x6A) and return list of 3-byte AIDs."""
    resp = _des_transceive(cmd, 0x6A)
    status = resp[-1]
    payload = resp[:-1]
    aids = []
    # Fixed: iterate full payload in 3-byte steps (previous code used len-2, dropping the last AID)
    for i in range(0, len(payload), 3):
        if i + 3 <= len(payload):
            aids.append(payload[i : i + 3])
    while status == 0xAF:
        resp = _des_transceive(cmd, 0xAF)
        status = resp[-1]
        payload = resp[:-1]
        for i in range(0, len(payload), 3):
            if i + 3 <= len(payload):
                aids.append(payload[i : i + 3])
    return aids


def _desfire_select_app(cmd, aid: bytes):
    """Send SelectApplication (0x5A) for a 3-byte AID."""
    resp = _des_transceive(cmd, 0x5A, aid)
    return resp[-1] == 0x00


def _desfire_get_version(cmd) -> dict:
    """Send GetVersion (0x60) and return a dict of card info.

    HW frame: vendor(0) type(1) subtype(2) major(3) minor(4) storage(5) protocol(6)
    SW frame: same layout.
    UID frame: uid(0:7) batch(7:12) prod_week(12) prod_year(13)

    Per-field length guards make the parser robust against short frames.
    If the SW frame returns no payload (some reader/BLE stacks don't relay it)
    sw_major, sw_storage and sw_proto are derived from the HW frame values.
    """
    resp = _des_transceive(cmd, 0x60)
    info: dict = {}
    hw = resp[:-1]
    # HW frame — individual guards so a short frame still populates what it has
    if len(hw) >= 1:
        info["hw_vendor"] = hw[0]
    if len(hw) >= 2:
        info["hw_type"] = hw[1]
    if len(hw) >= 3:
        info["hw_subtype"] = hw[2]
    if len(hw) >= 4:
        info["hw_major"] = hw[3]
    if len(hw) >= 5:
        info["hw_minor"] = hw[4]
    if len(hw) >= 6:
        info["hw_storage"] = hw[5]
    if len(hw) >= 7:
        info["hw_proto"] = hw[6]

    if resp[-1] == 0xAF:
        resp2 = _des_transceive(cmd, 0xAF)
        sw = resp2[:-1]
        # SW frame — same per-field guards
        if len(sw) >= 1:
            info["sw_vendor"] = sw[0]
        if len(sw) >= 2:
            info["sw_type"] = sw[1]
        if len(sw) >= 3:
            info["sw_subtype"] = sw[2]
        if len(sw) >= 4:
            info["sw_major"] = sw[3]
        if len(sw) >= 5:
            info["sw_minor"] = sw[4]
        if len(sw) >= 6:
            info["sw_storage"] = sw[5]
        if len(sw) >= 7:
            info["sw_proto"] = sw[6]

        # Fallback: derive SW fields from HW when SW frame payload is empty
        if "sw_major" not in info and "hw_major" in info:
            info["sw_major"] = _DESFIRE_HW_MAJOR_TO_SW_MAJOR.get(
                info["hw_major"], info["hw_major"]
            )
            info["sw_minor"] = 0
        if "sw_storage" not in info:
            info["sw_storage"] = info.get("hw_storage")
        if "sw_proto" not in info:
            info["sw_proto"] = info.get("hw_proto")

        if resp2[-1] == 0xAF:
            resp3 = _des_transceive(cmd, 0xAF)
            p3 = resp3[:-1]
            if len(p3) >= 7:
                info["uid"] = p3[:7].hex().upper()
            if len(p3) >= 12:
                info["batch"] = p3[7:12].hex().upper()
            if len(p3) >= 13:
                info["prod_week"] = p3[12]
            if len(p3) >= 14:
                info["prod_year"] = p3[13]
    return info


_DESFIRE_HW_TYPE = {0x01: "DESFire", 0x81: "DESFire (SW)"}
# Keyed on hw_major (payload[3]), matching PM3 logic.
# hw_subtype (payload[2]) is always 0x01 for all EV variants and cannot
# distinguish EV1 from EV2/EV3.
_DESFIRE_HW_MAJOR = {
    0x00: "MF3ICD40 (D40)",
    0x01: "EV1",
    0x12: "EV2",
    0x30: "Light",
    0x33: "EV3",
}
_DESFIRE_STORAGE = {0x16: "2 KB", 0x18: "4 KB", 0x1A: "8 KB"}
_DESFIRE_PROTOCOL = {
    0x03: "ISO 14443-3",
    0x04: "ISO 14443-4",
    0x05: "ISO 14443-3, 14443-4",
}
# hw_major -> SW major (EV generation number), used as fallback when the SW
# frame returns no data (some reader/BLE stacks don't relay it).
_DESFIRE_HW_MAJOR_TO_SW_MAJOR = {0x01: 1, 0x12: 2, 0x30: 3, 0x33: 3}


# ---------------------------------------------------------------------------
# hf des auth-trace — full host-side DESFire auth flow with on-wire frame
# capture. Companion to `hf 14a auth-trace` (Crypto1/MFC) — for DESFire the
# crypto is not time-sensitive so we drive the round-trip from the host using
# hf14a_scan_keep + hf14a_raw and record every wire frame as we go.
# ---------------------------------------------------------------------------


def _crc14a(data: bytes) -> bytes:
    """ISO 14443-A CRC-16 (CRC-A): poly 0x1021, reflected, init 0x6363.
    Returns 2 bytes in transmission order (low byte first)."""
    crc = 0x6363
    for b in data:
        b ^= crc & 0xFF
        b = (b ^ (b << 4)) & 0xFF
        crc = ((crc >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4)) & 0xFFFF
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def _synth_14a_anticoll_frames(uid: bytes, atqa: bytes, sak: int, ats: bytes):
    """
    Reconstruct the on-wire anticoll/SELECT/SAK/RATS/ATS frame sequence from a
    populated tag descriptor returned by hf14a_scan / hf14a_scan_keep. Returns
    list of (szBits, data, is_tx, annot) tuples; is_tx=True means card→reader.

    Mirrors firmware-side auth_trace_emit_anticoll() in app_cmd.c so the same
    `_decode_14a_frame_col` decoder renders the prefix identically to the
    firmware-captured MFC auth-trace.
    """
    frames = []
    # REQA: 7-bit, reader→card
    frames.append((7, bytes([0x26]), False, "REQA"))
    # ATQA: 16-bit, card→reader (LSB-first on air — bytes already in air order)
    frames.append((16, bytes(atqa), True, None))

    cascade = 1 if len(uid) == 4 else (2 if len(uid) == 7 else 3)
    cascade_sel = [0x93, 0x95, 0x97]
    uid_pos = 0
    for cl in range(cascade):
        is_last = cl == cascade - 1
        # Anticoll request: SEL 0x20 — 16 bits, reader→card
        frames.append((16, bytes([cascade_sel[cl], 0x20]), False, None))
        # Anticoll response: 4 UID bytes (CT+UID0..2 if cascading) + BCC — 40 bits
        if is_last:
            uid_seg = bytes(uid[uid_pos : uid_pos + 4])
        else:
            uid_seg = bytes([0x88]) + bytes(uid[uid_pos : uid_pos + 3])
            uid_pos += 3
        bcc = uid_seg[0] ^ uid_seg[1] ^ uid_seg[2] ^ uid_seg[3]
        frames.append((40, uid_seg + bytes([bcc]), True, None))
        # SELECT: SEL 0x70 || UID+BCC || CRC — 72 bits, reader→card
        sel = bytes([cascade_sel[cl], 0x70]) + uid_seg + bytes([bcc])
        sel_full = sel + _crc14a(sel)
        frames.append((72, sel_full, False, None))
        # SAK + CRC — 24 bits. Intermediate cascades return 0x04 (cascade bit);
        # the captured `sak` is the final cascade's SAK only.
        sak_byte = sak if is_last else 0x04
        sak_full = bytes([sak_byte]) + _crc14a(bytes([sak_byte]))
        frames.append((24, sak_full, True, None))

    # RATS / ATS if the card answered RATS (ats_len > 0)
    if ats:
        # 0xE0 0x40 = RATS, FSDI=4 (FSD=48 bytes), CID=0
        rats = bytes([0xE0, 0x40])
        rats_full = rats + _crc14a(rats)
        frames.append((32, rats_full, False, "RATS  FSDI=4 CID=0"))
        ats_full = bytes(ats) + _crc14a(bytes(ats))
        frames.append(
            (len(ats_full) * 8, ats_full, True, f"ATS ({len(ats)} bytes payload)")
        )

    return frames


@hf_des.command("auth-trace")
class HfDesAuthTrace(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        parser.description = (
            "Run a full DESFire authentication against a real card and print "
            "every wire frame: REQA → ATQA → anticoll → SELECT → SAK → RATS → "
            "ATS → (optional SELECT AID) → AUTHENTICATE → E(RndB) → "
            "E(RndA||RndB') → E(RndA'), with host-side AES / 3DES / 3K3DES "
            "decryption of the random nonces for verification.\n\n"
            "Supports AuthenticateDES (0x0A, D40), AuthenticateAES (0xAA, "
            "EV1+) and AuthenticateISO 3K3DES (0x1A). Requires the "
            "'cryptography' Python package.\n\n"
            "This is the verbose per-frame tracer. To simply authenticate a "
            "card reliably in one firmware call (no per-frame USB round trips), "
            "use `hf des readerauth`."
        )
        parser.add_argument(
            "--keyno",
            type=int,
            default=0,
            metavar="<n>",
            help="DESFire key number (default 0 = master)",
        )
        parser.add_argument(
            "-k",
            "--key",
            type=str,
            required=True,
            metavar="<hex>",
            help="Auth key in hex. 8 bytes = DES, 16 bytes = "
            "AES or 2TDEA (use --type to disambiguate), "
            "24 bytes = 3K3DES.",
        )
        parser.add_argument(
            "--type",
            choices=["des", "aes", "3k3des"],
            default=None,
            help="Auth type. Auto-detected if omitted: 8=DES, " "16=AES, 24=3K3DES.",
        )
        parser.add_argument(
            "--aid",
            type=str,
            default=None,
            metavar="<hex>",
            help="Optional 3-byte AID to select before auth. "
            "Pass in the same form `hf des info` displays "
            "(e.g. --aid 808020 if info shows 'AID: 808020'). "
            "Default: PICC level (no SelectApplication).",
        )
        parser.add_argument(
            "-t",
            "--timeout",
            type=int,
            default=5000,
            metavar="<ms>",
            help="Tag-presence polling timeout in ms (default 5000). "
            "Reader keeps the field on and polls for a card; "
            "auth aborts if no card appears within this window.",
        )
        parser.epilog = """
examples:
  hf des auth-trace -k 00000000000000000000000000000000
        # AES default key, PICC master
  hf des auth-trace -k 0000000000000000 --type des
        # legacy DES (D40)
  hf des auth-trace --type 3k3des -k 000000000000000000000000000000000000000000000000
        # 3K3DES (24-byte key)
  hf des auth-trace --aid 010203 --keyno 1 -k <16-byte AES key>
        # auth against key 1 of application 010203
  hf des auth-trace -k 00000000000000000000000000000000 -t 15000
        # wait up to 15s for a card to be placed on the antenna
"""
        return parser

    def on_exec(self, args: argparse.Namespace):
        # ---------- arg validation ------------------------------------------
        key_hex = args.key.replace(" ", "")
        if not re.fullmatch(r"[0-9a-fA-F]+", key_hex) or len(key_hex) % 2:
            print(f"{CR}Key must be an even-length hex string{C0}")
            return
        key = bytes.fromhex(key_hex)

        if args.type:
            auth_type = args.type
        elif len(key) == 8:
            auth_type = "des"
        elif len(key) == 16:
            auth_type = "aes"  # default 16-byte interpretation
        elif len(key) == 24:
            auth_type = "3k3des"
        else:
            print(f"{CR}Key length {len(key)} invalid (need 8/16/24 bytes){C0}")
            return

        valid_lens = {"des": (8, 16), "aes": (16,), "3k3des": (24,)}
        if len(key) not in valid_lens[auth_type]:
            print(
                f"{CR}{auth_type.upper()} expects key length {valid_lens[auth_type]} "
                f"bytes, got {len(key)}{C0}"
            )
            return

        aid_bytes = None
        if args.aid:
            aid_hex = args.aid.replace(" ", "")
            if not re.fullmatch(r"[0-9a-fA-F]{6}", aid_hex):
                print(f"{CR}AID must be 6 hex chars (3 bytes){C0}")
                return
            # AID is passed in the same wire-byte form `hf des info` displays
            # — i.e. already in transmission order. No reversal needed.
            aid_bytes = bytes.fromhex(aid_hex)

        # ---------- crypto availability -------------------------------------
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            import os as _os
        except ImportError:
            print(
                f"{CR}This command needs the 'cryptography' Python package.\n"
                f"  pip install cryptography{C0}"
            )
            return

        # Cipher factory for the chosen auth type
        def _cipher(iv: bytes, key_arg: bytes):
            if auth_type == "aes":
                return Cipher(
                    algorithms.AES(key_arg), modes.CBC(iv), backend=default_backend()
                )
            elif auth_type == "des":
                # D40: legacy DES uses 8-byte key, or 2TDEA with 16-byte key.
                # 'cryptography' TripleDES accepts both 16-byte (k1+k2) and
                # 24-byte forms; for 8-byte we triple by replication.
                if len(key_arg) == 8:
                    k = key_arg + key_arg + key_arg
                elif len(key_arg) == 16:
                    k = key_arg + key_arg[:8]
                else:
                    k = key_arg
                return Cipher(
                    algorithms.TripleDES(k), modes.CBC(iv), backend=default_backend()
                )
            elif auth_type == "3k3des":
                return Cipher(
                    algorithms.TripleDES(key_arg),
                    modes.CBC(iv),
                    backend=default_backend(),
                )
            raise RuntimeError(f"Unsupported auth_type {auth_type}")

        block_sz = 16 if auth_type == "aes" else 8
        rnd_len = 16 if auth_type == "aes" else (16 if auth_type == "3k3des" else 8)
        auth_cmd = {"des": 0x0A, "aes": 0xAA, "3k3des": 0x1A}[auth_type]

        # ---------- scan + keep field, poll until present or timeout ---------
        print(
            f" Running DESFire {auth_type.upper()} auth-trace: "
            f"keyno={args.keyno} key={key_hex.upper()}"
            + (f" aid={aid_bytes.hex().upper()}" if aid_bytes else " (PICC)")
        )
        timeout_ms = max(1, min(60000, int(args.timeout)))
        print(
            f" Waiting up to {timeout_ms} ms for a 14443-4 tag... "
            f"({CY}place CU on a card now{C0})"
        )
        print()
        deadline = time.monotonic() + (timeout_ms / 1000.0)
        tags = None
        last_err = None
        while time.monotonic() < deadline:
            try:
                tags = self.cmd.hf14a_scan_keep()
                if tags:
                    break
            except UnexpectedResponseError as e:
                last_err = e  # HF_TAG_NO etc. — keep polling
            except Exception as e:
                # Unexpected error (USB/BLE issue) — abort immediately
                print(f"{CR}Scan aborted: {e}{C0}")
                return
            time.sleep(0.05)
        if not tags:
            msg = f": {last_err}" if last_err else ""
            print(f"{CR}No 14443A tag detected within {timeout_ms} ms{msg}{C0}")
            return
        tag = tags[0]
        uid, atqa, sak, ats = tag["uid"], tag["atqa"], tag["sak"][0], tag["ats"]
        if not ats:
            print(
                f"{CR}Tag did not respond to RATS — not a 14443-4 card (DESFire requires RATS){C0}"
            )
            return

        # ---------- trace accumulator ---------------------------------------
        # Each entry: (szBits, bytes, is_tx (True=card→reader), annot_or_None)
        frames = _synth_14a_anticoll_frames(uid, atqa, sak, ats)
        block_num = 0  # T=CL I-block sequence bit (PCB low bit)

        def _exchange_iblock(
            payload: bytes, annot_tx: str, annot_rx_prefix: str
        ) -> bytes:
            """Send one T=CL I-block, return inner card payload (no PCB, no CRC).
            Records the full wire frames (PCB + payload + CRC) in `frames`."""
            nonlocal block_num
            pcb = 0x02 | block_num
            tx_inner = bytes([pcb]) + payload
            tx_wire = tx_inner + _crc14a(tx_inner)
            options = {
                "activate_rf_field": 0,
                "wait_response": 1,
                "append_crc": 0,  # we already appended
                "auto_select": 0,
                "keep_rf_field": 1,
                "check_response_crc": 0,
            }
            rx_wire = self.cmd.hf14a_raw(
                options=options, resp_timeout_ms=2000, data=list(tx_wire)
            )
            frames.append((len(tx_wire) * 8, tx_wire, False, annot_tx))
            if not rx_wire or len(rx_wire) < 3:
                frames.append((0, b"", True, f"{CR}<no response>{C0}"))
                raise RuntimeError(
                    f"Empty response to I-block PCB=0x{pcb:02X} "
                    f"(got {len(rx_wire) if rx_wire else 0} bytes)"
                )
            rx_wire = bytes(rx_wire)
            frames.append((len(rx_wire) * 8, rx_wire, True, annot_rx_prefix))
            block_num ^= 1
            # Strip PCB byte and 2-byte CRC; caller doesn't see T=CL framing
            if (rx_wire[0] & 0xC0) != 0x00:
                raise RuntimeError(f"Expected I-block, got PCB=0x{rx_wire[0]:02X}")
            return rx_wire[1:-2]

        # ---------- optional SelectApplication (AID) ------------------------
        try:
            if aid_bytes:
                # ISO-wrapped SelectApplication: 90 5A 00 00 03 <aid_le> 00
                sel_apdu = (
                    bytes([0x90, 0x5A, 0x00, 0x00, 0x03]) + aid_bytes + bytes([0x00])
                )
                resp = _exchange_iblock(
                    sel_apdu,
                    annot_tx=f"I-block: SelectApplication AID={aid_bytes.hex().upper()}",
                    annot_rx_prefix=None,
                )
                # ISO response: [...payload...] 91 SW2
                if len(resp) < 2 or resp[-2] != 0x91 or resp[-1] != 0x00:
                    print(
                        f"{CR}SelectApplication failed: response={resp.hex().upper()}{C0}"
                    )
                    self._render_trace(frames, "select-failed", None)
                    return
                # Update last RX annotation
                frames[-1] = (
                    frames[-1][0],
                    frames[-1][1],
                    frames[-1][2],
                    f"I-block resp: 91 00 (SelectApplication OK)",
                )

            # ---------- AUTHENTICATE round 1 --------------------------------
            auth_apdu1 = bytes(
                [0x90, auth_cmd, 0x00, 0x00, 0x01, args.keyno & 0xFF, 0x00]
            )
            cmdname = {
                "des": "AuthenticateDES (0x0A)",
                "aes": "AuthenticateAES (0xAA)",
                "3k3des": "AuthenticateISO 3K3DES (0x1A)",
            }[auth_type]
            resp1 = _exchange_iblock(
                auth_apdu1,
                annot_tx=f"I-block: {cmdname} keyno={args.keyno}",
                annot_rx_prefix=None,
            )
            if len(resp1) < 2 or resp1[-2] != 0x91 or resp1[-1] != 0xAF:
                # 0x91 0xAE = authentication error; 0x91 0xAF = additional frame
                sw = resp1[-2:].hex().upper() if len(resp1) >= 2 else "??"
                print(
                    f"{CR}Auth round 1 failed: SW={sw}, payload={resp1[:-2].hex().upper()}{C0}"
                )
                self._render_trace(frames, "auth-round-1-failed", None)
                return
            enc_rndb = resp1[:-2]
            if len(enc_rndb) != rnd_len:
                print(f"{CR}Expected {rnd_len}-byte E(RndB), got {len(enc_rndb)}{C0}")
                self._render_trace(frames, "bad-rndb-length", None)
                return
            frames[-1] = (
                frames[-1][0],
                frames[-1][1],
                frames[-1][2],
                f"I-block resp: 91 AF + E(RndB) [{rnd_len} bytes]",
            )

            # Decrypt RndB (IV=0)
            iv0 = bytes(block_sz)
            dec = _cipher(iv0, key).decryptor()
            rndb = dec.update(enc_rndb) + dec.finalize()

            # Generate RndA, rotate RndB left by 1 byte, encrypt CBC IV=E(RndB)
            rnda = _os.urandom(rnd_len)
            rndb_rot = rndb[1:] + rndb[:1]
            enc2 = _cipher(enc_rndb, key).encryptor()
            enc_token = enc2.update(rnda + rndb_rot) + enc2.finalize()

            # ---------- AUTHENTICATE round 2 --------------------------------
            auth_apdu2 = (
                bytes([0x90, 0xAF, 0x00, 0x00, len(enc_token)])
                + enc_token
                + bytes([0x00])
            )
            resp2 = _exchange_iblock(
                auth_apdu2,
                annot_tx=f"I-block: 90 AF (continue) + E(RndA||RndB')",
                annot_rx_prefix=None,
            )
            if len(resp2) < 2 or resp2[-2] != 0x91 or resp2[-1] != 0x00:
                sw = resp2[-2:].hex().upper() if len(resp2) >= 2 else "??"
                # Try to render the trace before giving up
                frames[-1] = (
                    frames[-1][0],
                    frames[-1][1],
                    frames[-1][2],
                    f"I-block resp: SW={sw}  (auth rejected)",
                )
                print(f"{CR}Auth round 2 failed: SW={sw} — wrong key or replay{C0}")
                self._render_trace(frames, "auth-rejected", None)
                return
            enc_rnda_card = resp2[:-2]
            if len(enc_rnda_card) != rnd_len:
                print(
                    f"{CR}Expected {rnd_len}-byte E(RndA'), got {len(enc_rnda_card)}{C0}"
                )
                self._render_trace(frames, "bad-rnda-length", None)
                return
            frames[-1] = (
                frames[-1][0],
                frames[-1][1],
                frames[-1][2],
                f"I-block resp: 91 00 + E(RndA') [{rnd_len} bytes]",
            )

            # Decrypt + verify RndA' == rotL1(RndA)
            iv3 = enc_token[-block_sz:]
            dec3 = _cipher(iv3, key).decryptor()
            rnda_card = dec3.update(enc_rnda_card) + dec3.finalize()
            rnda_rot = rnda[1:] + rnda[:1]
            verified = rnda_card == rnda_rot

        except Exception as e:
            print(f"{CR}Auth aborted: {e}{C0}")
            self._render_trace(frames, "error", None)
            return

        # ---------- session key derivation (for the report) -----------------
        # DESFire EV1 session keys: take parts of RndA + RndB depending on
        # auth_type. This is just for the report — we don't use it further.
        if auth_type == "des":
            # D40: K_SES = RndA[0..3] || RndB[0..3] (8 bytes)
            ses_key = rnda[:4] + rndb[:4]
        elif auth_type == "aes":
            # EV1 AES: K_SES = RndA[0..3] || RndB[0..3] || RndA[12..15] || RndB[12..15]
            ses_key = rnda[:4] + rndb[:4] + rnda[12:16] + rndb[12:16]
        elif auth_type == "3k3des":
            # EV1 3K3DES: 24-byte key
            ses_key = (
                rnda[:4]
                + rndb[:4]
                + rnda[6:10]
                + rndb[6:10]
                + rnda[12:16]
                + rndb[12:16]
            )
        else:
            ses_key = b""

        # ---------- render the trace ----------------------------------------
        status_label = (
            f"{CG}auth verified ✓{C0}"
            if verified
            else f"{CR}auth FAILED — RndA' mismatch{C0}"
        )
        self._render_trace(
            frames,
            status_label,
            {
                "auth_type": auth_type,
                "uid": uid,
                "rndb": rndb,
                "enc_rndb": enc_rndb,
                "rnda": rnda,
                "rnda_card": rnda_card,
                "rnda_rot": rnda_rot,
                "enc_token": enc_token,
                "enc_rnda_card": enc_rnda_card,
                "ses_key": ses_key,
                "verified": verified,
            },
        )

    @staticmethod
    def _render_trace(frames, status_label, crypto_info):
        rx_count = sum(1 for _, _, tx, _ in frames if tx)
        tx_count = sum(1 for _, _, tx, _ in frames if not tx)
        print(
            f" Captured : {CG}{len(frames)}{C0} frame(s)  "
            f"({CY}{tx_count}{C0} reader→card  {CG}{rx_count}{C0} card→reader)  "
            f"{status_label}"
        )
        print()
        print(f"  {'#':>3}  {'dir':<3}  {'bits':>4}  {'hex data':<42}  decoded")
        print(f"  {'---':>3}  {'---':<3}  {'----':>4}  {'-' * 42}  {'-' * 35}")

        for n, (szBits, data, is_tx, annot) in enumerate(frames):
            hex_str = " ".join(f"{b:02x}" for b in data)
            if len(hex_str) > 42:
                hex_str = hex_str[:39] + "..."
            if annot is not None:
                decoded, col = annot, CG
            else:
                try:
                    decoded, col, _ = _decode_14a_frame_col(data, szBits, is_tx=is_tx)
                except Exception:
                    decoded, col = "(undecoded)", CC
            dir_str = f"{CG}<<<{C0}" if is_tx else f"{CY}>>>{C0}"
            print(
                f"  {CY}{n + 1:>3}{C0}  {dir_str}  {szBits:>4}  {hex_str:<42}  {col}{decoded}{C0}"
            )

        # Crypto info block
        if crypto_info:
            print()
            print(f" {CC}Crypto analysis ({crypto_info['auth_type'].upper()}):{C0}")
            print(f"   UID            : {crypto_info['uid'].hex().upper()}")
            print(f"   E(RndB) [wire] : {crypto_info['enc_rndb'].hex().upper()}")
            print(f"   RndB (decrypt) : {crypto_info['rndb'].hex().upper()}")
            print(f"   RndA (reader)  : {crypto_info['rnda'].hex().upper()}")
            print(f"   E(RndA||RndB') : {crypto_info['enc_token'].hex().upper()}")
            print(f"   E(RndA') [wire]: {crypto_info['enc_rnda_card'].hex().upper()}")
            print(
                f"   RndA' expected : {crypto_info['rnda_rot'].hex().upper()}  (= rotL1(RndA))"
            )
            mark = "✓ MATCH" if crypto_info["verified"] else "✗ MISMATCH"
            colour = CG if crypto_info["verified"] else CR
            print(
                f"   RndA' from card: {colour}{crypto_info['rnda_card'].hex().upper()}{C0}  {colour}{mark}{C0}"
            )
            if crypto_info["verified"] and crypto_info["ses_key"]:
                print(
                    f"   Session key    : {CG}{crypto_info['ses_key'].hex().upper()}{C0}  "
                    f"({len(crypto_info['ses_key'])} bytes)"
                )


def dfc_read_credential_file(path: str) -> DfcCredential:
    """Read a credential from either encoding.

    A binary credential always opens with octet 0x60, which is what every other
    loader sniffs for, so the file's extension is not consulted.
    """
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw[:1] == b"\x60":
        return DfcCredential.from_wire(raw)
    text = raw.decode("utf-8", errors="replace")
    # Proxmark3 'mfdes v1' dump JSON -> DfcCredential (contents sniffed, not ext)
    stripped = text.lstrip()
    if stripped[:1] == "{" and '"mfdes v1"' in text:
        import json

        return chameleon_pm3.mfdes_json_to_dfc(json.loads(text))
    return DfcCredential.parse_text(text)


@hf_des.command("parse")
class HfDesParse(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Parse a credential file, in either encoding, and show what it contains. "
            "Needs no device, so it is the quickest way to check a file before loading it."
        )
        parser.add_argument(
            "-f",
            "--file",
            required=True,
            help="path to a .dfc, .dfcb, or Proxmark3 mfdes-v1 .json file",
        )
        parser.add_argument(
            "--hexdump",
            action="store_true",
            help="also print the .dfcb octets the device would receive",
        )
        parser.epilog = (
            "examples:\n  hf des parse -f card.dfc\n"
            "  hf des parse -f card.dfcb\n"
            "  hf des parse -f hf-mfdes-<UID>-dump.json\n"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            cred = dfc_read_credential_file(args.file)
        except (OSError, DfcError) as e:
            print(f" {CR}[!] {e}{C0}")
            return
        print(cred.describe())
        try:
            blob = cred.to_wire()
        except DfcError as e:
            print(f" {CR}[!] cannot be encoded for the device: {e}{C0}")
            return
        print(f" Wire blob     : {len(blob)} bytes (.dfcb)")
        if args.hexdump:
            print(blob.hex())


@hf_des.command("eload")
class HfDesELoad(SlotIndexArgsAndGoUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Load a credential, in either encoding, into a DESFire emulation slot."
        )
        self.add_slot_args(parser)
        parser.add_argument(
            "-f",
            "--file",
            required=True,
            help="path to a .dfc, .dfcb, or Proxmark3 mfdes-v1 .json file",
        )
        parser.epilog = (
            "examples:\n  hf des eload -f card.dfc\n"
            "  hf des eload -f hf-mfdes-<UID>-dump.json\n"
            "  hf des eload -f card.dfcb -s 2\n"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            cred = dfc_read_credential_file(args.file)
        except (OSError, DfcError) as e:
            print(f" {CR}[!] {e}{C0}")
            return

        try:
            blob = cred.to_wire()
        except DfcError as e:
            print(f" {CR}[!] cannot be encoded for the device: {e}{C0}")
            return
        # Label the slot by the credential's generation AND storage tier so
        # `hw slot list` matches what einfo/edump report; the engine still drives
        # behaviour from the credential itself.
        _ev = cred.generation == 2  # 2 == EV2
        if cred.storage > 4096:
            dfc_tag_type = (
                TagSpecificType.DESFIRE_EV2_8K
                if _ev
                else TagSpecificType.DESFIRE_EV1_8K
            )
        elif cred.storage > 2048:
            dfc_tag_type = (
                TagSpecificType.DESFIRE_EV2_4K
                if _ev
                else TagSpecificType.DESFIRE_EV1_4K
            )
        else:
            dfc_tag_type = (
                TagSpecificType.DESFIRE_EV2_2K
                if _ev
                else TagSpecificType.DESFIRE_EV1_2K
            )
        self.cmd.set_slot_tag_type(self.slot_num, dfc_tag_type)
        # NB: do NOT seed the slot with default DESFire data here. If the
        # credential load below is refused (e.g. the tag is emulating in an RF
        # field), the default card would remain and be silently emulated in
        # place of the intended credential. desfire_set_credential establishes
        # the slot from the credential itself and now raises on rejection.

        # The slot's anti-collision record is the device's to settle: it is the
        # only party that knows what the engine answers activation with for the
        # fields a credential leaves out. Setting it from here would mean
        # duplicating those defaults, and getting them wrong clears values the
        # card needs.

        def progress(sent, total):
            print(".", end="", flush=True)

        try:
            self.cmd.desfire_set_credential(blob, progress=progress)
        except Exception as e:
            print(f"\n {CR}[!] device rejected the credential: {e}{C0}")
            return
        # Stamp the slot's anti-collision record from the credential so
        # `hw slot list` and a reader's anticollision see the card's real UID,
        # not the default the slot was seeded with. DESFire answers as
        # ISO14443-4: SAK 0x20; ATQA 0x0344 for a 7-byte UID (0x0044 for 4-byte);
        # ATS/SAK/ATQA from the credential when it carries them.
        try:
            uid = cred.uid
            if cred.picc_atqa is not None:
                atqa = bytes(cred.picc_atqa)
            else:
                atqa = bytes([0x03, 0x44]) if len(uid) == 7 else bytes([0x00, 0x44])
            sak = bytes([cred.picc_sak]) if cred.picc_sak is not None else bytes([0x20])
            ats = bytes(cred.picc_ats) if cred.picc_ats else b""
            self.cmd.hf14a_set_anti_coll_data(uid, atqa, sak, ats)
        except Exception as e:
            print(
                f" {CY}[!] loaded, but could not set slot UID ({e}); "
                f"hw slot list may show a default UID{C0}"
            )

        print(f"\n - Loaded {len(blob)} bytes into slot {self.slot_num}")
        print(
            f"   UID {cred.uid.hex().upper()}, "
            f"{len(cred.apps)} application(s), {len(cred.files)} file(s)"
        )
        print(f" {CY}Run 'hw slot store' to keep it across a power cycle.{C0}")

    def after_exec(self, args: argparse.Namespace):
        # Stay on the slot we just loaded — do NOT revert to the previously
        # active slot. A user who loads a card into slot N expects the device
        # to be emulating that card (and edump/readers to see it), not to
        # silently switch back. Persist the active-slot choice.
        self.cmd.set_active_slot(self.slot_num)


@hf_des.command("edump")
class HfDesEDump(SlotIndexArgsAndGoUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Read a DESFire emulation slot's credential back."
        self.add_slot_args(parser)
        parser.add_argument(
            "-f",
            "--file",
            help="write the credential here; .json -> Proxmark3 mfdes-v1 dump, else raw .dfcb",
        )
        parser.epilog = (
            "examples:\n  hf des edump\n  hf des edump -f slot.dfcb\n"
            "  hf des edump -f hf-mfdes-dump.json\n"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            blob = self.cmd.desfire_get_credential()
        except Exception as e:
            print(f" {CR}[!] {e}{C0}")
            return
        try:
            cred = DfcCredential.from_wire(blob)
        except DfcError as e:
            print(f" {CR}[!] device returned an unusable blob: {e}{C0}")
            return
        print(cred.describe())
        if args.file:
            if args.file.lower().endswith(".json"):
                import json

                obj = chameleon_pm3.dfc_to_mfdes_json(cred)
                with open(args.file, "w") as fh:
                    fh.write(json.dumps(obj, indent=4))
                napps = len(obj.get("Applications", {}))
                print(
                    f" - Wrote Proxmark3 'mfdes v1' dump to {args.file} "
                    f"({napps} application record(s) incl. PICC)"
                )
            else:
                with open(args.file, "wb") as fh:
                    fh.write(blob)
                print(f" - Wrote {len(blob)} bytes to {args.file}")


@hf_des.command("einfo")
class HfDesEInfo(SlotIndexArgsAndGoUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Show the DESFire emulation slot summary."
        self.add_slot_args(parser)
        parser.epilog = "examples:\n  hf des einfo\n"
        return parser

    def on_exec(self, args: argparse.Namespace):
        info = self.cmd.desfire_get_info()
        print(f" UID           : {info['uid'].hex().upper()}")
        print(f" Applications  : {info['num_apps']} / {info['max_apps']}")
        print(f" Files         : {info['num_files']} / {info['max_files']}")
        print(f" File data pool: {info['pool_used']} / {info['pool_size']} bytes")
        print(f" Keys per app  : up to {info['max_keys']}")
        print(f" PICC auth     : 0x{info['picc_auth_command']:02X}")
        print(f" Credential    : {info['cred_size']} bytes on device")


@hf_des.command("eblank")
class HfDesEBlank(SlotIndexArgsAndGoUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Reset a DESFire emulation slot to a blank card: one application, "
            "one all-zero DES key, and one writable Standard Data file."
        )
        self.add_slot_args(parser)
        parser.add_argument(
            "-u",
            "--uid",
            type=str,
            help="7-byte UID in hex, must start with 04. Random if omitted.",
        )
        parser.epilog = (
            "examples:\n  hf des eblank\n  hf des eblank -u 04112233445566\n"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        uid = b""
        if args.uid:
            try:
                uid = bytes.fromhex(args.uid.replace(" ", ""))
            except ValueError:
                print(f" {CR}[!] UID is not valid hex{C0}")
                return
            if len(uid) != 7 or uid[0] != 0x04:
                print(f" {CR}[!] UID must be 7 bytes starting with 04{C0}")
                return
        self.cmd.set_slot_tag_type(self.slot_num, TagSpecificType.DESFIRE_EV1_2K)
        self.cmd.set_slot_data_default(self.slot_num, TagSpecificType.DESFIRE_EV1_2K)
        installed = self.cmd.desfire_factory_blank(uid)
        print(
            f" - Blank DESFire card in slot {self.slot_num}, UID {installed.hex().upper()}"
        )


@hf_des.command("estats")
class HfDesEStats(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "DESFire emulation diagnostics. max_handler_us is the worst observed "
            "engine time for one frame; it must stay well under the ~19 ms frame "
            "delay budget. entropy_starvations should stay at 0."
        )
        parser.epilog = "examples:\n  hf des estats\n"
        return parser

    def on_exec(self, args: argparse.Namespace):
        st = self.cmd.desfire_get_stats()
        print(f" Frames received : {st['frames_rx']}")
        print(f" Frames sent     : {st['frames_tx']}")
        print(f" Engine errors   : {st['engine_errors']}")
        print(f" Max handler time: {st['max_handler_us']} us")
        if "activation_requests" in st:
            print(f" Activation reqs : {st['activation_requests']}")
            print(f" ATQA sent       : {st['atqa_tx']}")
            timeouts = st["fdt_timeouts"]
            colour = CR if timeouts else CG
            print(f" FDT timeouts    : {colour}{timeouts}{C0}")
            print(f" Max reset time  : {st['max_reset_us']} us")
        starv = st["entropy_starvations"]
        colour = CR if starv else CG
        print(f" Entropy misses  : {colour}{starv}{C0}")


@hf_des.command("info")
class HfDesInfo(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get MIFARE DESFire card information (version, UID, AIDs)."
        parser.epilog = "examples:\n  hf des info\n"
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            uid_bytes, sak, ats = _des_select(self.cmd)
        except RuntimeError as e:
            print(f" {CR}[!] {e}{C0}")
            return

        print(f" UID           : {uid_bytes.hex().upper()}")
        print(f" SAK           : 0x{sak:02X}")

        try:
            ver = _desfire_get_version(self.cmd)

            def _fmtver(major, minor):
                """Format as PM3-style bare hex digits: 0x33, 0x00 -> '33.0'"""
                return f"{major:x}.{minor:x}" if minor else f"{major:x}.0"

            hw_maj = ver.get("hw_major")
            hw_min = ver.get("hw_minor", 0)
            sw_maj = ver.get("sw_major")
            sw_min = ver.get("sw_minor", 0)

            hw_gen = (
                _DESFIRE_HW_MAJOR.get(hw_maj, f"hw_major 0x{hw_maj:02X}")
                if hw_maj is not None
                else "?"
            )
            hw_stor = _DESFIRE_STORAGE.get(
                ver.get("hw_storage"),
                f"0x{ver['hw_storage']:02X}" if "hw_storage" in ver else "?",
            )
            sw_stor = _DESFIRE_STORAGE.get(
                ver.get("sw_storage"),
                f"0x{ver['sw_storage']:02X}" if "sw_storage" in ver else "?",
            )
            proto = _DESFIRE_PROTOCOL.get(
                ver.get("sw_proto"),
                f"0x{ver['sw_proto']:02X}" if "sw_proto" in ver else "?",
            )

            hw_ver_str = _fmtver(hw_maj, hw_min) if hw_maj is not None else "?"
            sw_ver_str = _fmtver(sw_maj, sw_min) if sw_maj is not None else "?"

            print(f" HW version    : {hw_ver_str}  ({hw_gen})  storage: {hw_stor}")
            print(f" SW version    : {sw_ver_str}  storage: {sw_stor}")
            print(f" Protocol      : {proto}")
            if "uid" in ver:
                print(f" Card UID      : {ver['uid']}")
            if "batch" in ver:
                print(f" Batch no      : {ver['batch']}")
            if "prod_week" in ver:
                print(
                    f" Production    : week {ver['prod_week']:02d} / 20{ver['prod_year']:02d}"
                )
        except Exception as e:
            print(f" {CY}[!] GetVersion failed: {e}{C0}")

        try:
            aids = _desfire_get_app_ids(self.cmd)
            if aids:
                print(f"\n Applications  : {len(aids)} found")
                for aid in aids:
                    print(
                        f"   AID: {aid.hex().upper()}  ({int.from_bytes(aid, 'little'):06X})"
                    )
            else:
                print(f"\n Applications  : none")
        except Exception as e:
            print(f" {CY}[!] GetApplicationIDs failed: {e}{C0}")


# DfcReaderStatus (dfc_reader.h) -- final outcome of the reader-mode exchange.
_DFC_READER_STATUS_NAMES = {
    0: "ok",
    2: "invalid_argument",
    3: "buffer_too_small",
    4: "protocol_error",
    5: "integrity_error",
    6: "card_error",
    7: "unsupported",
}
_DFC_READER_STATUS_CARD_ERROR = 6

# DFC_STATUS_* (dfc_common.h) -- the card's own native DESFire status byte,
# only meaningful when the reader status above is card_error (6).
_DFC_NATIVE_STATUS_NAMES = {
    0x00: "OK",
    0x0B: "PROXIMITY_KEY_DISABLED",
    0x0C: "NO_CHANGES",
    0x0E: "OUT_OF_EEPROM",
    0x1C: "ILLEGAL_COMMAND_CODE",
    0x1E: "INTEGRITY_ERROR",
    0x40: "NO_SUCH_KEY",
    0x7E: "LENGTH_ERROR",
    0x90: "SPECIAL_SUCCESS",
    0x9D: "PERMISSION_DENIED",
    0x9E: "PARAMETER_ERROR",
    0xA0: "APPLICATION_NOT_FOUND",
    0xAE: "AUTHENTICATION_ERROR",
    0xBE: "BOUNDARY_ERROR",
    0xCA: "COMMAND_ABORTED",
    0xCE: "COUNT_ERROR",
    0xDE: "DUPLICATE_ERROR",
    0xF0: "FILE_NOT_FOUND",
}


@hf_des.command("readerauth")
class HfDesReaderAuth(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "ISO 7816 mutual authentication against a physical DESFire card "
            "in a single firmware call (field cycle + select/RATS + optional "
            "AID select + auth), so the card's T=CL session never has to "
            "survive a USB/BLE round trip.\n\n"
            "Use this to authenticate reliably (EV1+; 2TDEA/3TDEA/AES). For a "
            "verbose host-side crypto walkthrough with every wire frame, or for "
            "legacy D40 single-DES cards, use `hf des auth-trace` instead."
        )
        parser.add_argument(
            "--aid",
            type=str,
            default=None,
            metavar="<hex>",
            help="3-byte AID to select first -> application-level "
            "auth. Omit for PICC master-key auth.",
        )
        parser.add_argument(
            "-n",
            "--key-no",
            type=int,
            required=True,
            metavar="<0-31>",
            help="Key number to authenticate with.",
        )
        parser.add_argument(
            "-a",
            "--algo",
            type=str,
            required=True,
            choices=["2tdea", "3tdea", "aes"],
            help="2tdea = 2-key 3DES, EV1+ 16-byte key "
            "(for legacy D40 single-DES use hf des auth-trace); "
            "3tdea = 3-key 3DES (24-byte key); "
            "aes = AES-128 (16-byte key)",
        )
        parser.add_argument(
            "-k",
            "--key",
            type=str,
            required=True,
            metavar="<hex>",
            help="Key bytes in hex; length must match --algo",
        )
        parser.epilog = (
            "examples:\n"
            "  hf des readerauth -n 0 -a aes -k 00000000000000000000000000000000\n"
            "  hf des readerauth --aid 123456 -n 1 -a 3tdea "
            "-k 00112233445566778899AABBCCDDEEFF0102030405060708\n"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            aid = bytes.fromhex(args.aid) if args.aid else None
            if aid is not None and len(aid) != 3:
                print(f" {CR}[!] --aid must be exactly 3 bytes{C0}")
                return
            key = bytes.fromhex(args.key)
        except ValueError as e:
            print(f" {CR}[!] {e}{C0}")
            return

        try:
            resp = self.cmd.desfire_reader_auth_iso7816(
                key_no=args.key_no, algorithm=args.algo, key=key, aid=aid
            )
        except ValueError as e:
            print(f" {CR}[!] {e}{C0}")
            return

        if resp.status == Status.HF_TAG_NO:
            print(f" {CR}[!] No card in the field{C0}")
            return
        if resp.status != Status.HF_TAG_OK:
            print(f" {CR}[!] Device rejected the request: {resp.status}{C0}")
            return

        data = resp.data
        if not data:
            print(f" {CR}[!] Empty response from device{C0}")
            return

        reader_status = data[0]
        if reader_status == 0:
            print(f" {CG}[+] Authenticated{C0}")
            return

        status_name = _DFC_READER_STATUS_NAMES.get(
            reader_status, f"0x{reader_status:02X}"
        )
        if reader_status == _DFC_READER_STATUS_CARD_ERROR and len(data) >= 2:
            native = data[1]
            native_name = _DFC_NATIVE_STATUS_NAMES.get(native, f"0x{native:02X}")
            print(
                f" {CR}[!] Card refused authentication: "
                f"{native_name} (native status 0x{native:02X}){C0}"
            )
        else:
            print(f" {CR}[!] Authentication failed: {status_name}{C0}")


@hf_des.command("chk")
class HfDesChk(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Check DESFire keys against a card (dictionary / pattern / single key). "
            "Tries DES, 2TDEA, and AES for each key. "
            "Iterates all AIDs on card unless --aid is specified."
        )
        parser.add_argument(
            "--aid",
            type=str,
            default=None,
            metavar="<hex>",
            help="Target AID (3 hex bytes, e.g. 123456). Default: PICC master (000000) + all apps.",
        )
        parser.add_argument(
            "-n",
            "--keyno",
            type=int,
            default=0,
            metavar="<0-13>",
            help="Key number to authenticate with (default: 0)",
        )
        parser.add_argument(
            "-k",
            "--key",
            type=str,
            default=None,
            metavar="<hex>",
            help="Single key to try (8, 16 or 24 hex bytes)",
        )
        parser.add_argument(
            "-f",
            "--file",
            type=str,
            default=None,
            metavar="<file>",
            help="Dictionary file (one hex key per line)",
        )
        parser.add_argument(
            "--pattern1b",
            action="store_true",
            help="Try all 1-byte patterns (0000..00, 0101..01, ..., FFFF..FF) for DES and AES",
        )
        parser.add_argument(
            "--pattern2b",
            action="store_true",
            help="Try all 2-byte patterns for AES (0000..00 to FFFF..FF, step 0x0101)",
        )
        parser.add_argument(
            "-t",
            "--timeout",
            type=int,
            default=5000,
            metavar="<ms>",
            help="Card presence timeout ms (default 5000)",
        )
        parser.epilog = (
            "examples:\n"
            "  hf des chk                              -> try built-in defaults on all AIDs\n"
            "  hf des chk --aid 123456 -k 00112233445566778899AABBCCDDEEFF\n"
            "  hf des chk -f mykeys.txt\n"
            "  hf des chk --pattern1b\n"
        )
        return parser

    # ---- built-in default keys (matches PM3 mfdes_default_keys.dic) ----
    # DES / 2TDEA keys (8 bytes each)
    DES_DEFAULTS = [
        bytes(8),  # NXP Default DES
        bytes([0xFF] * 8),
        bytes.fromhex("7544d1652bc9bd43"),
        bytes.fromhex("0011223344556677"),
        bytes.fromhex("1122334455667788"),
        bytes.fromhex("a0a1a2a3a4a5a6a7"),
        bytes.fromhex("d3f7d3f7d3f7d3f7"),
    ]
    # AES-128 keys (16 bytes each)
    AES_DEFAULTS = [
        bytes(16),  # NXP Default AES
        bytes([0x79, 0x70, 0x25, 0x53] * 4),  # TI TRF7970A
        bytes.fromhex("00112233445566778899AABBCCDDEEFF"),  # TI TRF7970A sloa213
        bytes.fromhex("4E617468616E2E4C6920546564647920"),
        bytes.fromhex("43464F494D48504E4C4359454E528841"),  # NHIF
        bytes.fromhex("6AC292FAA1315B4D858AB3A3D7D5933A"),
        bytes.fromhex("404142434445464748494a4b4c4d4e4f"),
        bytes.fromhex("3112B738D8862CCD34302EB299AAB456"),  # Gallagher AES
        bytes.fromhex("47454D5850524553534F53414D504C45"),  # Gemalto
        bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
        bytes.fromhex("fbeed618357133667c85e08f7236a8de"),
        bytes.fromhex("f7ddac306ae266ccf90bc11ee46d513b"),
        bytes.fromhex("54686973206973206D79206B65792020"),
        bytes.fromhex("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7"),
        bytes.fromhex("b0b1b2b3b4b5b6b7b0b1b2b3b4b5b6b7"),
        bytes.fromhex("a0a1a2a3b0b1b2b3c0c1c2c3d0d1d2d3"),
        bytes.fromhex("d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7"),
        bytes.fromhex("C238E449F725B1510EAA699550CABA16"),  # J2A040
        bytes([0x11] * 16),
        bytes([0x22] * 16),
        bytes([0x33] * 16),
        bytes([0x44] * 16),
        bytes([0x55] * 16),
        bytes([0x66] * 16),
        bytes([0x77] * 16),
        bytes([0x88] * 16),
        bytes([0x99] * 16),
        bytes([0xAA] * 16),
        bytes([0xBB] * 16),
        bytes([0xCC] * 16),
        bytes([0xDD] * 16),
        bytes([0xEE] * 16),
        bytes([0xFF] * 16),
        bytes(range(16)),  # 000102...0f
        bytes(range(1, 17)),  # 010203...10
        bytes(
            [
                0x00,
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
                0x11,
                0x12,
                0x13,
                0x14,
                0x15,
            ]
        ),
        bytes(
            [
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
                0x11,
                0x12,
                0x13,
                0x14,
                0x15,
                0x16,
            ]
        ),
        bytes(
            [
                0x16,
                0x15,
                0x14,
                0x13,
                0x12,
                0x11,
                0x10,
                0x09,
                0x08,
                0x07,
                0x06,
                0x05,
                0x04,
                0x03,
                0x02,
                0x01,
            ]
        ),
        bytes(
            [
                0x15,
                0x14,
                0x13,
                0x12,
                0x11,
                0x10,
                0x09,
                0x08,
                0x07,
                0x06,
                0x05,
                0x04,
                0x03,
                0x02,
                0x01,
                0x00,
            ]
        ),
        bytes(
            [
                0x0F,
                0x0E,
                0x0D,
                0x0C,
                0x0B,
                0x0A,
                0x09,
                0x08,
                0x07,
                0x06,
                0x05,
                0x04,
                0x03,
                0x02,
                0x01,
                0x00,
            ]
        ),
        bytes(
            [
                0x10,
                0x0F,
                0x0E,
                0x0D,
                0x0C,
                0x0B,
                0x0A,
                0x09,
                0x08,
                0x07,
                0x06,
                0x05,
                0x04,
                0x03,
                0x02,
                0x01,
            ]
        ),
        bytes(
            [
                0x30,
                0x31,
                0x32,
                0x33,
                0x34,
                0x35,
                0x36,
                0x37,
                0x38,
                0x39,
                0x3A,
                0x3B,
                0x3C,
                0x3D,
                0x3E,
                0x3F,
            ]
        ),
        bytes.fromhex("9CABF398358405AE2F0E2B3D31C99A8A"),
        bytes.fromhex("605F5E5D5C5B5A59605F5E5D5C5B5A59"),  # access control
        bytes.fromhex("22094904FF22677E5D28C6E3ED4F694C"),
        bytes([0x40 + i for i in range(16)]),
    ]
    # 3K3DES keys (24 bytes each)
    TDEA3_DEFAULTS = [
        bytes(24),  # NXP Default 3K3DES
        bytes.fromhex("00112233445566778899AABBCCDDEEFF0102030405060708"),
        bytes([0xFF] * 24),
        bytes.fromhex("d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7"),
    ]

    def _build_key_lists(self, args):
        des_keys = list(self.DES_DEFAULTS)
        aes_keys = list(self.AES_DEFAULTS)
        tdea3_keys = list(self.TDEA3_DEFAULTS)

        if args.key:
            raw = bytes.fromhex(args.key.replace(" ", ""))
            if len(raw) == 8:
                return [raw], [], []
            elif len(raw) == 16:
                return [], [raw], []
            elif len(raw) == 24:
                return [], [], [raw]
            else:
                raise ValueError("Key must be 8, 16 or 24 bytes")

        if args.file:
            des_keys, aes_keys, tdea3_keys = [], [], []
            with open(args.file) as fh:
                for line in fh:
                    # Strip inline comments (text after #) then whitespace
                    line = line.split("#")[0].strip()
                    if not line:
                        continue
                    try:
                        raw = bytes.fromhex(line.split()[0])
                    except ValueError:
                        continue
                    if len(raw) == 8:
                        des_keys.append(raw)
                    elif len(raw) == 16:
                        aes_keys.append(raw)
                    elif len(raw) == 24:
                        tdea3_keys.append(raw)
            return des_keys, aes_keys, tdea3_keys

        if args.pattern1b:
            des_keys = [bytes([i] * 8) for i in range(256)]
            aes_keys = [bytes([i] * 16) for i in range(256)]
            tdea3_keys = [bytes([i] * 24) for i in range(256)]
            return des_keys, aes_keys, tdea3_keys

        if args.pattern2b:
            des_keys, aes_keys, tdea3_keys = [], [], []
            for i in range(0x10000):
                hi, lo = (i >> 8) & 0xFF, i & 0xFF
                des_keys.append(bytes([hi, lo] * 4))
                aes_keys.append(bytes([hi, lo] * 8))
                tdea3_keys.append(bytes([hi, lo] * 12))
            return des_keys, aes_keys, tdea3_keys

        return des_keys, aes_keys, tdea3_keys

    def _try_key(self, aid_label, key_no, key, algo):
        """
        Try one key against a DESFire AID+keyno.

        A failed authentication leaves the DESFire session in an aborted state.
        We must reset it before the next attempt by issuing SelectApplication(000000)
        (which selects the PICC master app and clears any partial auth state).
        If that APDU itself fails (e.g. card went away), fall back to a full
        ISO14443-A re-select so the RF field / T=CL layer is re-established.
        """
        # --- Reset DESFire session state ---
        try:
            _desfire_select_app(self.cmd, bytes([0x00, 0x00, 0x00]))
        except Exception:
            # SelectApp(000000) failed — card may have dropped; do a full re-select
            try:
                _des_select(self.cmd)
            except Exception:
                return False

        # Select the target application (skip for PICC master 000000)
        if aid_label != "000000":
            aid_bytes = bytes.fromhex(aid_label)
            try:
                if not _desfire_select_app(self.cmd, aid_bytes):
                    return False
            except Exception:
                return False

        try:
            if algo == "DES":
                return _desfire_auth_des(self.cmd, key, key_no)
            elif algo == "AES":
                return _desfire_auth_aes(self.cmd, key, key_no)
            else:  # 3K3DES
                return _desfire_auth_3k3des(self.cmd, key, key_no)
        except Exception:
            return False

    def on_exec(self, args: argparse.Namespace):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            print(
                f" {CR}[!] 'cryptography' library required: pip install cryptography{C0}"
            )
            return

        try:
            des_keys, aes_keys, tdea3_keys = self._build_key_lists(args)
        except Exception as e:
            print(f" {CR}[!] {e}{C0}")
            return

        key_no = args.keyno

        # Select card and get AID list
        print(f" Selecting card...")
        try:
            uid_bytes, sak, _ = _des_select(self.cmd)
        except RuntimeError as e:
            print(f" {CR}[!] {e}{C0}")
            return
        print(f" UID: {uid_bytes.hex().upper()}  SAK: 0x{sak:02X}")
        # Determine target AIDs
        if args.aid:
            aid_list = [args.aid.upper().zfill(6)]
        else:
            try:
                raw_aids = _desfire_get_app_ids(self.cmd)
                aid_list = ["000000"] + [a.hex().upper() for a in raw_aids]
            except Exception as e:
                print(f" {CY}[!] Could not enumerate AIDs: {e} — trying PICC only{C0}")
                aid_list = ["000000"]

        total_des = len(des_keys)
        total_aes = len(aes_keys)
        total_tdea3 = len(tdea3_keys)
        total_keys = (total_des + total_aes + total_tdea3) * len(aid_list)
        print(f" AIDs to check  : {len(aid_list)}  ({', '.join(aid_list)})")
        print(f" DES keys       : {total_des}")
        print(f" AES-128 keys   : {total_aes}")
        print(f" 3K3DES keys    : {total_tdea3}")
        print(f" Total attempts : {total_keys}")
        print()

        found = []
        checked = 0
        start = time.time()

        for aid in aid_list:
            print(f" Checking AID {CY}{aid}{C0}  key#{key_no} ...")
            aid_found = False

            for key in des_keys:
                checked += 1
                ok = self._try_key(aid, key_no, key, "DES")
                if ok:
                    msg = f"  {CG}[+] AID {aid}  DES/2TDEA  key#{key_no}  key: {key.hex().upper()}{C0}"
                    print(msg)
                    found.append(("DES", aid, key_no, key.hex().upper()))
                    aid_found = True
                    break
                else:
                    print(f"   {CR}✗{C0} DES    {key.hex().upper()}")

            if not aid_found:
                for key in aes_keys:
                    checked += 1
                    ok = self._try_key(aid, key_no, key, "AES")
                    if ok:
                        msg = f"  {CG}[+] AID {aid}  AES-128    key#{key_no}  key: {key.hex().upper()}{C0}"
                        print(msg)
                        found.append(("AES", aid, key_no, key.hex().upper()))
                        aid_found = True
                        break
                    else:
                        print(f"   {CR}✗{C0} AES    {key.hex().upper()}")

            if not aid_found:
                for key in tdea3_keys:
                    checked += 1
                    ok = self._try_key(aid, key_no, key, "3K3DES")
                    if ok:
                        msg = f"  {CG}[+] AID {aid}  3K3DES     key#{key_no}  key: {key.hex().upper()}{C0}"
                        print(msg)
                        found.append(("3K3DES", aid, key_no, key.hex().upper()))
                        aid_found = True
                        break
                    else:
                        print(f"   {CR}✗{C0} 3K3DES {key.hex().upper()}")

            if not aid_found:
                print(f"  {CY}[-] AID {aid}  no key found{C0}\n")

        elapsed = time.time() - start
        print()
        print(f"Checked {checked} combinations in {elapsed:.1f}s")
        if found:
            print(f"\n {CG}Found {len(found)} key(s):{C0}")
            for algo, aid, kno, key_hex in found:
                print(f"\n   {CG}{algo:8s}  AID {aid}  key#{kno}  {key_hex}{C0}")
        else:
            print(f"\n {CR}No keys found{C0}")


# =============================================================================
# Standalone (host-less) modes subsystem
# =============================================================================


# --- AuthTrace wire format ---------------------------------------------------
# Result buffer is a stream of sessions:
#   For each session:
#     u8  session_num
#     u8  status       (STATUS_HF_* from hf14a_auth_trace_run)
#     u16 trace_len_le
#     u8[trace_len] trace_bytes
#
# Inside trace_bytes, each frame is:
#   u16 hdr_be        (bit 15 = direction: 1=card->reader, 0=reader->card,
#                      bits 14..0 = frame length in BITS)
#   u8[ceil(szBits/8)] frame_bytes
# -----------------------------------------------------------------------------
