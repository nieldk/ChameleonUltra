"""Proxmark3 <-> Chameleon interchange (mfdes v1 dump JSON, mfc v2 dump JSON).

Bidirectional, byte-faithful bridge between the Chameleon .dfc credential model
(chameleon_dfc.DfcCredential) and Proxmark3's on-disk formats:

  * DESFire : `mfdes v1` card image, what `hf mfdes dump` writes and
              `hf mfdes view` / `hf mfdes eload` read. Spec: doc/mfdes_dump_format.md.
  * MIFARE  : `mfc v2` block image, what `hf mf dump` writes and
              `hf mf restore` / `hf mf eload` read.

The two rules that keep a DESFire image honest, straight from the spec, and both
already modelled in DfcCredential so nothing is invented:

  * a key with no value is "known by version, not recovered" -- NOT all-zeros.
    DfcKey.value == b"" -> emit `Version` only, never a `Key`.
  * a file that could not be read carries `Read: false` and NO `Data` key -- a
    missing Data is never a run of 00. DfcFile.contents_complete drives `Read`.

Field spellings, token strings and byte orders match doc/mfdes_dump_format.md so
output is interchangeable with Proxmark3's own tools/dfc_converter.py.
"""

from __future__ import annotations

import json

from chameleon_dfc import (
    DfcCredential, DfcApplication, DfcFile, DfcKey,
    KEY_TYPE_MASK, KEY_TYPE_3K3DES, KEY_TYPE_AES,
    FILE_TYPE_STANDARD, FILE_TYPE_BACKUP, FILE_TYPE_VALUE,
    FILE_TYPE_LINEAR, FILE_TYPE_CYCLIC,
    OWNER_PICC, DEFAULT_CARD_STORAGE, GENERATIONS,
    key_length_for_ks2, auth_command_for_ks2, DfcError,
)

# ---------------------------------------------------------------- tokens ------

# TypeRaw byte  <-> spec `Type` token
_FILE_TYPE_TOKEN = {
    FILE_TYPE_STANDARD: "standard",
    FILE_TYPE_BACKUP:   "backup",
    FILE_TYPE_VALUE:    "value",
    FILE_TYPE_LINEAR:   "linear_record",
    FILE_TYPE_CYCLIC:   "cyclic_record",
    0x05:               "transaction_mac",
}
_FILE_TOKEN_TYPE = {v: k for k, v in _FILE_TYPE_TOKEN.items()}

# comm mode: raw 2-bit value <-> spec token
_COMM_TOKEN = {0: "plain", 1: "mac", 2: "plain_rfu", 3: "encrypt"}
_COMM_TOKEN_VAL = {v: k for k, v in _COMM_TOKEN.items()}

# ks2 top two bits -> KeyType token (key length is fixed by type, per spec)
_KEYTYPE_LEN = {"des": 8, "2tdea": 16, "3tdea": 24, "aes": 16}


def _keytype_token(ks2: int, key_len: int) -> str:
    crypto = ks2 & KEY_TYPE_MASK
    if crypto == KEY_TYPE_AES:
        return "aes"
    if crypto == KEY_TYPE_3K3DES:
        return "3tdea"
    # crypto == 0x00 -> DES family; 8-byte key is single-DES (D40), 16 is 2TDEA
    return "des" if key_len == 8 else "2tdea"


def _ks2_from_token(token: str, num_keys: int, has_iso: bool) -> int:
    """Rebuild the raw NumKeysRaw/ks2 byte: keytype<<6 | iso<<5 | count(low5)."""
    top = {"des": 0x00, "2tdea": 0x00, "3tdea": KEY_TYPE_3K3DES,
           "aes": KEY_TYPE_AES}[token]
    return top | (0x20 if has_iso else 0x00) | (num_keys & 0x1F)


def _h(b: bytes) -> str:
    return b.hex().upper()


def _uh(s: str) -> bytes:
    return bytes.fromhex(s)


# ============================================================ DESFire: save ===

def dfc_to_mfdes_json(cred: DfcCredential) -> dict:
    """DfcCredential -> `mfdes v1` dict (json.dump-ready)."""
    card: dict = {"UID": _h(cred.uid)}
    if cred.picc_atqa is not None:
        card["ATQA"] = _h(cred.picc_atqa)          # wire order, as pm3 stores it
    if cred.picc_sak is not None:
        card["SAK"] = f"{cred.picc_sak:02X}"
    if cred.picc_ats:
        card["ATS"] = _h(cred.picc_ats)
    if cred.hardware_version:
        card["VersionHW"] = _h(cred.hardware_version)
    if cred.software_version:
        card["VersionSW"] = _h(cred.software_version)
    if getattr(cred, "production_version", b""):
        card["VersionProd"] = _h(cred.production_version)
    if getattr(cred, "signature", b""):
        card["Signature"] = _h(cred.signature)
    # FreeMem: absent unless known (never zero-filled)

    apps: dict = {}

    # PICC master level is application 000000, per spec: every key says its AID.
    picc_len = cred.picc_key_len
    picc_token = _keytype_token(cred.picc_key_settings_2, picc_len)
    apps["000000"] = {
        "KeySettings": f"{cred.picc_key_settings_1:02X}",
        "NumKeysRaw":  f"{cred.picc_key_settings_2 & 0xFF:02X}",
        "NumKeys":     len(cred.picc_keys) or 1,
        "KeyType":     picc_token,
        "Authenticated": True,
        "Keys":        _keys_to_json(cred.picc_keys),
    }

    for idx, app in enumerate(cred.apps):
        token = _keytype_token(app.key_settings_2, app.key_len)
        entry: dict = {
            "KeySettings": f"{app.key_settings_1:02X}",
            "NumKeysRaw":  f"{app.key_settings_2 & 0xFF:02X}",
            "NumKeys":     len(app.keys),
            "KeyType":     token,
            "Authenticated": True,
            "Keys":        _keys_to_json(app.keys),
            "Files":       _files_to_json(cred, idx),
        }
        if app.has_iso_file_id:
            entry["ISOFileID"] = f"{app.iso_file_id:04X}"
        if app.iso_aid:
            entry["DFName"] = _h(app.iso_aid)
        # object keyed by 3-byte AID as 6 upper hex
        apps[_h(app.aid)] = entry

    return {
        "Created": "proxmark3",
        "FileType": "mfdes v1",
        "Version": 1,
        "Card": card,
        "Applications": apps,
    }


def _keys_to_json(keys: list[DfcKey]) -> dict:
    out: dict = {}
    for n, k in enumerate(keys):
        rec = {"Version": f"{k.version:02X}"}
        if k.value:                       # value present ONLY when actually known
            rec["Key"] = _h(k.value)
        out[str(n)] = rec
    return out


def _files_to_json(cred: DfcCredential, app_index: int) -> dict:
    out: dict = {}
    for f in cred.files:
        if f.app_index != app_index:
            continue
        rec: dict = {
            "Type":    _FILE_TYPE_TOKEN.get(f.type, "standard"),
            "TypeRaw": f"{f.type:02X}",
            "CommMode": _COMM_TOKEN.get(f.comm_settings & 0x03, "plain"),
            "AccessRights": f"{f.access_rights:04X}",   # big-endian, as printed
        }
        if f.has_iso_file_id:
            rec["ISOFileID"] = f"{f.iso_file_id:04X}"

        if f.type in (FILE_TYPE_STANDARD, FILE_TYPE_BACKUP, 0x05):
            rec["FileSize"] = f.declared_size
            rec["Read"] = bool(f.contents_complete)
            if f.contents_complete and f.data:
                rec["Data"] = _h(f.data)
        elif f.type == FILE_TYPE_VALUE:
            rec["LowerLimit"] = f.value_lower_limit
            rec["UpperLimit"] = f.value_upper_limit
            rec["LimitedCredit"] = f"{f.limited_credit:02X}"
            rec["Read"] = bool(f.contents_complete)
            if f.contents_complete:
                rec["Value"] = f.value
        elif f.type in (FILE_TYPE_LINEAR, FILE_TYPE_CYCLIC):
            rec["RecordSize"] = f.record_size
            rec["MaxRecords"] = f.max_records
            rec["CurRecords"] = f.record_count
            rec["Read"] = bool(f.contents_complete)
            if f.contents_complete and f.records:
                rec["Records"] = {str(i): _h(r) for i, r in enumerate(f.records)}

        out[f"{f.number:02X}"] = rec
    return out


# ============================================================ DESFire: load ===

def mfdes_json_to_dfc(obj: dict) -> DfcCredential:
    """`mfdes v1` dict -> DfcCredential (ready for to_wire / desfire_set_credential)."""
    ft = obj.get("FileType")
    if ft != "mfdes v1":
        raise DfcError(f"not a DESFire dump (FileType: {ft!r}), expected 'mfdes v1'")

    card = obj.get("Card", {})
    cred = DfcCredential()
    cred.uid = _uh(card["UID"]) if card.get("UID") else b""
    if card.get("ATQA"):
        cred.picc_atqa = _uh(card["ATQA"])
    if card.get("SAK"):
        cred.picc_sak = int(card["SAK"], 16)
    if card.get("ATS"):
        cred.picc_ats = _uh(card["ATS"])
    if card.get("VersionHW"):
        cred.hardware_version = _uh(card["VersionHW"])
    if card.get("VersionSW"):
        cred.software_version = _uh(card["VersionSW"])
    if card.get("VersionProd"):
        cred.production_version = _uh(card["VersionProd"])
    if card.get("Signature"):
        cred.signature = _uh(card["Signature"])

    # generation from VersionHW major/minor (bytes 3,4): EV1 01, EV2 12/42/22
    if cred.hardware_version and len(cred.hardware_version) >= 5:
        major = cred.hardware_version[3]
        cred.generation = {0x01: 1, 0x12: 2, 0x42: 2, 0x22: 2, 0x33: 3}.get(major, 1)

    applications = obj.get("Applications", {})

    # PICC level, application 000000
    picc = applications.get("000000")
    if picc:
        cred.picc_key_settings_1 = int(picc.get("KeySettings", "0F"), 16)
        cred.picc_key_settings_2 = int(picc.get("NumKeysRaw", "01"), 16)
        cred.picc_auth_command = auth_command_for_ks2(cred.picc_key_settings_2)
        cred.picc_keys = _keys_from_json(
            picc.get("Keys", {}), key_length_for_ks2(cred.picc_key_settings_2))

    for aid_hex, app in applications.items():
        if aid_hex == "000000":
            continue
        token = app.get("KeyType", "2tdea")
        num = int(app.get("NumKeys", len(app.get("Keys", {}))))
        has_iso = "ISOFileID" in app
        # prefer the raw byte if present, else rebuild it from the tokens
        if app.get("NumKeysRaw"):
            ks2 = int(app["NumKeysRaw"], 16)
        else:
            ks2 = _ks2_from_token(token, num, has_iso)
        dapp = DfcApplication(
            aid=_uh(aid_hex),
            key_settings_1=int(app.get("KeySettings", "0F"), 16),
            key_settings_2=ks2,
            auth_command=auth_command_for_ks2(ks2),
            key_len=_KEYTYPE_LEN.get(token, 16),
        )
        if app.get("ISOFileID"):
            dapp.has_iso_file_id = True
            dapp.iso_file_id = int(app["ISOFileID"], 16)
        if app.get("DFName"):
            dapp.iso_aid = _uh(app["DFName"])
        dapp.keys = _keys_from_json(app.get("Keys", {}), dapp.key_len)
        idx = len(cred.apps)
        cred.apps.append(dapp)

        for fno_hex, f in app.get("Files", {}).items():
            cred.files.append(_file_from_json(fno_hex, f, idx))

    return cred


def _keys_from_json(keys: dict, key_len: int) -> list[DfcKey]:
    # keys keyed by decimal string; must be dense 0..n-1 in card order
    out: list[DfcKey] = []
    for n in range(len(keys)):
        rec = keys.get(str(n))
        if rec is None:
            out.append(DfcKey(value=b"", version=0))   # absent -> unknown, no value
            continue
        ver = int(rec.get("Version", "00"), 16) if rec.get("Version") else 0
        val = _uh(rec["Key"]) if rec.get("Key") else b""   # missing Key != zeros
        out.append(DfcKey(value=val, version=ver))
    return out


def _file_from_json(fno_hex: str, f: dict, app_index: int) -> DfcFile:
    traw = int(f["TypeRaw"], 16) if f.get("TypeRaw") \
        else _FILE_TOKEN_TYPE.get(f.get("Type", "standard"), FILE_TYPE_STANDARD)
    df = DfcFile(app_index=app_index, number=int(fno_hex, 16), type=traw)
    df.comm_settings = _COMM_TOKEN_VAL.get(f.get("CommMode", "plain"), 0)
    df.access_rights = int(f.get("AccessRights", "0000"), 16)
    if f.get("ISOFileID"):
        df.has_iso_file_id = True
        df.iso_file_id = int(f["ISOFileID"], 16)

    read = bool(f.get("Read", False))
    if traw in (FILE_TYPE_STANDARD, FILE_TYPE_BACKUP, 0x05):
        df.declared_size = int(f.get("FileSize", 0))
        if read and f.get("Data"):
            df.data = _uh(f["Data"])
            df.contents_complete = True
    elif traw == FILE_TYPE_VALUE:
        df.value_lower_limit = int(f.get("LowerLimit", 0))
        df.value_upper_limit = int(f.get("UpperLimit", 0))
        df.limited_credit = int(f.get("LimitedCredit", "00"), 16)
        if read and "Value" in f:
            df.value = int(f["Value"])
            df.contents_complete = True
    elif traw in (FILE_TYPE_LINEAR, FILE_TYPE_CYCLIC):
        df.record_size = int(f.get("RecordSize", 0))
        df.max_records = int(f.get("MaxRecords", 0))
        df.record_count = int(f.get("CurRecords", 0))
        recs = f.get("Records")
        if read and recs:
            df.records = [_uh(recs[str(i)]) for i in range(len(recs))]
            df.contents_complete = True
    return df


# =============================================================== MIFARE mfc ===

def mfc_blocks_to_json(uid: bytes, atqa: bytes, sak: int,
                       blocks: dict[int, bytes]) -> dict:
    """Raw MIFARE Classic blocks -> `mfc v2` dict.

    blocks: {block_number: 16 bytes}. Trailers must already carry keys/access.
    """
    return {
        "Created": "proxmark3",
        "FileType": "mfc v2",
        "Card": {
            "UID": _h(uid),
            "ATQA": _h(atqa),          # wire order
            "SAK": f"{sak:02X}",
        },
        "blocks": {str(n): _h(blocks[n]) for n in sorted(blocks)},
    }


def mfc_json_to_blocks(obj: dict) -> tuple[dict, dict[int, bytes]]:
    """`mfc v2` dict -> (Card dict, {block_number: bytes})."""
    ft = obj.get("FileType", "")
    if not ft.startswith("mfc"):
        raise DfcError(f"not a MIFARE Classic dump (FileType: {ft!r})")
    blocks = {int(k): _uh(v) for k, v in obj.get("blocks", {}).items()}
    return obj.get("Card", {}), blocks


# ================================================================= helpers ====

def dumps(obj: dict) -> str:
    """Serialize with the 4-space, key-ordered style pm3 files use."""
    return json.dumps(obj, indent=4)
