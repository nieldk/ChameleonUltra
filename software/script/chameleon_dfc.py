"""DESFire credential handling: `.dfc` text parsing and the `.dfcb` wire format.

Device-independent on purpose, so it can be unit tested and used offline via
`hf des parse`.

Two encodings are involved. `.dfc` is line-oriented `Key: Value` text, the form
a human edits. `.dfcb` is the binary form the device consumes: a restricted DER
profile with implicit context tags, one canonical encoding per credential. The
device carries no text parser, so this module compiles text to octets before a
transfer.

Properties of the text grammar that matter and are easy to get wrong:

* Version 4 is the only version. Every container is spelled with an index
  (`Application 00 Key 00`) and a file's declared `Size` is stated separately
  from its known `Data`. Anything declaring another version is refused rather
  than read, because earlier versions carried no card record, no PICC keys past
  the master and no declared size, so reading one means inventing all three.
* Key length is never stored. It is derived from the Key Settings 2 crypto-type
  bits, and a key whose hex length disagrees is an error rather than something
  to pad or truncate.
* A repeated key is an error, not a first-occurrence-wins scan. Line order is
  otherwise irrelevant among recognised keys.

Properties of the binary encoding that matter:

* Lengths are definite and minimal, integers are minimal two's complement, and
  booleans are `00` or `FF`. Two conforming writers given the same model emit
  identical octets, which is what makes a cross-implementation comparison
  meaningful.
* `PICC Random ID` and `PICC Format Disabled` default to false, and DER omits a
  component equal to its default, so a false one is absent rather than `00`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

# Version 4 is the only format, and it declares exactly one Filetype.
DFC_FILETYPE = "DFC Credential"
DFC_VERSION = 4

# Largest encoded credential. Bounds every length to two octets.
DER_MAX_SIZE = 65535

KEY_TYPE_MASK = 0xC0
KEY_TYPE_3K3DES = 0x40
KEY_TYPE_AES = 0x80
NUM_KEYS_MASK = 0x0F

UID_LEN = 7
UID_LENGTHS = (4, 7)
UID_FIRST_BYTE = 0x04
MAX_KEY_LEN = 24
MAX_KEYS = 14
U24_MAX = 16777215
U32_MAX = 4294967295
# The reference parser caps a single file payload at this size.
MAX_FILE_DATA_PER_ENTRY = 512
# User memory a credential advertises when the text does not say.
DEFAULT_CARD_STORAGE = 2048

# Owner of a file that lives at PICC level rather than inside an application.
OWNER_PICC = -1

FILE_TYPE_STANDARD = 0x00
FILE_TYPE_BACKUP = 0x01
FILE_TYPE_VALUE = 0x02
FILE_TYPE_LINEAR = 0x03
FILE_TYPE_CYCLIC = 0x04
FILE_TYPE_TMAC = 0x05

FILE_TYPES = {
    "Standard Data": FILE_TYPE_STANDARD,
    "Backup Data": FILE_TYPE_BACKUP,
    "Value": FILE_TYPE_VALUE,
    "Linear Record": FILE_TYPE_LINEAR,
    "Cyclic Record": FILE_TYPE_CYCLIC,
    "Transaction MAC": FILE_TYPE_TMAC,
}

GENERATIONS = {"EV1": 1, "EV2": 2, "EV3": 3}

# Generations the firmware emulator actually implements. The firmware's
# DFC_BUILD_PROFILE now defaults to FULL_EV3 (dfc-core provides the EV2/EV3
# auth, secure-messaging, SDM, transaction-MAC, key-set, proximity,
# virtual-card, and DAM-key paths), so all three are emulated.
EMULATED_GENERATIONS = {GENERATIONS["EV1"], GENERATIONS["EV2"], GENERATIONS["EV3"]}
PROVENANCES = {"Real": 0, "Random": 1, "Unknown": 2}

# Key-set type tokens. Oddly, the reference text grammar reuses the native
# authentication-mode names ("D40"/"ISO"/"AES") as the three key-set type
# tokens, even though they mean 2K3DES/3K3DES/AES here, not an auth mode.
KEY_SET_TYPE_NAMES = ("D40", "ISO", "AES")
KEY_SET_TYPE_2K3DES = 0
KEY_SET_TYPE_3K3DES = 1
KEY_SET_TYPE_AES = 2
KEY_SET_MINIMUM_COUNT = 2
KEY_SET_MAX_SETS = 16

# Fixed octet lengths from dfc_common.h.
AES_KEY_LEN = 16
WIRE_MAC_LEN = 8
TRANSACTION_READER_ID_LEN = 16
VIRTUAL_CARD_CAPABILITY_LEN = 2
VIRTUAL_CARD_MAX_INSTALL_ID_LEN = 16
STATIC_SIGNATURE_LEN = 56
EV2_CAPABILITY_LEN = 6
APPLICATION_CAPABILITY_DATA_LEN = 10

# ISO file IDs that name the master file or are otherwise reserved, so they
# cannot identify an application or a file.
RESERVED_ISO_FILE_IDS = (0x0000, 0x3F00, 0x3FFF, 0xFFFF)

# Exactly the names the engine accepts, including its aliases. These are the
# values that appear in real .dfc files -- do not substitute the cipher names,
# which is a different vocabulary.
AUTH_MODES = {
    "D40": 0x0A,
    "Legacy": 0x0A,
    "NativeD40": 0x0A,
    "Native-D40": 0x0A,
    "2TDEA": 0x0A,
    "ISO": 0x1A,
    "AES": 0xAA,
}
# Authentication mode as the binary encoding numbers it.
AUTH_MODE_CODES = {0x0A: 0, 0x1A: 1, 0xAA: 2}

# --- v6 authentication-command masks (credential format v6) -------------------
# In v6 the PICC 0x82 / application 0x85 INTEGER is a six-bit command mask, not
# the v4/v5 scalar enum. Bits: D40 0x01, ISO(native 0x1A) 0x02, AES 0x04,
# EV2First 0x08, EV2NonFirst 0x10, ISO7816 0x20.
DFC_VERSION_V6 = 6
AUTH_CMD_BITS = {
    "D40": 0x01,
    "ISO": 0x02,
    "AES": 0x04,
    "EV2First": 0x08,
    "EV2NonFirst": 0x10,
    "ISO7816": 0x20,
}
AUTH_CMD_ORDER = ["D40", "ISO", "AES", "EV2First", "EV2NonFirst", "ISO7816"]
# native command byte <-> canonical v6 name (for the preferred command tag)
AUTH_CMD_TO_NATIVE = {"D40": 0x0A, "ISO": 0x1A, "AES": 0xAA}
NATIVE_TO_AUTH_CMD = {0x0A: "D40", 0x1A: "ISO", 0xAA: "AES"}


def auth_mask_to_names(mask: int) -> list:
    return [n for n in AUTH_CMD_ORDER if mask & AUTH_CMD_BITS[n]]


def auth_names_to_mask(names) -> int:
    m = 0
    for n in names:
        if n not in AUTH_CMD_BITS:
            raise DfcError(f"unknown authentication command {n!r}")
        m |= AUTH_CMD_BITS[n]
    return m


def native_cmd_to_mask(native_cmd: int) -> int:
    """Infer a v6 supported-command mask from a v4/v5 scalar native command,
    per the format doc's upgrade rule (supported set inferred from key type)."""
    name = NATIVE_TO_AUTH_CMD.get(native_cmd)
    if name is None:
        return AUTH_CMD_BITS["AES"]
    if name == "AES":
        # AES key type: AES native + EV2 secure messaging + ISO7816
        return (
            AUTH_CMD_BITS["AES"]
            | AUTH_CMD_BITS["EV2First"]
            | AUTH_CMD_BITS["EV2NonFirst"]
            | AUTH_CMD_BITS["ISO7816"]
        )
    if name == "ISO":
        return AUTH_CMD_BITS["ISO"] | AUTH_CMD_BITS["ISO7816"]
    return AUTH_CMD_BITS["D40"]


AUTH_COMMANDS_BY_CODE = {0: 0x0A, 1: 0x1A, 2: 0xAA}


class DfcErrorClass(str, Enum):
    """Stable failure classes defined by DFC format version 4."""

    MALFORMED = "malformed"
    UNSUPPORTED = "unsupported"
    CAPACITY = "capacity"


class DfcError(Exception):
    """A `.dfc` file or `.dfcb` blob that cannot be used as-is."""

    def __init__(
        self,
        message: str,
        error_class: DfcErrorClass = DfcErrorClass.MALFORMED,
    ) -> None:
        super().__init__(message)
        self.error_class = error_class


def key_length_for_ks2(ks2: int) -> int:
    """Mirror of the engine's key-length derivation."""
    crypto = ks2 & KEY_TYPE_MASK
    if crypto == KEY_TYPE_3K3DES:
        return 24
    return 16


def auth_command_for_ks2(ks2: int) -> int:
    crypto = ks2 & KEY_TYPE_MASK
    if crypto == KEY_TYPE_AES:
        return 0xAA
    if crypto == KEY_TYPE_3K3DES:
        return 0x1A
    return 0x0A


@dataclass
class DfcKey:
    value: bytes = b""
    version: int = 0


@dataclass
class DfcKeySet:
    version: int = 0
    type: int = KEY_SET_TYPE_AES
    initialized: bool = False
    keys: list[DfcKey] = field(default_factory=list)


@dataclass
class DfcApplication:
    aid: bytes = b"\x00\x00\x00"
    iso_aid: bytes = b""
    has_iso_file_id: bool = False
    iso_file_id: int = 0
    key_settings_1: int = 0x0F
    key_settings_2: int = 0x01
    auth_command: int = 0x0A
    auth_mask: int = 0  # v6: supported-command mask (0 = derive from native)
    preferred_cmd: str = ""  # v6: preferred command name
    sm_disable: int = -1  # v6: app SM-disable octet, -1 = absent
    key_len: int = 16
    keys: list[DfcKey] = field(default_factory=list)
    # Key sets are an alternative to `keys`: present (>= 2 sets) means the
    # application stores APP_KEY_SETS on the wire instead of plain APP_KEYS.
    key_set_key_count: int = 0
    key_set_max_size: int = 16
    key_set_settings: int = 0
    key_sets: list[DfcKeySet] = field(default_factory=list)
    has_capability_data: bool = False
    capability_data: bytes = b""
    delegated: bool = False
    delegated_slot_number: int = 0
    delegated_slot_version: int = 0
    delegated_quota_limit: int = 0
    delegated_free_blocks: int = 0


@dataclass
class DfcFile:
    app_index: int = 0
    number: int = 0
    type: int = FILE_TYPE_STANDARD
    comm_settings: int = 0x00
    access_rights: int = 0x0000
    has_iso_file_id: bool = False
    iso_file_id: int = 0
    # Declared allocation, which is what a read returns. `data` is the contents
    # actually known and may be shorter.
    declared_size: int = 0
    data: bytes = b""
    contents_complete: bool = False
    value_lower_limit: int = 0
    value_upper_limit: int = 0
    value: int = 0
    limited_credit: int = 0
    record_size: int = 0
    max_records: int = 0
    record_count: int = 0
    # Leading known records, in card order. Fewer than record_count is legal.
    records: list[bytes] = field(default_factory=list)
    # Transaction MAC file contents (type == FILE_TYPE_TMAC only).
    transaction_counter: int = 0
    transaction_mac: bytes = b""
    transaction_mac_key_type: int = 0
    transaction_mac_key_version: int = 0
    transaction_mac_key: bytes = b""
    previous_reader_id: bytes = b""
    # Secure dynamic messaging, standard-data files only.
    sdm_enabled: bool = False
    sdm_options: int = 0
    sdm_access_rights: int = 0
    sdm_has_uid_offset: bool = False
    sdm_uid_offset: int = 0
    sdm_has_counter_offset: bool = False
    sdm_counter_offset: int = 0
    sdm_has_picc_data_offset: bool = False
    sdm_picc_data_offset: int = 0
    sdm_has_mac_input_offset: bool = False
    sdm_mac_input_offset: int = 0
    sdm_has_mac_offset: bool = False
    sdm_mac_offset: int = 0
    sdm_has_encrypted_file_offset: bool = False
    sdm_encrypted_file_offset: int = 0
    sdm_encrypted_file_length: int = 0
    sdm_has_counter_limit: bool = False
    sdm_counter_limit: int = 0
    sdm_read_counter: int = 0


@dataclass
class DfcCredential:
    uid: bytes = b""
    generation: int = 1
    storage: int = DEFAULT_CARD_STORAGE
    hardware_version: bytes = b""  # v5: 7-byte GetVersion HW frame override
    software_version: bytes = b""  # v5: 7-byte GetVersion SW frame override
    uid_provenance: int = 2
    picc_key_settings_1: int = 0x0F
    picc_key_settings_2: int = 0x01
    picc_auth_command: int = 0x0A
    picc_auth_mask: int = 0  # v6: supported-command mask (0 = derive from native)
    picc_preferred_cmd: str = ""  # v6: preferred command name, "" = none
    cred_version: int = 4  # decoded/target wire version (4/5/6)
    picc_keys: list[DfcKey] = field(default_factory=list)
    picc_random_id: bool = False
    picc_format_disabled: bool = False
    picc_ats: bytes = b""
    picc_sak: int | None = None
    picc_atqa: bytes | None = None
    picc_sm_disable: int | None = None
    apps: list[DfcApplication] = field(default_factory=list)
    files: list[DfcFile] = field(default_factory=list)
    picc_has_static_signature: bool = False
    picc_static_signature: bytes = b""
    picc_has_ev2_capabilities: bool = False
    picc_ev2_capabilities: bytes = b""
    picc_has_proximity_key: bool = False
    picc_proximity_key: bytes = b""
    picc_proximity_option: int = 0
    picc_proximity_published_response_time: int = 0
    picc_has_proximity_bitrate: bool = False
    picc_proximity_bitrate: int = 0
    virtual_card_configured: bool = False
    virtual_card_installation_id: bytes = b""
    virtual_card_information: int = 0
    virtual_card_capabilities: bytes = b""
    virtual_card_uid: bytes = b""
    virtual_card_select_mac_key: bytes = b""
    virtual_card_select_encryption_key: bytes = b""
    virtual_card_authentication_mandatory: bool = False
    virtual_card_proximity_mandatory: bool = False
    picc_has_dam_keys: bool = False
    picc_dam_auth_key: bytes = b""
    picc_dam_mac_key: bytes = b""
    picc_dam_encryption_key: bytes = b""

    @property
    def picc_key_len(self) -> int:
        return key_length_for_ks2(self.picc_key_settings_2)

    # ---------------------------------------------------------------- text --

    @classmethod
    def parse_text(cls, text: str) -> "DfcCredential":
        fields = _scan_fields(text)

        filetype = fields.get("Filetype")
        if filetype != DFC_FILETYPE:
            raise DfcError(f"not a DESFire credential file (Filetype: {filetype!r})")
        version = _parse_int(fields.get("Version", "0"))
        if version not in (DFC_VERSION, 5, DFC_VERSION_V6):
            # Earlier versions carried no card record, no PICC keys beyond the
            # master, and no declared file size. Reading one means inventing
            # those, and inventing them is what this format exists to stop.
            raise DfcError(
                f"unsupported .dfc version {version}, expected 4, 5, or 6",
                DfcErrorClass.UNSUPPORTED,
            )
        _validate_text_keys(fields)
        return _parse_v4(cls, fields)

    # ---------------------------------------------------------------- wire --

    def to_wire(self) -> bytes:
        """Encode as `.dfcb` octets, the form the device accepts."""
        return der_encode(self)

    @classmethod
    def from_wire(cls, blob: bytes) -> "DfcCredential":
        """Decode `.dfcb` octets, as the device returns them."""
        return der_decode(blob, cls)

    # --------------------------------------------------------------- report --

    def describe(self) -> str:
        generation = _name_of(GENERATIONS, self.generation, f"gen {self.generation}")
        provenance = _name_of(PROVENANCES, self.uid_provenance, "?")
        lines = [
            f"UID: {self.uid.hex().upper()} ({provenance})",
            f"Card: {generation}, {self.storage} bytes of user memory",
        ]
        picc = (
            f"PICC: key settings {self.picc_key_settings_1:02X}/"
            f"{self.picc_key_settings_2:02X}, auth 0x{self.picc_auth_command:02X}, "
            f"{len(self.picc_keys)} key(s) of {self.picc_key_len} bytes"
        )
        extras = []
        if self.picc_random_id:
            extras.append("random ID")
        if self.picc_format_disabled:
            extras.append("format disabled")
        if self.picc_ats:
            extras.append(f"ATS {self.picc_ats.hex().upper()}")
        if self.picc_sak is not None:
            extras.append(f"SAK {self.picc_sak:02X}")
        if self.picc_atqa is not None:
            extras.append(f"ATQA {self.picc_atqa.hex().upper()}")
        if self.picc_sm_disable is not None:
            extras.append(f"SM disable {self.picc_sm_disable:02X}")
        if self.picc_has_static_signature:
            extras.append("static signature")
        if self.picc_has_ev2_capabilities:
            extras.append(f"EV2 caps {self.picc_ev2_capabilities.hex().upper()}")
        if self.picc_has_proximity_key:
            extras.append("proximity check")
        if self.virtual_card_configured:
            extras.append("virtual card")
        if self.picc_has_dam_keys:
            extras.append("DAM keys")
        if extras:
            picc += " [" + ", ".join(extras) + "]"
        lines.append(picc)

        lines.append(f"Applications: {len(self.apps)}")
        for i, app in enumerate(self.apps):
            if len(app.key_sets) >= KEY_SET_MINIMUM_COUNT:
                key_desc = (
                    f"{len(app.key_sets)} key set(s) of "
                    f"{app.key_set_key_count}x{app.key_set_max_size}B"
                )
            else:
                key_desc = f"keys {len(app.keys)}x{app.key_len}B"
            desc = f"  [{i}] AID {app.aid.hex().upper()} {key_desc} auth 0x{app.auth_command:02X}"
            if app.has_iso_file_id:
                desc += f" ISO FID {app.iso_file_id:04X}"
            if app.iso_aid:
                desc += f" DF name {app.iso_aid.hex().upper()}"
            if app.has_capability_data:
                desc += " [capability data]"
            if app.delegated:
                desc += f" [delegated slot {app.delegated_slot_number}]"
            lines.append(desc)

        lines.append(f"Files: {len(self.files)}")
        type_names = {v: k for k, v in FILE_TYPES.items()}
        for f in self.files:
            owner = "PICC" if f.app_index == OWNER_PICC else f"app {f.app_index}"
            desc = (
                f"  {owner} file {f.number:02X} "
                f"{type_names.get(f.type, f'type {f.type}')} "
                f"comm {f.comm_settings:02X} access {f.access_rights:04X}"
            )
            if f.type == FILE_TYPE_VALUE:
                desc += (
                    f" value {f.value} [{f.value_lower_limit}..{f.value_upper_limit}]"
                )
            elif f.type in (FILE_TYPE_LINEAR, FILE_TYPE_CYCLIC):
                desc += (
                    f" records {f.record_count}/{f.max_records} of {f.record_size}B"
                    f", {len(f.records)} known"
                )
            elif f.type == FILE_TYPE_TMAC:
                desc += f" counter {f.transaction_counter}"
            else:
                desc += f" size {f.declared_size}B, {len(f.data)}B known"
                if f.contents_complete:
                    desc += " (complete)"
                if f.sdm_enabled:
                    desc += " [SDM]"
            lines.append(desc)
        return "\n".join(lines)


# ------------------------------------------------------------- DER writer --


def _der_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    if n < 256:
        return bytes([0x81, n])
    if n <= 0xFFFF:
        return bytes([0x82, n >> 8, n & 0xFF])
    raise DfcError(f"value of {n} bytes exceeds the encoding's two-octet length")


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _int_body(v: int) -> bytes:
    """Minimal two's-complement contents octets."""
    n = max(1, (v.bit_length() + 8) // 8)
    while True:
        try:
            b = v.to_bytes(n, "big", signed=True)
            break
        except OverflowError:
            n += 1
    while len(b) > 1 and (
        (b[0] == 0x00 and not b[1] & 0x80) or (b[0] == 0xFF and b[1] & 0x80)
    ):
        b = b[1:]
    return b


def _int(tag: int, v: int) -> bytes:
    return _tlv(tag, _int_body(v))


def _bool(tag: int, v: bool) -> bytes:
    return _tlv(tag, b"\xff" if v else b"\x00")


def _u16(v: int) -> bytes:
    return bytes([(v >> 8) & 0xFF, v & 0xFF])


def _encode_key(slot: int, key: DfcKey, key_len: int) -> bytes:
    value = key.value.ljust(key_len, b"\x00")[:key_len]
    body = _int(0x80, slot) + _tlv(0x81, value) + _tlv(0x82, bytes([key.version]))
    return _tlv(0x30, body)


def _encode_keys(tag: int, keys: list[DfcKey], key_len: int) -> bytes:
    body = b"".join(_encode_key(i, k, key_len) for i, k in enumerate(keys))
    return _tlv(tag, body)


def _encode_key_set(index: int, ks: "DfcKeySet", key_len: int) -> bytes:
    body = (
        _int(0x80, index)
        + _tlv(0x81, bytes([ks.version]))
        + _int(0x82, ks.type)
        + _bool(0x83, ks.initialized)
        + _tlv(0xA4, b"".join(_encode_key(i, k, key_len) for i, k in enumerate(ks.keys)))
    )
    return _tlv(0x30, body)


def _encode_key_sets(app: DfcApplication) -> bytes:
    sets = b"".join(
        _encode_key_set(i, ks, app.key_set_max_size) for i, ks in enumerate(app.key_sets)
    )
    body = (
        _int(0x80, app.key_set_key_count)
        + _int(0x81, app.key_set_max_size)
        + _tlv(0x82, bytes([app.key_set_settings]))
        + _tlv(0xA3, sets)
    )
    return _tlv(0xA8, body)


def _encode_sdm(f: DfcFile) -> bytes:
    body = _tlv(0x80, bytes([f.sdm_options])) + _tlv(0x81, _u16(f.sdm_access_rights))
    if f.sdm_has_uid_offset:
        body += _int(0x82, f.sdm_uid_offset)
    if f.sdm_has_counter_offset:
        body += _int(0x83, f.sdm_counter_offset)
    if f.sdm_has_picc_data_offset:
        body += _int(0x84, f.sdm_picc_data_offset)
    if f.sdm_has_mac_input_offset:
        body += _int(0x85, f.sdm_mac_input_offset)
    if f.sdm_has_mac_offset:
        body += _int(0x86, f.sdm_mac_offset)
    if f.sdm_has_encrypted_file_offset:
        body += _int(0x87, f.sdm_encrypted_file_offset) + _int(
            0x88, f.sdm_encrypted_file_length
        )
    if f.sdm_has_counter_limit:
        body += _int(0x89, f.sdm_counter_limit)
    body += _int(0x8A, f.sdm_read_counter)
    return _tlv(0xA9, body)


def _encode_file(f: DfcFile) -> bytes:
    body = (
        _int(0x80, f.number)
        + _int(0x81, f.type)
        + _tlv(0x82, bytes([f.comm_settings]))
        + _tlv(0x83, _u16(f.access_rights))
    )
    if f.has_iso_file_id:
        body += _tlv(0x84, _u16(f.iso_file_id))

    if f.type in (FILE_TYPE_STANDARD, FILE_TYPE_BACKUP):
        contents = _int(0x80, f.declared_size)
        if f.data:
            contents += _tlv(0x81, f.data)
        contents += _bool(0x82, f.contents_complete)
        body += _tlv(0xA5, contents)
    elif f.type == FILE_TYPE_VALUE:
        contents = (
            _int(0x80, f.value_lower_limit)
            + _int(0x81, f.value_upper_limit)
            + _int(0x82, f.value)
            + _tlv(0x83, bytes([f.limited_credit]))
        )
        body += _tlv(0xA6, contents)
    elif f.type == FILE_TYPE_TMAC:
        contents = (
            _int(0x80, f.transaction_counter)
            + _tlv(0x81, f.transaction_mac)
            + _tlv(0x82, bytes([f.transaction_mac_key_type]))
            + _tlv(0x83, bytes([f.transaction_mac_key_version]))
            + _tlv(0x84, f.transaction_mac_key)
            + _tlv(0x85, f.previous_reader_id)
        )
        body += _tlv(0xA8, contents)
    else:
        records = b"".join(_tlv(0x04, r) for r in f.records)
        contents = (
            _int(0x80, f.record_size)
            + _int(0x81, f.max_records)
            + _int(0x82, f.record_count)
            + _bool(0x83, f.contents_complete)
            + _tlv(0xA4, records)
        )
        body += _tlv(0xA7, contents)

    # FILE_SDM follows whichever contents alternative was written above, only
    # on a standard data file (section 2.2.4 rule 5).
    if f.sdm_enabled:
        body += _encode_sdm(f)
    return _tlv(0x30, body)


def _encode_files(tag: int, cred: DfcCredential, owner: int) -> bytes:
    body = b"".join(_encode_file(f) for f in cred.files if f.app_index == owner)
    return _tlv(tag, body)


def _encode_app(cred: DfcCredential, index: int, app: DfcApplication) -> bytes:
    body = _tlv(0x80, app.aid)
    if app.has_iso_file_id:
        body += _tlv(0x81, _u16(app.iso_file_id))
    if app.iso_aid:
        body += _tlv(0x82, app.iso_aid)
    body += _tlv(0x83, bytes([app.key_settings_1])) + _tlv(
        0x84, bytes([app.key_settings_2])
    ) + _int(
        0x85,
        (
            (app.auth_mask or native_cmd_to_mask(app.auth_command))
            if _target_v6(cred)
            else AUTH_MODE_CODES.get(app.auth_command, 0)
        ),
    )
    # Key storage is an exclusive alternative: fewer than 2 sets means plain
    # APP_KEYS declared here, before files; 2 or more means APP_KEY_SETS
    # instead, declared after files (APP_KEYS, APP_FILES, APP_KEY_SETS).
    use_key_sets = len(app.key_sets) >= KEY_SET_MINIMUM_COUNT
    if not use_key_sets:
        body += _encode_keys(0xA6, app.keys, app.key_len)
    body += _encode_files(0xA7, cred, index)
    if use_key_sets:
        body += _encode_key_sets(app)
    if app.has_capability_data:
        body += _tlv(0x89, app.capability_data)
    if app.delegated:
        delegated = (
            _int(0x80, app.delegated_slot_number)
            + _tlv(0x81, bytes([app.delegated_slot_version]))
            + _int(0x82, app.delegated_quota_limit)
            + _int(0x83, app.delegated_free_blocks)
        )
        body += _tlv(0xAA, delegated)
    # v6 APP_SM_DISABLE=P(11)=0x8B, APP_PREFERRED_AUTH=P(12)=0x8C, both
    # declared AFTER keys(6)/files(7)/key_sets(8)/capability(9)/delegated(10).
    if _target_v6(cred) and app.sm_disable >= 0:
        body += _tlv(0x8B, bytes([app.sm_disable]))
    if _target_v6(cred) and app.preferred_cmd:
        body += _int(0x8C, AUTH_CMD_BITS[app.preferred_cmd])
    return _tlv(0x30, body)


def _target_v6(cred) -> bool:
    return (
        cred.cred_version == 6
        or cred.picc_auth_mask
        or cred.picc_preferred_cmd
        or any(a.auth_mask or a.preferred_cmd or a.sm_disable >= 0 for a in cred.apps)
    )


def der_encode(cred: DfcCredential) -> bytes:
    """Encode `cred` as `.dfcb` octets. Raises DfcError on an invalid model."""
    _validate(cred)

    card = (
        _int(0x80, cred.generation)
        + _int(0x81, cred.storage)
        + _tlv(0x82, cred.uid)
        + _int(0x83, cred.uid_provenance)
    )
    if cred.picc_has_static_signature:
        card += _tlv(0x84, cred.picc_static_signature)
    if cred.hardware_version:
        card += _tlv(0x85, cred.hardware_version)
    if cred.software_version:
        card += _tlv(0x86, cred.software_version)
    picc = (
        _tlv(0x80, bytes([cred.picc_key_settings_1]))
        + _tlv(0x81, bytes([cred.picc_key_settings_2]))
        + _int(
            0x82,
            (
                (cred.picc_auth_mask or native_cmd_to_mask(cred.picc_auth_command))
                if _target_v6(cred)
                else AUTH_MODE_CODES.get(cred.picc_auth_command, 0)
            ),
        )
    )
    # DEFAULT FALSE: omit rather than emit an explicit false.
    if cred.picc_random_id:
        picc += _bool(0x83, True)
    if cred.picc_format_disabled:
        picc += _bool(0x84, True)
    if cred.picc_ats:
        picc += _tlv(0x85, cred.picc_ats)
    if cred.picc_sak is not None:
        picc += _tlv(0x86, bytes([cred.picc_sak]))
    if cred.picc_atqa is not None:
        picc += _tlv(0x87, cred.picc_atqa)
    if cred.picc_sm_disable is not None:
        picc += _tlv(0x88, bytes([cred.picc_sm_disable]))
    # Declared order from here on (not numeric by tag): keys, files, EV2
    # capabilities, proximity, virtual card, DAM keys, preferred auth.
    picc += _encode_keys(0xA9, cred.picc_keys, cred.picc_key_len)
    picc += _encode_files(0xAA, cred, OWNER_PICC)
    if cred.picc_has_ev2_capabilities:
        picc += _tlv(0x8B, cred.picc_ev2_capabilities)
    if cred.picc_has_proximity_key:
        proximity = _tlv(0x80, cred.picc_proximity_key) + _tlv(
            0x81, bytes([cred.picc_proximity_option])
        ) + _int(0x82, cred.picc_proximity_published_response_time)
        if cred.picc_has_proximity_bitrate:
            proximity += _tlv(0x83, bytes([cred.picc_proximity_bitrate]))
        picc += _tlv(0xAC, proximity)
    if cred.virtual_card_configured:
        vcard = (
            _tlv(0x80, cred.virtual_card_installation_id)
            + _tlv(0x81, bytes([cred.virtual_card_information]))
            + _tlv(0x82, cred.virtual_card_capabilities)
            + _tlv(0x83, cred.virtual_card_uid)
            + _tlv(0x84, cred.virtual_card_select_mac_key)
            + _tlv(0x85, cred.virtual_card_select_encryption_key)
            + _bool(0x86, cred.virtual_card_authentication_mandatory)
            + _bool(0x87, cred.virtual_card_proximity_mandatory)
        )
        picc += _tlv(0xAD, vcard)
    if cred.picc_has_dam_keys:
        dam = (
            _tlv(0x80, cred.picc_dam_auth_key)
            + _tlv(0x81, cred.picc_dam_mac_key)
            + _tlv(0x82, cred.picc_dam_encryption_key)
        )
        picc += _tlv(0xAE, dam)
    # v6 PICC_PREFERRED_AUTH is P(15) = 0x8F, declared last.
    if _target_v6(cred) and cred.picc_preferred_cmd:
        picc += _int(0x8F, AUTH_CMD_BITS[cred.picc_preferred_cmd])

    apps = b"".join(_encode_app(cred, i, app) for i, app in enumerate(cred.apps))

    _v6 = (
        cred.cred_version == 6
        or cred.picc_auth_mask
        or cred.picc_preferred_cmd
        or any(a.auth_mask or a.preferred_cmd or a.sm_disable >= 0 for a in cred.apps)
    )
    if _v6:
        ver = DFC_VERSION_V6
    elif cred.hardware_version or cred.software_version or cred.picc_has_static_signature:
        ver = 5
    else:
        ver = DFC_VERSION
    body = _int(0x80, ver) + _tlv(0xA1, card) + _tlv(0xA2, picc) + _tlv(0xA3, apps)
    out = _tlv(0x60, body)
    if len(out) > DER_MAX_SIZE:
        raise DfcError(
            f"credential encodes to {len(out)} bytes, the limit is {DER_MAX_SIZE}"
        )
    return out


def _validate(cred: DfcCredential) -> None:
    for _n, _v in (
        ("hardware", cred.hardware_version),
        ("software", cred.software_version),
    ):
        if _v and len(_v) != 7:
            raise DfcError(f"Card {_n} version must be 7 bytes, got {len(_v)}")
    if len(cred.uid) not in UID_LENGTHS:
        raise DfcError(f"UID must be 4 or 7 bytes, got {len(cred.uid)}")
    if cred.generation not in GENERATIONS.values():
        raise DfcError(f"unknown card generation {cred.generation}")
    if cred.generation not in EMULATED_GENERATIONS:
        raise DfcError(
            f"{_name_of(GENERATIONS, cred.generation, 'this card generation')} "
            "is not emulated by this firmware",
            DfcErrorClass.UNSUPPORTED,
        )
    if cred.uid_provenance not in PROVENANCES.values():
        raise DfcError(f"unknown UID provenance {cred.uid_provenance}")
    if not 0 <= cred.storage <= U32_MAX:
        raise DfcError(f"card storage {cred.storage} out of range")
    if cred.picc_has_static_signature and len(cred.picc_static_signature) != STATIC_SIGNATURE_LEN:
        raise DfcError(
            f"Card Static Signature must be {STATIC_SIGNATURE_LEN} bytes, "
            f"got {len(cred.picc_static_signature)}"
        )
    # A slot with no key entry carries the factory default (specification section
    # 1.4), so a credential may record no key material at all. The default is
    # supplied where the key is used, on the device, and is never written here.
    if len(cred.picc_keys) > MAX_KEYS:
        raise DfcError(f"{len(cred.picc_keys)} PICC keys, the limit is {MAX_KEYS}")
    if cred.picc_has_ev2_capabilities and len(cred.picc_ev2_capabilities) != EV2_CAPABILITY_LEN:
        raise DfcError(
            f"PICC EV2 Card Capabilities must be {EV2_CAPABILITY_LEN} bytes"
        )
    if cred.picc_has_proximity_key:
        if len(cred.picc_proximity_key) != AES_KEY_LEN:
            raise DfcError(f"PICC Proximity Key must be {AES_KEY_LEN} bytes")
        if not 0 <= cred.picc_proximity_published_response_time <= 0xFFFF:
            raise DfcError("PICC Proximity Published Response Time out of range")
    if cred.virtual_card_configured:
        if not 1 <= len(cred.virtual_card_installation_id) <= VIRTUAL_CARD_MAX_INSTALL_ID_LEN:
            raise DfcError(
                "PICC Virtual Card Installation ID must be 1 to "
                f"{VIRTUAL_CARD_MAX_INSTALL_ID_LEN} bytes"
            )
        if len(cred.virtual_card_capabilities) != VIRTUAL_CARD_CAPABILITY_LEN:
            raise DfcError(
                f"PICC Virtual Card Capabilities must be {VIRTUAL_CARD_CAPABILITY_LEN} bytes"
            )
        if len(cred.virtual_card_uid) not in (4, 7, 10):
            raise DfcError("PICC Virtual Card UID must be 4, 7, or 10 bytes")
        if len(cred.virtual_card_select_mac_key) != AES_KEY_LEN:
            raise DfcError(f"PICC Virtual Card Select MAC Key must be {AES_KEY_LEN} bytes")
        if len(cred.virtual_card_select_encryption_key) != AES_KEY_LEN:
            raise DfcError(
                f"PICC Virtual Card Select Encryption Key must be {AES_KEY_LEN} bytes"
            )
    if cred.picc_has_dam_keys:
        for _n, _v in (
            ("Authentication", cred.picc_dam_auth_key),
            ("MAC", cred.picc_dam_mac_key),
            ("Encryption", cred.picc_dam_encryption_key),
        ):
            if len(_v) != AES_KEY_LEN:
                raise DfcError(f"PICC DAM {_n} Key must be {AES_KEY_LEN} bytes")

    seen_aids = set()
    for app in cred.apps:
        if len(app.aid) != 3:
            raise DfcError(f"AID must be 3 bytes, got {len(app.aid)}")
        if app.aid in seen_aids:
            raise DfcError(f"duplicate AID {app.aid.hex().upper()}")
        seen_aids.add(app.aid)
        if app.key_sets:
            if len(app.key_sets) < KEY_SET_MINIMUM_COUNT:
                raise DfcError(
                    f"application {app.aid.hex().upper()} has "
                    f"{len(app.key_sets)} key sets, the minimum is "
                    f"{KEY_SET_MINIMUM_COUNT}"
                )
            if len(app.key_sets) > KEY_SET_MAX_SETS:
                raise DfcError(
                    f"application {app.aid.hex().upper()} has "
                    f"{len(app.key_sets)} key sets, the limit is {KEY_SET_MAX_SETS}"
                )
            if not app.key_sets[0].initialized:
                raise DfcError(
                    f"application {app.aid.hex().upper()} key set 00 shall be initialized"
                )
            for si, ks in enumerate(app.key_sets):
                required = AES_KEY_LEN if ks.type != KEY_SET_TYPE_3K3DES else 24
                if required > app.key_set_max_size:
                    raise DfcError(
                        f"application {app.aid.hex().upper()} key set {si:02X} "
                        "type exceeds the maximum key size"
                    )
                for k in ks.keys:
                    if len(k.value) != required:
                        raise DfcError(
                            f"application {app.aid.hex().upper()} key set {si:02X} "
                            f"key is {len(k.value)} bytes, expected {required}"
                        )
        elif len(app.keys) > MAX_KEYS:
            raise DfcError(
                f"application {app.aid.hex().upper()} has {len(app.keys)} keys, "
                f"the limit is {MAX_KEYS}"
            )
        if app.has_capability_data and len(app.capability_data) != APPLICATION_CAPABILITY_DATA_LEN:
            raise DfcError(
                f"{app.aid.hex().upper()} Capability Data must be "
                f"{APPLICATION_CAPABILITY_DATA_LEN} bytes"
            )
        if app.delegated and app.delegated_free_blocks > app.delegated_quota_limit:
            raise DfcError(
                f"application {app.aid.hex().upper()} delegated free blocks "
                "exceed the quota"
            )
        if len(app.iso_aid) > 16:
            raise DfcError("DF name longer than 16 bytes")
        if app.has_iso_file_id and app.iso_file_id in RESERVED_ISO_FILE_IDS:
            raise DfcError(f"ISO file ID {app.iso_file_id:04X} is reserved")

    seen_files = set()
    for f in cred.files:
        if f.app_index != OWNER_PICC and not 0 <= f.app_index < len(cred.apps):
            raise DfcError(
                f"file {f.number:02X} references application {f.app_index}, "
                f"but only {len(cred.apps)} are defined"
            )
        if not 0 <= f.number <= 0x1F:
            raise DfcError(f"file number {f.number:02X} out of range")
        if (f.app_index, f.number) in seen_files:
            raise DfcError(f"duplicate file number {f.number:02X}")
        seen_files.add((f.app_index, f.number))
        if f.has_iso_file_id and f.iso_file_id in RESERVED_ISO_FILE_IDS:
            raise DfcError(f"ISO file ID {f.iso_file_id:04X} is reserved")

        if f.type in (FILE_TYPE_STANDARD, FILE_TYPE_BACKUP):
            if not 1 <= f.declared_size <= U24_MAX:
                raise DfcError(
                    f"file {f.number:02X} declares a size of {f.declared_size}, "
                    f"expected 1 to {U24_MAX}"
                )
            if len(f.data) > f.declared_size:
                raise DfcError(
                    f"file {f.number:02X} carries {len(f.data)} bytes but declares "
                    f"only {f.declared_size}"
                )
            if f.contents_complete and len(f.data) != f.declared_size:
                raise DfcError(
                    f"file {f.number:02X} is marked complete but carries "
                    f"{len(f.data)} of {f.declared_size} bytes"
                )
        elif f.type == FILE_TYPE_VALUE:
            if not f.value_lower_limit <= f.value <= f.value_upper_limit:
                raise DfcError(
                    f"file {f.number:02X} value {f.value} is outside "
                    f"[{f.value_lower_limit}..{f.value_upper_limit}]"
                )
        elif f.type in (FILE_TYPE_LINEAR, FILE_TYPE_CYCLIC):
            if not 1 <= f.record_size <= U24_MAX:
                raise DfcError(
                    f"file {f.number:02X} record size {f.record_size} out of range"
                )
            if not 1 <= f.max_records <= U24_MAX:
                raise DfcError(
                    f"file {f.number:02X} max records {f.max_records} out of range"
                )
            if f.record_count > f.max_records:
                raise DfcError(
                    f"file {f.number:02X} holds {f.record_count} records but its "
                    f"capacity is {f.max_records}"
                )
            if f.type == FILE_TYPE_CYCLIC and f.max_records < 2:
                raise DfcError(
                    f"cyclic file {f.number:02X} needs capacity for two records"
                )
            if any(len(r) != f.record_size for r in f.records):
                raise DfcError(f"file {f.number:02X} has a record of the wrong length")
            if len(f.records) > f.record_count:
                raise DfcError(
                    f"file {f.number:02X} carries {len(f.records)} records but "
                    f"holds {f.record_count}"
                )
            if f.contents_complete and len(f.records) != f.record_count:
                raise DfcError(
                    f"file {f.number:02X} is marked complete but carries "
                    f"{len(f.records)} of {f.record_count} records"
                )
        elif f.type == FILE_TYPE_TMAC:
            if len(f.transaction_mac) != WIRE_MAC_LEN:
                raise DfcError(f"file {f.number:02X} Transaction MAC must be {WIRE_MAC_LEN} bytes")
            if len(f.transaction_mac_key) != AES_KEY_LEN:
                raise DfcError(
                    f"file {f.number:02X} Transaction Key must be {AES_KEY_LEN} bytes"
                )
            if len(f.previous_reader_id) != TRANSACTION_READER_ID_LEN:
                raise DfcError(
                    f"file {f.number:02X} Previous Reader ID must be "
                    f"{TRANSACTION_READER_ID_LEN} bytes"
                )
        else:
            raise DfcError(
                f"file type {f.type:02X} has no representation in version {DFC_VERSION}",
                DfcErrorClass.UNSUPPORTED,
            )

        if f.sdm_enabled and f.type != FILE_TYPE_STANDARD:
            raise DfcError(
                f"file {f.number:02X} SDM belongs to a standard data file only"
            )


# ------------------------------------------------------------- DER reader --


def _read_tlv(blob: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos + 2 > len(blob):
        raise DfcError("truncated encoding")
    tag = blob[pos]
    if tag & 0x1F == 0x1F:
        raise DfcError("high-tag-number identifiers are not part of this encoding")
    n = blob[pos + 1]
    hdr = 2
    if n & 0x80:
        count = n & 0x7F
        if count == 0 or count > 2:
            raise DfcError("indefinite or over-long length")
        if pos + 2 + count > len(blob):
            raise DfcError("truncated length")
        n = int.from_bytes(blob[pos + 2 : pos + 2 + count], "big")
        hdr = 2 + count
        if n < 128 or (count == 2 and n < 256):
            raise DfcError("non-minimal length")
    if pos + hdr + n > len(blob):
        raise DfcError("truncated value")
    return tag, blob[pos + hdr : pos + hdr + n], pos + hdr + n


def _split(body: bytes) -> list[tuple[int, bytes]]:
    out = []
    pos = 0
    while pos < len(body):
        tag, value, pos = _read_tlv(body, pos)
        out.append((tag, value))
    return out


def _fields(body: bytes, order: tuple[int, ...]) -> dict[int, bytes]:
    got: dict[int, bytes] = {}
    cursor = 0
    for tag, value in _split(body):
        if tag not in order:
            raise DfcError(f"tag 0x{tag:02X} is not a component of this type")
        if tag in got:
            raise DfcError(f"duplicate tag 0x{tag:02X}")
        idx = order.index(tag)
        if idx < cursor:
            raise DfcError(f"tag 0x{tag:02X} is out of declaration order")
        cursor = idx + 1
        got[tag] = value
    return got


def _req(got: dict[int, bytes], tag: int) -> bytes:
    if tag not in got:
        raise DfcError(f"required component 0x{tag:02X} is missing")
    return got[tag]


def _read_int(body: bytes) -> int:
    if not body or len(body) > 8:
        raise DfcError("integer of unusable length")
    if len(body) > 1 and (
        (body[0] == 0x00 and not body[1] & 0x80) or (body[0] == 0xFF and body[1] & 0x80)
    ):
        raise DfcError("non-minimal integer")
    return int.from_bytes(body, "big", signed=True)


def _read_uint(body: bytes, hi: int) -> int:
    v = _read_int(body)
    if not 0 <= v <= hi:
        raise DfcError(f"integer {v} out of range 0..{hi}")
    return v


def _read_bool(body: bytes) -> bool:
    if len(body) != 1 or body[0] not in (0x00, 0xFF):
        raise DfcError("boolean must be 00 or FF")
    return body[0] == 0xFF


def _read_default_false(got: dict[int, bytes], tag: int) -> bool:
    if tag not in got:
        return False
    if not _read_bool(got[tag]):
        raise DfcError(
            f"component 0x{tag:02X} defaults to false, so an explicit false is invalid"
        )
    return True


def _read_octets(body: bytes, want: int) -> bytes:
    if len(body) != want:
        raise DfcError(f"expected {want} octets, got {len(body)}")
    return body


def _read_iso_file_id(body: bytes) -> int:
    v = int.from_bytes(_read_octets(body, 2), "big")
    if v in RESERVED_ISO_FILE_IDS:
        raise DfcError(f"ISO file ID {v:04X} is reserved")
    return v


def _read_keys(body: bytes, key_len: int) -> list[DfcKey]:
    keys: list[DfcKey] = []
    for tag, value in _split(body):
        if tag != 0x30:
            raise DfcError(f"tag 0x{tag:02X} where a key was expected")
        got = _fields(value, (0x80, 0x81, 0x82))
        slot = _read_uint(_req(got, 0x80), 13)
        if slot != len(keys):
            raise DfcError(f"key slot {slot} out of ascending contiguous order")
        keys.append(DfcKey(_read_octets(_req(got, 0x81), key_len), _req(got, 0x82)[0]))
        if len(_req(got, 0x82)) != 1:
            raise DfcError("key version must be one octet")
    # An empty list is well formed: the slot then carries the factory default
    # (specification section 1.4, and rule 16 on a required empty SEQUENCE OF).
    return keys


def _key_set_type_length(type_: int) -> int:
    return 24 if type_ == KEY_SET_TYPE_3K3DES else AES_KEY_LEN


def _read_key_sets(app: DfcApplication, body: bytes) -> None:
    got = _fields(body, (0x80, 0x81, 0x82, 0xA3))
    key_count = _read_uint(_req(got, 0x80), MAX_KEYS)
    if key_count == 0:
        raise DfcError("Key Set Key Count must be at least one")
    max_size = _read_uint(_req(got, 0x81), 24)
    if max_size not in (16, 24):
        raise DfcError("Key Set Maximum Key Size must be 16 or 24")
    app.key_set_key_count = key_count
    app.key_set_max_size = max_size
    app.key_set_settings = _read_octets(_req(got, 0x82), 1)[0]

    sets_body = _req(got, 0xA3)
    entries = _split(sets_body)
    if len(entries) < KEY_SET_MINIMUM_COUNT:
        raise DfcError(f"at least {KEY_SET_MINIMUM_COUNT} key sets are required")
    if len(entries) > KEY_SET_MAX_SETS:
        raise DfcError(f"{len(entries)} key sets exceed the limit of {KEY_SET_MAX_SETS}")

    for index, (tag, value) in enumerate(entries):
        if tag != 0x30:
            raise DfcError(f"tag 0x{tag:02X} where a key set was expected")
        sf = _fields(value, (0x80, 0x81, 0x82, 0x83, 0xA4))
        number = _read_uint(_req(sf, 0x80), KEY_SET_MAX_SETS - 1)
        if number != index:
            raise DfcError(f"key set {number} out of ascending contiguous order")
        ks = DfcKeySet()
        ks.version = _read_octets(_req(sf, 0x81), 1)[0]
        ks.type = _read_uint(_req(sf, 0x82), 0xFF)
        if ks.type > KEY_SET_TYPE_AES:
            raise DfcError(f"key set {index:02X} has an unknown type {ks.type}")
        required = _key_set_type_length(ks.type)
        if required > max_size:
            raise DfcError(f"key set {index:02X} type exceeds the maximum key size")
        ks.initialized = _read_bool(_req(sf, 0x83))
        ks.keys = _read_keys(_req(sf, 0xA4), required)
        if len(ks.keys) > key_count:
            raise DfcError(f"key set {index:02X} carries more keys than Key Set Key Count")
        app.key_sets.append(ks)
    if not app.key_sets[0].initialized:
        raise DfcError("key set 00 shall be initialized")


def _read_file(body: bytes, owner: int) -> DfcFile:
    got = _fields(body, (0x80, 0x81, 0x82, 0x83, 0x84, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9))
    f = DfcFile(app_index=owner)
    f.number = _read_uint(_req(got, 0x80), 0x1F)
    f.type = _read_uint(_req(got, 0x81), 0xFF)
    if f.type > FILE_TYPE_TMAC:
        raise DfcError(
            f"file type {f.type:02X} has no representation in version {DFC_VERSION}",
            DfcErrorClass.UNSUPPORTED,
        )
    f.comm_settings = _read_octets(_req(got, 0x82), 1)[0]
    f.access_rights = int.from_bytes(_read_octets(_req(got, 0x83), 2), "big")
    if 0x84 in got:
        f.has_iso_file_id = True
        f.iso_file_id = _read_iso_file_id(got[0x84])

    present = [t for t in (0xA5, 0xA6, 0xA7, 0xA8) if t in got]
    if len(present) != 1:
        raise DfcError("a file carries exactly one contents alternative")
    expected = {
        FILE_TYPE_STANDARD: 0xA5,
        FILE_TYPE_BACKUP: 0xA5,
        FILE_TYPE_VALUE: 0xA6,
        FILE_TYPE_LINEAR: 0xA7,
        FILE_TYPE_CYCLIC: 0xA7,
        FILE_TYPE_TMAC: 0xA8,
    }[f.type]
    if present[0] != expected:
        raise DfcError(
            f"file type {f.type:02X} requires contents 0x{expected:02X}, "
            f"not 0x{present[0]:02X}"
        )

    if expected == 0xA5:
        c = _fields(got[0xA5], (0x80, 0x81, 0x82))
        f.declared_size = _read_uint(_req(c, 0x80), U24_MAX)
        if f.declared_size == 0:
            raise DfcError("declared size must be at least one octet")
        f.contents_complete = _read_bool(_req(c, 0x82))
        if 0x81 in c:
            if not c[0x81] or len(c[0x81]) > f.declared_size:
                raise DfcError("known contents longer than the declared size")
            f.data = c[0x81]
        if f.contents_complete and len(f.data) != f.declared_size:
            raise DfcError(
                "contents marked complete but shorter than the declared size"
            )
    elif expected == 0xA6:
        c = _fields(got[0xA6], (0x80, 0x81, 0x82, 0x83))
        f.value_lower_limit = _read_int(_req(c, 0x80))
        f.value_upper_limit = _read_int(_req(c, 0x81))
        f.value = _read_int(_req(c, 0x82))
        for v in (f.value_lower_limit, f.value_upper_limit, f.value):
            if not -0x80000000 <= v <= 0x7FFFFFFF:
                raise DfcError(f"value {v} outside the signed 32-bit range")
        if not f.value_lower_limit <= f.value <= f.value_upper_limit:
            raise DfcError("value outside its own limits")
        f.limited_credit = _read_octets(_req(c, 0x83), 1)[0]
    elif expected == 0xA8:
        c = _fields(got[0xA8], (0x80, 0x81, 0x82, 0x83, 0x84, 0x85))
        f.transaction_counter = _read_uint(_req(c, 0x80), U32_MAX)
        f.transaction_mac = _read_octets(_req(c, 0x81), WIRE_MAC_LEN)
        f.transaction_mac_key_type = _read_octets(_req(c, 0x82), 1)[0]
        f.transaction_mac_key_version = _read_octets(_req(c, 0x83), 1)[0]
        f.transaction_mac_key = _read_octets(_req(c, 0x84), AES_KEY_LEN)
        f.previous_reader_id = _read_octets(_req(c, 0x85), TRANSACTION_READER_ID_LEN)
    else:
        c = _fields(got[0xA7], (0x80, 0x81, 0x82, 0x83, 0xA4))
        f.record_size = _read_uint(_req(c, 0x80), U24_MAX)
        f.max_records = _read_uint(_req(c, 0x81), U24_MAX)
        f.record_count = _read_uint(_req(c, 0x82), U24_MAX)
        if f.record_size == 0 or f.max_records == 0:
            raise DfcError("record size and capacity must be at least one")
        if f.record_count > f.max_records:
            raise DfcError("record count exceeds the file's capacity")
        if f.type == FILE_TYPE_CYCLIC and f.max_records < 2:
            raise DfcError("a cyclic file needs capacity for two records")
        f.contents_complete = _read_bool(_req(c, 0x83))
        for tag, value in _split(_req(c, 0xA4)):
            if tag != 0x04:
                raise DfcError(f"tag 0x{tag:02X} where a record was expected")
            if len(value) != f.record_size:
                raise DfcError("record of the wrong length")
            f.records.append(value)
        if len(f.records) > f.record_count:
            raise DfcError("more records carried than the file holds")
        if f.contents_complete and len(f.records) != f.record_count:
            raise DfcError("records marked complete but fewer carried than held")

    if 0xA9 in got:
        # Secure dynamic messaging belongs to a standard data file only.
        if f.type != FILE_TYPE_STANDARD:
            raise DfcError("SDM belongs to a standard data file only")
        _read_sdm(f, got[0xA9])
    return f


def _read_sdm_offset(sf: dict[int, bytes], tag: int) -> tuple[bool, int]:
    if tag not in sf:
        return False, 0
    return True, _read_uint(sf[tag], U24_MAX)


def _read_sdm(f: DfcFile, body: bytes) -> None:
    sf = _fields(body, (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A))
    f.sdm_options = _read_octets(_req(sf, 0x80), 1)[0]
    f.sdm_access_rights = int.from_bytes(_read_octets(_req(sf, 0x81), 2), "big")
    f.sdm_has_uid_offset, f.sdm_uid_offset = _read_sdm_offset(sf, 0x82)
    f.sdm_has_counter_offset, f.sdm_counter_offset = _read_sdm_offset(sf, 0x83)
    f.sdm_has_picc_data_offset, f.sdm_picc_data_offset = _read_sdm_offset(sf, 0x84)
    f.sdm_has_mac_input_offset, f.sdm_mac_input_offset = _read_sdm_offset(sf, 0x85)
    f.sdm_has_mac_offset, f.sdm_mac_offset = _read_sdm_offset(sf, 0x86)
    f.sdm_has_encrypted_file_offset, f.sdm_encrypted_file_offset = _read_sdm_offset(sf, 0x87)
    # The encrypted offset and its length occur together.
    if (0x88 in sf) != f.sdm_has_encrypted_file_offset:
        raise DfcError("SDM encrypted offset and length occur together")
    if 0x88 in sf:
        f.sdm_encrypted_file_length = _read_uint(sf[0x88], U24_MAX)
    f.sdm_has_counter_limit, f.sdm_counter_limit = _read_sdm_offset(sf, 0x89)
    f.sdm_read_counter = _read_uint(_req(sf, 0x8A), U24_MAX)
    f.sdm_enabled = True


def der_decode(blob: bytes, cls=DfcCredential) -> "DfcCredential":
    """Decode `.dfcb` octets into a credential. Raises DfcError on anything the
    encoding does not permit."""
    if len(blob) > DER_MAX_SIZE:
        raise DfcError(f"{len(blob)} bytes exceeds the {DER_MAX_SIZE}-byte limit")
    tag, body, end = _read_tlv(blob, 0)
    if tag != 0x60:
        raise DfcError(f"first identifier is 0x{tag:02X}, not 0x60")
    if end != len(blob):
        raise DfcError("trailing octets after the credential")

    got = _fields(body, (0x80, 0xA1, 0xA2, 0xA3))
    version = _read_uint(_req(got, 0x80), 0xFF)
    if version not in (DFC_VERSION, 5, DFC_VERSION_V6):
        raise DfcError(
            f"credential encoding version {version} is not supported",
            DfcErrorClass.UNSUPPORTED,
        )

    cred = cls()

    if version == DFC_VERSION:
        # Format version 4 carries no card record past provenance: no static
        # signature, no hardware/software GetVersion override.
        card = _fields(_req(got, 0xA1), (0x80, 0x81, 0x82, 0x83))
    else:
        card = _fields(_req(got, 0xA1), (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86))
    cred.generation = _read_uint(_req(card, 0x80), 0xFF)
    if cred.generation not in GENERATIONS.values():
        raise DfcError(f"unknown card generation {cred.generation}")
    if cred.generation not in EMULATED_GENERATIONS:
        raise DfcError(
            f"{_name_of(GENERATIONS, cred.generation, 'this card generation')} "
            "is not emulated by this firmware",
            DfcErrorClass.UNSUPPORTED,
        )
    cred.storage = _read_uint(_req(card, 0x81), U32_MAX)
    cred.uid = _req(card, 0x82)
    if len(cred.uid) not in UID_LENGTHS:
        raise DfcError(f"UID must be 4 or 7 bytes, got {len(cred.uid)}")
    cred.uid_provenance = _read_uint(_req(card, 0x83), 0xFF)
    if 0x84 in card:
        cred.picc_has_static_signature = True
        cred.picc_static_signature = _read_octets(card[0x84], STATIC_SIGNATURE_LEN)
    if 0x85 in card:
        cred.hardware_version = card[0x85]
    if 0x86 in card:
        cred.software_version = card[0x86]
    if cred.uid_provenance not in PROVENANCES.values():
        raise DfcError(f"unknown UID provenance {cred.uid_provenance}")

    # Declared order (not numeric by tag): see dfc_der.c's `porder`. Keys and
    # files come before EV2 capabilities/proximity/virtual card/DAM, and the
    # v6 preferred-auth tag is declared last of all.
    picc = _fields(
        _req(got, 0xA2),
        (
            0x80,
            0x81,
            0x82,
            0x83,
            0x84,
            0x85,
            0x86,
            0x87,
            0x88,
            0xA9,
            0xAA,
            0x8B,
            0xAC,
            0xAD,
            0xAE,
            0x8F,
        ),
    )
    cred.picc_key_settings_1 = _read_octets(_req(picc, 0x80), 1)[0]
    cred.picc_key_settings_2 = _read_octets(_req(picc, 0x81), 1)[0]
    if version == DFC_VERSION_V6:
        cred.cred_version = 6
        cred.picc_auth_mask = _read_uint(_req(picc, 0x82), 0x3F)
        names = auth_mask_to_names(cred.picc_auth_mask)
        if 0x8F in picc:  # preferred command (v6)
            pref_bit = _read_uint(picc[0x8F], 0x3F)
            pref = auth_mask_to_names(pref_bit)
            if len(pref) != 1 or not (pref_bit & cred.picc_auth_mask):
                raise DfcError("PICC preferred auth command not a single enabled bit")
            cred.picc_preferred_cmd = pref[0]
        # native command the emulator will actually use: preferred if native,
        # else the first native-capable enabled command
        pick = cred.picc_preferred_cmd or next(
            (n for n in ("AES", "ISO", "D40") if n in names), "AES"
        )
        cred.picc_auth_command = AUTH_CMD_TO_NATIVE.get(pick, 0xAA)
    else:
        cred.cred_version = version
        cred.picc_auth_command = AUTH_COMMANDS_BY_CODE[_read_uint(_req(picc, 0x82), 2)]
    cred.picc_random_id = _read_default_false(picc, 0x83)
    cred.picc_format_disabled = _read_default_false(picc, 0x84)
    if 0x85 in picc:
        if not picc[0x85]:
            raise DfcError("an emitted ATS must be at least one octet")
        cred.picc_ats = picc[0x85]
    if 0x86 in picc:
        cred.picc_sak = _read_octets(picc[0x86], 1)[0]
    if 0x87 in picc:
        cred.picc_atqa = _read_octets(picc[0x87], 2)
    if 0x88 in picc:
        cred.picc_sm_disable = _read_octets(picc[0x88], 1)[0]
    cred.picc_keys = _read_keys(_req(picc, 0xA9), cred.picc_key_len)

    if 0x8B in picc:
        cred.picc_has_ev2_capabilities = True
        cred.picc_ev2_capabilities = _read_octets(picc[0x8B], EV2_CAPABILITY_LEN)
    if 0xAC in picc:
        pr = _fields(picc[0xAC], (0x80, 0x81, 0x82, 0x83))
        cred.picc_proximity_key = _read_octets(_req(pr, 0x80), AES_KEY_LEN)
        cred.picc_proximity_option = _read_octets(_req(pr, 0x81), 1)[0]
        cred.picc_proximity_published_response_time = _read_uint(_req(pr, 0x82), 0xFFFF)
        if 0x83 in pr:
            cred.picc_proximity_bitrate = _read_octets(pr[0x83], 1)[0]
            cred.picc_has_proximity_bitrate = True
        cred.picc_has_proximity_key = True
    if 0xAD in picc:
        vc = _fields(picc[0xAD], (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87))
        install = _req(vc, 0x80)
        if not install or len(install) > VIRTUAL_CARD_MAX_INSTALL_ID_LEN:
            raise DfcError("PICC Virtual Card Installation ID out of range")
        cred.virtual_card_installation_id = install
        cred.virtual_card_information = _read_octets(_req(vc, 0x81), 1)[0]
        cred.virtual_card_capabilities = _read_octets(
            _req(vc, 0x82), VIRTUAL_CARD_CAPABILITY_LEN
        )
        uid = _req(vc, 0x83)
        if len(uid) not in (4, 7, 10):
            raise DfcError("PICC Virtual Card UID must be 4, 7, or 10 bytes")
        cred.virtual_card_uid = uid
        cred.virtual_card_select_mac_key = _read_octets(_req(vc, 0x84), AES_KEY_LEN)
        cred.virtual_card_select_encryption_key = _read_octets(_req(vc, 0x85), AES_KEY_LEN)
        cred.virtual_card_authentication_mandatory = _read_bool(_req(vc, 0x86))
        cred.virtual_card_proximity_mandatory = _read_bool(_req(vc, 0x87))
        cred.virtual_card_configured = True
    if 0xAE in picc:
        dam = _fields(picc[0xAE], (0x80, 0x81, 0x82))
        cred.picc_dam_auth_key = _read_octets(_req(dam, 0x80), AES_KEY_LEN)
        cred.picc_dam_mac_key = _read_octets(_req(dam, 0x81), AES_KEY_LEN)
        cred.picc_dam_encryption_key = _read_octets(_req(dam, 0x82), AES_KEY_LEN)
        cred.picc_has_dam_keys = True

    for tag, value in _split(_req(got, 0xA3)):
        if tag != 0x30:
            raise DfcError(f"tag 0x{tag:02X} where an application was expected")
        # Declared order is not numeric: APP_CAPABILITY follows APP_KEY_SETS,
        # and APP_SM_DISABLE/APP_PREFERRED_AUTH are declared last of all.
        app_fields = _fields(
            value,
            (
                0x80,
                0x81,
                0x82,
                0x83,
                0x84,
                0x85,
                0xA6,
                0xA7,
                0xA8,
                0x89,
                0xAA,
                0x8B,
                0x8C,
            ),
        )
        app = DfcApplication()
        app.aid = _read_octets(_req(app_fields, 0x80), 3)
        if any(app.aid == other.aid for other in cred.apps):
            raise DfcError(f"duplicate AID {app.aid.hex().upper()}")
        if 0x81 in app_fields:
            app.has_iso_file_id = True
            app.iso_file_id = _read_iso_file_id(app_fields[0x81])
        if 0x82 in app_fields:
            if not 1 <= len(app_fields[0x82]) <= 16:
                raise DfcError("DF name must be 1 to 16 octets")
            app.iso_aid = app_fields[0x82]
        app.key_settings_1 = _read_octets(_req(app_fields, 0x83), 1)[0]
        app.key_settings_2 = _read_octets(_req(app_fields, 0x84), 1)[0]
        if version == DFC_VERSION_V6:
            app.auth_mask = _read_uint(_req(app_fields, 0x85), 0x3F)
            names = auth_mask_to_names(app.auth_mask)
            if 0x8C in app_fields:  # app preferred command (v6)
                pref_bit = _read_uint(app_fields[0x8C], 0x3F)
                pref = auth_mask_to_names(pref_bit)
                if len(pref) != 1 or not (pref_bit & app.auth_mask):
                    raise DfcError("application preferred auth command invalid")
                app.preferred_cmd = pref[0]
            if 0x8B in app_fields:  # app SM-disable octet (v6)
                app.sm_disable = _read_octets(app_fields[0x8B], 1)[0]
            pick = app.preferred_cmd or next(
                (n for n in ("AES", "ISO", "D40") if n in names), "AES"
            )
            app.auth_command = AUTH_CMD_TO_NATIVE.get(pick, 0xAA)
        else:
            app.auth_command = AUTH_COMMANDS_BY_CODE[
                _read_uint(_req(app_fields, 0x85), 2)
            ]
        app.key_len = key_length_for_ks2(app.key_settings_2)
        akeys = app_fields.get(0xA6)
        aksets = app_fields.get(0xA8)
        # Exactly one key-storage alternative is required.
        if (akeys is None) == (aksets is None):
            raise DfcError(f"application {app.aid.hex().upper()} key storage is ambiguous")
        if akeys is not None:
            app.keys = _read_keys(akeys, app.key_len)
        else:
            _read_key_sets(app, aksets)
        if 0x89 in app_fields:
            app.has_capability_data = True
            app.capability_data = _read_octets(
                app_fields[0x89], APPLICATION_CAPABILITY_DATA_LEN
            )
        if 0xAA in app_fields:
            dl = _fields(app_fields[0xAA], (0x80, 0x81, 0x82, 0x83))
            app.delegated_slot_number = _read_uint(_req(dl, 0x80), 0xFFFF)
            app.delegated_slot_version = _read_octets(_req(dl, 0x81), 1)[0]
            app.delegated_quota_limit = _read_uint(_req(dl, 0x82), 0xFFFF)
            app.delegated_free_blocks = _read_uint(_req(dl, 0x83), 0xFFFF)
            if app.delegated_free_blocks > app.delegated_quota_limit:
                raise DfcError(
                    f"application {app.aid.hex().upper()} delegated free blocks "
                    "exceed the quota"
                )
            app.delegated = True

        owner = len(cred.apps)
        cred.apps.append(app)
        for ftag, fvalue in _split(_req(app_fields, 0xA7)):
            if ftag != 0x30:
                raise DfcError(f"tag 0x{ftag:02X} where a file was expected")
            cred.files.append(_read_file(fvalue, owner))

    for ftag, fvalue in _split(_req(picc, 0xAA)):
        if ftag != 0x30:
            raise DfcError(f"tag 0x{ftag:02X} where a file was expected")
        cred.files.append(_read_file(fvalue, OWNER_PICC))

    return cred


# ------------------------------------------------------------------ text --


def _scan_fields(text: str) -> dict[str, str]:
    """Collect the canonical `Key: Value` lines."""
    fields: dict[str, str] = {}
    for raw in text.splitlines():
        if raw.endswith((" ", "\t")):
            raise DfcError("a text line has trailing whitespace")
        line = raw
        if not line:
            continue
        if line.startswith("#"):
            continue
        sep = line.find(":")
        if sep < 0:
            raise DfcError(f"text line has no key separator: {line!r}")
        key = line[:sep]
        value = line[sep + 1 :]
        if key != key.rstrip() or not value.startswith(" "):
            raise DfcError(f"text line is not canonical: {line!r}")
        value = value[1:]
        if not key or not value:
            raise DfcError("a text key or value is empty")
        if key in fields:
            raise DfcError(f"duplicate text key {key!r}")
        fields[key] = value
    return fields


_STATIC_TEXT_KEYS = {
    "Filetype",
    "Version",
    "Card Generation",
    "Card Storage",
    "Card Hardware Version",
    "Card Software Version",
    "UID",
    "UID Provenance",
    "PICC Key Settings 1",
    "PICC Key Settings 2",
    "PICC Authentication Mode",
    "PICC Authentication Commands",
    "PICC Preferred Authentication Command",
    "PICC Key Count",
    "PICC Random ID",
    "PICC Format Disabled",
    "PICC ATS",
    "PICC SAK",
    "PICC ATQA",
    "PICC SM Disable",
    "PICC File Count",
    "Application Count",
    "Card Static Signature",
    "PICC EV2 Card Capabilities",
    "PICC Proximity Key",
    "PICC Proximity Option",
    "PICC Proximity Published Response Time",
    "PICC Proximity Bitrate",
    "PICC Virtual Card Installation ID",
    "PICC Virtual Card Information",
    "PICC Virtual Card Capabilities",
    "PICC Virtual Card UID",
    "PICC Virtual Card Select MAC Key",
    "PICC Virtual Card Select Encryption Key",
    "PICC Virtual Card Authentication Mandatory",
    "PICC Virtual Card Proximity Mandatory",
    "PICC DAM Authentication Key",
    "PICC DAM MAC Key",
    "PICC DAM Encryption Key",
}

_KEY_SET_TEXT_PATTERN = re.compile(
    r"Application [0-9A-F]{2} (?:Key Set (?:Key Count|Maximum Key Size|Settings|Count)|"
    r"Key Set [0-9A-F]{2} (?:Version|Type|Initialized|Key Count|Key [0-9A-F]{2}(?: Version)?))"
)
_CAPABILITY_DELEGATED_TEXT_PATTERN = re.compile(
    r"Application [0-9A-F]{2} (?:"
    r"Capability Data|Delegated (?:Slot Number|Slot Version|Quota Limit|Free Blocks))"
)

_SDM_TMAC_TEXT_PATTERN = re.compile(
    r"(?:PICC |Application [0-9A-F]{2} )File [0-9A-F]{2} (?:"
    r"SDM (?:Options|Access Rights|UID Offset|Counter Offset|PICC Data Offset|"
    r"MAC Input Offset|MAC Offset|Encrypted File Offset|Encrypted File Length|"
    r"Counter Limit|Read Counter)|Transaction (?:Counter|MAC|Key Type|Key Version|Key)|"
    r"Previous Reader ID)"
)

_KEY_TEXT_PATTERN = re.compile(
    r"(?:PICC |Application [0-9A-F]{2} )Key [0-9A-F]{2}(?: Version)?"
)
_APPLICATION_TEXT_PATTERN = re.compile(
    r"Application [0-9A-F]{2} (?:AID|ISO File ID|DF Name|Key Settings 1|"
    r"Key Settings 2|Authentication Mode|Authentication Commands|"
    r"Preferred Authentication Command|SM Disable|Key Count|File Count)"
)
_FILE_TEXT_PATTERN = re.compile(
    r"(?:PICC |Application [0-9A-F]{2} )File [0-9A-F]{2} (?:Number|Type|"
    r"Communication Settings|Access Rights|ISO File ID|Size|Data|Data Complete|"
    r"Value Lower Limit|Value Upper Limit|Value|Limited Credit|Record Size|"
    r"Max Records|Record Count|Record Complete|Record [0-9A-F]{2})"
)


def _validate_text_keys(fields: dict[str, str]) -> None:
    for key in fields:
        if key in _STATIC_TEXT_KEYS:
            continue
        if _KEY_TEXT_PATTERN.fullmatch(key):
            continue
        if _APPLICATION_TEXT_PATTERN.fullmatch(key):
            continue
        if _FILE_TEXT_PATTERN.fullmatch(key):
            continue
        if _KEY_SET_TEXT_PATTERN.fullmatch(key):
            continue
        if _CAPABILITY_DELEGATED_TEXT_PATTERN.fullmatch(key):
            continue
        if _SDM_TMAC_TEXT_PATTERN.fullmatch(key):
            continue
        raise DfcError(f"unrecognised text key {key!r}")


def _name_of(table: dict[str, int], value: int, fallback: str) -> str:
    for name, v in table.items():
        if v == value:
            return name
    return fallback


def _parse_hex(value: str) -> bytes:
    value = value.strip()
    if not value:
        return b""
    if not re.fullmatch(r"[0-9A-F]{2}(?: [0-9A-F]{2})*", value):
        raise DfcError(f"bad canonical hex value {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise DfcError(f"bad hex value {value!r}") from exc


def _parse_int(value: str) -> int:
    value = value.strip()
    if not value:
        return 0
    try:
        return int(value, 0)
    except ValueError:
        # Several fields are spelled as a bare hex byte.
        try:
            return int(value, 16)
        except ValueError as exc:
            raise DfcError(f"bad integer value {value!r}") from exc


def _parse_octet(value: str, what: str) -> int:
    """A raw one-octet field. Spelled as a hex pair, never as a decimal number:
    `Key Settings 2: 81` is 0x81, and reading it as eighty-one would silently
    change the key type."""
    raw = _parse_hex(value)
    if len(raw) != 1:
        raise DfcError(f"{what} must be one hex octet, got {value!r}")
    return raw[0]


def _parse_decimal(value: str, what: str, signed: bool = False) -> int:
    """A decimal integer field. No hex, no leading zeros, no sign unless the
    field is one of the signed value-file limits."""
    text = value.strip()
    pattern = r"-?(0|[1-9][0-9]*)" if signed else r"(0|[1-9][0-9]*)"
    if not re.fullmatch(pattern, text):
        raise DfcError(f"{what} must be a decimal integer, got {value!r}")
    return int(text)


def _parse_bool(value: str, what: str) -> bool:
    value = value.strip()
    if value not in ("0", "1"):
        raise DfcError(f"{what} must be 0 or 1, got {value!r}")
    return value == "1"


def _auth_mode(text: str | None, ks2: int) -> int:
    if not text:
        return auth_command_for_ks2(ks2)
    if text not in AUTH_MODES:
        raise DfcError(f"unknown authentication mode {text!r}")
    return AUTH_MODES[text]


def _parse_auth_commands(text: str) -> int:
    """Text 'ISO, ISO7816' (canonical order) -> v6 six-bit command mask."""
    t = text.strip()
    if t.lower() == "none" or not t:
        return 0
    names = [p.strip() for p in t.split(",")]
    return auth_names_to_mask(names)


def _parse_preferred(text, mask: int, where: str) -> str:
    if text is None or not text.strip():
        return ""
    name = text.strip()
    if name not in AUTH_CMD_BITS:
        raise DfcError(f"{where} preferred authentication command {name!r} unknown")
    if not (AUTH_CMD_BITS[name] & mask):
        raise DfcError(f"{where} preferred command {name} is not in its command set")
    return name


def _native_from_mask(mask: int, preferred: str) -> int:
    """Native command byte the emulator uses: preferred if native, else first
    native-capable enabled command."""
    names = auth_mask_to_names(mask)
    pick = (
        preferred
        if preferred in ("D40", "ISO", "AES")
        else next((n for n in ("AES", "ISO", "D40") if n in names), "AES")
    )
    return AUTH_CMD_TO_NATIVE.get(pick, 0xAA)


def _parse_uid(fields: dict[str, str]) -> bytes:
    uid = _parse_hex(fields.get("UID", ""))
    if len(uid) not in UID_LENGTHS:
        raise DfcError(f"UID must be 4 or 7 bytes, got {len(uid)}")
    if len(uid) == UID_LEN and uid[0] != UID_FIRST_BYTE:
        raise DfcError(f"UID must start with 0x{UID_FIRST_BYTE:02X}")
    return uid


def _parse_key_list(
    fields: dict[str, str], prefix: str, count: int, key_len: int
) -> list[DfcKey]:
    keys = []
    for k in range(count):
        raw = fields.get(f"{prefix}Key {k:02X}", "")
        value = _parse_hex(raw)
        if value and len(value) != key_len:
            raise DfcError(
                f"{prefix}Key {k:02X} is {len(value)} bytes, expected {key_len}"
            )
        version = _parse_octet(
            fields.get(f"{prefix}Key {k:02X} Version", "00"),
            f"{prefix}Key {k:02X} Version",
        )
        keys.append(DfcKey(value or bytes(key_len), version))
    return keys


# ---- version 4 ----


def _parse_static_signature(fields: dict[str, str], cred: "DfcCredential") -> None:
    if "Card Static Signature" not in fields:
        return
    sig = _parse_hex(fields["Card Static Signature"])
    if len(sig) != STATIC_SIGNATURE_LEN:
        raise DfcError(f"Card Static Signature must be {STATIC_SIGNATURE_LEN} bytes")
    cred.picc_static_signature = sig
    cred.picc_has_static_signature = True


def _parse_ev2_capabilities(fields: dict[str, str], cred: "DfcCredential") -> None:
    if "PICC EV2 Card Capabilities" not in fields:
        return
    caps = _parse_hex(fields["PICC EV2 Card Capabilities"])
    if len(caps) != EV2_CAPABILITY_LEN:
        raise DfcError(f"PICC EV2 Card Capabilities must be {EV2_CAPABILITY_LEN} bytes")
    cred.picc_ev2_capabilities = caps
    cred.picc_has_ev2_capabilities = True


def _parse_proximity(fields: dict[str, str], cred: "DfcCredential") -> None:
    if "PICC Proximity Key" not in fields:
        return
    key = _parse_hex(fields["PICC Proximity Key"])
    if len(key) != AES_KEY_LEN:
        raise DfcError(f"PICC Proximity Key must be {AES_KEY_LEN} bytes")
    cred.picc_proximity_key = key
    cred.picc_proximity_option = _parse_octet(
        _need(fields, "PICC Proximity Option"), "PICC Proximity Option"
    )
    cred.picc_proximity_published_response_time = _parse_decimal(
        _need(fields, "PICC Proximity Published Response Time"),
        "PICC Proximity Published Response Time",
    )
    if not 0 <= cred.picc_proximity_published_response_time <= 0xFFFF:
        raise DfcError("PICC Proximity Published Response Time out of range")
    if "PICC Proximity Bitrate" in fields:
        cred.picc_proximity_bitrate = _parse_octet(
            fields["PICC Proximity Bitrate"], "PICC Proximity Bitrate"
        )
        cred.picc_has_proximity_bitrate = True
    cred.picc_has_proximity_key = True


def _parse_virtual_card(fields: dict[str, str], cred: "DfcCredential") -> None:
    if "PICC Virtual Card Installation ID" not in fields:
        return
    install = _parse_hex(fields["PICC Virtual Card Installation ID"])
    if not 1 <= len(install) <= VIRTUAL_CARD_MAX_INSTALL_ID_LEN:
        raise DfcError(
            "PICC Virtual Card Installation ID must be 1 to "
            f"{VIRTUAL_CARD_MAX_INSTALL_ID_LEN} bytes"
        )
    cred.virtual_card_installation_id = install
    cred.virtual_card_information = _parse_octet(
        _need(fields, "PICC Virtual Card Information"), "PICC Virtual Card Information"
    )
    caps = _parse_hex(_need(fields, "PICC Virtual Card Capabilities"))
    if len(caps) != VIRTUAL_CARD_CAPABILITY_LEN:
        raise DfcError(
            f"PICC Virtual Card Capabilities must be {VIRTUAL_CARD_CAPABILITY_LEN} bytes"
        )
    cred.virtual_card_capabilities = caps
    uid = _parse_hex(_need(fields, "PICC Virtual Card UID"))
    if len(uid) not in (4, 7, 10):
        raise DfcError("PICC Virtual Card UID must be 4, 7, or 10 bytes")
    cred.virtual_card_uid = uid
    mac_key = _parse_hex(_need(fields, "PICC Virtual Card Select MAC Key"))
    if len(mac_key) != AES_KEY_LEN:
        raise DfcError(f"PICC Virtual Card Select MAC Key must be {AES_KEY_LEN} bytes")
    cred.virtual_card_select_mac_key = mac_key
    enc_key = _parse_hex(_need(fields, "PICC Virtual Card Select Encryption Key"))
    if len(enc_key) != AES_KEY_LEN:
        raise DfcError(
            f"PICC Virtual Card Select Encryption Key must be {AES_KEY_LEN} bytes"
        )
    cred.virtual_card_select_encryption_key = enc_key
    cred.virtual_card_authentication_mandatory = _parse_bool(
        _need(fields, "PICC Virtual Card Authentication Mandatory"),
        "PICC Virtual Card Authentication Mandatory",
    )
    cred.virtual_card_proximity_mandatory = _parse_bool(
        _need(fields, "PICC Virtual Card Proximity Mandatory"),
        "PICC Virtual Card Proximity Mandatory",
    )
    cred.virtual_card_configured = True


def _parse_dam_keys(fields: dict[str, str], cred: "DfcCredential") -> None:
    if "PICC DAM Authentication Key" not in fields:
        return
    for name, attr in (
        ("PICC DAM Authentication Key", "picc_dam_auth_key"),
        ("PICC DAM MAC Key", "picc_dam_mac_key"),
        ("PICC DAM Encryption Key", "picc_dam_encryption_key"),
    ):
        value = _parse_hex(_need(fields, name))
        if len(value) != AES_KEY_LEN:
            raise DfcError(f"{name} must be {AES_KEY_LEN} bytes")
        setattr(cred, attr, value)
    cred.picc_has_dam_keys = True


def _parse_key_sets(fields: dict[str, str], prefix: str, app: DfcApplication) -> None:
    key_count = _parse_decimal(
        _need(fields, f"{prefix}Key Set Key Count"), f"{prefix}Key Set Key Count"
    )
    if not 1 <= key_count <= MAX_KEYS:
        raise DfcError(f"{prefix}Key Set Key Count out of range")
    max_size = _parse_decimal(
        _need(fields, f"{prefix}Key Set Maximum Key Size"),
        f"{prefix}Key Set Maximum Key Size",
    )
    if max_size not in (16, 24):
        raise DfcError(f"{prefix}Key Set Maximum Key Size must be 16 or 24")
    app.key_set_key_count = key_count
    app.key_set_max_size = max_size
    app.key_set_settings = _parse_octet(
        _need(fields, f"{prefix}Key Set Settings"), f"{prefix}Key Set Settings"
    )
    count = _parse_decimal(
        _need(fields, f"{prefix}Key Set Count"), f"{prefix}Key Set Count"
    )
    if not KEY_SET_MINIMUM_COUNT <= count <= KEY_SET_MAX_SETS:
        raise DfcError(f"{prefix}Key Set Count out of range")

    for set_index in range(count):
        name = f"{prefix}Key Set {set_index:02X} "
        ks = DfcKeySet()
        ks.version = _parse_octet(_need(fields, f"{name}Version"), f"{name}Version")
        type_name = _need(fields, f"{name}Type")
        if type_name not in KEY_SET_TYPE_NAMES:
            raise DfcError(f"{name}Type {type_name!r} is not a known key-set type")
        ks.type = KEY_SET_TYPE_NAMES.index(type_name)
        required = 24 if ks.type == KEY_SET_TYPE_3K3DES else AES_KEY_LEN
        if required > max_size:
            raise DfcError(f"{name}Type: key type exceeds the maximum key size")
        ks.initialized = _parse_bool(
            _need(fields, f"{name}Initialized"), f"{name}Initialized"
        )
        set_keys = _parse_decimal(
            _need(fields, f"{name}Key Count"), f"{name}Key Count"
        )
        if set_keys > key_count:
            raise DfcError(f"{name}Key Count exceeds the key set's key count")
        for slot in range(set_keys):
            raw = _parse_hex(_need(fields, f"{name}Key {slot:02X}"))
            if len(raw) != required:
                raise DfcError(f"{name}Key {slot:02X} is {len(raw)} bytes, expected {required}")
            version = _parse_octet(
                _need(fields, f"{name}Key {slot:02X} Version"),
                f"{name}Key {slot:02X} Version",
            )
            ks.keys.append(DfcKey(raw, version))
        app.key_sets.append(ks)
    if not app.key_sets[0].initialized:
        raise DfcError(f"{prefix}Key Set 00: set zero shall be initialized")


def _parse_capability_data(fields: dict[str, str], prefix: str, app: DfcApplication) -> None:
    if f"{prefix}Capability Data" not in fields:
        return
    data = _parse_hex(fields[f"{prefix}Capability Data"])
    if len(data) != APPLICATION_CAPABILITY_DATA_LEN:
        raise DfcError(
            f"{prefix}Capability Data must be {APPLICATION_CAPABILITY_DATA_LEN} bytes"
        )
    app.capability_data = data
    app.has_capability_data = True


def _parse_delegated(fields: dict[str, str], prefix: str, app: DfcApplication) -> None:
    if f"{prefix}Delegated Slot Number" not in fields:
        return
    app.delegated_slot_number = _parse_decimal(
        fields[f"{prefix}Delegated Slot Number"], f"{prefix}Delegated Slot Number"
    )
    app.delegated_slot_version = _parse_octet(
        _need(fields, f"{prefix}Delegated Slot Version"),
        f"{prefix}Delegated Slot Version",
    )
    app.delegated_quota_limit = _parse_decimal(
        _need(fields, f"{prefix}Delegated Quota Limit"),
        f"{prefix}Delegated Quota Limit",
    )
    app.delegated_free_blocks = _parse_decimal(
        _need(fields, f"{prefix}Delegated Free Blocks"),
        f"{prefix}Delegated Free Blocks",
    )
    if not 0 <= app.delegated_slot_number <= 0xFFFF:
        raise DfcError(f"{prefix}Delegated Slot Number out of range")
    if not 0 <= app.delegated_quota_limit <= 0xFFFF:
        raise DfcError(f"{prefix}Delegated Quota Limit out of range")
    if not 0 <= app.delegated_free_blocks <= 0xFFFF:
        raise DfcError(f"{prefix}Delegated Free Blocks out of range")
    if app.delegated_free_blocks > app.delegated_quota_limit:
        raise DfcError(f"{prefix}Delegated Free Blocks: exceeds the quota")
    app.delegated = True


def _parse_sdm(fields: dict[str, str], prefix: str, f: DfcFile) -> None:
    if f"{prefix}SDM Options" not in fields:
        return
    f.sdm_options = _parse_octet(fields[f"{prefix}SDM Options"], f"{prefix}SDM Options")
    rights = _parse_hex(_need(fields, f"{prefix}SDM Access Rights"))
    if len(rights) != 2:
        raise DfcError(f"{prefix}SDM Access Rights must be 2 bytes")
    f.sdm_access_rights = int.from_bytes(rights, "big")

    offsets = (
        ("UID Offset", "sdm_has_uid_offset", "sdm_uid_offset"),
        ("Counter Offset", "sdm_has_counter_offset", "sdm_counter_offset"),
        ("PICC Data Offset", "sdm_has_picc_data_offset", "sdm_picc_data_offset"),
        ("MAC Input Offset", "sdm_has_mac_input_offset", "sdm_mac_input_offset"),
        ("MAC Offset", "sdm_has_mac_offset", "sdm_mac_offset"),
        (
            "Encrypted File Offset",
            "sdm_has_encrypted_file_offset",
            "sdm_encrypted_file_offset",
        ),
    )
    for name, has_attr, value_attr in offsets:
        key = f"{prefix}SDM {name}"
        if key in fields:
            value = _parse_decimal(fields[key], key)
            if not 0 <= value <= U24_MAX:
                raise DfcError(f"{key} out of range")
            setattr(f, has_attr, True)
            setattr(f, value_attr, value)

    length_key = f"{prefix}SDM Encrypted File Length"
    has_length = length_key in fields
    if has_length != f.sdm_has_encrypted_file_offset:
        raise DfcError(f"{prefix}: SDM encrypted offset and length occur together")
    if has_length:
        length = _parse_decimal(fields[length_key], length_key)
        if not 0 <= length <= U24_MAX:
            raise DfcError(f"{length_key} out of range")
        f.sdm_encrypted_file_length = length

    limit_key = f"{prefix}SDM Counter Limit"
    if limit_key in fields:
        limit = _parse_decimal(fields[limit_key], limit_key)
        if not 0 <= limit <= U24_MAX:
            raise DfcError(f"{limit_key} out of range")
        f.sdm_has_counter_limit = True
        f.sdm_counter_limit = limit

    f.sdm_read_counter = _parse_decimal(
        _need(fields, f"{prefix}SDM Read Counter"), f"{prefix}SDM Read Counter"
    )
    if not 0 <= f.sdm_read_counter <= U24_MAX:
        raise DfcError(f"{prefix}SDM Read Counter out of range")
    f.sdm_enabled = True


def _parse_transaction_mac_contents(fields: dict[str, str], prefix: str, f: DfcFile) -> None:
    f.transaction_counter = _parse_decimal(
        _need(fields, f"{prefix}Transaction Counter"), f"{prefix}Transaction Counter"
    )
    if not 0 <= f.transaction_counter <= U32_MAX:
        raise DfcError(f"{prefix}Transaction Counter out of range")
    mac = _parse_hex(_need(fields, f"{prefix}Transaction MAC"))
    if len(mac) != WIRE_MAC_LEN:
        raise DfcError(f"{prefix}Transaction MAC must be {WIRE_MAC_LEN} bytes")
    f.transaction_mac = mac
    key_type = _parse_decimal(
        _need(fields, f"{prefix}Transaction Key Type"), f"{prefix}Transaction Key Type"
    )
    if not 0 <= key_type <= 0xFF:
        raise DfcError(f"{prefix}Transaction Key Type out of range")
    f.transaction_mac_key_type = key_type
    f.transaction_mac_key_version = _parse_octet(
        _need(fields, f"{prefix}Transaction Key Version"),
        f"{prefix}Transaction Key Version",
    )
    key = _parse_hex(_need(fields, f"{prefix}Transaction Key"))
    if len(key) != AES_KEY_LEN:
        raise DfcError(f"{prefix}Transaction Key must be {AES_KEY_LEN} bytes")
    f.transaction_mac_key = key
    reader_id = _parse_hex(_need(fields, f"{prefix}Previous Reader ID"))
    if len(reader_id) != TRANSACTION_READER_ID_LEN:
        raise DfcError(f"{prefix}Previous Reader ID must be {TRANSACTION_READER_ID_LEN} bytes")
    f.previous_reader_id = reader_id


def _parse_v4(cls, fields: dict[str, str]) -> "DfcCredential":
    cred = cls()
    generation = fields.get("Card Generation", "")
    if generation not in GENERATIONS:
        raise DfcError(f"unknown Card Generation {generation!r}")
    cred.generation = GENERATIONS[generation]
    cred.storage = _parse_decimal(
        fields.get("Card Storage", str(DEFAULT_CARD_STORAGE)), "Card Storage"
    )
    cred.hardware_version = _parse_hex(fields.get("Card Hardware Version", ""))
    cred.software_version = _parse_hex(fields.get("Card Software Version", ""))
    cred.uid = _parse_uid(fields)
    provenance = fields.get("UID Provenance", "")
    if provenance not in PROVENANCES:
        raise DfcError(f"unknown UID Provenance {provenance!r}")
    cred.uid_provenance = PROVENANCES[provenance]
    _parse_static_signature(fields, cred)

    cred.picc_key_settings_1 = _parse_octet(
        _need(fields, "PICC Key Settings 1"), "PICC Key Settings 1"
    )
    cred.picc_key_settings_2 = _parse_octet(
        _need(fields, "PICC Key Settings 2"), "PICC Key Settings 2"
    )
    if "PICC Authentication Commands" in fields:
        cred.picc_auth_mask = _parse_auth_commands(
            fields["PICC Authentication Commands"]
        )
        cred.picc_preferred_cmd = _parse_preferred(
            fields.get("PICC Preferred Authentication Command"),
            cred.picc_auth_mask,
            "PICC",
        )
        cred.cred_version = 6
        cred.picc_auth_command = _native_from_mask(
            cred.picc_auth_mask, cred.picc_preferred_cmd
        )
    else:
        cred.picc_auth_command = _auth_mode(
            fields.get("PICC Authentication Mode"), cred.picc_key_settings_2
        )
    picc_key_count = _parse_decimal(_need(fields, "PICC Key Count"), "PICC Key Count")
    if picc_key_count > MAX_KEYS:
        raise DfcError(f"PICC Key Count exceeds {MAX_KEYS}")
    cred.picc_keys = _parse_key_list(fields, "PICC ", picc_key_count, cred.picc_key_len)
    if "PICC Random ID" in fields:
        cred.picc_random_id = _parse_bool(fields["PICC Random ID"], "PICC Random ID")
    if "PICC Format Disabled" in fields:
        cred.picc_format_disabled = _parse_bool(
            fields["PICC Format Disabled"], "PICC Format Disabled"
        )
    if "PICC ATS" in fields:
        cred.picc_ats = _parse_hex(fields["PICC ATS"])
        if not cred.picc_ats:
            raise DfcError("PICC ATS is present but empty")
    if "PICC SAK" in fields:
        cred.picc_sak = _parse_octet(fields["PICC SAK"], "PICC SAK")
    if "PICC ATQA" in fields:
        atqa = _parse_hex(fields["PICC ATQA"])
        if len(atqa) != 2:
            raise DfcError(f"PICC ATQA must be 2 bytes, got {len(atqa)}")
        cred.picc_atqa = atqa
    if "PICC SM Disable" in fields:
        cred.picc_sm_disable = _parse_octet(
            fields["PICC SM Disable"], "PICC SM Disable"
        )
    _parse_ev2_capabilities(fields, cred)
    _parse_proximity(fields, cred)
    _parse_virtual_card(fields, cred)
    _parse_dam_keys(fields, cred)

    picc_file_count = _parse_decimal(
        fields.get("PICC File Count", "0"), "PICC File Count"
    )
    for i in range(picc_file_count):
        cred.files.append(_parse_file_v3(fields, f"PICC File {i:02X} ", OWNER_PICC))

    app_count = _parse_decimal(_need(fields, "Application Count"), "Application Count")
    app_files: list[DfcFile] = []
    for i in range(app_count):
        prefix = f"Application {i:02X} "
        app = DfcApplication()
        app.aid = _parse_hex(_need(fields, f"{prefix}AID"))
        if len(app.aid) != 3:
            raise DfcError(f"{prefix}AID must be 3 bytes, got {len(app.aid)}")
        if f"{prefix}ISO File ID" in fields:
            fid = _parse_hex(fields[f"{prefix}ISO File ID"])
            if len(fid) != 2:
                raise DfcError(f"{prefix}ISO File ID must be 2 bytes")
            app.has_iso_file_id = True
            app.iso_file_id = int.from_bytes(fid, "big")
        if f"{prefix}DF Name" in fields:
            app.iso_aid = _parse_hex(fields[f"{prefix}DF Name"])
            if not 1 <= len(app.iso_aid) <= 16:
                raise DfcError(f"{prefix}DF Name must be 1 to 16 bytes")
        app.key_settings_1 = _parse_octet(
            _need(fields, f"{prefix}Key Settings 1"), f"{prefix}Key Settings 1"
        )
        app.key_settings_2 = _parse_octet(
            _need(fields, f"{prefix}Key Settings 2"), f"{prefix}Key Settings 2"
        )
        if f"{prefix}Authentication Commands" in fields:
            app.auth_mask = _parse_auth_commands(
                fields[f"{prefix}Authentication Commands"]
            )
            app.preferred_cmd = _parse_preferred(
                fields.get(f"{prefix}Preferred Authentication Command"),
                app.auth_mask,
                prefix.strip(),
            )
            if f"{prefix}SM Disable" in fields:
                app.sm_disable = _parse_octet(
                    fields[f"{prefix}SM Disable"], f"{prefix}SM Disable"
                )
            cred.cred_version = 6
            app.auth_command = _native_from_mask(app.auth_mask, app.preferred_cmd)
        else:
            app.auth_command = _auth_mode(
                fields.get(f"{prefix}Authentication Mode"), app.key_settings_2
            )
        app.key_len = key_length_for_ks2(app.key_settings_2)
        # The key-set block replaces the ordinary key list.
        if f"{prefix}Key Set Count" in fields:
            _parse_key_sets(fields, prefix, app)
        else:
            key_count = _parse_decimal(
                _need(fields, f"{prefix}Key Count"), f"{prefix}Key Count"
            )
            if key_count > MAX_KEYS:
                raise DfcError(f"{prefix}Key Count exceeds {MAX_KEYS}")
            app.keys = _parse_key_list(fields, prefix, key_count, app.key_len)
        cred.apps.append(app)

        file_count = _parse_decimal(
            _need(fields, f"{prefix}File Count"), f"{prefix}File Count"
        )
        for j in range(file_count):
            app_files.append(_parse_file_v3(fields, f"{prefix}File {j:02X} ", i))
        _parse_capability_data(fields, prefix, app)
        _parse_delegated(fields, prefix, app)

    # Applications own their files; the PICC container is encoded after them, so
    # keep the model in that order too.
    cred.files = app_files + cred.files
    return cred


def _need(fields: dict[str, str], key: str) -> str:
    if key not in fields:
        raise DfcError(f"required key {key!r} is missing")
    return fields[key]


def _parse_file_v3(fields: dict[str, str], prefix: str, owner: int) -> DfcFile:
    f = DfcFile(app_index=owner)
    f.number = _parse_octet(_need(fields, f"{prefix}Number"), f"{prefix}Number")
    type_name = _need(fields, f"{prefix}Type")
    if type_name not in FILE_TYPES:
        raise DfcError(f"{prefix}Type {type_name!r} is not a known file type")
    f.type = FILE_TYPES[type_name]
    f.comm_settings = _parse_octet(
        _need(fields, f"{prefix}Communication Settings"),
        f"{prefix}Communication Settings",
    )
    access = _parse_hex(_need(fields, f"{prefix}Access Rights"))
    if len(access) != 2:
        raise DfcError(f"{prefix}Access Rights must be 2 bytes")
    f.access_rights = int.from_bytes(access, "big")
    if f"{prefix}ISO File ID" in fields:
        fid = _parse_hex(fields[f"{prefix}ISO File ID"])
        if len(fid) != 2:
            raise DfcError(f"{prefix}ISO File ID must be 2 bytes")
        f.has_iso_file_id = True
        f.iso_file_id = int.from_bytes(fid, "big")

    if f.type in (FILE_TYPE_STANDARD, FILE_TYPE_BACKUP):
        f.declared_size = _parse_decimal(
            _need(fields, f"{prefix}Size"), f"{prefix}Size"
        )
        f.data = _parse_hex(fields.get(f"{prefix}Data", ""))
        f.contents_complete = _parse_bool(
            _need(fields, f"{prefix}Data Complete"), f"{prefix}Data Complete"
        )
        _parse_sdm(fields, prefix, f)
    elif f.type == FILE_TYPE_TMAC:
        _parse_transaction_mac_contents(fields, prefix, f)
    elif f.type == FILE_TYPE_VALUE:
        f.value_lower_limit = _parse_decimal(
            _need(fields, f"{prefix}Value Lower Limit"),
            f"{prefix}Value Lower Limit",
            True,
        )
        f.value_upper_limit = _parse_decimal(
            _need(fields, f"{prefix}Value Upper Limit"),
            f"{prefix}Value Upper Limit",
            True,
        )
        f.value = _parse_decimal(
            _need(fields, f"{prefix}Value"), f"{prefix}Value", True
        )
        f.limited_credit = _parse_octet(
            _need(fields, f"{prefix}Limited Credit"), f"{prefix}Limited Credit"
        )
    else:
        f.record_size = _parse_decimal(
            _need(fields, f"{prefix}Record Size"), f"{prefix}Record Size"
        )
        f.max_records = _parse_decimal(
            _need(fields, f"{prefix}Max Records"), f"{prefix}Max Records"
        )
        f.record_count = _parse_decimal(
            _need(fields, f"{prefix}Record Count"), f"{prefix}Record Count"
        )
        f.contents_complete = _parse_bool(
            _need(fields, f"{prefix}Record Complete"), f"{prefix}Record Complete"
        )
        for r in range(f.record_count):
            key = f"{prefix}Record {r:02X}"
            if key not in fields:
                break
            f.records.append(_parse_hex(fields[key]))
    return f
