"""
Minimal NDEF (NFC Data Exchange Format) encoder/decoder.

Covers what's needed to read and write NDEF messages stored in the
Type 2 Tag (MIFARE Ultralight / NTAG) TLV area:
 - TLV wrapping/unwrapping (NDEF Message TLV 0x03, Terminator TLV 0xFE,
   and skipping over Lock Control / Memory Control / Proprietary / NULL TLVs)
 - NDEF record encode/decode for the common well-known types (Text, URI)
   plus generic/raw records for anything else.

This intentionally does not try to be a complete NDEF/NFC Forum library;
it covers the record types people actually write to tags day to day.
"""

import struct


class NdefError(Exception):
    pass


# ---------------------------------------------------------------------------
# TLV (Type-Length-Value) helpers - Type 2 Tag memory layout
# ---------------------------------------------------------------------------

TLV_NULL = 0x00
TLV_LOCK_CONTROL = 0x01
TLV_MEMORY_CONTROL = 0x02
TLV_NDEF_MESSAGE = 0x03
TLV_PROPRIETARY = 0xFD
TLV_TERMINATOR = 0xFE


def find_ndef_message(area: bytes):
    """
    Walk the TLV blocks in a Type 2 Tag user memory dump and return the
    raw NDEF message bytes (the value of the first NDEF Message TLV).

    Returns None if no NDEF Message TLV is found.
    """
    i = 0
    n = len(area)
    while i < n:
        tag = area[i]
        if tag == TLV_NULL:
            i += 1
            continue
        if tag == TLV_TERMINATOR:
            break
        if i + 1 >= n:
            break
        length = area[i + 1]
        if length == 0xFF:
            if i + 4 > n:
                break
            length = struct.unpack("!H", area[i + 2:i + 4])[0]
            value_start = i + 4
        else:
            value_start = i + 2
        value_end = value_start + length
        if value_end > n:
            # truncated TLV, best effort: return what we have
            value_end = n
        if tag == TLV_NDEF_MESSAGE:
            return area[value_start:value_end]
        i = value_end
    return None


def wrap_ndef_message(message: bytes) -> bytes:
    """
    Wrap a raw NDEF message in an NDEF Message TLV, followed by a
    Terminator TLV, ready to be written starting at the first user page.
    """
    length = len(message)
    if length < 0xFF:
        header = struct.pack("!BB", TLV_NDEF_MESSAGE, length)
    else:
        header = struct.pack("!BBH", TLV_NDEF_MESSAGE, 0xFF, length)
    return header + message + bytes([TLV_TERMINATOR])


# ---------------------------------------------------------------------------
# NDEF record encode/decode
# ---------------------------------------------------------------------------

TNF_EMPTY = 0x00
TNF_WELL_KNOWN = 0x01
TNF_MIME_MEDIA = 0x02
TNF_ABSOLUTE_URI = 0x03
TNF_EXTERNAL = 0x04
TNF_UNKNOWN = 0x05
TNF_UNCHANGED = 0x06

TNF_NAMES = {
    TNF_EMPTY: "Empty",
    TNF_WELL_KNOWN: "Well-known",
    TNF_MIME_MEDIA: "Media (MIME)",
    TNF_ABSOLUTE_URI: "Absolute URI",
    TNF_EXTERNAL: "External",
    TNF_UNKNOWN: "Unknown",
    TNF_UNCHANGED: "Unchanged (chunk)",
    0x07: "Reserved",
}

# NFC Forum URI Record Type Definition abbreviation table (RTD-URI 1.0)
URI_PREFIXES = [
    "", "http://www.", "https://www.", "http://", "https://",
    "tel:", "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.",
    "ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://",
    "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:",
    "sip:", "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://",
    "tcpobex://", "irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:",
    "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:",
]


class NdefRecord:
    def __init__(self, tnf, type_bytes=b"", payload=b"", id_bytes=b""):
        self.tnf = tnf
        self.type = type_bytes
        self.payload = payload
        self.id = id_bytes

    def __repr__(self):
        return f"NdefRecord(tnf={self.tnf}, type={self.type!r}, payload={self.payload!r})"

    # -- well-known constructors ------------------------------------------------

    @classmethod
    def text(cls, text: str, lang: str = "en", utf16: bool = False):
        lang_bytes = lang.encode("ascii")
        if len(lang_bytes) > 0x3F:
            raise NdefError("Language code too long")
        status = (0x80 if utf16 else 0x00) | len(lang_bytes)
        encoded_text = text.encode("utf-16-be" if utf16 else "utf-8")
        payload = bytes([status]) + lang_bytes + encoded_text
        return cls(TNF_WELL_KNOWN, b"T", payload)

    @classmethod
    def uri(cls, uri: str):
        best_idx = 0
        best_len = 0
        for idx, prefix in enumerate(URI_PREFIXES):
            if prefix and uri.startswith(prefix) and len(prefix) > best_len:
                best_idx = idx
                best_len = len(prefix)
        payload = bytes([best_idx]) + uri[best_len:].encode("utf-8")
        return cls(TNF_WELL_KNOWN, b"U", payload)

    @classmethod
    def mime(cls, mime_type: str, data: bytes):
        return cls(TNF_MIME_MEDIA, mime_type.encode("ascii"), data)

    @classmethod
    def raw(cls, tnf: int, type_bytes: bytes, payload: bytes, id_bytes: bytes = b""):
        return cls(tnf, type_bytes, payload, id_bytes)

    # -- decoding helpers ---------------------------------------------------

    def describe(self) -> str:
        """Human readable one-liner used by `hf mfu ndefread`."""
        if self.tnf == TNF_WELL_KNOWN and self.type == b"T":
            try:
                status = self.payload[0]
                lang_len = status & 0x3F
                utf16 = bool(status & 0x80)
                lang = self.payload[1:1 + lang_len].decode("ascii", "replace")
                text = self.payload[1 + lang_len:].decode(
                    "utf-16-be" if utf16 else "utf-8", "replace"
                )
                return f'Text [{lang}]: "{text}"'
            except (IndexError, UnicodeDecodeError):
                return f"Text record (malformed payload {self.payload.hex()})"
        if self.tnf == TNF_WELL_KNOWN and self.type == b"U":
            try:
                idx = self.payload[0]
                prefix = URI_PREFIXES[idx] if idx < len(URI_PREFIXES) else ""
                uri = prefix + self.payload[1:].decode("utf-8", "replace")
                return f"URI: {uri}"
            except IndexError:
                return f"URI record (malformed payload {self.payload.hex()})"
        if self.tnf == TNF_MIME_MEDIA:
            return f"MIME [{self.type.decode('ascii', 'replace')}]: {len(self.payload)} bytes"
        type_str = self.type.decode("ascii", "replace") if self.type else "(none)"
        return (
            f"{TNF_NAMES.get(self.tnf, 'Unknown TNF')} record, type={type_str}, "
            f"{len(self.payload)} bytes payload"
        )


def encode_message(records) -> bytes:
    """Encode a list of NdefRecord into a raw NDEF message."""
    if not records:
        raise NdefError("At least one record is required")

    out = bytearray()
    for i, rec in enumerate(records):
        mb = 0x80 if i == 0 else 0x00
        me = 0x40 if i == len(records) - 1 else 0x00
        il = 0x08 if rec.id else 0x00
        short = len(rec.payload) < 0x100
        sr = 0x10 if short else 0x00
        header = mb | me | sr | il | (rec.tnf & 0x07)

        out.append(header)
        out.append(len(rec.type))
        if short:
            out.append(len(rec.payload))
        else:
            out += struct.pack("!I", len(rec.payload))
        if il:
            out.append(len(rec.id))
        out += rec.type
        if il:
            out += rec.id
        out += rec.payload
    return bytes(out)


def decode_message(data: bytes):
    """Decode a raw NDEF message into a list of NdefRecord."""
    records = []
    i = 0
    n = len(data)
    while i < n:
        header = data[i]
        tnf = header & 0x07
        il = bool(header & 0x08)
        sr = bool(header & 0x10)
        i += 1

        if i >= n:
            raise NdefError("Truncated record header")
        type_len = data[i]
        i += 1

        if sr:
            if i >= n:
                raise NdefError("Truncated payload length")
            payload_len = data[i]
            i += 1
        else:
            if i + 4 > n:
                raise NdefError("Truncated payload length")
            payload_len = struct.unpack("!I", data[i:i + 4])[0]
            i += 4

        id_len = 0
        if il:
            if i >= n:
                raise NdefError("Truncated ID length")
            id_len = data[i]
            i += 1

        type_bytes = data[i:i + type_len]
        i += type_len
        id_bytes = data[i:i + id_len] if il else b""
        i += id_len
        payload = data[i:i + payload_len]
        i += payload_len

        records.append(NdefRecord(tnf, type_bytes, payload, id_bytes))

        if header & 0x40:  # ME - message end
            break
    return records


def pages_from_message(wrapped_tlv: bytes, page_size: int = 4):
    """Split TLV-wrapped NDEF bytes into page_size-byte pages, zero padded."""
    padded = wrapped_tlv + bytes(
        (-len(wrapped_tlv)) % page_size
    )
    return [padded[i:i + page_size] for i in range(0, len(padded), page_size)]
