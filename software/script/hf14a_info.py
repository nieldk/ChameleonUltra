"""pm3-style ISO14443-A identification helpers (ported from Proxmark3
client/src/cmdhf14a.c). Pure functions, no device access."""

# Manufacturer by UID0 (ISO/IEC 7816-6 / pm3 manufactureMapping)
MANUFACTURERS = {
    0x01: 'Motorola UK',
    0x02: 'ST Microelectronics SA France',
    0x03: 'Hitachi, Ltd Japan',
    0x04: 'NXP Semiconductors Germany',
    0x05: 'Infineon Technologies AG Germany',
    0x06: 'Cylink USA',
    0x07: 'Texas Instrument France',
    0x08: 'Fujitsu Limited Japan',
    0x09: 'Matsushita Electronics Corporation, Semiconductor Company Japan',
    0x0A: 'NEC Japan',
    0x0B: 'Oki Electric Industry Co. Ltd Japan',
    0x0C: 'Toshiba Corp. Japan',
    0x0D: 'Mitsubishi Electric Corp. Japan',
    0x0E: 'Samsung Electronics Co. Ltd Korea',
    0x0F: 'Hynix / Hyundai, Korea',
    0x10: 'LG-Semiconductors Co. Ltd Korea',
    0x11: 'Emosyn-EM Microelectronics USA',
    0x12: 'Wisekey Semiconductors (previously INSIDE Technology) France',
    0x13: 'ORGA Kartensysteme GmbH Germany',
    0x14: 'SHARP Corporation Japan',
    0x15: 'ATMEL France',
    0x16: 'EM Microelectronic-Marin SA Switzerland',
    0x17: 'SMARTRAC TECHNOLOGY GmbH Germany',
    0x18: 'ZMD AG Germany',
    0x19: 'XICOR, Inc. USA',
    0x1A: 'Sony Corporation Japan',
    0x1B: 'Malaysia Microelectronic Solutions Sdn. Bhd Malaysia',
    0x1C: 'Emosyn USA',
    0x1D: 'Shanghai Fudan Microelectronics Co. Ltd. P.R. China',
    0x1E: 'Magellan Technology Pty Limited Australia',
    0x1F: 'Melexis NV BO Switzerland',
    0x20: 'Renesas Technology Corp. Japan',
    0x21: 'TAGSYS France',
    0x22: 'Transcore USA',
    0x23: 'Shanghai belling corp., ltd. China',
    0x24: 'Masktech Germany Gmbh Germany',
    0x25: 'Innovision Research and Technology Plc UK',
    0x26: 'Hitachi ULSI Systems Co., Ltd. Japan',
    0x27: 'Yubico AB Sweden',
    0x28: 'Ricoh Japan',
    0x29: 'ASK France',
    0x2A: 'Unicore Microsystems, LLC Russian Federation',
    0x2B: 'Dallas Semiconductor/Maxim USA',
    0x2C: 'Impinj, Inc. USA',
    0x2D: 'RightPlug Alliance USA',
    0x2E: 'Broadcom Corporation USA',
    0x2F: 'MStar Semiconductor, Inc Taiwan, ROC',
    0x30: 'BeeDar Technology Inc. USA',
    0x31: 'RFIDsec Denmark',
    0x32: 'Schweizer Electronic AG Germany',
    0x33: 'AMIC Technology Corp Taiwan',
    0x34: 'Mikron JSC Russia',
    0x35: 'Fraunhofer Institute for Photonic Microsystems Germany',
    0x36: 'IDS Microchip AG Switzerland',
    0x37: 'Kovio USA',
    0x38: 'HMT Microelectronic Ltd Switzerland',
    0x39: 'Silicon Craft Technology Thailand',
    0x3A: 'Advanced Film Device Inc. Japan',
    0x3B: 'Nitecrest Ltd UK',
    0x3C: 'Verayo Inc. USA',
    0x3D: 'HID Global USA',
    0x3E: 'Productivity Engineering Gmbh Germany',
    0x3F: 'Austriamicrosystems AG (reserved) Austria',
    0x40: 'Thales DIS (previously Gemalto SA) France',
    0x41: 'Renesas Electronics Corporation Japan',
    0x42: '3Alogics Inc Korea',
    0x43: 'Top TroniQ Asia Limited Hong Kong',
    0x44: 'Gentag Inc. USA',
    0x45: 'Invengo Information Technology Co. Ltd China',
    0x46: 'Guangzhou Sysur Microelectronics, Inc China',
    0x47: 'CEITEC S.A. Brazil',
    0x48: 'Shanghai Quanray Electronics Co. Ltd. China',
    0x49: 'MediaTek Inc Taiwan',
    0x4A: 'Angstrem PJSC Russia',
    0x4B: 'Celisic Semiconductor (Hong Kong) Limited China',
    0x4C: 'LEGIC Identsystems AG Switzerland',
    0x4D: 'Balluff GmbH Germany',
    0x4E: 'Oberthur Technologies France',
    0x4F: 'Silterra Malaysia Sdn. Bhd. Malaysia',
    0x50: 'Presto Engineering Denmark',
    0x51: 'Giesecke & Devrient GmbH Germany',
    0x52: 'Shenzhen China Vision Microelectronics Co., Ltd. China',
    0x53: 'Shanghai Feiju Microelectronics Co. Ltd. China',
    0x54: 'Intel Corporation USA',
    0x55: 'Microsensys GmbH Germany',
    0x56: 'Sonix Technology Co., Ltd. Taiwan',
    0x57: 'Qualcomm Technologies Inc USA',
    0x58: 'Realtek Semiconductor Corp Taiwan',
    0x59: 'Freevision Technologies Co. Ltd China',
    0x5A: 'Giantec Semiconductor Inc. China',
    0x5B: 'JSC Angstrem-T Russia',
    0x5C: 'STARCHIP France',
    0x5D: 'SPIRTECH France',
    0x5E: 'GANTNER Electronic GmbH Austria',
    0x5F: 'Nordic Semiconductor Norway',
    0x60: 'Verisiti Inc USA',
    0x61: 'Wearlinks Technology Inc. China',
    0x62: 'Userstar Information Systems Co., Ltd Taiwan',
    0x63: 'Pragmatic Printing Ltd. UK',
    0x64: 'Associação do Laboratório de Sistemas Integráveis Tecnológico - LSI-TEC Brazil',
    0x65: 'Tendyron Corporation China',
    0x66: 'MUTO Smart Co., Ltd. Korea',
    0x67: 'ON Semiconductor USA',
    0x68: 'TÜBITAK BILGEM Turkey',
    0x69: 'Huada Semiconductor Co., Ltd China',
    0x6A: 'SEVENEY France',
    0x6B: 'THALES DIS Design Services SAS (previously ISSM) France',
    0x6C: 'Wisesec Ltd Israel',
    0x6D: 'LTD \\"NM-Teh\\" Russia',
    0x70: 'ifm electronic gmbh Germany',
    0x71: 'Sichuan Kiloway Technologies Co., Ltd. China',
    0x72: 'Ford Motor Company US',
    0x73: 'Beijing Tsingteng MicroSystem Co.,Ltd China',
    0x74: 'Huada EverCore Co., Ltd China',
    0x75: 'Smartchip Microelectronics Corporation Taiwan',
    0x76: 'Tongxin Microelectronics Co., Ltd. China',
    0x77: 'Ningbo IOT Microelectronics Co Ltd China',
    0x78: 'AU Optronics Taiwan',
    0x79: 'CUBIC USA',
    0x7A: 'Abbott Diabetes Care USA',
    0x7B: 'Shenzen Nation RFID Technology Co Ltd China',
    0x7C: 'DB HiTek Co Ltd Korea',
    0x7D: 'SATO Vicinity Australia',
    0x7E: 'Holtek Taiwan',
    0x7F: 'Shenzhen Goodix Technology Co., Ltd. China',
    0x80: 'Panthronics AG Austria',
    0x81: 'Beijing Huada Infosec Technology Co., Ltd China',
    0x82: 'Shanghai Oriental Magnetic Card Engineering Co Ltd. China',
    0x83: '8ApeX Inc USA',
    0x84: 'Abbott Ireland',
    0x85: 'Proqure Inc USA',
    0x86: 'Schreiner Group GmbH & Co. KG Germany',
    0x87: 'Beijing SmartChip Microelectronics Technology Company Limited China',
    0x88: 'Datang Microelectronics Technology Co., Ltd. China',
    0x89: 'Wise Security Technology (Guangzhou) Co., Ltd. China',
    0x8A: 'CEC Huada Electronic Design Co., Ltd. China',
    0x8B: 'Shanghai Techsun RFID Technology Co., Ltd. China',
    0x8C: 'North China Institute of Computing Technology China',
    0x8D: 'Shanghai Huahong Integrated Circuit Co., Ltd. China',
    0x8E: 'Shanghai MintSilicon Microelectronics Inc., Ltd. China',
    0x8F: 'Xinsheng Technology Co., Ltd. China',
    0x90: 'IDEX Biometrics ASA Norway',
    0x91: 'Novo Nordisk A/S Denmark',
    0x92: 'Shandong Huayi Micro-Electronics Technology Co., Ltd. China',
    0x93: 'Abbott Heart Failure USA',
    0x94: 'P&M Information Technology (Shenzhen) Co., Ltd. China',
    0x95: 'MARS TECHNOLOGY PTE. LTD. Singapore',
    0x96: 'Trovan Limited Isle of Man',
}

# (uid0, uid1) -> label, pm3 uid_label_map
UID_LABELS = {
    (0x02, 0x84): "M24SR64-Y",
    (0x02, 0xA3): "25TA02KB-P",
    (0x02, 0xC4): "25TA64K",
    (0x02, 0xE3): "25TA02KB",
    (0x02, 0xE4): "25TA512B",
    (0x02, 0xF3): "25TA02KB-D",
    (0x11, 0x22): "NTAG21x Modifiable",
}

ATS_FSC = [16, 24, 32, 40, 48, 64, 96, 128, 256]

# type flags returned by detect_types()
MTCLASSIC, MTMINI, MTPLUS, MTULTRALIGHT = 1, 2, 4, 8
MTFUDAN, MTEMV, MTSEOS, MTISO18092, MTOTHER = 16, 32, 64, 128, 256
MTDESFIRE, MT424 = 512, 1024


def manufacturer(uid0):
    return MANUFACTURERS.get(uid0, "no tag-info available")


def uid_type(uid):
    n = len(uid)
    if n == 4:
        if uid[0] == 0x08:
            return "( RID - random ID )"
        if uid[0] & 0xF == 0xF:
            return "( FNUID, fixed, non-unique ID )"
        if uid[0] == 0x88:
            return "( Cascade tag - not final )"
        if uid[0] == 0xF8:
            return "( RFU )"
        return "( ONUID, re-used )"
    if n == 7:
        return "( double )"
    if n == 10:
        return "( triple )"
    return ""


def _storage(sz):
    """NXP storage-size byte: bit0 set = between 2^n and 2^(n+1), else 2^n.
    (pm3 never reaches this code: its size string is initialised non-NULL.)"""
    lo = 1 << (sz >> 1)
    f = (lambda v: f"{v}B" if v < 1024 else f"{v // 1024}K")
    return f"{f(lo)} - {f(lo * 2)}" if sz & 1 else f(lo)


def version_strings(hw):
    """hw: 7-byte GetVersion HW part (vendor,type,subtype,major,minor,
    storage,proto). Returns (product, major, size) like pm3."""
    ptype, major, sz = hw[1], hw[3], hw[5]
    p, m, s = "", "", ""
    k = ptype & 0x0F
    if k == 0x1:
        p = "MIFARE DESFire"
        if ptype == 0x91:
            p = "Apple Wallet DESFire Applet"
        m = {1: "EV1", 2: "EV2", 3: "EV3"}.get(major & 0x0F, "")
        if major == 0x00:
            m = "MF3ICD40"
        elif major == 0x42:
            m = "EV2 + EMV"
        elif major == 0xA0:
            p = "MIFARE DUOX"
    elif k == 0x2:
        p = "MIFARE Plus"
        m = {0x11: "EV1", 0x22: "EV2"}.get(major, "n/a")
    elif k == 0x3:
        p = "MIFARE Ultralight"
        m = {0x01: "EV1", 0x02: "Nano", 0x04: "AES"}.get(major, "n/a")
        if major == 0x01 and sz == 0x0B:
            s = "48b"
        elif major == 0x01 and sz == 0x0E:
            s = "128b"
    elif k == 0x4:
        p = "NTAG"
        m = {0x01: "2xx", 0x02: "210\u00b5", 0x03: "213 TT", 0x10: "413 DNA",
             0x30: "4xx"}.get(major, "n/a")
    elif k == 0x7:
        p = "NTAG I2C"
    elif k == 0x8:
        p = "MIFARE DESFire Light"
    elif k == 0x9:
        p = "MIFARE Hospitality"
        m = "AES" if major == 0x01 else "n/a"
    else:
        p = "Unknown NXP tag"
    if not s:
        s = _storage(sz)
    return p, m, s


def _vtag(hw, suffix=""):
    p, m, s = version_strings(hw)
    return " ".join(x for x in (p, m, s) if x) + suffix


def _hist_len9(h, pre):
    return len(h) == 9 and h[:4] == pre


def detect_types(sak, atqa, has_ats, hist, hw=None):
    """Port of detect_nxp_card_print() without the GetVersion branches.
    atqa: int, pm3 order (second received byte is the high byte).
    hist: ATS history as pm3 sees it, i.e. including the 2 CRC bytes.
    hw: 7-byte GetVersion HW data or None.
    Returns (list of type strings, flags)."""
    t, f = [], 0
    cl2 = " CL2" if atqa & 0x0040 else ""

    if sak & 0x44 == 0x40:
        t.append("P2P Support / Proprietary" if atqa & 0x0110 == 0x0110
                 else "P2P Support / Android")
        f |= MTISO18092

    if sak & 0x02 == 0:
        if sak & 0x08:
            if sak & 0x10:
                if sak & 0x01:
                    t.append("MIFARE Classic 2K"); f |= MTCLASSIC
                elif sak & 0x20:
                    t.append("SmartMX with MIFARE Classic 4K"); f |= MTCLASSIC
                elif has_ats and hw:
                    t.append(_vtag(hw, " in SL1")); f |= MTPLUS
                elif has_ats:
                    if _hist_len9(hist, b"\xC1\x05\x2F\x2F"):
                        if hist[4:7] == b"\x00\x35\xC7":
                            t.append("MIFARE Plus S 4K in SL1")
                        elif hist[4:7] == b"\x01\xBC\xD6":
                            t.append("MIFARE Plus X 4K in SL1")
                        else:
                            t.append("Unrecognized MIFARE Plus??")
                        f |= MTPLUS
                    elif hist:
                        t.append(f"MIFARE Classic 4K{cl2} with ATS!"); f |= MTCLASSIC
                else:
                    t.append(f"MIFARE Classic 4K{cl2}"); f |= MTCLASSIC
            elif sak & 0x01:
                t.append(f"MIFARE Mini 0.3K{cl2}"); f |= MTMINI
            elif sak & 0x20:
                t += ["SmartMX with MIFARE Classic 1K",
                      "FM1208-10 with MIFARE Classic 1K",
                      "FM1216-137 with MIFARE Classic 1K"]
                f |= MTCLASSIC
            elif has_ats and hw:
                t.append(_vtag(hw, " in SL1")); f |= MTPLUS
            elif has_ats:
                if _hist_len9(hist, b"\xC1\x05\x2F\x2F"):
                    if hist[4:7] == b"\x00\x35\xC7":
                        t.append("MIFARE Plus S 2K in SL1")
                    elif hist[4:7] == b"\x01\xBC\xD6":
                        t.append("MIFARE Plus X 2K in SL1")
                    else:
                        t.append("Unrecognized MIFARE Plus??")
                    f |= MTPLUS
                elif _hist_len9(hist, b"\xC1\x05\x21\x30"):
                    if hist[4:7] == b"\x00\xF6\xD1":
                        t.append("MIFARE Plus SE 1K 17pF")
                    elif hist[4:7] == b"\x10\xF6\xD1":
                        t.append("MIFARE Plus SE 1K 70pF")
                    else:
                        t.append("Unrecognized MIFARE Plus SE??")
                    f |= MTPLUS
                elif hist:
                    t.append(f"MIFARE Classic 1K{cl2} with ATS!"); f |= MTCLASSIC
            else:
                t.append(f"MIFARE Classic 1K{cl2}"); f |= MTCLASSIC
        elif sak & 0x10:
            t.append("MIFARE Plus 4K in SL2" if sak & 0x01 else "MIFARE Plus 2K in SL2")
            f |= MTPLUS
        elif sak & 0x01:
            t.append("TNP3xxx (TagNPlay, Activision Game Appliance)"); f |= MTCLASSIC
        elif sak & 0x20:
            if has_ats and hw:
                pt = hw[1]
                t.append(_vtag(hw, " in SL0/SL3" if pt & 0x7F == 0x02 else ""))
                if pt & 0x7F == 0x02:
                    f |= MTPLUS
                elif pt & 0x7F == 0x01 or pt in (0x08, 0x91):
                    f |= MTDESFIRE
                elif pt == 0x04:
                    f |= MTDESFIRE | MT424
            elif has_ats:
                if _hist_len9(hist, b"\xC1\x05\x2F\x2F"):
                    if hist[4:7] == b"\x00\x35\xC7":
                        if atqa & 0xFF0F == 0x0004:
                            t.append("MIFARE Plus S 2K in SL0/SL3")
                        elif atqa & 0xFF0F == 0x0002:
                            t.append("MIFARE Plus S 4K in SL0/SL3")
                        else:
                            t.append("Unrecognized MIFARE Plus??")
                    elif hist[4:7] == b"\x01\xBC\xD6":
                        t.append("MIFARE Plus X 2K/4K in SL0/SL3")
                    elif hist[4:7] == b"\x00\xF6\xD1":
                        t.append("MIFARE Plus SE 1K 17pF")
                    elif hist[4:7] == b"\x10\xF6\xD1":
                        t.append("MIFARE Plus SE 1K 70pF")
                    else:
                        t.append("Unknown MIFARE Plus")
                    f |= MTPLUS
                elif hist:
                    if atqa in (0x0001, 0x0004):
                        t.append("HID SEOS (smartmx / javacard)"); f |= MTSEOS
                    if atqa in (0x0004, 0x0048):
                        t.append("EMV"); f |= MTEMV
            else:
                t.append("Unknown tag claims to support RATS in SAK but does not...")
        elif hw:
            t.append(_vtag(hw)); f |= MTULTRALIGHT
        else:
            t.append("MIFARE Ultralight"); f |= MTULTRALIGHT
    elif sak == 0x0A:
        if atqa == 0x0003:
            t.append("FM11RF005SH (FUDAN Shanghai Metro)"); f |= MTFUDAN
        elif atqa == 0x0005:
            t.append("FM11RF005M (FUDAN ISO14443A w Crypto-1 algo)"); f |= MTFUDAN
    elif sak == 0x53:
        t.append("FM11RF08SH (FUDAN)"); f |= MTFUDAN
    return t, f


def multi_uid_types(uid, sak, atqa):
    """7/10-byte UID branch of infoHF14A. Returns (types, flags), or None for NXP (use detect_types)."""
    t, f = [], 0
    u0 = uid[0]
    if u0 == 0x02:
        if atqa == 0x0044:
            t.append("EMV"); f |= MTEMV
    elif u0 == 0x05:
        h = uid[1] & 0xF0
        names = {0x10: "my-d(tm) command set SLE 66R04/16/32P, SLE 66R04/16/32S",
                 0x20: "my-d(tm) command set SLE 66R01/16/32P (Type 2 Tag)",
                 0x30: "my-d(tm) move lean SLE 66R01P/66R01PN",
                 0x70: "my-d(tm) move lean SLE 66R01L"}
        if h in names:
            t.append(names[h])
        f |= MTULTRALIGHT
        if sak == 0x88:
            t.append("Infineon MIFARE CLASSIC 1K")
            f = MTCLASSIC
    elif u0 == 0x46 and uid[:7] == b"FSTN10m":
        t.append('Waveshare NFC-Powered e-Paper 1.54" (please disregard MANUFACTURER mapping above)')
    elif u0 == 0x57 and uid[:7] == b"WSDZ10m":
        t.append("Waveshare NFC-Powered e-Paper (please disregard MANUFACTURER mapping above)")
    elif u0 == 0x04:
        return None  # NXP: caller uses detect_types
    else:
        sak_map = {0x20: "JCOP 31/41", 0x28: "JCOP31 or JCOP41 v2.3.1",
                   0x38: "Nokia 6212 or 6131", 0x53: "FM11RF08SH (FUDAN)",
                   0x98: "Gemplus MPCOS"}
        if sak == 0x00:
            t.append("MIFARE Ultralight/C/NTAG Compatible"); f |= MTULTRALIGHT
        elif sak == 0x0A:
            if atqa & 0xFF == 0x03:
                t.append("FM11RF005SH (FUDAN Shanghai Metro)")
            elif atqa & 0xFF == 0x05:
                t.append("FM11RF005M (FUDAN ISO14443A w Crypto-1 algo)")
        elif sak in sak_map:
            t.append(sak_map[sak])
    return t, f


_CTLV_LABEL = {
    1: "Country code in (ISO 3166-1)",
    2: "Issuer identification number (ISO 7812-1)",
    3: "Card service data byte",
    4: "Initial access data",
    5: "Card issuer data",
    6: "Pre-issuing data",
    7: "Card capabilities",
    8: "Status indicator",
    0xE: "Application identifier",
}
_SVC_BITS = [
    "Application selection: by full DF name",
    "Application selection: by partial DF name",
    "BER-TLV data objects available in EF.DIR",
    "BER-TLV data objects available in EF.ATR",
    "EF.DIR and EF.ATR access services: by READ BINARY command",
    "EF.DIR and EF.ATR access services: by GET DATA command",
    "EF.DIR and EF.ATR access services: by GET RECORD(s) command",
    "EF.DIR and EF.ATR access services: RFU",
]
_SEL_BITS = [
    "DF selection by full DF name", "DF selection by partial DF name",
    "DF selection by path", "DF selection by file identifier",
    "Implicit DF selection", "Short EF identifier supported",
    "Record number supported", "Record identifier supported",
]


def _bits(b, labels):
    out = []
    for i, lab in enumerate(labels):
        pat = ["."] * 8
        pat[i] = "1" if b & (0x80 >> i) else "0"
        out.append(f"    {''.join(pat)}    {lab}")
    return out


def compact_tlv(d, hl=lambda s: s):
    """d: historical bytes starting with the 0x80/0x00 category indicator."""
    out = []
    d = d[1:]
    n = len(d)
    i = 0
    while i < n:
        tag, ln = d[i] >> 4, d[i] & 0x0F
        v = d[i + 1:i + 1 + ln]
        if tag in _CTLV_LABEL:
            if tag in (8, 0xE):
                out.append(f"    {tag:x}{ln:x} ... {hl(v.hex().upper())}   {_CTLV_LABEL[tag]}")
            else:
                out.append(f"    {tag:x}{ln:x}  {hl(v.hex().upper())}   {_CTLV_LABEL[tag]}")
            if tag == 3 and v:
                out += _bits(v[0], _SVC_BITS)
            if tag == 7 and v:
                out.append(f"    {hl(f'{v[0]:02X}')} - Selection methods")
                out += _bits(v[0], _SEL_BITS)
                if ln > 1:
                    out.append(f"    {hl(f'{v[1]:02X}')} - Data coding byte")
                if ln > 2:
                    out.append(f"    {hl(f'{v[2]:02X}')} - Command chaining, length fields and logical channels")
        if ln + 1 > n - i:
            break
        i += 1 + ln
    return out


def ats_lines(ats, hl=lambda s: s, no=lambda s: s):
    """pm3-style ATS field tree. ats excludes CRC (TL counts the whole ATS).
    hl: highlight fn, no: 'NOT' highlight fn.
    Returns (lines, hist_lines, flags) where flags has desfire/plus/seos."""
    out, hist_out = [], []
    fl = {"desfire": False, "plus": False, "seos": False}
    ln = len(ats)
    bad = ats[0] != ln
    if bad:
        out.append(f"ATS may be corrupted. Length of ATS ({ln} bytes) doesn't match TL")
    out.append(f"ATS: {hl(ats.hex(' ').upper())}")
    out.append(f"     {hl(f'{ats[0]:02X}')}...............  TL    length is {hl(ats[0])} bytes")
    if bad:
        return out, hist_out, fl
    ta = tb = tc = False
    if ats[0] > 1 and ln > 1:
        t0 = ats[1]
        ta, tb, tc = bool(t0 & 0x10), bool(t0 & 0x20), bool(t0 & 0x40)
        fsci = t0 & 0x0F
        fsc = ATS_FSC[fsci] if fsci < len(ATS_FSC) else -1
        out.append(f"     ...{hl(f'{t0:02X}')}............  T0    TA1 is{'' if ta else no(' NOT')} present, "
                   f"TB1 is{'' if tb else no(' NOT')} present, TC1 is{'' if tc else no(' NOT')} present, "
                   f"FSCI is {fsci} (FSC = {fsc})")
    pos = 2
    if ta and ln > pos:
        b = ats[pos]
        ds = ", ".join(str(x) for m, x in ((0x10, 2), (0x20, 4), (0x40, 8)) if b & m)
        dr = ", ".join(str(x) for m, x in ((0x01, 2), (0x02, 4), (0x04, 8)) if b & m)
        out.append(f"     ......{hl(f'{b:02X}')}.........  TA1   different divisors are"
                   f"{no(' NOT') if b & 0x80 else ''} supported, DR: [{dr}], DS: [{ds}]")
        pos += 1
    if tb and ln > pos:
        b = ats[pos]
        sfgi, fwi = b & 0x0F, b >> 4
        sfgt = f"{'' if sfgi else '(not needed) '}{(1 << 12) << sfgi if sfgi else 0}/fc"
        out.append(f"     .........{hl(f'{b:02X}')}......  TB1   SFGI = {sfgi} (SFGT = {sfgt}), "
                   f"FWI = {hl(fwi)} (FWT = {(1 << 12) << fwi}/fc)")
        pos += 1
    if tc and ln > pos:
        b = ats[pos]
        out.append(f"     ............{hl(f'{b:02X}')}...  TC1   NAD is{'' if b & 1 else no(' NOT')} supported, "
                   f"CID is{'' if b & 2 else no(' NOT')} supported")
        pos += 1
    if ats[0] > pos and ln >= ats[0]:
        h = ats[pos:ats[0]]
        c = len(h)
        if h[0] == 0xC1:
            hist_out.append(f"    {h.hex(' ').upper()}")
            hist_out.append("    C1.....................   Mifare or (multiple) virtual cards of various type")
            if c > 2:
                hist_out.append(f"       {h[1]:02X}..................   length is {hl(h[1])} bytes")
                hi, lo = h[2] & 0xF0, h[2] & 0x0F
                if hi == 0x10:
                    hist_out.append("          1x...............   MIFARE DESFire"); fl["desfire"] = True
                elif hi == 0x20:
                    hist_out.append("          2x...............   MIFARE Plus"); fl["plus"] = True
                sz = {0: "< 1 kByte", 1: "1 kByte", 2: "2 kByte", 3: "4 kByte", 4: "8 kByte"}
                if lo in sz:
                    hist_out.append(f"          x{lo:x}...............   {sz[lo]}")
            if c > 3:
                hi, lo = h[3] & 0xF0, h[3] & 0x0F
                if hi == 0x00:
                    hist_out.append("             0x............   Engineering sample")
                elif hi == 0x20:
                    hist_out.append("             2x............   Released")
                gen = {0: "Generation 1", 1: "Generation 2", 2: "Generation 3"}
                if lo in gen:
                    hist_out.append(f"             x{lo:x}............   {gen[lo]}")
            if c > 4:
                lo = h[4] & 0x0F
                vc = {0: "Only VCSL supported", 1: "VCS, VCSL, and SVC supported",
                      0xE: "no VCS command supported"}
                if lo in vc:
                    hist_out.append(f"                x{lo:X}.........   {vc[lo]}")
        elif h[0] in (0x80, 0x00):
            hist_out.append(f"{h.hex().upper()}  (compact TLV data object)")
            hist_out += compact_tlv(h, hl)
        else:
            asc = "".join(chr(x) if 32 <= x < 127 else "." for x in h)
            hist_out.append(f"{h.hex().upper()} - {asc}")
    if ln == 5 and ats in (b"\x05\x78\x77\x80\x02", b"\x05\x78\x77\x94\x02"):
        fl["seos"] = True
    return out, hist_out, fl
