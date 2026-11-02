/* ISO14443-A info report: port of software/script/hf14a_info.py and HF14AScan.scan(deep=True). */
(function(){
const MANUFACTURERS = {
  0x01: "Motorola UK",
  0x02: "ST Microelectronics SA France",
  0x03: "Hitachi, Ltd Japan",
  0x04: "NXP Semiconductors Germany",
  0x05: "Infineon Technologies AG Germany",
  0x06: "Cylink USA",
  0x07: "Texas Instrument France",
  0x08: "Fujitsu Limited Japan",
  0x09: "Matsushita Electronics Corporation, Semiconductor Company Japan",
  0x0A: "NEC Japan",
  0x0B: "Oki Electric Industry Co. Ltd Japan",
  0x0C: "Toshiba Corp. Japan",
  0x0D: "Mitsubishi Electric Corp. Japan",
  0x0E: "Samsung Electronics Co. Ltd Korea",
  0x0F: "Hynix / Hyundai, Korea",
  0x10: "LG-Semiconductors Co. Ltd Korea",
  0x11: "Emosyn-EM Microelectronics USA",
  0x12: "Wisekey Semiconductors (previously INSIDE Technology) France",
  0x13: "ORGA Kartensysteme GmbH Germany",
  0x14: "SHARP Corporation Japan",
  0x15: "ATMEL France",
  0x16: "EM Microelectronic-Marin SA Switzerland",
  0x17: "SMARTRAC TECHNOLOGY GmbH Germany",
  0x18: "ZMD AG Germany",
  0x19: "XICOR, Inc. USA",
  0x1A: "Sony Corporation Japan",
  0x1B: "Malaysia Microelectronic Solutions Sdn. Bhd Malaysia",
  0x1C: "Emosyn USA",
  0x1D: "Shanghai Fudan Microelectronics Co. Ltd. P.R. China",
  0x1E: "Magellan Technology Pty Limited Australia",
  0x1F: "Melexis NV BO Switzerland",
  0x20: "Renesas Technology Corp. Japan",
  0x21: "TAGSYS France",
  0x22: "Transcore USA",
  0x23: "Shanghai belling corp., ltd. China",
  0x24: "Masktech Germany Gmbh Germany",
  0x25: "Innovision Research and Technology Plc UK",
  0x26: "Hitachi ULSI Systems Co., Ltd. Japan",
  0x27: "Yubico AB Sweden",
  0x28: "Ricoh Japan",
  0x29: "ASK France",
  0x2A: "Unicore Microsystems, LLC Russian Federation",
  0x2B: "Dallas Semiconductor/Maxim USA",
  0x2C: "Impinj, Inc. USA",
  0x2D: "RightPlug Alliance USA",
  0x2E: "Broadcom Corporation USA",
  0x2F: "MStar Semiconductor, Inc Taiwan, ROC",
  0x30: "BeeDar Technology Inc. USA",
  0x31: "RFIDsec Denmark",
  0x32: "Schweizer Electronic AG Germany",
  0x33: "AMIC Technology Corp Taiwan",
  0x34: "Mikron JSC Russia",
  0x35: "Fraunhofer Institute for Photonic Microsystems Germany",
  0x36: "IDS Microchip AG Switzerland",
  0x37: "Kovio USA",
  0x38: "HMT Microelectronic Ltd Switzerland",
  0x39: "Silicon Craft Technology Thailand",
  0x3A: "Advanced Film Device Inc. Japan",
  0x3B: "Nitecrest Ltd UK",
  0x3C: "Verayo Inc. USA",
  0x3D: "HID Global USA",
  0x3E: "Productivity Engineering Gmbh Germany",
  0x3F: "Austriamicrosystems AG (reserved) Austria",
  0x40: "Thales DIS (previously Gemalto SA) France",
  0x41: "Renesas Electronics Corporation Japan",
  0x42: "3Alogics Inc Korea",
  0x43: "Top TroniQ Asia Limited Hong Kong",
  0x44: "Gentag Inc. USA",
  0x45: "Invengo Information Technology Co. Ltd China",
  0x46: "Guangzhou Sysur Microelectronics, Inc China",
  0x47: "CEITEC S.A. Brazil",
  0x48: "Shanghai Quanray Electronics Co. Ltd. China",
  0x49: "MediaTek Inc Taiwan",
  0x4A: "Angstrem PJSC Russia",
  0x4B: "Celisic Semiconductor (Hong Kong) Limited China",
  0x4C: "LEGIC Identsystems AG Switzerland",
  0x4D: "Balluff GmbH Germany",
  0x4E: "Oberthur Technologies France",
  0x4F: "Silterra Malaysia Sdn. Bhd. Malaysia",
  0x50: "Presto Engineering Denmark",
  0x51: "Giesecke & Devrient GmbH Germany",
  0x52: "Shenzhen China Vision Microelectronics Co., Ltd. China",
  0x53: "Shanghai Feiju Microelectronics Co. Ltd. China",
  0x54: "Intel Corporation USA",
  0x55: "Microsensys GmbH Germany",
  0x56: "Sonix Technology Co., Ltd. Taiwan",
  0x57: "Qualcomm Technologies Inc USA",
  0x58: "Realtek Semiconductor Corp Taiwan",
  0x59: "Freevision Technologies Co. Ltd China",
  0x5A: "Giantec Semiconductor Inc. China",
  0x5B: "JSC Angstrem-T Russia",
  0x5C: "STARCHIP France",
  0x5D: "SPIRTECH France",
  0x5E: "GANTNER Electronic GmbH Austria",
  0x5F: "Nordic Semiconductor Norway",
  0x60: "Verisiti Inc USA",
  0x61: "Wearlinks Technology Inc. China",
  0x62: "Userstar Information Systems Co., Ltd Taiwan",
  0x63: "Pragmatic Printing Ltd. UK",
  0x64: "Associação do Laboratório de Sistemas Integráveis Tecnológico - LSI-TEC Brazil",
  0x65: "Tendyron Corporation China",
  0x66: "MUTO Smart Co., Ltd. Korea",
  0x67: "ON Semiconductor USA",
  0x68: "TÜBITAK BILGEM Turkey",
  0x69: "Huada Semiconductor Co., Ltd China",
  0x6A: "SEVENEY France",
  0x6B: "THALES DIS Design Services SAS (previously ISSM) France",
  0x6C: "Wisesec Ltd Israel",
  0x6D: "LTD \\\"NM-Teh\\\" Russia",
  0x70: "ifm electronic gmbh Germany",
  0x71: "Sichuan Kiloway Technologies Co., Ltd. China",
  0x72: "Ford Motor Company US",
  0x73: "Beijing Tsingteng MicroSystem Co.,Ltd China",
  0x74: "Huada EverCore Co., Ltd China",
  0x75: "Smartchip Microelectronics Corporation Taiwan",
  0x76: "Tongxin Microelectronics Co., Ltd. China",
  0x77: "Ningbo IOT Microelectronics Co Ltd China",
  0x78: "AU Optronics Taiwan",
  0x79: "CUBIC USA",
  0x7A: "Abbott Diabetes Care USA",
  0x7B: "Shenzen Nation RFID Technology Co Ltd China",
  0x7C: "DB HiTek Co Ltd Korea",
  0x7D: "SATO Vicinity Australia",
  0x7E: "Holtek Taiwan",
  0x7F: "Shenzhen Goodix Technology Co., Ltd. China",
  0x80: "Panthronics AG Austria",
  0x81: "Beijing Huada Infosec Technology Co., Ltd China",
  0x82: "Shanghai Oriental Magnetic Card Engineering Co Ltd. China",
  0x83: "8ApeX Inc USA",
  0x84: "Abbott Ireland",
  0x85: "Proqure Inc USA",
  0x86: "Schreiner Group GmbH & Co. KG Germany",
  0x87: "Beijing SmartChip Microelectronics Technology Company Limited China",
  0x88: "Datang Microelectronics Technology Co., Ltd. China",
  0x89: "Wise Security Technology (Guangzhou) Co., Ltd. China",
  0x8A: "CEC Huada Electronic Design Co., Ltd. China",
  0x8B: "Shanghai Techsun RFID Technology Co., Ltd. China",
  0x8C: "North China Institute of Computing Technology China",
  0x8D: "Shanghai Huahong Integrated Circuit Co., Ltd. China",
  0x8E: "Shanghai MintSilicon Microelectronics Inc., Ltd. China",
  0x8F: "Xinsheng Technology Co., Ltd. China",
  0x90: "IDEX Biometrics ASA Norway",
  0x91: "Novo Nordisk A/S Denmark",
  0x92: "Shandong Huayi Micro-Electronics Technology Co., Ltd. China",
  0x93: "Abbott Heart Failure USA",
  0x94: "P&M Information Technology (Shenzhen) Co., Ltd. China",
  0x95: "MARS TECHNOLOGY PTE. LTD. Singapore",
  0x96: "Trovan Limited Isle of Man"
};
const UID_LABELS = {
  "2,132": "M24SR64-Y", "2,163": "25TA02KB-P", "2,196": "25TA64K", "2,227": "25TA02KB",
  "2,228": "25TA512B", "2,243": "25TA02KB-D", "17,34": "NTAG21x Modifiable",
};
const ATS_FSC = [16, 24, 32, 40, 48, 64, 96, 128, 256];
const MTCLASSIC = 1, MTMINI = 2, MTPLUS = 4, MTULTRALIGHT = 8;
const MTFUDAN = 16, MTEMV = 32, MTSEOS = 64, MTISO18092 = 128, MTOTHER = 256;
const MTDESFIRE = 512, MT424 = 1024;

const hx2 = b => (b < 16 ? "0" : "") + b.toString(16).toUpperCase();
const hx = a => Array.from(a, hx2).join("");
const hxs = a => Array.from(a, hx2).join(" ");
const bytesEq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const startsWith = (a, p) => a.length >= p.length && p.every((v, i) => a[i] === v);

function manufacturer(u0){ return u0 in MANUFACTURERS ? MANUFACTURERS[u0] : "no tag-info available"; }

function uidType(uid){
  const n = uid.length;
  if(n === 4){
    if(uid[0] === 0x08) return "( RID - random ID )";
    if((uid[0] & 0xF) === 0xF) return "( FNUID, fixed, non-unique ID )";
    if(uid[0] === 0x88) return "( Cascade tag - not final )";
    if(uid[0] === 0xF8) return "( RFU )";
    return "( ONUID, re-used )";
  }
  if(n === 7) return "( double )";
  if(n === 10) return "( triple )";
  return "";
}

function storage(sz){
  const lo = 1n << BigInt(sz >> 1);
  const f = v => v < 1024n ? v + "B" : (v / 1024n) + "K";
  return (sz & 1) ? f(lo) + " - " + f(lo * 2n) : f(lo);
}

function versionStrings(hw){
  const ptype = hw[1], major = hw[3], sz = hw[5];
  let p = "", m = "", s = "";
  const k = ptype & 0x0F;
  if(k === 0x1){
    p = "MIFARE DESFire";
    if(ptype === 0x91) p = "Apple Wallet DESFire Applet";
    m = {1: "EV1", 2: "EV2", 3: "EV3"}[major & 0x0F] || "";
    if(major === 0x00) m = "MF3ICD40";
    else if(major === 0x42) m = "EV2 + EMV";
    else if(major === 0xA0) p = "MIFARE DUOX";
  }else if(k === 0x2){
    p = "MIFARE Plus";
    m = {0x11: "EV1", 0x22: "EV2"}[major] || "n/a";
  }else if(k === 0x3){
    p = "MIFARE Ultralight";
    m = {0x01: "EV1", 0x02: "Nano", 0x04: "AES"}[major] || "n/a";
    if(major === 0x01 && sz === 0x0B) s = "48b";
    else if(major === 0x01 && sz === 0x0E) s = "128b";
  }else if(k === 0x4){
    p = "NTAG";
    m = {0x01: "2xx", 0x02: "210µ", 0x03: "213 TT", 0x10: "413 DNA", 0x30: "4xx"}[major] || "n/a";
  }else if(k === 0x7){
    p = "NTAG I2C";
  }else if(k === 0x8){
    p = "MIFARE DESFire Light";
  }else if(k === 0x9){
    p = "MIFARE Hospitality";
    m = major === 0x01 ? "AES" : "n/a";
  }else{
    p = "Unknown NXP tag";
  }
  if(!s) s = storage(sz);
  return [p, m, s];
}

function vtag(hw, suffix){
  return versionStrings(hw).filter(x => x).join(" ") + (suffix || "");
}

const histLen9 = (h, pre) => h.length === 9 && startsWith(h, pre);

// atqa: int, first received byte low. hist: ATS history incl. 2 CRC bytes. hw: 7 bytes or null.
function detectTypes(sak, atqa, hasAts, hist, hw){
  const t = [];
  let f = 0;
  const cl2 = (atqa & 0x0040) ? " CL2" : "";

  if((sak & 0x44) === 0x40){
    t.push((atqa & 0x0110) === 0x0110 ? "P2P Support / Proprietary" : "P2P Support / Android");
    f |= MTISO18092;
  }

  if((sak & 0x02) === 0){
    if(sak & 0x08){
      if(sak & 0x10){
        if(sak & 0x01){
          t.push("MIFARE Classic 2K"); f |= MTCLASSIC;
        }else if(sak & 0x20){
          t.push("SmartMX with MIFARE Classic 4K"); f |= MTCLASSIC;
        }else if(hasAts && hw){
          t.push(vtag(hw, " in SL1")); f |= MTPLUS;
        }else if(hasAts){
          if(histLen9(hist, [0xC1, 0x05, 0x2F, 0x2F])){
            const k = hist.slice(4, 7);
            if(bytesEq(k, [0x00, 0x35, 0xC7])) t.push("MIFARE Plus S 4K in SL1");
            else if(bytesEq(k, [0x01, 0xBC, 0xD6])) t.push("MIFARE Plus X 4K in SL1");
            else t.push("Unrecognized MIFARE Plus??");
            f |= MTPLUS;
          }else if(hist.length){
            t.push("MIFARE Classic 4K" + cl2 + " with ATS!"); f |= MTCLASSIC;
          }
        }else{
          t.push("MIFARE Classic 4K" + cl2); f |= MTCLASSIC;
        }
      }else if(sak & 0x01){
        t.push("MIFARE Mini 0.3K" + cl2); f |= MTMINI;
      }else if(sak & 0x20){
        t.push("SmartMX with MIFARE Classic 1K", "FM1208-10 with MIFARE Classic 1K", "FM1216-137 with MIFARE Classic 1K");
        f |= MTCLASSIC;
      }else if(hasAts && hw){
        t.push(vtag(hw, " in SL1")); f |= MTPLUS;
      }else if(hasAts){
        if(histLen9(hist, [0xC1, 0x05, 0x2F, 0x2F])){
          const k = hist.slice(4, 7);
          if(bytesEq(k, [0x00, 0x35, 0xC7])) t.push("MIFARE Plus S 2K in SL1");
          else if(bytesEq(k, [0x01, 0xBC, 0xD6])) t.push("MIFARE Plus X 2K in SL1");
          else t.push("Unrecognized MIFARE Plus??");
          f |= MTPLUS;
        }else if(histLen9(hist, [0xC1, 0x05, 0x21, 0x30])){
          const k = hist.slice(4, 7);
          if(bytesEq(k, [0x00, 0xF6, 0xD1])) t.push("MIFARE Plus SE 1K 17pF");
          else if(bytesEq(k, [0x10, 0xF6, 0xD1])) t.push("MIFARE Plus SE 1K 70pF");
          else t.push("Unrecognized MIFARE Plus SE??");
          f |= MTPLUS;
        }else if(hist.length){
          t.push("MIFARE Classic 1K" + cl2 + " with ATS!"); f |= MTCLASSIC;
        }
      }else{
        t.push("MIFARE Classic 1K" + cl2); f |= MTCLASSIC;
      }
    }else if(sak & 0x10){
      t.push((sak & 0x01) ? "MIFARE Plus 4K in SL2" : "MIFARE Plus 2K in SL2");
      f |= MTPLUS;
    }else if(sak & 0x01){
      t.push("TNP3xxx (TagNPlay, Activision Game Appliance)"); f |= MTCLASSIC;
    }else if(sak & 0x20){
      if(hasAts && hw){
        const pt = hw[1];
        t.push(vtag(hw, (pt & 0x7F) === 0x02 ? " in SL0/SL3" : ""));
        if((pt & 0x7F) === 0x02) f |= MTPLUS;
        else if((pt & 0x7F) === 0x01 || pt === 0x08 || pt === 0x91) f |= MTDESFIRE;
        else if(pt === 0x04) f |= MTDESFIRE | MT424;
      }else if(hasAts){
        if(histLen9(hist, [0xC1, 0x05, 0x2F, 0x2F])){
          const k = hist.slice(4, 7);
          if(bytesEq(k, [0x00, 0x35, 0xC7])){
            if((atqa & 0xFF0F) === 0x0004) t.push("MIFARE Plus S 2K in SL0/SL3");
            else if((atqa & 0xFF0F) === 0x0002) t.push("MIFARE Plus S 4K in SL0/SL3");
            else t.push("Unrecognized MIFARE Plus??");
          }else if(bytesEq(k, [0x01, 0xBC, 0xD6])){
            t.push("MIFARE Plus X 2K/4K in SL0/SL3");
          }else if(bytesEq(k, [0x00, 0xF6, 0xD1])){
            t.push("MIFARE Plus SE 1K 17pF");
          }else if(bytesEq(k, [0x10, 0xF6, 0xD1])){
            t.push("MIFARE Plus SE 1K 70pF");
          }else{
            t.push("Unknown MIFARE Plus");
          }
          f |= MTPLUS;
        }else if(hist.length){
          if(atqa === 0x0001 || atqa === 0x0004){ t.push("HID SEOS (smartmx / javacard)"); f |= MTSEOS; }
          if(atqa === 0x0004 || atqa === 0x0048){ t.push("EMV"); f |= MTEMV; }
        }
      }else{
        t.push("Unknown tag claims to support RATS in SAK but does not...");
      }
    }else if(hw){
      t.push(vtag(hw)); f |= MTULTRALIGHT;
    }else{
      t.push("MIFARE Ultralight"); f |= MTULTRALIGHT;
    }
  }else if(sak === 0x0A){
    if(atqa === 0x0003){ t.push("FM11RF005SH (FUDAN Shanghai Metro)"); f |= MTFUDAN; }
    else if(atqa === 0x0005){ t.push("FM11RF005M (FUDAN ISO14443A w Crypto-1 algo)"); f |= MTFUDAN; }
  }else if(sak === 0x53){
    t.push("FM11RF08SH (FUDAN)"); f |= MTFUDAN;
  }
  return [t, f];
}

const asciiOf = (a, n) => String.fromCharCode(...a.slice(0, n));

// 7/10-byte UID branch; returns null for NXP (caller uses detectTypes).
function multiUidTypes(uid, sak, atqa){
  const t = [];
  let f = 0;
  const u0 = uid[0];
  if(u0 === 0x02){
    if(atqa === 0x0044){ t.push("EMV"); f |= MTEMV; }
  }else if(u0 === 0x05){
    const h = uid[1] & 0xF0;
    const names = {0x10: "my-d(tm) command set SLE 66R04/16/32P, SLE 66R04/16/32S",
                   0x20: "my-d(tm) command set SLE 66R01/16/32P (Type 2 Tag)",
                   0x30: "my-d(tm) move lean SLE 66R01P/66R01PN",
                   0x70: "my-d(tm) move lean SLE 66R01L"};
    if(h in names) t.push(names[h]);
    f |= MTULTRALIGHT;
    if(sak === 0x88){ t.push("Infineon MIFARE CLASSIC 1K"); f = MTCLASSIC; }
  }else if(u0 === 0x46 && asciiOf(uid, 7) === "FSTN10m" && uid.length >= 7){
    t.push('Waveshare NFC-Powered e-Paper 1.54" (please disregard MANUFACTURER mapping above)');
  }else if(u0 === 0x57 && asciiOf(uid, 7) === "WSDZ10m" && uid.length >= 7){
    t.push("Waveshare NFC-Powered e-Paper (please disregard MANUFACTURER mapping above)");
  }else if(u0 === 0x04){
    return null;
  }else{
    const sakMap = {0x20: "JCOP 31/41", 0x28: "JCOP31 or JCOP41 v2.3.1", 0x38: "Nokia 6212 or 6131",
                    0x53: "FM11RF08SH (FUDAN)", 0x98: "Gemplus MPCOS"};
    if(sak === 0x00){
      t.push("MIFARE Ultralight/C/NTAG Compatible"); f |= MTULTRALIGHT;
    }else if(sak === 0x0A){
      if((atqa & 0xFF) === 0x03) t.push("FM11RF005SH (FUDAN Shanghai Metro)");
      else if((atqa & 0xFF) === 0x05) t.push("FM11RF005M (FUDAN ISO14443A w Crypto-1 algo)");
    }else if(sak in sakMap){
      t.push(sakMap[sak]);
    }
  }
  return [t, f];
}

const CTLV_LABEL = {
  1: "Country code in (ISO 3166-1)", 2: "Issuer identification number (ISO 7812-1)",
  3: "Card service data byte", 4: "Initial access data", 5: "Card issuer data",
  6: "Pre-issuing data", 7: "Card capabilities", 8: "Status indicator", 0xE: "Application identifier",
};
const SVC_BITS = [
  "Application selection: by full DF name", "Application selection: by partial DF name",
  "BER-TLV data objects available in EF.DIR", "BER-TLV data objects available in EF.ATR",
  "EF.DIR and EF.ATR access services: by READ BINARY command",
  "EF.DIR and EF.ATR access services: by GET DATA command",
  "EF.DIR and EF.ATR access services: by GET RECORD(s) command",
  "EF.DIR and EF.ATR access services: RFU",
];
const SEL_BITS = [
  "DF selection by full DF name", "DF selection by partial DF name",
  "DF selection by path", "DF selection by file identifier",
  "Implicit DF selection", "Short EF identifier supported",
  "Record number supported", "Record identifier supported",
];

function bitLines(b, labels){
  return labels.map((lab, i) => {
    const pat = Array(8).fill(".");
    pat[i] = (b & (0x80 >> i)) ? "1" : "0";
    return "    " + pat.join("") + "    " + lab;
  });
}

function compactTlv(d){
  const out = [];
  d = d.slice(1);
  const n = d.length;
  let i = 0;
  while(i < n){
    const tag = d[i] >> 4, ln = d[i] & 0x0F;
    const v = d.slice(i + 1, i + 1 + ln);
    if(tag in CTLV_LABEL){
      if(tag === 8 || tag === 0xE) out.push("    " + tag.toString(16) + ln.toString(16) + " ... " + hx(v) + "   " + CTLV_LABEL[tag]);
      else out.push("    " + tag.toString(16) + ln.toString(16) + "  " + hx(v) + "   " + CTLV_LABEL[tag]);
      if(tag === 3 && v.length) out.push(...bitLines(v[0], SVC_BITS));
      if(tag === 7 && v.length){
        out.push("    " + hx2(v[0]) + " - Selection methods");
        out.push(...bitLines(v[0], SEL_BITS));
        if(v.length > 1) out.push("    " + hx2(v[1]) + " - Data coding byte");
        if(v.length > 2) out.push("    " + hx2(v[2]) + " - Command chaining, length fields and logical channels");
      }
    }
    if(ln + 1 > n - i) break;
    i += 1 + ln;
  }
  return out;
}

// ats excludes CRC. Returns [lines, histLines, flags].
function atsLines(ats){
  const out = [], histOut = [];
  const fl = {desfire: false, plus: false, seos: false};
  const ln = ats.length;
  const bad = ats[0] !== ln;
  if(bad) out.push("ATS may be corrupted. Length of ATS (" + ln + " bytes) doesn't match TL");
  out.push("ATS: " + hxs(ats));
  out.push("     " + hx2(ats[0]) + "...............  TL    length is " + ats[0] + " bytes");
  if(bad) return [out, histOut, fl];
  let ta = false, tb = false, tc = false;
  if(ats[0] > 1 && ln > 1){
    const t0 = ats[1];
    ta = !!(t0 & 0x10); tb = !!(t0 & 0x20); tc = !!(t0 & 0x40);
    const fsci = t0 & 0x0F;
    const fsc = fsci < ATS_FSC.length ? ATS_FSC[fsci] : -1;
    out.push("     ..." + hx2(t0) + "............  T0    TA1 is" + (ta ? "" : " NOT") + " present, " +
             "TB1 is" + (tb ? "" : " NOT") + " present, TC1 is" + (tc ? "" : " NOT") + " present, " +
             "FSCI is " + fsci + " (FSC = " + fsc + ")");
  }
  let pos = 2;
  if(ta && ln > pos){
    const b = ats[pos];
    const ds = [[0x10, 2], [0x20, 4], [0x40, 8]].filter(([m]) => b & m).map(([, x]) => x).join(", ");
    const dr = [[0x01, 2], [0x02, 4], [0x04, 8]].filter(([m]) => b & m).map(([, x]) => x).join(", ");
    out.push("     ......" + hx2(b) + ".........  TA1   different divisors are" +
             ((b & 0x80) ? " NOT" : "") + " supported, DR: [" + dr + "], DS: [" + ds + "]");
    pos += 1;
  }
  if(tb && ln > pos){
    const b = ats[pos];
    const sfgi = b & 0x0F, fwi = b >> 4;
    const sfgt = (sfgi ? "" : "(not needed) ") + (sfgi ? 2 ** (12 + sfgi) : 0) + "/fc";
    out.push("     ........." + hx2(b) + "......  TB1   SFGI = " + sfgi + " (SFGT = " + sfgt + "), " +
             "FWI = " + fwi + " (FWT = " + 2 ** (12 + fwi) + "/fc)");
    pos += 1;
  }
  if(tc && ln > pos){
    const b = ats[pos];
    out.push("     ............" + hx2(b) + "...  TC1   NAD is" + ((b & 1) ? "" : " NOT") + " supported, " +
             "CID is" + ((b & 2) ? "" : " NOT") + " supported");
    pos += 1;
  }
  if(ats[0] > pos && ln >= ats[0]){
    const h = ats.slice(pos, ats[0]);
    const c = h.length;
    if(h[0] === 0xC1){
      histOut.push("    " + hxs(h));
      histOut.push("    C1.....................   Mifare or (multiple) virtual cards of various type");
      if(c > 2){
        histOut.push("       " + hx2(h[1]) + "..................   length is " + h[1] + " bytes");
        const hi = h[2] & 0xF0, lo = h[2] & 0x0F;
        if(hi === 0x10){ histOut.push("          1x...............   MIFARE DESFire"); fl.desfire = true; }
        else if(hi === 0x20){ histOut.push("          2x...............   MIFARE Plus"); fl.plus = true; }
        const sz = {0: "< 1 kByte", 1: "1 kByte", 2: "2 kByte", 3: "4 kByte", 4: "8 kByte"};
        if(lo in sz) histOut.push("          x" + lo.toString(16) + "...............   " + sz[lo]);
      }
      if(c > 3){
        const hi = h[3] & 0xF0, lo = h[3] & 0x0F;
        if(hi === 0x00) histOut.push("             0x............   Engineering sample");
        else if(hi === 0x20) histOut.push("             2x............   Released");
        const gen = {0: "Generation 1", 1: "Generation 2", 2: "Generation 3"};
        if(lo in gen) histOut.push("             x" + lo.toString(16) + "............   " + gen[lo]);
      }
      if(c > 4){
        const lo = h[4] & 0x0F;
        const vc = {0: "Only VCSL supported", 1: "VCS, VCSL, and SVC supported", 0xE: "no VCS command supported"};
        if(lo in vc) histOut.push("                x" + lo.toString(16).toUpperCase() + ".........   " + vc[lo]);
      }
    }else if(h[0] === 0x80 || h[0] === 0x00){
      histOut.push(hx(h) + "  (compact TLV data object)");
      histOut.push(...compactTlv(h));
    }else{
      const asc = Array.from(h, x => x >= 32 && x < 127 ? String.fromCharCode(x) : ".").join("");
      histOut.push(hx(h) + " - " + asc);
    }
  }
  if(ln === 5 && (bytesEq(ats, [0x05, 0x78, 0x77, 0x80, 0x02]) || bytesEq(ats, [0x05, 0x78, 0x77, 0x94, 0x02]))) fl.seos = true;
  return [out, histOut, fl];
}

// Types for one scanned tag, as HF14AScan._types does.
function tagTypes(tag, hw){
  const uid = tag.uid, sak = tag.sak, ats = tag.ats;
  const atqa = tag.atqa[0] | (tag.atqa[1] << 8);
  let hist = [];
  if(ats.length){
    let pos = 0;
    if(ats.length > 1 && ats[0] > 1) pos = 2 + [0x10, 0x20, 0x40].filter(m => ats[1] & m).length;
    hist = ats.slice(pos).concat([0, 0]);
  }
  if(uid.length <= 4 || uid[0] === 0x04){
    let [types, flags] = detectTypes(sak, atqa, ats.length > 0, hist, hw);
    if((flags & MTULTRALIGHT) && sak === 0x00 && !hw) types = ["MIFARE Ultralight Classic/C/EV1/Nano | NTAG 2xx"]; // type_id_SAK_dict[0x00]
    return [types, flags];
  }
  return multiUidTypes(uid, sak, atqa) || [[], 0];
}

/* ---- device side: needs request(), CU, u16be() from the page ---- */
const OPT_ACT = 1 << 7, OPT_WAIT = 1 << 6, OPT_CRC = 1 << 5, OPT_SEL = 1 << 4, OPT_KEEP = 1 << 3, OPT_CHKCRC = 1 << 2;

async function rawTx(opts, timeoutMs, data, bitlen){
  const f = await request(CU.HF14A_RAW, [opts, ...u16be(timeoutMs), ...u16be(bitlen === undefined ? data.length * 8 : bitlen), ...data]);
  return Array.from(f.data || []);
}

async function dropField(){
  try{ await rawTx(OPT_ACT | OPT_CRC | OPT_SEL, 200, []); }catch(e){}   // keep_rf and wait cleared
}

// Port of cli_hf_mf.identify_magic_gen: read-only probes.
async function identifyMagicGen(){
  const opt = OPT_ACT | OPT_WAIT | OPT_KEEP;
  for(const [byte, name] of [[0x40, "gen1a"], [0x20, "gen4-gdm"]]){
    try{
      const r = await rawTx(opt, 500, [byte], 7);
      if(r.length && r[0] === 0x0a) return name;
    }catch(e){}
    finally{ await dropField(); }
  }
  const plain = OPT_WAIT | OPT_CRC | OPT_SEL | OPT_CHKCRC;
  try{
    const r = await rawTx(plain, 1000, [0x90, 0xFB, 0xCC, 0xCC, 0x00]);
    if(r.length) return "gen3";
  }catch(e){}
  try{
    const r = await rawTx(plain, 1000, [0xCF, 0, 0, 0, 0, 0xC6]);
    if(r.length) return "gen4-gtu";
  }catch(e){}
  return null;
}

async function getVersion(tag){
  const uid = tag.uid;
  if(!(uid.length === 4 || (uid.length === 7 && uid[0] === 0x04))) return null;
  try{
    if(tag.ats.length){
      const f = await request(CU.HF14A_4_READER_APDU, [0x90, 0x60, 0, 0, 0]);
      const d = Array.from(f.data || []);
      if((f.status === 0x68 || f.status === 0x00) && d.length === 9) return d.slice(0, 7);
      return null;
    }
    const d = await rawTx(OPT_WAIT | OPT_CRC | OPT_SEL | OPT_CHKCRC, 200, [0x60]);
    return d.length >= 8 ? d.slice(1, 8) : null;
  }catch(e){ return null; }
}

// HF14A_SCAN reply: repeated uidlen|uid|atqa[2]|sak|atslen|ats.
function parseScanAll(d){
  const tags = [];
  let off = 0;
  while(off < d.length){
    const ul = d[off++];
    const uid = Array.from(d.slice(off, off + ul)); off += ul;
    const atqa = Array.from(d.slice(off, off + 2)); off += 2;
    const sak = d[off++];
    const al = d[off++];
    const ats = Array.from(d.slice(off, off + al)); off += al;
    tags.push({uid, atqa, sak, ats});
  }
  return tags;
}

function recommend(prng, magic, sak, hasAts){
  if(magic === "gen1a") return "  # Recommended: hf mf cview (read via backdoor, no keys needed), or hf mf cload -f <dump.bin> (write)";
  if(magic === "gen3") return "  # Recommended: hf mf gen3uid / gen3blk";
  if(magic === "gen4") return "  # Recommended: hf mf ggetblk / gconfig (default pwd 00000000 unless set otherwise)";
  if(prng !== null) return "  # Recommended: hf mf autopwn";
  if(sak === 0x00 && !hasAts) return "  # Recommended: hf mfu dump";
  if(hasAts && sak === 0x20) return "  # Recommended: hf des chk --pattern1b";
  return "";
}

function hints(flags, atsFlags, tag){
  const h = [];
  const uid = tag.uid;
  if(flags & MTDESFIRE) h.push("hf des info");
  if(flags & MTULTRALIGHT) h.push("hf mfu version");
  if((flags & MTPLUS) || atsFlags.plus) h.push("hf mfplus info");
  if(atsFlags.desfire) h.push("hf des info");
  if(uid.length > 4 && uid[0] === 0x02) h.push(tag.ats.length ? "hf st25ta info" : "hf mfu version");
  return [...new Set(h)].map(x => "Hint: Try `" + x + "`");
}

function basicLines(tag, hw){
  const uid = tag.uid;
  const lines = [("- UID  : " + hx(uid) + " " + uidType(uid)).replace(/\s+$/, "")];
  const atqaInt = tag.atqa[0] | (tag.atqa[1] << 8);
  lines.push("- ATQA : " + hx(tag.atqa) + " (0x" + atqaInt.toString(16).padStart(4, "0") + ")");
  lines.push("- SAK  : " + hx2(tag.sak));
  if(uid.length > 4){
    lines.push("- Manufacturer: " + manufacturer(uid[0]));
    const label = UID_LABELS[uid[0] + "," + uid[1]];
    if(label) lines.push("    " + label);
  }
  const [types, flags] = tagTypes(tag, hw);
  lines.push("- Possible types:");
  for(const t of types) lines.push("    " + t);
  if(!types.length) lines.push("    failed to fingerprint");
  return [lines, flags];
}

// Full `hf 14a info` report as an array of lines (port of HF14AScan.scan(deep=True)).
async function infoReport(){
  const f = await request(CU.HF14A_SCAN);
  if(f.status !== 0x00) return ["ISO14443-A Tag no found"];
  const tags = parseScanAll(Array.from(f.data || []));
  const out = ["---------- ISO14443-A Information ----------"];
  for(const tag of tags){
    const hw = tags.length === 1 ? await getVersion(tag) : null;
    const [bl, flags] = basicLines(tag, hw);
    out.push(...bl);
    let atsFlags = {};
    if(tag.ats.length){
      const [al, hist, fl] = atsLines(tag.ats);
      out.push("----------------------- ATS -----------------------", ...al);
      if(hist.length){
        out.push("-------------------- Historical bytes ---------------------", ...hist);
      }
      atsFlags = fl;
    }else{
      out.push("Proprietary non iso14443-4 card found, RATS not supported");
    }
    if(tags.length === 1){
      let prng = null, magic = null;
      const sup = await request(CU.MF1_DETECT_SUPPORT);
      if(sup.status === 0x00){
        const p = await request(CU.MF1_DETECT_PRNG);
        if(p.status === 0x00) prng = p.data[0];
        magic = await identifyMagicGen();
        if(magic) out.push("Magic capabilities. " + magic + " backdoor detected");
        out.push(prng === 0 ? "Static nonce....... yes" : prng === 1 ? "Prng detection..... weak" : "Prng detection..... hard");
      }
      const rec = recommend(prng, magic, tag.sak, tag.ats.length > 0);
      if(rec) out.push(rec);
      out.push(...hints(flags, atsFlags, tag));
    }else{
      out.push("Multiple tags detected, skipping deep tests...");
    }
  }
  return out;
}

const Hf14aInfo = {
  manufacturer, uidType, versionStrings, detectTypes, multiUidTypes, compactTlv, atsLines,
  tagTypes, basicLines, recommend, hints, parseScanAll, identifyMagicGen, getVersion, infoReport,
};
if(typeof module !== "undefined") module.exports = Hf14aInfo;
else window.Hf14aInfo = Hf14aInfo;
})();
