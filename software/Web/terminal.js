"use strict";
/* ---------------------------------------------------------------------
 * terminal.js — a Linux-terminal-styled copy of the real chameleon_cli_unit.py
 * / cli_hf_mf.py command grammar (hw / hw slot / hw settings / hf 14a / hf mf),
 * running in-browser over the same request()/CU plumbing fullcmd.js uses.
 * Loaded after canary.js and fullcmd.js: reuses their globals (request(),
 * connected(), need(), $(), hexBytes(), bhex(), stname(), OK_STATUSES, CU).
 *
 * THIS IS A SUBSET, NOT THE WHOLE CLI. The real CLI is ~195 commands across
 * hw/hf/lf/slot/standalone/data/emv, several of which (hf mf nested/darkside/
 * hardnested/autopwn/senested, the DESFire/SEOS/MF+ groups, most of lf) are
 * nontrivial algorithm ports (PRNG/crypto1 recovery, etc.) and are NOT here.
 * Unimplemented groups still exist in the command tree (so `help`/tab-complete
 * walk them) but their leaf commands print a "not ported yet" notice instead
 * of a real result. Commands this file DOES implement mirror the Python
 * CLI's flags and output text as closely as the two environments allow.
 * ------------------------------------------------------------------- */

(function(){

/* ---- reverse lookups built from fullcmd.js's data, for CLI-shaped flags ---- */

// TagSpecificType names exactly as chameleon_enum.py defines them (the real
// `-t`/`--type` choices), not the prettied-up display strings TAG_TYPE_NAMES
// uses elsewhere on this page.
const TAG_TYPE_BY_NAME = {
  EM410X:100, EM410X_16:101, EM410X_32:102, EM410X_64:103, EM410X_ELECTRA:104,
  FDXB:105, PAC:150, Viking:170, Jablotron:180, HIDProx:200, ioProx:201,
  IDTECK:310, Indala:311,
  MIFARE_Mini:1000, MIFARE_1024:1001, MIFARE_2048:1002, MIFARE_4096:1003,
  MIFARE_PLUS_S2K:1004, MIFARE_PLUS_S4K:1005, MIFARE_PLUS_S2K_SL3:1006, MIFARE_PLUS_S4K_SL3:1007,
  NTAG_213:1100, NTAG_215:1101, NTAG_216:1102, MF0ICU1:1103, MF0ICU2:1104,
  MF0UL11:1105, MF0UL21:1106, NTAG_210:1107, NTAG_212:1108,
  DESFIRE_EV1_2K:1300, DESFIRE_EV1_4K:1301, DESFIRE_EV1_8K:1302,
  DESFIRE_EV2_2K:1303, DESFIRE_EV2_4K:1304, DESFIRE_EV2_8K:1305,
  ST25TA:2000, HF14A_4:3000, SEOS:3001,
};

const ANIMATION_BY_NAME = { FULL:0, MINIMAL:1, NONE:2, SYMMETRIC:3 };
const BUTTON_FN_BY_NAME = { NONE:0, NEXTSLOT:1, PREVSLOT:2, CLONE:3, BATTERY:4, FIELDGEN:5, STANDALONE_DISARM:6 };
const SENSE_NAMES = { 1:"HF", 2:"LF" }; // TagSenseType, matches firmware's hw_main.h

// UID byte 0 -> manufacturer, ISO/IEC 7816-6 (pm3 manufactureMapping), ported
// verbatim from hf14a_info.py's MANUFACTURERS table.
const MANUFACTURERS = {
0x01:"Motorola UK",0x02:"ST Microelectronics SA France",0x03:"Hitachi, Ltd Japan",0x04:"NXP Semiconductors Germany",0x05:"Infineon Technologies AG Germany",0x06:"Cylink USA",0x07:"Texas Instrument France",0x08:"Fujitsu Limited Japan",0x09:"Matsushita Electronics Corporation, Semiconductor Company Japan",0x0A:"NEC Japan",0x0B:"Oki Electric Industry Co. Ltd Japan",0x0C:"Toshiba Corp. Japan",0x0D:"Mitsubishi Electric Corp. Japan",0x0E:"Samsung Electronics Co. Ltd Korea",0x0F:"Hynix / Hyundai, Korea",0x10:"LG-Semiconductors Co. Ltd Korea",0x11:"Emosyn-EM Microelectronics USA",0x12:"Wisekey Semiconductors (previously INSIDE Technology) France",0x13:"ORGA Kartensysteme GmbH Germany",0x14:"SHARP Corporation Japan",0x15:"ATMEL France",0x16:"EM Microelectronic-Marin SA Switzerland",0x17:"SMARTRAC TECHNOLOGY GmbH Germany",0x18:"ZMD AG Germany",0x19:"XICOR, Inc. USA",0x1A:"Sony Corporation Japan",0x1B:"Malaysia Microelectronic Solutions Sdn. Bhd Malaysia",0x1C:"Emosyn USA",0x1D:"Shanghai Fudan Microelectronics Co. Ltd. P.R. China",0x1E:"Magellan Technology Pty Limited Australia",0x1F:"Melexis NV BO Switzerland",0x20:"Renesas Technology Corp. Japan",0x21:"TAGSYS France",0x22:"Transcore USA",0x23:"Shanghai belling corp., ltd. China",0x24:"Masktech Germany Gmbh Germany",0x25:"Innovision Research and Technology Plc UK",0x26:"Hitachi ULSI Systems Co., Ltd. Japan",0x27:"Yubico AB Sweden",0x28:"Ricoh Japan",0x29:"ASK France",0x2A:"Unicore Microsystems, LLC Russian Federation",0x2B:"Dallas Semiconductor/Maxim USA",0x2C:"Impinj, Inc. USA",0x2D:"RightPlug Alliance USA",0x2E:"Broadcom Corporation USA",0x2F:"MStar Semiconductor, Inc Taiwan, ROC",0x30:"BeeDar Technology Inc. USA",0x31:"RFIDsec Denmark",0x32:"Schweizer Electronic AG Germany",0x33:"AMIC Technology Corp Taiwan",0x34:"Mikron JSC Russia",0x35:"Fraunhofer Institute for Photonic Microsystems Germany",0x36:"IDS Microchip AG Switzerland",0x37:"Kovio USA",0x38:"HMT Microelectronic Ltd Switzerland",0x39:"Silicon Craft Technology Thailand",0x3A:"Advanced Film Device Inc. Japan",0x3B:"Nitecrest Ltd UK",0x3C:"Verayo Inc. USA",0x3D:"HID Global USA",0x3E:"Productivity Engineering Gmbh Germany",0x3F:"Austriamicrosystems AG (reserved) Austria",0x40:"Thales DIS (previously Gemalto SA) France",0x41:"Renesas Electronics Corporation Japan",0x42:"3Alogics Inc Korea",0x43:"Top TroniQ Asia Limited Hong Kong",0x44:"Gentag Inc. USA",0x45:"Invengo Information Technology Co. Ltd China",0x46:"Guangzhou Sysur Microelectronics, Inc China",0x47:"CEITEC S.A. Brazil",0x48:"Shanghai Quanray Electronics Co. Ltd. China",0x49:"MediaTek Inc Taiwan",0x4A:"Angstrem PJSC Russia",0x4B:"Celisic Semiconductor (Hong Kong) Limited China",0x4C:"LEGIC Identsystems AG Switzerland",0x4D:"Balluff GmbH Germany",0x4E:"Oberthur Technologies France",0x4F:"Silterra Malaysia Sdn. Bhd. Malaysia",0x50:"Presto Engineering Denmark",0x51:"Giesecke & Devrient GmbH Germany",0x52:"Shenzhen China Vision Microelectronics Co., Ltd. China",0x53:"Shanghai Feiju Microelectronics Co. Ltd. China",0x54:"Intel Corporation USA",0x55:"Microsensys GmbH Germany",0x56:"Sonix Technology Co., Ltd. Taiwan",0x57:"Qualcomm Technologies Inc USA",0x58:"Realtek Semiconductor Corp Taiwan",0x59:"Freevision Technologies Co. Ltd China",0x5A:"Giantec Semiconductor Inc. China",0x5B:"JSC Angstrem-T Russia",0x5C:"STARCHIP France",0x5D:"SPIRTECH France",0x5E:"GANTNER Electronic GmbH Austria",0x5F:"Nordic Semiconductor Norway",0x60:"Verisiti Inc USA",0x61:"Wearlinks Technology Inc. China",0x62:"Userstar Information Systems Co., Ltd Taiwan",0x63:"Pragmatic Printing Ltd. UK",0x64:"Associação do Laboratório de Sistemas Integráveis Tecnológico - LSI-TEC Brazil",0x65:"Tendyron Corporation China",0x66:"MUTO Smart Co., Ltd. Korea",0x67:"ON Semiconductor USA",0x68:"TÜBITAK BILGEM Turkey",0x69:"Huada Semiconductor Co., Ltd China",0x6A:"SEVENEY France",0x6B:"THALES DIS Design Services SAS (previously ISSM) France",0x6C:"Wisesec Ltd Israel",0x6D:"LTD \\\"NM-Teh\\\" Russia",0x70:"ifm electronic gmbh Germany",0x71:"Sichuan Kiloway Technologies Co., Ltd. China",0x72:"Ford Motor Company US",0x73:"Beijing Tsingteng MicroSystem Co.,Ltd China",0x74:"Huada EverCore Co., Ltd China",0x75:"Smartchip Microelectronics Corporation Taiwan",0x76:"Tongxin Microelectronics Co., Ltd. China",0x77:"Ningbo IOT Microelectronics Co Ltd China",0x78:"AU Optronics Taiwan",0x79:"CUBIC USA",0x7A:"Abbott Diabetes Care USA",0x7B:"Shenzen Nation RFID Technology Co Ltd China",0x7C:"DB HiTek Co Ltd Korea",0x7D:"SATO Vicinity Australia",0x7E:"Holtek Taiwan",0x7F:"Shenzhen Goodix Technology Co., Ltd. China",0x80:"Panthronics AG Austria",0x81:"Beijing Huada Infosec Technology Co., Ltd China",0x82:"Shanghai Oriental Magnetic Card Engineering Co Ltd. China",0x83:"8ApeX Inc USA",0x84:"Abbott Ireland",0x85:"Proqure Inc USA",0x86:"Schreiner Group GmbH & Co. KG Germany",0x87:"Beijing SmartChip Microelectronics Technology Company Limited China",0x88:"Datang Microelectronics Technology Co., Ltd. China",0x89:"Wise Security Technology (Guangzhou) Co., Ltd. China",0x8A:"CEC Huada Electronic Design Co., Ltd. China",0x8B:"Shanghai Techsun RFID Technology Co., Ltd. China",0x8C:"North China Institute of Computing Technology China",0x8D:"Shanghai Huahong Integrated Circuit Co., Ltd. China",0x8E:"Shanghai MintSilicon Microelectronics Inc., Ltd. China",0x8F:"Xinsheng Technology Co., Ltd. China",0x90:"IDEX Biometrics ASA Norway",0x91:"Novo Nordisk A/S Denmark",0x92:"Shandong Huayi Micro-Electronics Technology Co., Ltd. China",0x93:"Abbott Heart Failure USA",0x94:"P&M Information Technology (Shenzhen) Co., Ltd. China",0x95:"MARS TECHNOLOGY PTE. LTD. Singapore",0x96:"Trovan Limited Isle of Man"
};
function manufacturerName(uid0){ return MANUFACTURERS[uid0] || "no tag-info available"; }

// HIDFormat (chameleon_enum.py) -- name -> value, for `lf hid prox` -f/--format.
const HID_FORMAT_BY_NAME = {
  H10301:1, IND26:2, IND27:3, INDASC27:4, TECOM27:5, W2804:6, IND29:7, ATSW30:8,
  ADT31:9, HCP32:10, HPP32:11, KASTLE:12, KANTECH:13, WIE32:14, D10202:15,
  H10306:16, N10002:17, OPTUS34:18, SMP34:19, BQT34:20, C1K35S:21, C15001:22,
  S12906:23, ACTPHID:42, SIE36:24, H10320:25, H10302:26, H10304:27, P10004:28,
  HGEN37:29, MDI37:30,
};
const HID_FORMAT_BY_VALUE = Object.fromEntries(Object.entries(HID_FORMAT_BY_NAME).map(([k,v])=>[v,k]));

/* ---------------------------------------------------------------------
 *  Minimal argparse-lite: tokenize (quote-aware) + flag parsing.
 * ------------------------------------------------------------------- */

function tokenize(line){
  const out = [];
  let cur = "", q = null;
  for(let i=0;i<line.length;i++){
    const c = line[i];
    if(q){
      if(c === q) q = null;
      else cur += c;
    } else if(c === '"' || c === "'"){
      q = c;
    } else if(/\s/.test(c)){
      if(cur){ out.push(cur); cur=""; }
    } else {
      cur += c;
    }
  }
  if(cur) out.push(cur);
  return out;
}

class ArgError extends Error {}

// Mirrors ReaderRequiredUnit.before_exec (cli_core.py): every hf14a/hf mf
// command the real CLI builds on that base auto-switches the device into
// Tag Reader mode first. Without this, scan/raw/rdbl/wrbl silently report
// "no tag" whenever the device is left in Tag Emulator mode.
async function needReader(){
  need();
  const f = okOrThrow(await request(CU.GET_DEVICE_MODE));
  if(!f.data[0]) okOrThrow(await request(CU.CHANGE_DEVICE_MODE, [1]));
}

/* spec: { flags: [{names:["-s","--slot"], takesValue:bool, required:bool, dest, choices?}] } */
function parseFlags(tokens, specs){
  const out = {};
  const positional = specs.find(s => s.positional);
  if(positional) out[positional.dest] = [];
  for(const s of specs) if(!s.takesValue && !s.positional) out[s.dest] = false;
  for(let i=0;i<tokens.length;i++){
    const t = tokens[i];
    const spec = specs.find(s => s.names && s.names.includes(t));
    if(!spec){
      // nargs="*"-style positional: a bare (non-flag-shaped) token is
      // collected instead of rejected, same as argparse's `nargs="*"`.
      if(positional && !/^-/.test(t)){ out[positional.dest].push(t); continue; }
      throw new ArgError("unrecognized argument: "+t);
    }
    if(spec.takesValue){
      if(i+1 >= tokens.length) throw new ArgError("argument "+spec.names.join("/")+": expected one value");
      const v = tokens[++i];
      if(spec.choices && !spec.choices.includes(v)) throw new ArgError("argument "+spec.names.join("/")+": invalid choice: '"+v+"' (choose from "+spec.choices.join(", ")+")");
      out[spec.dest] = v;
    } else {
      out[spec.dest] = true;
    }
  }
  for(const s of specs) if(s.required && out[s.dest] === undefined) {
    throw new ArgError("the following arguments are required: "+s.names.join("/"));
  }
  return out;
}

/* ---------------------------------------------------------------------
 *  Command tree -- mirrors cli_core.py's root.subgroup()/*.command() shape.
 * ------------------------------------------------------------------- */

class Group {
  constructor(name, help){ this.name=name; this.help=help; this.children=new Map(); }
  subgroup(name, help){ const g=new Group(name, help); this.children.set(name, g); return g; }
  command(name, help, specs, run){ this.children.set(name, {name, help, specs:specs||[], run, leaf:true}); return this; }
}

const ROOT = new Group("", "ChameleonUltra (Phreakbyte) in-browser terminal");

function notPorted(groupPath){
  // .run is what dispatch() actually calls (via node.name==="*") -- the rest
  // of this object is never read. An earlier version of this helper left
  // .run undefined, so every "*" stub built from it (e.g. `hf mfu`) threw
  // "node.run is not a function" the moment it was invoked.
  return { run: async () => ["("+groupPath+" commands aren't ported to this terminal yet.)"] };
}

/* ================= hw ================= */
const hw = ROOT.subgroup("hw", "Hardware-related commands");

hw.command("connect", "Connection is managed by this page's own Connect button, not from here.", [],
  async () => [connected() ? "- Already connected." : "- Not connected. Use the page's Connect button (BLE/serial picker can't be driven from a typed command)."]);

hw.command("disconnect", "Disconnection is managed by this page's own Disconnect/Connect toggle.", [],
  async () => ["- Use the page's Connect button to disconnect."]);

hw.command("mode", "Get or change device mode: tag reader or tag emulator", [
  {names:["-r","--reader"], takesValue:false, dest:"reader"},
  {names:["-e","--emulator"], takesValue:false, dest:"emulator"},
], async (a) => {
  need();
  if(a.reader && a.emulator) throw new ArgError("-r/--reader and -e/--emulator are mutually exclusive");
  if(a.reader){
    okOrThrow(await request(CU.CHANGE_DEVICE_MODE, [1]));
    return ["Switch to {  Tag Reader  } mode successfully."];
  } else if(a.emulator){
    okOrThrow(await request(CU.CHANGE_DEVICE_MODE, [0]));
    return ["Switch to { Tag Emulator } mode successfully."];
  } else {
    const f = okOrThrow(await request(CU.GET_DEVICE_MODE));
    return ["- Device Mode ( Tag "+(f.data[0]?"Reader":"Emulator")+" )"];
  }
});

hw.command("chipid", "Get device chipset ID", [], async () => {
  need();
  const f = okOrThrow(await request(CU.GET_DEVICE_CHIP_ID));
  return [" - Device chip ID: "+bhex(f.data)];
});

hw.command("address", "Get device address (used with Bluetooth)", [], async () => {
  need();
  const f = okOrThrow(await request(CU.GET_DEVICE_ADDRESS));
  return [" - Device address: "+bhex(f.data)];
});

hw.command("version", "Get current device firmware version", [], async () => {
  need();
  const fv = okOrThrow(await request(CU.GET_APP_VERSION));
  const gv = okOrThrow(await request(CU.GET_GIT_VERSION));
  const mv = okOrThrow(await request(CU.GET_DEVICE_MODEL));
  const model = ["Ultra","Lite"][mv.data[0]] || ("unknown ("+mv.data[0]+")");
  return [" - Phreakbyte edition ("+model+"), Version: v"+fv.data[0]+"."+fv.data[1]+" ("+bytesToUtf8(gv.data)+")"];
});

hw.command("battery", "Get battery information, voltage and level", [], async () => {
  need();
  const f = okOrThrow(await request(CU.GET_BATTERY_INFO));
  const mv=(f.data[0]<<8)|f.data[1], pct=f.data[2];
  const lines = [" - Battery information:", "   voltage    -> "+mv+" mV", "   percentage -> "+pct+"%"];
  if(pct < 30) lines.push("[!] Low battery, please charge.");
  return lines;
});

hw.command("blver", "Show the bootloader version (settings counter; full info-block decode not ported here)", [], async () => {
  need();
  const f = okOrThrow(await request(CU.GET_BOOTLOADER_VERSION));
  let v;
  if(f.data.length===4) v = ((f.data[0]<<24)|(f.data[1]<<16)|(f.data[2]<<8)|f.data[3])>>>0;
  else if(f.data.length===2) v = (f.data[0]<<8)|f.data[1];
  else v = bhex(f.data);
  return [" - Bootloader Version: "+v+" (settings counter; use the Device tab for the full info-block decode)"];
});

hw.command("freemem", "Get device heap memory usage", [], async () => {
  need();
  const f = okOrThrow(await request(CU.GET_FREE_MEMORY));
  const free=(f.data[0]<<24|f.data[1]<<16|f.data[2]<<8|f.data[3])>>>0;
  const total=(f.data[4]<<24|f.data[5]<<16|f.data[6]<<8|f.data[7])>>>0;
  return [" - Free memory: "+free+" / "+total+" bytes (used "+(total-free)+")"];
});

hw.command("raw", "Send a raw command (same as this page's Shell tab) -- see `hw raw -h`-style usage below", [
  {names:["-c","--command"], takesValue:true, dest:"command"},
  {names:["-n","--num_command"], takesValue:true, dest:"num_command"},
  {names:["-d","--data"], takesValue:true, dest:"data"},
], async (a) => {
  need();
  let cmdId;
  if(a.command !== undefined){
    if(!(a.command.toUpperCase() in CU)) throw new ArgError("unknown --command "+a.command);
    cmdId = CU[a.command.toUpperCase()];
  } else if(a.num_command !== undefined){
    cmdId = parseInt(a.num_command, 10);
  } else {
    throw new ArgError("one of -c/--command or -n/--num_command is required");
  }
  const payload = hexBytes(a.data || "");
  const f = await request(cmdId, payload);
  const lines = [" - Received:", "   Command: "+cmdId, "   Status:  0x"+f.status.toString(16).padStart(2,"0")+" "+stname(f.status)];
  lines.push(f.data && f.data.length ? "   Data (HEX): "+bhex(f.data) : "   Data (HEX): (none)");
  return lines;
});

/* ---- hw slot ---- */
const hwSlot = hw.subgroup("slot", "Emulation slots commands");

function slotFlag(required){ return {names:["-s","--slot"], takesValue:true, dest:"slot", required: !!required}; }
function senseFlags(){ return [
  {names:["--hf"], takesValue:false, dest:"hf"},
  {names:["--lf"], takesValue:false, dest:"lf"},
]; }
function resolveSense(a){
  if(a.hf && a.lf) throw new ArgError("--hf and --lf are mutually exclusive");
  if(!a.hf && !a.lf) throw new ArgError("one of --hf or --lf is required");
  return a.hf ? "HF" : "LF";
}
async function currentSlot1(){
  const f = okOrThrow(await request(CU.GET_ACTIVE_SLOT));
  return f.data[0] + 1; // firmware is 0-based, CLI is 1-based
}

hwSlot.command("list", "Get information about slots (reduced: active slot + per-slot HF/LF tag type only -- nicknames/MF1 config columns not ported here)", [], async () => {
  need();
  const info = okOrThrow(await request(CU.GET_SLOT_INFO));
  const active = await currentSlot1();
  const lines = [];
  // GET_SLOT_INFO: 8 slots * {hf type u16, lf type u16}, big-endian.
  for(let s=0;s<8;s++){
    const off = s*4;
    const hfT = (info.data[off]<<8)|info.data[off+1];
    const lfT = (info.data[off+2]<<8)|info.data[off+3];
    const mark = (s+1)===active ? "  (active)" : "";
    lines.push("Slot "+(s+1)+mark+":  HF="+tagTypeName(hfT)+"  LF="+tagTypeName(lfT));
  }
  return lines;
});

hwSlot.command("change", "Set emulation tag slot activated", [slotFlag(true)], async (a) => {
  need();
  const slot = Number(a.slot);
  if(!(slot>=1 && slot<=8)) throw new ArgError("--slot must be 1-8");
  okOrThrow(await request(CU.SET_ACTIVE_SLOT, [slot-1]));
  return [" - Set slot "+slot+" activated success."];
});

hwSlot.command("type", "Set emulation tag type", [slotFlag(false), {names:["-t","--type"], takesValue:true, dest:"type", required:true, choices:Object.keys(TAG_TYPE_BY_NAME)}], async (a) => {
  need();
  const typeId = TAG_TYPE_BY_NAME[a.type];
  const slot = a.slot !== undefined ? Number(a.slot) : await currentSlot1();
  okOrThrow(await request(CU.SET_SLOT_TAG_TYPE, [slot-1, (typeId>>8)&255, typeId&255]));
  okOrThrow(await request(CU.SET_SLOT_DATA_DEFAULT, [slot-1, (typeId>>8)&255, typeId&255]));
  return [" - Set slot "+slot+" tag type success."];
});

hwSlot.command("delete", "Delete sense type data for a specific slot", [slotFlag(false), ...senseFlags()], async (a) => {
  need();
  const sense = resolveSense(a);
  const slot = a.slot !== undefined ? Number(a.slot) : await currentSlot1();
  okOrThrow(await request(CU.DELETE_SLOT_SENSE_TYPE, [slot-1, sense==="HF"?1:2]));
  return [" - Delete slot "+slot+" "+sense+" tag type success."];
});

hwSlot.command("enable", "Enable tag slot", [slotFlag(false), ...senseFlags()], async (a) => {
  need();
  const sense = resolveSense(a);
  const slot = a.slot !== undefined ? Number(a.slot) : await currentSlot1();
  okOrThrow(await request(CU.SET_SLOT_ENABLE, [slot-1, sense==="HF"?1:2, 1]));
  return [" - Enable slot "+slot+" "+sense+" success."];
});

hwSlot.command("disable", "Disable tag slot", [slotFlag(true), ...senseFlags()], async (a) => {
  need();
  const sense = resolveSense(a);
  okOrThrow(await request(CU.SET_SLOT_ENABLE, [Number(a.slot)-1, sense==="HF"?1:2, 0]));
  return [" - Disable slot "+a.slot+" "+sense+" success."];
});

hwSlot.command("nick", "Get/Set/Delete tag nick name for slot", [slotFlag(false), ...senseFlags(),
  {names:["-n","--name"], takesValue:true, dest:"name"},
  {names:["-d","--delete"], takesValue:false, dest:"delete"},
], async (a) => {
  need();
  const sense = resolveSense(a);
  const senseByte = sense==="HF"?1:2;
  const slot = a.slot !== undefined ? Number(a.slot) : await currentSlot1();
  if(a.name !== undefined){
    okOrThrow(await request(CU.SET_SLOT_TAG_NICK, [slot-1, senseByte, ...utf8Bytes(a.name)]));
    return [" - Set tag nick name for slot "+slot+" "+sense+": "+a.name];
  } else if(a.delete){
    okOrThrow(await request(CU.DELETE_SLOT_TAG_NICK, [slot-1, senseByte]));
    return [" - Delete tag nick name for slot "+slot+" "+sense];
  } else {
    const f = okOrThrow(await request(CU.GET_SLOT_TAG_NICK, [slot-1, senseByte]));
    return [" - Get tag nick name for slot "+slot+" "+sense+": "+bytesToUtf8(f.data)];
  }
});

/* ---- hw settings ---- */
const hwSettings = hw.subgroup("settings", "Chameleon settings commands");

hwSettings.command("animation", "Get or change current animation mode value", [
  {names:["-m","--mode"], takesValue:true, dest:"mode", choices:Object.keys(ANIMATION_BY_NAME)},
], async (a) => {
  need();
  if(a.mode !== undefined){
    okOrThrow(await request(CU.SET_ANIMATION_MODE, [ANIMATION_BY_NAME[a.mode]]));
    return ["Animation mode change success.", "Do not forget to store your settings in flash! (hw settings store)"];
  }
  const f = okOrThrow(await request(CU.GET_ANIMATION_MODE));
  const name = Object.keys(ANIMATION_BY_NAME).find(k=>ANIMATION_BY_NAME[k]===f.data[0]) || f.data[0];
  return [String(name)];
});

hwSettings.command("sleeptimeout", "Get or set the wake timeout after a button press (5-60 seconds)", [
  {names:["-s","--seconds"], takesValue:true, dest:"seconds"},
], async (a) => {
  need();
  if(a.seconds !== undefined){
    const s = Number(a.seconds);
    if(s<5) return ["Error: value is too low. Please enter a value between 5 and 60 seconds."];
    if(s>60) return ["Error: value is too high. Please enter a value between 5 and 60 seconds."];
    const lines = [];
    if(s>=30) lines.push("Warning: a long wake timeout will drain the battery faster.");
    okOrThrow(await request(CU.SET_SLEEP_TIMEOUT, [s&0xFF]));
    lines.push("Wake timeout set to "+s+" seconds.", "Do not forget to store your settings in flash! (hw settings store)");
    return lines;
  }
  const f = okOrThrow(await request(CU.GET_SLEEP_TIMEOUT));
  return ["Current wake timeout: "+f.data[0]+" seconds"];
});

hwSettings.command("bleclearbonds", "Delete all BLE bonds", [], async () => {
  need();
  okOrThrow(await request(CU.DELETE_ALL_BLE_BONDS));
  return [" - Delete all bonds success."];
});

hwSettings.command("btnpress", "Get or set button press function of Button A and Button B", [
  {names:["-a","-A"], takesValue:false, dest:"a"},
  {names:["-b","-B"], takesValue:false, dest:"b"},
  {names:["-s","--short"], takesValue:false, dest:"short"},
  {names:["-l","--long"], takesValue:false, dest:"long"},
  {names:["-f","--function"], takesValue:true, dest:"fn", choices:Object.keys(BUTTON_FN_BY_NAME)},
], async (a) => {
  need();
  if(a.a && a.b) throw new ArgError("-a and -b are mutually exclusive");
  if(a.short && a.long) throw new ArgError("-s/--short and -l/--long are mutually exclusive");
  const isLong = !!a.long;
  if(a.fn !== undefined){
    if(!a.a && !a.b) return ["You must specify which button you want to change (-a or -b)"];
    const type = (a.a ? "A" : "B").charCodeAt(0);
    const fn = BUTTON_FN_BY_NAME[a.fn];
    okOrThrow(await request(isLong ? CU.SET_LONG_BUTTON_PRESS_CONFIG : CU.SET_BUTTON_PRESS_CONFIG, [type, fn]));
    return ["Button "+(a.a?"A":"B")+" ("+(isLong?"long":"short")+" press) set to: "+a.fn,
            "Do not forget to store your settings in flash! (hw settings store)"];
  }
  if(!a.a && !a.b) throw new ArgError("-a or -b is required to read a button's current function");
  const type = (a.a ? "A" : "B").charCodeAt(0);
  const f = okOrThrow(await request(isLong ? CU.GET_LONG_BUTTON_PRESS_CONFIG : CU.GET_BUTTON_PRESS_CONFIG, [type]));
  const name = Object.keys(BUTTON_FN_BY_NAME).find(k=>BUTTON_FN_BY_NAME[k]===f.data[0]) || f.data[0];
  return ["Button "+(a.a?"A":"B")+" ("+(isLong?"long":"short")+" press): "+name];
});

/* ================= hf ================= */
const hf = ROOT.subgroup("hf", "High Frequency commands");
const hf14a = hf.subgroup("14a", "ISO14443-a commands");
const hfMf  = hf.subgroup("mf", "MIFARE Classic commands");
hf.subgroup("mfu", "MIFARE Ultralight / NTAG commands").command("*", null, [], notPorted("hf mfu").run);
hf.subgroup("des", "MIFARE DESFire commands");
hf.subgroup("seos", "SEOS commands");
hf.subgroup("st25ta", "ST25TA (NFC Forum Type 4) commands");
hf.subgroup("mfplus", "MIFARE Plus SL3 (AES) commands");

// one tag: uid_len(1) uid(uid_len) atqa(2) sak(1) ats_len(1) ats(ats_len) --
// uid is exactly uid_len bytes on the wire, NOT padded (app_cmd.c
// cmd_processor_hf14a_scan). Shared by `scan` and `info`.
async function hf14aScanOnce(){
  const f = await request(CU.HF14A_SCAN);
  if(!OK_STATUSES.has(f.status)) return null;
  const d = f.data;
  const uidLen = d[0];
  const uid = d.slice(1, 1+uidLen);
  let off = 1 + uidLen;
  const atqa = d.slice(off, off+2); off+=2;
  const sak = d[off]; off+=1;
  const atsLen = d[off]; off+=1;
  const ats = d.slice(off, off+atsLen);
  return {uid, atqa, sak, ats};
}

hf14a.command("scan", "Scan 14a tag, print UID/ATQA/SAK/ATS (PRNG/magic-card detection not ported here -- see `hf 14a info`)", [], async () => {
  await needReader();
  const tag = await hf14aScanOnce();
  if(!tag) return ["ISO14443-A Tag No Found."];
  const lines = [
    "- UID  : "+bhex(tag.uid),
    "- ATQA : "+bhex(tag.atqa),
    "- SAK  : "+bhex([tag.sak]),
  ];
  if(tag.ats.length) lines.push("- ATS  : "+bhex(tag.ats));
  return lines;
});

// Reduced port of HF14AInfo/HF14AScan.scan(deep=True) (chameleon_cli_unit.py).
// Covers: basic fields, manufacturer (7-byte UIDs), MF1 support/PRNG, and a
// read-only gen1a magic-card probe. NOT ported: the full pm3-style
// type-fingerprint table (detect_types/multi_uid_types), ATS TLV decode
// (ats_lines), the GetVersion APDU, and gen3/gen4-gdm magic probes -- these
// are ~400 lines of table-driven logic in hf14a_info.py/cli_hf_mf.py that
// didn't fit this batch. Use the real CLI's `hf 14a info` for the full report.
hf14a.command("info", "Scan 14a tag, print detail information (reduced -- see command help)", [], async () => {
  await needReader();
  const tag = await hf14aScanOnce();
  if(!tag) return ["ISO14443-A Tag no found"];
  const lines = [
    "- UID  : "+bhex(tag.uid),
    "- ATQA : "+bhex(tag.atqa),
    "- SAK  : "+bhex([tag.sak]),
  ];
  if(tag.uid.length > 4) lines.push("- Manufacturer: "+manufacturerName(tag.uid[0]));
  if(tag.ats.length) lines.push("- ATS  : "+bhex(tag.ats));
  else lines.push("Proprietary non iso14443-4 card found, RATS not supported");

  // mf1_detect_support / mf1_detect_prng (MF1_DETECT_SUPPORT/MF1_DETECT_PRNG,
  // already used by this page's HF14A/MF1 tab).
  // mf1_detect_support (chameleon_cmd.py) checks the exact STATUS_HF_TAG_OK
  // (0x00), not the broader OK_STATUSES set used elsewhere.
  const sup = await request(CU.MF1_DETECT_SUPPORT);
  if(sup.status === 0x00){
    const prng = okOrThrow(await request(CU.MF1_DETECT_PRNG));
    const pt = prng.data[0];
    lines.push(pt===0 ? "Static nonce....... yes" : pt===1 ? "Prng detection..... weak" : "Prng detection..... hard");

    // Read-only gen1a magic-card probe: 7-bit 0x40 "unlock stage 1" command;
    // a real card ignores/NAKs it, a gen1a card ACKs with 0x0a. Never sends
    // the stage-2 0x43 or any write (cli_hf_mf.identify_magic_gen).
    try{
      const optsOn  = (1<<7)|(1<<6)|(1<<3); // activate_rf, wait_response, keep_rf
      const probe = await request(CU.HF14A_RAW, [optsOn, ...u16be(500), ...u16be(7), 0x40]);
      if(OK_STATUSES.has(probe.status) && probe.data.length && probe.data[0]===0x0a){
        lines.push("Magic capabilities. gen1a backdoor detected");
      }
    }catch(e){ /* best-effort probe; a real card erroring out here is expected */ }
    finally{
      try{ await request(CU.HF14A_RAW, [(1<<7), ...u16be(200), ...u16be(0)]); }catch(e){} // drop field
    }
  }
  return lines;
});

// Flags mirror the real `hf 14a raw` (chameleon_cli_unit.py HF14ARaw) exactly,
// including -r's inverted sense (it means "do NOT wait for response").
hf14a.command("raw", "Send raw ISO14443-A data", [
  {names:["-a","--activate-rf"], takesValue:false, dest:"activateRf"},
  {names:["-s","--select-tag"], takesValue:false, dest:"selectTag"},
  {names:["-d","--data"], takesValue:true, dest:"data"},
  {names:["-b","--bits"], takesValue:true, dest:"bits"},
  {names:["-c","--crc"], takesValue:false, dest:"crc"},
  {names:["-r","--no-response"], takesValue:false, dest:"noResponse"},
  {names:["-cc","--crc-clear"], takesValue:false, dest:"crcClear"},
  {names:["-k","--keep-rf"], takesValue:false, dest:"keepRf"},
  {names:["-t","--timeout"], takesValue:true, dest:"timeout"},
], async (a) => {
  await needReader();
  if(a.bits !== undefined && a.crc) throw new ArgError("--bits and --crc are mutually exclusive");
  const bytes = a.data !== undefined ? hexBytes(a.data) : [];
  const bitlen = a.bits !== undefined ? Number(a.bits) : bytes.length*8;
  const timeout = a.timeout !== undefined ? Math.max(0, Math.min(65535, Number(a.timeout))) : 100;
  // options byte, LSB->MSB (cmd_processor_hf14a_raw, app_cmd.c): reserved
  // (b0-1), check_response_crc(b2), keep_rf_field(b3), auto_select(b4),
  // append_crc(b5), wait_response(b6), activate_rf_field(b7).
  const waitResponse = !a.noResponse;
  const opts = ((a.activateRf?1:0)<<7) | ((waitResponse?1:0)<<6) | ((a.crc?1:0)<<5) |
               ((a.selectTag?1:0)<<4) | ((a.keepRf?1:0)<<3) | ((a.crcClear?1:0)<<2);
  const payload = [opts, ...u16be(timeout), ...u16be(bitlen), ...bytes];
  const f = await request(CU.HF14A_RAW, payload);
  const data = f.data || [];
  return ["- status: "+stname(f.status), "- data  : "+(data.length ? bhex(data) : "(none)")];
});

hfMf.command("rdbl", "Mifare Classic read one block", [
  {names:["--blk","--block"], takesValue:true, dest:"blk", required:true},
  {names:["-a","-A"], takesValue:false, dest:"a"},
  {names:["-b","-B"], takesValue:false, dest:"b"},
  {names:["-k","--key"], takesValue:true, dest:"key", required:true},
], async (a) => {
  await needReader();
  if(a.a && a.b) throw new ArgError("-a and -b are mutually exclusive");
  const keytype = a.b ? 0x61 : 0x60;
  const key = hexBytes(a.key, 6);
  if(key.length!==6) throw new ArgError("key must be 12 hex chars (6 bytes)");
  const f = okOrThrow(await request(CU.MF1_READ_ONE_BLOCK, [keytype, Number(a.blk), ...key]));
  return [" - Data: "+bhex(f.data)];
});

hfMf.command("wrbl", "Mifare Classic write one block", [
  {names:["--blk","--block"], takesValue:true, dest:"blk", required:true},
  {names:["-a","-A"], takesValue:false, dest:"a"},
  {names:["-b","-B"], takesValue:false, dest:"b"},
  {names:["-k","--key"], takesValue:true, dest:"key", required:true},
  {names:["-d","--data"], takesValue:true, dest:"data", required:true},
], async (a) => {
  await needReader();
  if(a.a && a.b) throw new ArgError("-a and -b are mutually exclusive");
  const keytype = a.b ? 0x61 : 0x60;
  const key = hexBytes(a.key, 6);
  if(key.length!==6) throw new ArgError("key must be 12 hex chars (6 bytes)");
  const wdata = hexBytes(a.data, 16);
  if(wdata.length!==16) throw new ArgError("Data must include 32 HEX symbols");
  const f = await request(CU.MF1_WRITE_ONE_BLOCK, [keytype, Number(a.blk), ...key, ...wdata]);
  return [OK_STATUSES.has(f.status) ? " - Write done." : " - Write fail."];
});

// Mirrors HFMFFCHK (cli_hf_mf.py): fast multi-key, multi-sector check via
// MF1_CHECK_KEYS_OF_SECTORS. Keys are given inline (space-separated hex12),
// not via --key/--dic files -- this terminal has no filesystem. --export-key/
// --export-dic are likewise not ported (nothing to write a file to).
hfMf.command("fchk", "Mifare Classic fast key check on sectors", [
  {positional:true, dest:"keys"},
  {names:["--mini"], takesValue:false, dest:"mini"},
  {names:["--1k"], takesValue:false, dest:"k1"},
  {names:["--2k"], takesValue:false, dest:"k2"},
  {names:["--4k"], takesValue:false, dest:"k4"},
  {names:["-m","--mask"], takesValue:true, dest:"mask"},
], async (a) => {
  await needReader();
  const sel = [a.mini, a.k1, a.k2, a.k4].filter(Boolean);
  if(sel.length>1) throw new ArgError("--mini/--1k/--2k/--4k are mutually exclusive");
  const maxSectors = a.mini?5 : a.k2?32 : a.k4?40 : 16; // --1k is also the default
  const maskHex = a.mask || "00000000000000000000";
  if(!/^[a-fA-F0-9]{1,20}$/.test(maskHex)) throw new ArgError("mask should be in hex[20] format");
  const mask = hexBytes(maskHex.padEnd(20,"0"), 10);
  for(let i=maxSectors;i<40;i++) mask[i>>2] |= 3 << (6 - (i%4)*2); // skip sectors beyond maxSectors
  const keys = [];
  for(const k of a.keys){
    if(!/^[a-fA-F0-9]{12}$/.test(k)){ return ["error: key must be hex[12], invalid key ignored: "+k]; }
    keys.push(hexBytes(k,6));
  }
  if(!keys.length) return ["error: no keys given"];

  // check_keys (cli_hf_mf.py): chunk requests, OR found bits into mask so
  // later chunks skip sector/keytypes already resolved.
  const sectorKeys = new Map();
  for(let i=0;i<keys.length;i+=20){
    const chunk = keys.slice(i,i+20);
    const resp = await request(CU.MF1_CHECK_KEYS_OF_SECTORS, [...mask, ...chunk.flat()]);
    if(!OK_STATUSES.has(resp.status)) break;
    if(resp.data.length!==490) break; // all sectorKey is found or masked
    const found = resp.data.slice(0,10);
    for(let j=0;j<10;j++) mask[j] |= found[j];
    for(let bit=0; bit<80; bit++){
      if(found[bit>>3] & (0x80 >> (bit&7))) sectorKeys.set(bit, resp.data.slice(10+6*bit, 16+6*bit));
    }
  }
  const lines = [" - result of key checking:", "-----+-----+--------------+---+--------------+----",
                 " Sec | Blk | key A        |res| key B        |res ",
                 "-----+-----+--------------+---+--------------+----"];
  for(let sectorNo=0; sectorNo<maxSectors; sectorNo++){
    const blk = sectorNo<32 ? sectorNo*4+3 : sectorNo*16-369;
    const ka = sectorKeys.get(sectorNo*2), kb = sectorKeys.get(sectorNo*2+1);
    lines.push(` ${String(sectorNo).padStart(3,"0")} | ${String(blk).padStart(3)} | `+
      (ka?bhex(ka)+" | 1":"------------ | 0")+" | "+(kb?bhex(kb)+" | 1":"------------ | 0"));
  }
  lines.push("-----+-----+--------------+---+--------------+----");
  return lines;
});

function i32le(d, o){ const v = d[o] | (d[o+1]<<8) | (d[o+2]<<16) | (d[o+3]<<24); return v|0; }
function i32leBytes(v){ v = v|0; return [v&255, (v>>8)&255, (v>>16)&255, (v>>24)&255]; }

// Mirrors HFMFVALUE (cli_hf_mf.py): --get/--set decode/encode the MIFARE
// Classic value-block format directly (get_value/set_value); --inc/--dec/
// --res go through MF1_MANIPULATE_VALUE_BLOCK (src auth -> op -> dst auth ->
// transfer), same wire layout as this page's own h_vbrun handler (fullcmd.js).
hfMf.command("value", "Mifare Classic value block commands (--get/--set/--inc/--dec/--res)", [
  {names:["--get"], takesValue:false, dest:"get"},
  {names:["--set"], takesValue:true, dest:"set"},
  {names:["--inc"], takesValue:true, dest:"inc"},
  {names:["--dec"], takesValue:true, dest:"dec"},
  {names:["--res","--cp"], takesValue:false, dest:"res"},
  {names:["--blk","--src-block"], takesValue:true, dest:"blk", required:true},
  {names:["-a","-A"], takesValue:false, dest:"a"},
  {names:["-b","-B"], takesValue:false, dest:"b"},
  {names:["-k","--src-key"], takesValue:true, dest:"key", required:true},
  {names:["--tblk","--dst-block"], takesValue:true, dest:"tblk"},
  {names:["--ta","--tA"], takesValue:false, dest:"ta"},
  {names:["--tb","--tB"], takesValue:false, dest:"tb"},
  {names:["--tkey","--dst-key"], takesValue:true, dest:"tkey"},
], async (a) => {
  await needReader();
  const modes = ["get","set","inc","dec","res"].filter(m => a[m]!==false && a[m]!==undefined);
  if(modes.length>1) throw new ArgError("--get/--set/--inc/--dec/--res are mutually exclusive");
  if(a.a && a.b) throw new ArgError("-a and -b are mutually exclusive");
  if(a.ta && a.tb) throw new ArgError("--ta and --tb are mutually exclusive");
  const srcType = a.b ? 0x61 : 0x60;
  const srcKey = hexBytes(a.key,6);
  if(srcKey.length!==6) throw new ArgError("src_key must include 12 HEX symbols");
  const srcBlk = Number(a.blk);

  async function getValue(block, type, key){
    const f = await request(CU.MF1_READ_ONE_BLOCK, [type, block, ...key]);
    if(!OK_STATUSES.has(f.status) || f.data.length<16) return [" - read failed: "+stname(f.status)];
    const d = f.data;
    const val1=i32le(d,0), val2=i32le(d,4), val3=i32le(d,8);
    const adr1=d[12], adr2=d[13], adr3=d[14], adr4=d[15];
    if(val1!==val3 || (val1+val2)!==-1) return [" - Invalid value of value block: "+bhex(d)];
    if(adr1!==adr3 || adr2!==adr4 || ((adr1+adr2)&0xFF)!==0xFF) return [" - Invalid address of value block: "+bhex(d)];
    return [" - block["+block+"] = { value: "+val1+", adr: "+adr1+" }"];
  }

  if(a.get !== false){ return getValue(srcBlk, srcType, srcKey); }

  if(a.set !== undefined){
    const value = Number(a.set);
    if(value < -2147483647 || value > 2147483647) throw new ArgError("Set value must be between -2147483647 and 2147483647");
    const adrInv = (0xFF - srcBlk) & 0xFF;
    const data = [...i32leBytes(value), ...i32leBytes(-value-1), ...i32leBytes(value), srcBlk&0xFF, adrInv, srcBlk&0xFF, adrInv];
    const f = await request(CU.MF1_WRITE_ONE_BLOCK, [srcType, srcBlk, ...srcKey, ...data]);
    if(!OK_STATUSES.has(f.status)) return [" - Set fail."];
    return [" - Set done.", ...(await getValue(srcBlk, srcType, srcKey))];
  }

  const dstBlk = a.tblk !== undefined ? Number(a.tblk) : srcBlk;
  const dstType = a.ta ? 0x60 : a.tb ? 0x61 : srcType;
  const dstKey = a.tkey !== undefined ? hexBytes(a.tkey,6) : srcKey;
  if(dstKey.length!==6) throw new ArgError("dst_key must include 12 HEX symbols");

  let op, operand, label;
  if(a.inc !== undefined){
    operand = Number(a.inc);
    if(operand<0 || operand>2147483647) throw new ArgError("Increment value must be between 0 and 2147483647");
    op=0xC1; label="Increment";
  } else if(a.dec !== undefined){
    operand = Number(a.dec);
    if(operand<0 || operand>2147483647) throw new ArgError("Decrement value must be between 0 and 2147483647");
    op=0xC0; label="Decrement";
  } else if(a.res !== false){
    op=0xC2; operand=0; label="Restore";
  } else {
    throw new ArgError("Please specify a value command (--get/--set/--inc/--dec/--res)");
  }

  const payload = [srcType, srcBlk, ...srcKey, op, ...u32be(operand>>>0), dstType, dstBlk, ...dstKey];
  const f = await request(CU.MF1_MANIPULATE_VALUE_BLOCK, payload);
  if(!OK_STATUSES.has(f.status)) return [" - "+label+" fail."];
  return [" - "+label+" done.", ...(await getValue(dstBlk, dstType, dstKey))];
});

/* Stub out the remaining real CLI groups so they exist for help/tab-complete
   but are honest about not being implemented here yet. */
const lf = ROOT.subgroup("lf", "Low Frequency commands");

// Reduced port of LFSearch (cli_lf.py): the real command decodes each tag
// type's id into its own fields (EM410x, HID, IDTECK, FDXB, PAC, Indala,
// ioProx...); that per-type table is the same one `hf 14a info` left out.
// This prints the raw type + id instead, same as this page's own LF tab.
lf.command("search", "Search for any supported LF tag -- tries every decoder in turn and reports the first match (reduced: raw type/id, not per-type decoded)", [], async () => {
  await needReader();
  const f = await request(CU.LF_SEARCH);
  if(!OK_STATUSES.has(f.status)) return ["No known LF tag found"];
  const type = (f.data[0]<<8)|f.data[1];
  return ["- "+tagTypeName(type)+" : "+bhex(f.data.slice(2))];
});

const lfEm = lf.subgroup("em", "EM commands");
const lfEm410x = lfEm.subgroup("410x", "EM410x commands");
lfEm.subgroup("4x05", "EM4x05/EM4x69 commands").command("*", null, [], notPorted("lf em 4x05").run);

lfEm410x.command("read", "Scan em410x tag and print id", [], async () => {
  await needReader();
  const f = await request(CU.EM410X_SCAN);
  if(!OK_STATUSES.has(f.status)) return ["No tag: "+stname(f.status)];
  const type = (f.data[0]<<8)|f.data[1];
  const id = f.data.slice(2);
  return ["- "+(type===104?"Electra":"EM410x")+" id: "+bhex(id)];
});
lfEm410x.command("write", "Write em410x id to t55xx", [
  {names:["--id"], takesValue:true, dest:"id", required:true},
], async (a) => {
  await needReader();
  const idHex = (a.id||"").replace(/[^0-9a-fA-F]/g,"");
  if(idHex.length!==10 && idHex.length!==26) throw new ArgError("Writing to T55xx supports 5-byte EM410X (10 hex) or 13-byte Electra (26 hex) IDs.");
  const id = hexBytes(idHex);
  const cmd = id.length===5 ? CU.EM410X_WRITE_TO_T55XX : CU.EM410X_ELECTRA_WRITE_TO_T55XX;
  okOrThrow(await request(cmd, t55xxPayload(id)));
  return [" - EM410x ID write sent: "+idHex+" (verify with `lf em 410x read`)"];
});

const lfHid = lf.subgroup("hid", "HID commands");
const lfHidProx = lfHid.subgroup("prox", "HID Prox commands");

lfHidProx.command("read", "Scan hid prox tag and print card format, facility code, card number, issue level and OEM code", [
  {names:["-f","--format"], takesValue:true, dest:"format", choices:Object.keys(HID_FORMAT_BY_NAME)},
], async (a) => {
  await needReader();
  const fmt = a.format ? HID_FORMAT_BY_NAME[a.format] : 0;
  const f = await request(CU.HIDPROX_SCAN, [fmt]);
  if(!OK_STATUSES.has(f.status)) return ["No tag: "+stname(f.status)];
  const d = f.data;
  const [format, fc, cn1, cn2, il, oem] = [d[0], (d[1]<<24|d[2]<<16|d[3]<<8|d[4])>>>0, d[5],
    (d[6]<<24|d[7]<<16|d[8]<<8|d[9])>>>0, d[10], (d[11]<<8|d[12])];
  const cn = cn1*0x100000000 + cn2;
  const lines = ["HIDProx/"+(HID_FORMAT_BY_VALUE[format]||format)];
  if(fc>0) lines.push(" FC: "+fc);
  if(il>0) lines.push(" IL: "+il);
  if(oem>0) lines.push(" OEM: "+oem);
  lines.push(" CN: "+cn);
  return lines;
});
lfHidProx.command("write", "Write hidprox card data to t55xx", [
  {names:["-f","--format"], takesValue:true, dest:"format", required:true, choices:Object.keys(HID_FORMAT_BY_NAME)},
  {names:["--fc"], takesValue:true, dest:"fc"},
  {names:["--cn"], takesValue:true, dest:"cn", required:true},
  {names:["--il"], takesValue:true, dest:"il"},
  {names:["--oem"], takesValue:true, dest:"oem"},
], async (a) => {
  await needReader();
  const format = HID_FORMAT_BY_NAME[a.format];
  const fc = a.fc!==undefined ? Number(a.fc) : 0;
  const il = a.il!==undefined ? Number(a.il) : 0;
  const oem = a.oem!==undefined ? Number(a.oem) : 0;
  const cn = Number(a.cn);
  const cnHi = Math.floor(cn / 0x100000000), cnLo = cn >>> 0;
  const id = [format, ...u32be(fc), cnHi&0xFF, ...u32be(cnLo), il&0xFF, (oem>>8)&0xFF, oem&0xFF];
  okOrThrow(await request(CU.HIDPROX_WRITE_TO_T55XX, t55xxPayload(id)));
  const lines = ["HIDProx/"+a.format];
  if(fc>0) lines.push(" FC: "+fc);
  if(il>0) lines.push(" IL: "+il);
  if(oem>0) lines.push(" OEM: "+oem);
  lines.push(" CN: "+cn, "write done.");
  return lines;
});

/* Stub out the remaining real CLI groups/subgroups so they exist for
   help/tab-complete but are honest about not being implemented here yet. */
for(const path of ["indala","ioprox","pac","viking","jablotron","fdxb","generic","idteck","t55xx"]){
  lf.subgroup(path, "("+path+" commands)").command("*", null, [], notPorted("lf "+path).run);
}
lf.command("clone", "(not ported to this terminal yet -- use the matching GUI tab)", [], notPorted("lf clone").run);
lf.command("sniff", "(not ported to this terminal yet -- use the matching GUI tab)", [], notPorted("lf sniff").run);

for(const [path, grp] of [["data", ROOT.subgroup("data","Data analysis and visualization commands")],
                          ["emv", ROOT.subgroup("emv","EMV contactless payment card commands")],
                          ["standalone", ROOT.subgroup("standalone","Host-less standalone modes -- use the Standalone tab")]]){
  grp.command("*", "(not ported to this terminal yet -- use the matching GUI tab)", [], async () =>
    ["("+path+" commands aren't ported to this terminal yet -- use the "+path+" tab above.)"]);
}

/* ---------------------------------------------------------------------
 *  Dispatch: walk tokens through the group tree.
 * ------------------------------------------------------------------- */

function listChildren(group){
  return [...group.children.values()].map(c => c.leaf ? c.name : c.name+"/").sort();
}

function helpFor(node){
  if(node instanceof Group){
    const lines = [node.name ? "'"+node.name+"' subcommands:" : "Available command groups:"];
    for(const c of [...node.children.values()].sort((x,y)=>x.name.localeCompare(y.name))){
      lines.push("  "+c.name.padEnd(14)+(c.help||(c.leaf?"":"...")));
    }
    return lines;
  }
  const lines = [node.help || node.name];
  if(node.specs && node.specs.length){
    lines.push("flags:");
    for(const s of node.specs){
      lines.push("  "+s.names.join(", ")+(s.takesValue?" <value>":"")+(s.required?"  (required)":""));
    }
  }
  return lines;
}

async function dispatch(line){
  const tokens = tokenize(line);
  if(tokens.length===0) return [];
  if(tokens[0]==="clear"){ clearLog(); return []; }
  if(tokens[0]==="help" || tokens[0]==="?"){
    return helpFor(tokens.length>1 ? walk(tokens.slice(1)).node : ROOT);
  }

  let node = ROOT, i = 0;
  while(node instanceof Group){
    // A group whose only child is the "*" catch-all (built via notPorted())
    // has nothing else to show; running the bare group name should hit the
    // stub message directly instead of a one-item "available: *" listing.
    if(i >= tokens.length){
      const onlyStar = node.children.size===1 && node.children.get("*");
      if(onlyStar) return onlyStar.run();
      return helpFor(node);
    }
    // children.get() is an exact-name Map lookup, so a group's "*" child is
    // never reached by a real subcommand name unless we fall back to it
    // explicitly here -- without this, typing e.g. `hf mfu dump` reports
    // "unknown 'mfu' subcommand: dump" instead of the "not ported" message.
    const next = node.children.get(tokens[i]) || node.children.get("*");
    if(!next) return ["error: unknown "+(node.name?"'"+node.name+"' subcommand":"command")+": "+tokens[i], ...helpFor(node)];
    node = next; i++;
  }
  if(node.notPorted || node.name==="*") return node.run();
  if(tokens[i]==="-h" || tokens[i]==="--help") return helpFor(node);
  try{
    const args = parseFlags(tokens.slice(i), node.specs);
    const out = await node.run(args);
    return out || [];
  }catch(e){
    if(e instanceof ArgError) return ["error: "+e.message, ...helpFor(node)];
    return ["error: "+e.message];
  }
}

function walk(tokens){
  let node = ROOT;
  for(const t of tokens){
    if(!(node instanceof Group)) break;
    const next = node.children.get(t);
    if(!next) break;
    node = next;
  }
  return {node};
}

/* Tab completion: longest-common-prefix over the live tree at the current
   cursor depth -- same idea as a real shell completing over a known set. */
function complete(line){
  const tokens = tokenize(line);
  const hasTrailingSpace = /\s$/.test(line);
  let node = ROOT, consumed = [];
  let i = 0;
  while(i < tokens.length - (hasTrailingSpace?0:1)){
    if(!(node instanceof Group)) return null;
    const next = node.children.get(tokens[i]);
    if(!next) return null;
    node = next; consumed.push(tokens[i]); i++;
  }
  if(!(node instanceof Group)) return null;
  const partial = hasTrailingSpace ? "" : (tokens[tokens.length-1] || "");
  const names = listChildren(node).filter(n => n.replace(/\/$/,"").startsWith(partial));
  if(names.length===0) return null;
  if(names.length===1){
    return consumed.concat([names[0].replace(/\/$/,"")]).join(" ") + (names[0].endsWith("/") ? " " : " ");
  }
  // common prefix across candidates, for a partial fill (classic shell behaviour)
  let cp = names[0];
  for(const n of names.slice(1)){
    let k=0; while(k<cp.length && k<n.length && cp[k]===n[k]) k++;
    cp = cp.slice(0,k);
  }
  return {ambiguous: names, prefix: consumed.concat([cp.replace(/\/$/,"")]).join(" ")};
}

/* ---------------------------------------------------------------------
 *  Terminal widget: scrollback + prompt row + blinking cursor, driven by
 *  a hidden real <input> (so mobile keyboards and IME work).
 * ------------------------------------------------------------------- */

const PROMPT = "chameleon> ";
let out, typed, cursorEl, hidden;
const history = [];
let histIdx = 0;

function clearLog(){ if(out) out.textContent = ""; }

function printLines(lines, cls){
  for(const l of lines){
    const row = document.createElement("div");
    if(cls) row.className = cls;
    row.textContent = l;
    out.appendChild(row);
  }
  out.scrollTop = out.scrollHeight;
}

function render(){
  typed.textContent = hidden.value;
}

async function submit(){
  const line = hidden.value;
  printLines([PROMPT + line], "term-echo");
  hidden.value = "";
  render();
  if(line.trim()){
    history.push(line);
    histIdx = history.length;
  }
  if(!line.trim()) return;
  try{
    const result = await dispatch(line);
    if(result && result.length) printLines(result);
  }catch(e){
    printLines(["error: "+e.message], "term-err");
  }
}

function initTerminal(){
  out = $("term_out");
  typed = $("term_typed");
  cursorEl = $("term_cursor");
  hidden = $("term_hidden");
  if(!out || !typed || !hidden) return;

  printLines([
    "ChameleonUltra (Phreakbyte) terminal -- type `help` for commands.",
    "This is a subset of the real CLI; unimplemented groups say so when you run them.",
    "",
  ]);

  const screen = $("term_screen");
  if(screen) screen.addEventListener("click", () => hidden.focus());
  hidden.focus();

  hidden.addEventListener("input", render);
  hidden.addEventListener("keydown", (ev) => {
    if(ev.key === "Enter"){ ev.preventDefault(); submit(); }
    else if(ev.key === "ArrowUp"){
      if(history.length===0) return;
      ev.preventDefault();
      histIdx = Math.max(0, histIdx-1);
      hidden.value = history[histIdx] || "";
      render();
    } else if(ev.key === "ArrowDown"){
      ev.preventDefault();
      histIdx = Math.min(history.length, histIdx+1);
      hidden.value = history[histIdx] || "";
      render();
    } else if(ev.key === "Tab"){
      ev.preventDefault();
      const res = complete(hidden.value);
      if(res == null) return;
      if(typeof res === "string"){ hidden.value = res; }
      else { printLines([res.ambiguous.join("  ")], "term-meta"); }
      render();
    }
  });
}

if(document.readyState === "loading"){
  document.addEventListener("DOMContentLoaded", initTerminal);
} else {
  initTerminal();
}

})();
