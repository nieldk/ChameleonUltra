"use strict";
/* ---------------------------------------------------------------------
 * terminal.js — a Linux-terminal-styled copy of the real chameleon_cli_unit.py
 * / cli_hf_mf.py command grammar (hw / hw slot / hw settings / hf 14a / hf mf),
 * running in-browser over the same request()/CU plumbing fullcmd.js uses.
 * Loaded after canary.js and fullcmd.js: reuses their globals (request(),
 * connected(), need(), $(), hexBytes(), bhex(), stname(), OK_STATUSES, CU,
 * rawWrite(), rawRspSink -- the last two by `hw gdb`, see below).
 *
 * THIS IS A SUBSET, NOT THE WHOLE CLI. The real CLI is ~195 commands across
 * hw/hf/lf/slot/standalone/data/emv. `hf mf nested/darkside/hardnested/
 * senested`, `hf seos`, `hf st25ta` and `hf mfplus` ARE here now -- but only
 * as far as the device protocol goes (nonce/perso acquisition, one round).
 * None of this terminal does actual crypto1 key recovery (darkside's
 * decrypt, hardnested's/nested's PRNG-successor unrolling) -- that math runs
 * in external tools on the Python side (a `darkside` binary, hardnested's
 * nonce-file solver) this environment doesn't have; raw acquired data is
 * printed for you to feed to those yourself. `hf mf autopwn` (orchestrates
 * all of the above plus dictionary/fchk/nested in sequence) and most of
 * `lf`'s per-tag-type decode tables are still not ported. Unported groups/
 * commands simply aren't registered: they're absent from `help`/tab-complete
 * and running them reports an unknown command, same as any other command
 * this terminal doesn't have. Commands this file DOES implement mirror the
 * Python CLI's flags and output text as closely as the two environments
 * allow.
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
  // cmd_processor_get_bootloader_version (app_cmd.c) always returns a
  // single big-endian u32 (dfuver_get's bl_v).
  const f = okOrThrow(await request(CU.GET_BOOTLOADER_VERSION));
  const v = ((f.data[0]<<24)|(f.data[1]<<16)|(f.data[2]<<8)|f.data[3])>>>0;
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

CU.GET_DFU_APP_VERSION = 1046; // only hw status needs this opcode so far

// Mirrors HWStatus (chameleon_cli_unit.py): one-shot summary of already-ported
// single calls. Link speed/transport name isn't meaningful over this page's
// Web Bluetooth/Serial transport, so that line is left out.
hw.command("status", "Show a one-shot summary of connection, firmware and hardware status", [], async () => {
  need();
  const model = ["Ultra","Lite"][(okOrThrow(await request(CU.GET_DEVICE_MODEL))).data[0]];
  const t0 = (performance||Date).now();
  const fv = okOrThrow(await request(CU.GET_APP_VERSION));
  const latencyMs = (performance||Date).now() - t0;
  const gv = okOrThrow(await request(CU.GET_GIT_VERSION));
  const lines = [" - Device status",
    "   latency     -> "+latencyMs.toFixed(1)+" ms (round-trip)",
    "   model       -> Phreakbyte edition ("+model+")",
    "   firmware    -> v"+fv.data[0]+"."+fv.data[1]+" ("+bytesToUtf8(gv.data)+")"];
  try{
    const d = okOrThrow(await request(CU.GET_BOOTLOADER_VERSION)).data;
    lines.push("   bootloader  -> "+(((d[0]<<24)|(d[1]<<16)|(d[2]<<8)|d[3])>>>0));
  }catch(e){ lines.push("   bootloader  -> not supported by current firmware"); }
  try{
    const d = okOrThrow(await request(CU.GET_DFU_APP_VERSION)).data;
    lines.push("   application -> "+(((d[0]<<24)|(d[1]<<16)|(d[2]<<8)|d[3])>>>0));
  }catch(e){ lines.push("   application -> not supported by current firmware"); }
  lines.push("   chip ID     -> "+bhex(okOrThrow(await request(CU.GET_DEVICE_CHIP_ID)).data));
  lines.push("   address     -> "+bhex(okOrThrow(await request(CU.GET_DEVICE_ADDRESS)).data));
  try{
    const bn = okOrThrow(await request(CU.GET_BLE_NAME));
    lines.push("   ble name    -> "+(bn.data.length?bytesToUtf8(bn.data):"(default)"));
  }catch(e){ lines.push("   ble name    -> not supported by current firmware"); }
  lines.push("   mode        -> Tag "+((okOrThrow(await request(CU.GET_DEVICE_MODE))).data[0]?"Reader":"Emulator"));
  try{ lines.push("   active slot -> "+(okOrThrow(await request(CU.GET_ACTIVE_SLOT)).data[0]+1)); }catch(e){}
  try{
    const bf = okOrThrow(await request(CU.GET_BATTERY_INFO));
    const mv=(bf.data[0]<<8)|bf.data[1], pct=bf.data[2];
    lines.push("   battery     -> "+mv+" mV, "+pct+"%"+(pct<30?" [!] Low battery":""));
  }catch(e){ lines.push("   battery     -> not supported by current firmware"); }
  try{
    const mf = okOrThrow(await request(CU.GET_FREE_MEMORY));
    const free=(mf.data[0]<<24|mf.data[1]<<16|mf.data[2]<<8|mf.data[3])>>>0;
    const total=(mf.data[4]<<24|mf.data[5]<<16|mf.data[6]<<8|mf.data[7])>>>0;
    const used=total-free, pct=total>0?(used/total*100):0;
    lines.push("   heap        -> "+used.toLocaleString()+"/"+total.toLocaleString()+" bytes used ("+pct.toFixed(1)+"%)");
  }catch(e){ lines.push("   heap        -> not supported by current firmware"); }
  return lines;
});

hw.command("reset", "Reboot the device. Plain restart only -- slots and settings are untouched.", [], async () => {
  need();
  try{ await request(CU.RESET_DEVICE); }catch(e){} // device closes the link as part of the reset
  return [" - Reset successful! Please reconnect."];
});

hw.command("factory_reset", "Wipe all slot data and custom settings and return to factory settings", [
  {names:["--force"], takesValue:false, dest:"force"},
], async (a) => {
  need();
  if(!a.force) return ["If you are you really sure, read the command documentation to see how to proceed."];
  try{ await request(CU.WIPE_FDS); }catch(e){} // device closes the link as part of the wipe
  return [" - Reset successful! Please reconnect."];
});

hw.command("dfu", "Restart application to bootloader/DFU mode", [], async () => {
  need();
  try{ await request(CU.ENTER_BOOTLOADER); }catch(e){} // device closes the port entering DFU
  return ["Application restarting...", " - Enter success @.@~"];
});

// `hw flash` needs a local .zip/.hex/.bin file -- this terminal has no
// filesystem, so the command isn't registered rather than left as a stub.

/* ---- hw slot ---- */
const hwSlot = hw.subgroup("slot", "Emulation slots commands");

function slotFlag(required){ return {names:["-s","--slot"], takesValue:true, dest:"slot", required: !!required}; }
const PRNG_TYPE_NAMES = {0:"Static", 1:"Weak", 2:"Hard"}; // MifareClassicPrngType (chameleon_enum.py)
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

hwSlot.command("init", "Set emulation tag data to default", [slotFlag(false), {names:["-t","--type"], takesValue:true, dest:"type", required:true, choices:Object.keys(TAG_TYPE_BY_NAME)}], async (a) => {
  need();
  const typeId = TAG_TYPE_BY_NAME[a.type];
  const slot = a.slot !== undefined ? Number(a.slot) : await currentSlot1();
  okOrThrow(await request(CU.SET_SLOT_DATA_DEFAULT, [slot-1, ...u16be(typeId)]));
  return [" - Set slot tag data init success."];
});

hwSlot.command("store", "Store slots config & data to device flash", [], async () => {
  need();
  okOrThrow(await request(CU.SLOT_DATA_CONFIG_SAVE));
  return [" - Store slots config and data from device memory to flash success."];
});

hwSlot.command("prng", "Get or set the PRNG type for the MF1 emulator of a slot (0=Static, 1=Weak, 2=Hard)", [slotFlag(false), {names:["-t","--type"], takesValue:true, dest:"type", choices:["0","1","2"]}], async (a) => {
  need();
  return withSlot(a.slot, async (slot) => {
    if(a.type === undefined){
      const f = okOrThrow(await request(CU.MF1_GET_PRNG_TYPE));
      return [" - Slot "+slot+" PRNG type: "+PRNG_TYPE_NAMES[f.data[0]]+" ("+f.data[0]+")"];
    }
    okOrThrow(await request(CU.MF1_SET_PRNG_TYPE, [Number(a.type)]));
    return [" - Slot "+slot+" PRNG type set to: "+PRNG_TYPE_NAMES[Number(a.type)]+" ("+a.type+")"];
  });
});

hwSlot.command("openall", "Open all slots and set to default data", [], async () => {
  need();
  const lines = [];
  for(let s=0;s<8;s++){
    lines.push(" Slot "+(s+1)+" setting...");
    okOrThrow(await request(CU.SET_SLOT_TAG_TYPE, [s, ...u16be(TAG_TYPE_BY_NAME.MIFARE_1024)]));
    okOrThrow(await request(CU.SET_SLOT_TAG_TYPE, [s, ...u16be(TAG_TYPE_BY_NAME.EM410X)]));
    okOrThrow(await request(CU.SET_SLOT_DATA_DEFAULT, [s, ...u16be(TAG_TYPE_BY_NAME.MIFARE_1024)]));
    okOrThrow(await request(CU.SET_SLOT_DATA_DEFAULT, [s, ...u16be(TAG_TYPE_BY_NAME.EM410X)]));
    okOrThrow(await request(CU.SET_SLOT_ENABLE, [s, 1, 1])); // HF
    okOrThrow(await request(CU.SET_SLOT_ENABLE, [s, 2, 1])); // LF
    lines.push(" Slot "+(s+1)+" setting done.");
  }
  okOrThrow(await request(CU.SLOT_DATA_CONFIG_SAVE));
  lines.push(" - Succeeded opening all slots and setting data to default.");
  return lines;
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

hwSettings.command("blekey", "Get or set the ble connect key", [
  {names:["-k","--key"], takesValue:true, dest:"key"},
], async (a) => {
  need();
  const cur = okOrThrow(await request(CU.GET_BLE_PAIRING_KEY));
  const lines = [" - The current key of the device(ascii): "+bytesToUtf8(cur.data)];
  if(a.key !== undefined){
    if(a.key.length !== 6){ lines.push(" - The ble connect key length must be 6"); return lines; }
    if(!/^[0-9]{6}$/.test(a.key)){ lines.push(" - Only 6 ASCII characters from 0 to 9 are supported."); return lines; }
    okOrThrow(await request(CU.SET_BLE_PAIRING_KEY, utf8Bytes(a.key)));
    lines.push(" - Successfully set ble connect key to : "+a.key, "Do not forget to store your settings in flash!");
  }
  return lines;
});

hwSettings.command("blepair", "Show or configure BLE pairing", [
  {names:["-e","--enable"], takesValue:false, dest:"enable"},
  {names:["-d","--disable"], takesValue:false, dest:"disable"},
], async (a) => {
  need();
  if(a.enable && a.disable) throw new ArgError("-e/--enable and -d/--disable are mutually exclusive");
  const cur = okOrThrow(await request(CU.GET_BLE_PAIRING_ENABLE)).data[0];
  if(!a.enable && !a.disable) return [" - BLE pairing: "+(cur?"Enabled":"Disabled")];
  if(a.enable){
    if(cur) return ["BLE pairing is already enabled."];
    okOrThrow(await request(CU.SET_BLE_PAIRING_ENABLE, [1]));
    return [" - Successfully change ble pairing to Enabled.", "Do not forget to store your settings in flash!"];
  }
  if(!cur) return ["BLE pairing is already disabled."];
  okOrThrow(await request(CU.SET_BLE_PAIRING_ENABLE, [0]));
  return [" - Successfully change ble pairing to Disabled.", "Do not forget to store your settings in flash!"];
});

hwSettings.command("blename", "Get or set the BLE advertised name (max 20 chars). Pass an empty string to reset to the firmware default.", [
  {names:["-n","--name"], takesValue:true, dest:"name"},
], async (a) => {
  need();
  const cur = okOrThrow(await request(CU.GET_BLE_NAME));
  const lines = [" - The current BLE name of the device: "+(cur.data.length?bytesToUtf8(cur.data):"(default)")];
  if(a.name !== undefined){
    if(a.name.length > 20){ lines.push(" - The BLE name must be at most 20 characters"); return lines; }
    okOrThrow(await request(CU.SET_BLE_NAME, utf8Bytes(a.name)));
    lines.push(" - Successfully set BLE name to: "+(a.name||"(default)"),
      "Do not forget to store your settings in flash!",
      "You may need to reconnect/rescan for the new name to show up.");
  }
  return lines;
});

hwSettings.command("store", "Store current settings to flash", [], async () => {
  need();
  okOrThrow(await request(CU.SAVE_SETTINGS));
  return ["Storing settings...", " - Store success @.@~"];
});

hwSettings.command("reset", "Reset settings to default values", [
  {names:["--force"], takesValue:false, dest:"force"},
], async (a) => {
  need();
  if(!a.force) return ["If you are you really sure, read the command documentation to see how to proceed."];
  okOrThrow(await request(CU.RESET_SETTINGS));
  return ["Initializing settings...", " - Reset success @.@~"];
});

/* ---- hw bl ---- */
const hwBl = hw.subgroup("bl", "Bootloader update through the running firmware");

// Mirrors HWBlInfo (cli_hw_bl.py) -- the Python CLI only decodes the leading
// 28-byte MBR/UICR header plus (if present) a 96-byte ACL block, NOT the
// trailing bl_info_t identity block this page's own Device tab (D8) also
// shows -- that's a GUI-only extra, kept out here to match the real CLI.
hwBl.command("info", "Read-only bootloader-forwarding snapshot: where the MBR boots from (UICR NRFFW / MBR flash words), REGOUT0, and the vector table at 0xF3000. Does not write anything.", [], async () => {
  need();
  const f = await request(CU.BL_INFO);
  if(f.status !== 0x68 || !f.data || f.data.length < 28) return [" - bl info not supported by this app build (reflash the app)"];
  const d = f.data;
  const u32 = o => ((d[o] | d[o+1]<<8 | d[o+2]<<16 | d[o+3]<<24) >>> 0);
  const [nrffw0, nrffw1, mbrBl, mbrPp, regout0, sp, rst] = [u32(0),u32(4),u32(8),u32(12),u32(16),u32(20),u32(24)];
  const a = x => x===0xFFFFFFFF ? "blank" : "0x"+x.toString(16).padStart(8,"0").toUpperCase();
  const VOUT = {0:"1.8V",1:"2.1V",2:"2.4V",3:"2.7V",4:"3.0V",5:"3.3V",7:"default 1.8V"};
  const lines = [
    " UICR NRFFW[0] bootloader addr : "+a(nrffw0),
    " UICR NRFFW[1] MBR param page  : "+a(nrffw1),
    " MBR flash 0xFF8 (bl addr)     : "+a(mbrBl),
    " MBR flash 0xFFC (param page)  : "+a(mbrPp),
  ];
  const rv = regout0===0xFFFFFFFF ? 7 : (regout0 & 7);
  lines.push(" UICR REGOUT0                  : "+a(regout0)+"  (VOUT "+(VOUT[rv]||rv)+")");
  lines.push(" Vector @0xF3000  SP / reset   : 0x"+sp.toString(16).padStart(8,"0").toUpperCase()+" / 0x"+rst.toString(16).padStart(8,"0").toUpperCase());
  const boot = nrffw0!==0xFFFFFFFF ? nrffw0 : (mbrBl!==0xFFFFFFFF ? mbrBl : null);
  if(boot===null){
    lines.push(" - MBR has no bootloader address: it boots the SoftDevice/app directly,");
    lines.push("   so a bootloader at 0xF3000 is never entered via MBR forwarding.");
  } else {
    lines.push(" - MBR boots the bootloader at "+a(boot)+(boot===0xF3000?"  (matches 0xF3000)":"  (NOT 0xF3000)"));
  }
  if(d.length >= 7*4 + 8*3*4){
    lines.push(" ACL regions (flash write/erase lock):");
    let any=false, blocksBl=false;
    for(let i=0;i<8;i++){
      const o = 28 + i*12;
      const addr=u32(o), size=u32(o+4), perm=u32(o+8);
      if(size===0) continue;
      any = true;
      const w = (perm>>1)&1 ? "WRITE-BLOCKED" : "write-ok";
      const r = (perm>>2)&1 ? "read-blocked" : "read-ok";
      const covers = addr <= 0xF3000 && 0xF3000 < addr+size;
      if(covers && ((perm>>1)&1)) blocksBl = true;
      lines.push("   ["+i+"] 0x"+addr.toString(16).padStart(8,"0").toUpperCase()+" +0x"+size.toString(16)+"  "+w+", "+r+(covers?"  <-- covers 0xF3000":""));
    }
    if(!any) lines.push("   (none set)");
    if(blocksBl){
      lines.push(" - 0xF3000 is ACL write-locked: no app-side write (raw NVMC or COPY_BL)");
      lines.push("   can change the bootloader. ACL is re-applied every boot and clears");
      lines.push("   only on reset, so this needs SWD or the bootloader's own update path.");
    }
  }
  return lines;
});
// `hw bl push` needs a local .hex/.bin file -- this terminal has no
// filesystem, so the command isn't registered rather than left as a stub.

/* ---- hw fds ---- */
const hwFds = hw.subgroup("fds", "Inspect the device FDS flash store");

function fdsKind(fileId, key){
  if(fileId === 0x1000) return "emulation config";
  if(fileId === 0x1001) return "settings";
  if(fileId === 0x1010) return "standalone modes";
  if(fileId >= 0x1100 && fileId <= 0x1107) return "slot "+(fileId-0x1100+1)+" ("+({1:"LF",2:"HF"}[key]||"?")+") tag dump";
  if(fileId >= 0x1200 && fileId <= 0x1207) return "slot "+(fileId-0x1200+1)+" ("+({1:"LF",2:"HF"}[key]||"?")+") nickname";
  if(fileId >= 0xC000) return "BLE bond (peer manager)";
  return "";
}

hwFds.command("ls", "List FDS records: file_id, key, size and kind.", [], async () => {
  need();
  const f = okOrThrow(await request(CU.FDS_LIST));
  const recs = [];
  for(let i=0;i+5<f.data.length;i+=6){
    recs.push({fileId:(f.data[i]<<8)|f.data[i+1], key:(f.data[i+2]<<8)|f.data[i+3], len:(f.data[i+4]<<8)|f.data[i+5]});
  }
  if(!recs.length) return [" - No FDS records."];
  recs.sort((x,y)=> x.fileId-y.fileId || x.key-y.key);
  const total = recs.reduce((s,r)=>s+r.len,0);
  const lines = [" - "+recs.length+" record(s), "+total+" bytes", "   file_id  key     size  kind"];
  for(const r of recs){
    lines.push("   0x"+r.fileId.toString(16).padStart(4,"0").toUpperCase()+"   0x"+r.key.toString(16).padStart(4,"0").toUpperCase()+"  "+String(r.len).padStart(5)+"  "+fdsKind(r.fileId,r.key));
  }
  return lines;
});

hwFds.command("dump", "Hex-dump one FDS record by file_id and key.", [
  {names:["-f","--file-id"], takesValue:true, dest:"fileId", required:true},
  {names:["-k","--key"], takesValue:true, dest:"key"},
], async (a) => {
  need();
  const fileId = parseInt(a.fileId, a.fileId.toLowerCase().startsWith("0x") ? 16 : 10);
  const key = a.key !== undefined ? parseInt(a.key, a.key.toLowerCase().startsWith("0x") ? 16 : 10) : 1;
  const fileIdB = [(fileId>>8)&0xFF, fileId&0xFF], keyB = [(key>>8)&0xFF, key&0xFF];
  const CHUNK = 240;
  let offset=0, bytes=[], guard=0;
  while(guard++ < 64){
    const f = await request(CU.FDS_READ, [...fileIdB, ...keyB, ...u16be(offset), ...u16be(CHUNK)]);
    if(!OK_STATUSES.has(f.status)){
      if(offset===0) return [" - No record for file 0x"+fileId.toString(16).padStart(4,"0").toUpperCase()+" key 0x"+key.toString(16).padStart(4,"0").toUpperCase()+"."];
      break;
    }
    if(f.data.length===0) break;
    bytes.push(...f.data);
    offset += f.data.length;
    if(f.data.length < CHUNK) break;
  }
  if(!bytes.length) return [" - Record is empty."];
  const lines = [" - file 0x"+fileId.toString(16).padStart(4,"0").toUpperCase()+" key 0x"+key.toString(16).padStart(4,"0").toUpperCase()+" ("+fdsKind(fileId,key)+"): "+bytes.length+" bytes"];
  for(let off=0; off<bytes.length; off+=16){
    const chunk = bytes.slice(off, off+16);
    const hexs = chunk.map(b=>b.toString(16).padStart(2,"0")).join(" ");
    const text = chunk.map(b => (b>=0x20&&b<0x7F) ? String.fromCharCode(b) : ".").join("");
    lines.push("   "+off.toString(16).padStart(4,"0")+"  "+hexs.padEnd(47)+"  "+text);
  }
  return lines;
});

/* ---- hw log ---- */
const hwLog = hw.subgroup("log", "Persistent debug log (kept in flash, readable as LOG.TXT in UF2 mode)");
const LOG_LEVELS = ["off","error","warning","info","debug"];

async function logStatus(){
  const f = okOrThrow(await request(CU.LOG_GET_STATUS));
  const d = f.data, u32 = o => (d[o]<<24|d[o+1]<<16|d[o+2]<<8|d[o+3])>>>0;
  return {level:d[0], failed:d[1], pages:d[2], stored:u32(4), pending:u32(8), dropped:u32(12), boots:u32(16), err:u32(20)};
}

hwLog.command("status", "Show debug log level and storage", [], async () => {
  need();
  const st = await logStatus();
  const lines = [
    " - Level   : "+st.level+" ("+LOG_LEVELS[st.level]+")",
    " - Stored  : "+st.stored.toLocaleString()+" bytes in flash ("+st.pages+" pages)",
    " - Pending : "+st.pending.toLocaleString()+" bytes in RAM, not yet in flash",
    " - Dropped : "+st.dropped.toLocaleString()+" bytes (RAM buffer was full)",
    " - Boots   : "+st.boots,
  ];
  if(st.failed){
    lines.push(" - Flash writes FAILED, logging to RAM only until reboot");
    if(st.err) lines.push(" - Error   : stage "+(st.err>>>24)+" (1 call, 2 event, 3 init), op "+((st.err>>>16)&0xFF)+" (1 erase, 2 hdr, 3 data, 4 clear), code 0x"+(st.err&0xFFFF).toString(16).padStart(4,"0"));
  }
  return lines;
});

hwLog.command("level", "Get or set the debug log level (persisted)", [
  {positional:true, dest:"level", optional:true},
], async (a) => {
  need();
  let level;
  if(!a.level || !a.level.length){ level = (await logStatus()).level; }
  else {
    const arg = a.level[0];
    level = LOG_LEVELS.includes(arg) ? LOG_LEVELS.indexOf(arg) : Number(arg);
    if(!(level>=0 && level<=4)) throw new ArgError("level must be off/error/warning/info/debug (0-4)");
    okOrThrow(await request(CU.LOG_SET_LEVEL, [level]));
  }
  return [" - Log level: "+level+" ("+LOG_LEVELS[level]+")"];
});

hwLog.command("dump", "Read the stored debug log", [], async () => {
  need();
  await logStatus(); // asks the device to flush its RAM tail
  const total = (await logStatus()).stored;
  const CHUNK = 480;
  let offset=0, text="";
  while(offset < total){
    const f = okOrThrow(await request(CU.LOG_READ, [...u32be(offset), ...u16be(Math.min(CHUNK, total-offset))]));
    if(!f.data.length) break;
    text += bytesToUtf8(f.data);
    offset += f.data.length;
  }
  if(offset===0) return [" - Log is empty (is the level above 0?)"];
  return text.split("\n");
});

hwLog.command("clear", "Erase the stored debug log", [], async () => {
  need();
  okOrThrow(await request(CU.LOG_CLEAR));
  return [" - Log clear requested"];
});

// `hw log stream`'s Ctrl-C/Enter-to-stop live poll doesn't map onto this
// terminal's synchronous command model -- not registered; use `hw log dump`.

// `hw u2f set-attestation` needs a local PEM/DER key+cert file and a crypto
// library this terminal doesn't have -- the whole `hw u2f` group isn't
// registered rather than left as an empty stub.

/* ---- hw gdb --------------------------------------------------------
 * A GDB Remote Serial Protocol client for the gdb_gateway standalone mode,
 * built straight into the terminal -- no arm-none-eabi-gdb, no local bridge.
 * app_standalone_trigger() (CMD_TRIGGER/7006, used by `hw gdb arm` below)
 * software-arms the mode via transition_arm() the same way a both-buttons
 * long-press does (app_standalone.c), so this needs no physical button.
 * Once armed, the active link -- BLE here -- speaks RSP instead of the
 * framed CLI protocol (gdb_rsp.c), so everything below bypasses `request()`
 * and talks raw $...#cksum packets over rawWrite()/rawRspSink.
 * Memory/flash only: no breakpoints or stepping (that needs a real gdb
 * front-end -- see software/script/gdb_ble_bridge.py for that path). */
const hwGdb = hw.subgroup("gdb", "GDB RSP client for the gdb_gateway standalone mode (memory/flash, no breakpoints)");

const RSP_TIMEOUT_MS = 5000;
let rspBuf = [], rspWaiter = null;

function rspOnBytes(v){
  for(const b of v) rspBuf.push(b);
  while(rspBuf.length && rspBuf[0] !== 0x24 /* $ */) rspBuf.shift();   // drop acks/junk before '$'
  if(rspBuf.length < 4) return;
  const hashAt = rspBuf.indexOf(0x23 /* # */, 1);
  if(hashAt < 0 || rspBuf.length < hashAt+3) return;
  const payload = rspBuf.slice(1, hashAt);
  rspBuf = rspBuf.slice(hashAt+3);
  if(rspWaiter){ const w=rspWaiter; rspWaiter=null; w.resolve(payload); }
}

function rspAsciiFrame(bodyBytes){
  let cs=0; for(const b of bodyBytes) cs=(cs+b)&0xFF;
  const hx="0123456789abcdef", c1=hx[(cs>>4)&0xF], c2=hx[cs&0xF];
  return new Uint8Array([0x24, ...bodyBytes, 0x23, c1.charCodeAt(0), c2.charCodeAt(0)]);
}
const rspAscii = s => Array.from(s, c => c.charCodeAt(0));

// gdb's binary escaping (vFlashWrite payload): $, #, 0x7d and 0x2a are sent
// as 0x7d followed by byte^0x20 -- mirrors unescape() in gdb_rsp.c.
function rspEscape(bytes){
  const out=[];
  for(const b of bytes){
    if(b===0x24||b===0x23||b===0x7d||b===0x2a) out.push(0x7d, b^0x20);
    else out.push(b);
  }
  return out;
}

function rspSend(bodyBytes){
  // withDeviceLock (canary.js): serializes against request() and against
  // any remote-session peer's forwarded traffic on the same physical link.
  return withDeviceLock(() => new Promise((resolve,reject)=>{
    const t=setTimeout(()=>{ rspWaiter=null; reject(new Error("no RSP reply (armed? try 'hw gdb arm' first)")); }, RSP_TIMEOUT_MS);
    rspWaiter = {resolve:p=>{clearTimeout(t); resolve(p);}};
    rawWrite(rspAsciiFrame(bodyBytes)).catch(e=>{ clearTimeout(t); rspWaiter=null; reject(e); });
  }));
}
function rspEnter(){ rspBuf=[]; rawRspSink=rspOnBytes; }
function rspLeave(){ if(rawRspSink===rspOnBytes) rawRspSink=null; }
function rspActive(){ return rawRspSink===rspOnBytes; }
function hexAddr(s){   // addresses are always hex here; parseInt(…,16) ignores an optional "0x"
  const v = parseInt(s, 16);
  if(!Number.isFinite(v)) throw new ArgError("bad address: "+s);
  return v>>>0;
}
const numArg = s => s.toLowerCase().startsWith("0x") ? parseInt(s,16) : parseInt(s,10);   // length args: decimal, or 0x-hex

hwGdb.command("arm", "Select and arm gdb_gateway (software arm, same path as a both-buttons long-press)", [], async () => {
  need();
  const f0 = okOrThrow(await request(CMD_GET_MODE));
  if(f0.data[1] !== MODE_GDB){
    okOrThrow(await request(CMD_SET_MODE, [MODE_GDB, FLAG_OPTIN]));
  }
  okOrThrow(await request(CMD_TRIGGER));   // arms if disarmed (app_standalone_trigger)
  const f1 = okOrThrow(await request(CMD_GET_MODE));
  if(f1.data[0] === 0) return [" - Arm rejected (status ok but still disarmed) -- opt-in flag missing?"];
  return [" - gdb_gateway armed. The active link now speaks GDB RSP.", "   Use 'hw gdb enter' to start, 'hw gdb disarm' when done."];
});

hwGdb.command("disarm", "Disarm gdb_gateway (leaves RSP mode on the terminal side first)", [], async () => {
  rspLeave();
  need();
  okOrThrow(await request(CMD_DISARM));
  return [" - Disarm requested. The device saves state and returns to the framed CLI protocol."];
});

hwGdb.command("enter", "Switch this terminal into raw RSP mode and confirm the device answers", [], async () => {
  need();
  if(rspActive()) return [" - Already in RSP mode."];
  rspEnter();
  try{
    const p = await rspSend(rspAscii("?"));
    return [" - RSP mode active (device replied: "+String.fromCharCode(...p)+")."];
  }catch(e){
    rspLeave();
    return [" - "+e.message, "   Run 'hw gdb arm' first if you haven't."];
  }
});

hwGdb.command("exit", "Leave raw RSP mode on the terminal side (does not disarm the device)", [], async () => {
  rspLeave();
  return [" - Back to the framed CLI protocol. Device is still armed; use 'hw gdb disarm' to fully exit."];
});

hwGdb.command("mem-read", "Read memory: hw gdb mem-read <addr> <len>", [
  {positional:true, dest:"args", required:true},
], async (a) => {
  if(!rspActive()) throw new ArgError("not in RSP mode; run 'hw gdb enter' first");
  const [addrS, lenS] = a.args;
  if(addrS===undefined || lenS===undefined) throw new ArgError("usage: mem-read <addr> <len>");
  const addr = hexAddr(addrS), len = numArg(lenS);
  const p = await rspSend(rspAscii("m"+addr.toString(16)+","+len.toString(16)));
  const s = String.fromCharCode(...p);
  if(s[0]==="E") return [" - error: "+s];
  const bytes = []; for(let i=0;i+1<s.length;i+=2) bytes.push(parseInt(s.substr(i,2),16));
  const lines = [" - 0x"+addr.toString(16)+" ("+bytes.length+" bytes):"];
  for(let off=0; off<bytes.length; off+=16){
    const chunk = bytes.slice(off, off+16);
    const hexs = chunk.map(b=>b.toString(16).padStart(2,"0")).join(" ");
    const text = chunk.map(b => (b>=0x20&&b<0x7F) ? String.fromCharCode(b) : ".").join("");
    lines.push("   "+(addr+off).toString(16).padStart(8,"0")+"  "+hexs.padEnd(47)+"  "+text);
  }
  return lines;
});

hwGdb.command("mem-write", "Write memory: hw gdb mem-write <addr> <hex-bytes>", [
  {positional:true, dest:"args", required:true},
], async (a) => {
  if(!rspActive()) throw new ArgError("not in RSP mode; run 'hw gdb enter' first");
  const [addrS, hexS] = a.args;
  if(addrS===undefined || hexS===undefined) throw new ArgError("usage: mem-write <addr> <hex-bytes>");
  const addr = hexAddr(addrS), clean = hexS.replace(/[^0-9a-fA-F]/g,"");
  if(clean.length % 2) throw new ArgError("hex-bytes must be an even number of hex digits");
  const p = await rspSend(rspAscii("M"+addr.toString(16)+","+(clean.length/2).toString(16)+":"+clean));
  const s = String.fromCharCode(...p);
  return [s==="OK" ? " - OK" : " - error: "+s];
});

hwGdb.command("flash-erase", "Erase a flash range (0xC7000-0x100000 only): hw gdb flash-erase <addr> <len>", [
  {positional:true, dest:"args", required:true},
], async (a) => {
  if(!rspActive()) throw new ArgError("not in RSP mode; run 'hw gdb enter' first");
  const [addrS, lenS] = a.args;
  if(addrS===undefined || lenS===undefined) throw new ArgError("usage: flash-erase <addr> <len>");
  const addr = hexAddr(addrS), len = numArg(lenS);
  const p = await rspSend(rspAscii("vFlashErase:"+addr.toString(16)+","+len.toString(16)));
  const s = String.fromCharCode(...p);
  return [s==="OK" ? " - Erase OK" : " - error: "+s];
});

hwGdb.command("flash-write", "Stream bytes into an erased flash range: hw gdb flash-write <addr> <hex-bytes>", [
  {positional:true, dest:"args", required:true},
], async (a) => {
  if(!rspActive()) throw new ArgError("not in RSP mode; run 'hw gdb enter' first");
  const [addrS, hexS] = a.args;
  if(addrS===undefined || hexS===undefined) throw new ArgError("usage: flash-write <addr> <hex-bytes>");
  let addr = hexAddr(addrS);
  const clean = hexS.replace(/[^0-9a-fA-F]/g,"");
  if(clean.length % 2) throw new ArgError("hex-bytes must be an even number of hex digits");
  const bytes = []; for(let i=0;i<clean.length;i+=2) bytes.push(parseInt(clean.substr(i,2),16));
  const CHUNK = 256;   // raw bytes per vFlashWrite, well under GDB_PACKET_SIZE after escaping
  for(let off=0; off<bytes.length; off+=CHUNK){
    const chunk = bytes.slice(off, off+CHUNK);
    const body = [...rspAscii("vFlashWrite:"+(addr+off).toString(16)+":"), ...rspEscape(chunk)];
    const p = await rspSend(body);
    const s = String.fromCharCode(...p);
    if(s!=="OK") return [" - error at offset "+off+": "+s];
  }
  return [" - Wrote "+bytes.length+" bytes at 0x"+addr.toString(16)+". Run 'hw gdb flash-done' to flush."];
});

hwGdb.command("flash-done", "Flush any buffered flash-write bytes", [], async () => {
  if(!rspActive()) throw new ArgError("not in RSP mode; run 'hw gdb enter' first");
  const p = await rspSend(rspAscii("vFlashDone"));
  const s = String.fromCharCode(...p);
  return [s==="OK" ? " - Flash write finalized" : " - error: "+s];
});

hwGdb.command("monitor", "Send a 'monitor <cmd>' (help/info/unlock-app/lock/reset)", [
  {positional:true, dest:"args", required:true},
], async (a) => {
  if(!rspActive()) throw new ArgError("not in RSP mode; run 'hw gdb enter' first");
  const cmd = a.args.join(" ");
  const hex = Array.from(cmd).map(c=>c.charCodeAt(0).toString(16).padStart(2,"0")).join("");
  const p = await rspSend(rspAscii("qRcmd,"+hex));
  const s = String.fromCharCode(...p);
  if(!s.length) return [" - (unknown monitor command)"];
  let out=""; for(let i=0;i+1<s.length;i+=2) out+=String.fromCharCode(parseInt(s.substr(i,2),16));
  return out.split("\n").filter(l=>l.length);
});

hwGdb.command("regs", "Read r0-r15, xPSR (all-zero unless halted; this terminal has no breakpoints)", [], async () => {
  if(!rspActive()) throw new ArgError("not in RSP mode; run 'hw gdb enter' first");
  const p = await rspSend(rspAscii("g"));
  const s = String.fromCharCode(...p);
  const NAMES=["r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","sp","lr","pc","xpsr"];
  const lines=[];
  for(let i=0;i<17;i++){
    const w = s.substr(i*8,8);
    if(w.length<8) break;
    // target sends each register little-endian; reverse the byte pairs to print MSB-first.
    const be = w.match(/../g).reverse().join("");
    lines.push("   "+NAMES[i].padEnd(5)+"0x"+be);
  }
  return lines.length ? lines : [" - no register data"];
});

/* ================= hf ================= */
const hf = ROOT.subgroup("hf", "High Frequency commands");
const hf14a = hf.subgroup("14a", "ISO14443-a commands");
const hfMf  = hf.subgroup("mf", "MIFARE Classic commands");
// hf mfu / hf seos / hf st25ta / hf mfplus: not ported -- not registered, so
// they don't show in help/tab-complete and "hf mfu" reports an unknown
// subcommand, same as any other command this terminal doesn't have.
const hfDes = hf.subgroup("des", "MIFARE DESFire commands");

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

// Everything else under `hf mf` (dump/sim/nested/hardnested/darkside/
// autopwn/clone/gen3*/gdm*/e*/c* -- magic-card and crypto-attack flows this
// JS terminal doesn't implement) isn't registered; those names report an
// unknown subcommand, the same as any other command this terminal lacks.

/* ================= hf des ================= */
// Reuses fullcmd.js's already-tested DESFire/EMV plumbing directly (same
// top-level script scope): dfcSend, DFC_INS, DFC_STATUS_NAMES/dfcStatusName,
// DESFIRE_VENDOR/HW_MAJOR/STORAGE/PROTOCOL/HW_MAJOR_TO_SW_MAJOR, fmtVer, lut,
// splitVersionFrames, DFC_ALGOS, bhex, u16be, parseHf14aScan. Two CU ids that
// fullcmd.js's GUI never needed (it uses the generic single-APDU paths
// instead) are added here.
CU.HF14A_4_STATIC_RESP = 6003; // hf14a_4_add/clear_static_response (chameleon_cmd.py)
CU.EMV_DEBUG = 6010;           // raw id, chameleon_cli_unit.py's EMVDebug calls it directly too

// _DFC_READER_STATUS_NAMES / _DFC_NATIVE_STATUS_NAMES (cli_hf_des.py) -- the
// full tables for `readerauth`'s result decode; fullcmd.js's own f_auth only
// special-cases rc 0/6, so these are ported from the Python source instead.
const DFC_READER_STATUS_NAMES = {0:"ok",2:"invalid_argument",3:"buffer_too_small",
  4:"protocol_error",5:"integrity_error",6:"card_error",7:"unsupported"};
const DFC_NATIVE_STATUS_NAMES = {0x00:"OK",0x0B:"PROXIMITY_KEY_DISABLED",0x0C:"NO_CHANGES",
  0x0E:"OUT_OF_EEPROM",0x1C:"ILLEGAL_COMMAND_CODE",0x1E:"INTEGRITY_ERROR",0x40:"NO_SUCH_KEY",
  0x7E:"LENGTH_ERROR",0x90:"SPECIAL_SUCCESS",0x9D:"PERMISSION_DENIED",0x9E:"PARAMETER_ERROR",
  0xA0:"APPLICATION_NOT_FOUND",0xAE:"AUTHENTICATION_ERROR",0xBE:"BOUNDARY_ERROR",
  0xCA:"COMMAND_ABORTED",0xCE:"COUNT_ERROR",0xDE:"DUPLICATE_ERROR",0xF0:"FILE_NOT_FOUND"};

// SlotIndexArgsAndGoUnit (cli_core.py): -s/--slot is optional, defaults to the
// active slot, and if a different slot is given the device is switched to it
// for the call and switched back afterwards. Mirrored here for einfo/eblank.
async function withSlot(slotArg, fn){
  const cur = okOrThrow(await request(CU.GET_ACTIVE_SLOT)).data[0] + 1;
  const slot = slotArg != null ? Number(slotArg) : cur;
  if(slot<1 || slot>8) throw new ArgError("slot must be 1-8");
  if(slot !== cur) okOrThrow(await request(CU.SET_ACTIVE_SLOT, [slot-1]));
  try{ return await fn(slot); }
  finally{ if(slot !== cur) okOrThrow(await request(CU.SET_ACTIVE_SLOT, [cur-1])); }
}

hfDes.command("info", "Get MIFARE DESFire card information (version, UID, AIDs)", [], async () => {
  await needReader();
  const out = [];
  const s = await request(CU.HF14A_SCAN);
  if(s.status !== 0x00) return [" [!] No tag: "+stname(s.status)];
  const tags = parseHf14aScan(s.data);
  if(!tags.length) return [" [!] No tag found."];
  out.push(" UID           : "+tags[0].uid);
  out.push(" SAK           : 0x"+tags[0].sak);
  try{
    const f = await request(CU.DESFIRE_READER_GET_VERSION);
    if(f.status !== 0x00) throw new Error(stname(f.status));
    const frames = splitVersionFrames(f.data);
    const hw = frames[0]||[], sw = frames[1]||[], uidf = frames[2]||[];
    const hwMaj = hw.length>=4?hw[3]:null, hwMin = hw.length>=5?hw[4]:null;
    let swMaj = sw.length>=4?sw[3]:null, swMin = sw.length>=5?sw[4]:null;
    let hwStor = hw.length>=6?hw[5]:null, swStor = sw.length>=6?sw[5]:hwStor;
    let swProto = sw.length>=7?sw[6]:(hw.length>=7?hw[6]:null);
    if(swMaj==null && hwMaj!=null){ swMaj = DESFIRE_HW_MAJOR_TO_SW_MAJOR[hwMaj] ?? hwMaj; swMin = 0; }
    if(hw.length>=1) out.push(" Vendor        : "+lut(DESFIRE_VENDOR, hw[0], ""));
    out.push(" HW version    : "+fmtVer(hwMaj,hwMin)+"  ("+lut(DESFIRE_HW_MAJOR,hwMaj,"hw_major ")+")  storage: "+lut(DESFIRE_STORAGE,hwStor,""));
    out.push(" SW version    : "+fmtVer(swMaj,swMin)+"  storage: "+lut(DESFIRE_STORAGE,swStor,""));
    out.push(" Protocol      : "+lut(DESFIRE_PROTOCOL,swProto,""));
    if(uidf.length>=7) out.push(" Card UID      : "+bhex(uidf.slice(0,7)).toUpperCase());
    if(uidf.length>=12) out.push(" Batch no      : "+bhex(uidf.slice(7,12)).toUpperCase());
    if(uidf.length>=14) out.push(" Production    : week "+uidf[12].toString(16).padStart(2,"0").toUpperCase()+" / 20"+uidf[13].toString(16).padStart(2,"0").toUpperCase());
  }catch(e){ out.push(" [!] GetVersion failed: "+e.message); }
  try{
    const apps = await dfcSend(DFC_INS.GET_APPLICATION_IDS);
    if(!apps.ok) throw new Error(dfcStatusName(apps.status));
    const aids=[]; for(let o=0;o+3<=apps.data.length;o+=3) aids.push(apps.data.slice(o,o+3));
    out.push("");
    out.push(" Applications  : "+(aids.length ? aids.length+" found" : "none"));
    for(const aid of aids) out.push("   AID: "+bhex(aid).toUpperCase());
  }catch(e){ out.push(" [!] GetApplicationIDs failed: "+e.message); }
  return out;
});

hfDes.command("einfo", "Show the DESFire emulation slot summary", [
  {names:["-s","--slot"], takesValue:true, dest:"slot"},
], async (a) => {
  need();
  return withSlot(a.slot, async () => {
    const f = await request(CU.DESFIRE_GET_INFO);
    if(f.status === 0x60) throw new Error("PAR_ERR -- this slot's live DESFire buffer isn't populated (set the slot's tag type + default data first)");
    okOrThrow(f);
    if(f.data.length < 20) return [" [!] short reply ("+f.data.length+" bytes)"];
    const d = f.data;
    const uidLen=d[0], uid=d.slice(1,1+uidLen);
    const numApps=d[8], numFiles=d[9];
    const poolUsed=(d[10]<<8)|d[11], poolSize=(d[12]<<8)|d[13], credSize=(d[14]<<8)|d[15];
    const maxApps=d[16], maxKeys=d[17], maxFiles=d[18], piccAuthCmd=d[19];
    return [
      " UID           : "+bhex(uid).toUpperCase(),
      " Applications  : "+numApps+" / "+maxApps,
      " Files         : "+numFiles+" / "+maxFiles,
      " File data pool: "+poolUsed+" / "+poolSize+" bytes",
      " Keys per app  : up to "+maxKeys,
      " PICC auth     : 0x"+piccAuthCmd.toString(16).padStart(2,"0").toUpperCase(),
      " Credential    : "+credSize+" bytes on device",
    ];
  });
});

hfDes.command("estats", "DESFire emulation diagnostics", [], async () => {
  need();
  const f = okOrThrow(await request(CU.DESFIRE_GET_STATS));
  if(f.data.length < 10) return [" [!] short reply ("+f.data.length+" bytes)"];
  const d = f.data, u16 = o => (d[o]<<8)|d[o+1];
  const out = [
    " Frames received : "+u16(0),
    " Frames sent     : "+u16(2),
    " Engine errors   : "+u16(4),
    " Max handler time: "+u16(6)+" us",
  ];
  if(d.length >= 18){
    out.push(" Activation reqs : "+u16(10));
    out.push(" ATQA sent       : "+u16(12));
    out.push(" FDT timeouts    : "+u16(14));
    out.push(" Max reset time  : "+u16(16)+" us");
  }
  out.push(" Entropy misses  : "+u16(8));
  return out;
});

hfDes.command("eblank", "Reset a DESFire emulation slot to a blank card", [
  {names:["-s","--slot"], takesValue:true, dest:"slot"},
  {names:["-u","--uid"], takesValue:true, dest:"uid"},
], async (a) => {
  need();
  let uid = [];
  if(a.uid){
    uid = hexBytes(a.uid.replace(/\s/g,""));
    if(uid.length !== 7 || uid[0] !== 0x04) throw new ArgError("UID must be 7 bytes starting with 04");
  }
  return withSlot(a.slot, async (slot) => {
    okOrThrow(await request(CU.SET_SLOT_TAG_TYPE, [slot-1, ...u16be(TAG_TYPE_BY_NAME.DESFIRE_EV1_2K)]));
    okOrThrow(await request(CU.SET_SLOT_DATA_DEFAULT, [slot-1, ...u16be(TAG_TYPE_BY_NAME.DESFIRE_EV1_2K)]));
    const f = okOrThrow(await request(CU.DESFIRE_FACTORY_BLANK, uid.length ? [uid.length, ...uid] : []));
    return [" - Blank DESFire card in slot "+slot+", UID "+bhex(f.data).toUpperCase()];
  });
});

hfDes.command("edump", "Read a DESFire emulation slot's credential back (raw .dfcb hex only -- no PM3 JSON decode here)", [
  {names:["-s","--slot"], takesValue:true, dest:"slot"},
  {names:["-f","--file"], takesValue:true, dest:"file"},
], async (a) => {
  need();
  return withSlot(a.slot, async () => {
    let total=null, offset=0, out=[];
    for(let i=0;i<200;i++){
      const f = okOrThrow(await request(CU.DESFIRE_GET_CREDENTIAL, u16be(offset)));
      if(f.data.length < 6) throw new Error("short reply");
      const gotTotal=(f.data[0]<<8)|f.data[1], gotOffset=(f.data[2]<<8)|f.data[3], chunkLen=(f.data[4]<<8)|f.data[5];
      if(gotOffset !== offset) throw new Error("device returned offset "+gotOffset+", expected "+offset);
      if(total===null) total=gotTotal;
      out.push(...f.data.slice(6, 6+chunkLen));
      offset += chunkLen;
      if(chunkLen===0 || offset>=total) break;
    }
    const lines = [" - Read "+out.length+" byte(s) from the device."];
    lines.push(out[0]===0x60 ? " - Looks like a .dfcb credential." : " - Does NOT start with 0x60 -- slot may be blank or non-DESFire.");
    lines.push(" - This terminal has no filesystem, so the real CLI's -f/--describe/.json output isn't ported; raw hex follows:");
    lines.push(bhex(out));
    if(a.file) lines.push(" (real CLI would have written this to "+a.file+")");
    return lines;
  });
});

hfDes.command("eload", "Load a credential into a DESFire emulation slot (inline hex, not a file path -- no filesystem here)", [
  {names:["-s","--slot"], takesValue:true, dest:"slot"},
  {names:["-f","--file"], takesValue:true, dest:"file", required:true},
], async (a) => {
  need();
  const blob = hexBytes(a.file);
  if(!blob.length) throw new ArgError("-f/--file: this terminal has no filesystem -- pass the .dfcb credential as inline hex instead of a path");
  if(blob[0] !== 0x60) throw new ArgError("not a .dfcb credential: first byte is 0x"+blob[0].toString(16)+", not 0x60");
  if(blob.length > 0xFFFF) throw new ArgError("credential too large for the protocol ("+blob.length+" bytes, max 65535)");
  return withSlot(a.slot, async (slot) => {
    let sent = 0;
    while(sent < blob.length){
      const chunk = blob.slice(sent, sent+DESFIRE_CHUNK);
      const payload = [...u16be(blob.length), ...u16be(sent), ...u16be(chunk.length), ...chunk];
      const f = await request(CU.DESFIRE_SET_CREDENTIAL, payload);
      if(f.status !== 0x68) throw new Error("device rejected the credential at offset "+sent+": "+stname(f.status));
      sent += chunk.length;
    }
    return [" - Loaded "+blob.length+" bytes into slot "+slot+".", " Run 'hw slot store' to keep it across a power cycle."];
  });
});

hfDes.command("readerauth", "ISO 7816 mutual authentication against a physical DESFire card in one firmware call", [
  {names:["--aid"], takesValue:true, dest:"aid"},
  {names:["-n","--key-no"], takesValue:true, dest:"keyno", required:true},
  {names:["-a","--algo"], takesValue:true, dest:"algo", required:true, choices:["2tdea","3tdea","aes"]},
  {names:["-k","--key"], takesValue:true, dest:"key", required:true},
], async (a) => {
  await needReader();
  let aid = null;
  if(a.aid){
    aid = hexBytes(a.aid);
    if(aid.length !== 3) throw new ArgError("--aid must be exactly 3 bytes");
  }
  const [algByte, wantLen] = DFC_ALGOS[a.algo];
  const key = hexBytes(a.key);
  if(key.length !== wantLen) throw new ArgError("--key: "+a.algo+" needs exactly "+wantLen+" bytes");
  const keyno = Number(a.keyno);
  if(!(keyno>=0 && keyno<=31)) throw new ArgError("-n/--key-no must be 0-31");
  // DFC_ISO7816_AUTH_APP_REFERENCE (0x80) | key_no, matching
  // desfire_reader_auth_iso7816's own key_reference encoding (chameleon_cmd.py).
  const keyRef = (aid ? 0x80 : 0) | keyno;
  const payload = [aid?1:0, ...(aid||[0,0,0]), keyRef, algByte, wantLen, ...key];
  const f = await request(CU.DESFIRE_READER_AUTH_ISO7816, payload);
  if(f.status === 0x01) return [" [!] No card in the field"];
  if(f.status !== 0x00) return [" [!] Device rejected the request: "+stname(f.status)];
  if(!f.data.length) return [" [!] Empty response from device"];
  const rc = f.data[0];
  if(rc === 0) return [" [+] Authenticated"];
  if(rc === 6 && f.data.length>=2){
    const native = f.data[1];
    return [" [!] Card refused authentication: "+(DFC_NATIVE_STATUS_NAMES[native]||("0x"+native.toString(16)))+" (native status 0x"+native.toString(16).padStart(2,"0")+")"];
  }
  return [" [!] Authentication failed: "+(DFC_READER_STATUS_NAMES[rc]||("0x"+rc.toString(16)))];
});

hfDes.command("bruteaid", "Brute-force the DESFire application-ID space via SelectApplication (slow: one field cycle per AID)", [
  {names:["--start"], takesValue:true, dest:"start"},
  {names:["--end"], takesValue:true, dest:"end"},
], async (a) => {
  await needReader();
  const start = parseInt((a.start||"000000").replace(/\s/g,""), 16);
  const end = parseInt((a.end||"0000FF").replace(/\s/g,""), 16);
  if(Number.isNaN(start) || Number.isNaN(end)) throw new ArgError("--start/--end must be hex, e.g. 000000");
  if(!(start>=0 && start<=0xFFFFFF && end>=0 && end<=0xFFFFFF && start<=end)) throw new ArgError("range must be within 000000..FFFFFF and start <= end");
  const total = end-start+1;
  const out = [" - Scanning "+total+" AID(s) "+start.toString(16).padStart(6,"0").toUpperCase()+".."+end.toString(16).padStart(6,"0").toUpperCase()];
  const found = [];
  for(let aid=start; aid<=end; aid++){
    const aidBytes = [(aid>>16)&0xFF, (aid>>8)&0xFF, aid&0xFF];
    try{
      const r = await dfcSend(DFC_INS.SELECT_APPLICATION, aidBytes);
      if(r.ok) { found.push(aid); out.push("   + AID "+aid.toString(16).padStart(6,"0").toUpperCase()+" accepted"); }
    }catch(e){ /* non-card-error replies are expected misses */ }
  }
  out.push(found.length ? "Found "+found.length+" AID(s): "+found.map(a=>a.toString(16).padStart(6,"0").toUpperCase()).join(", ") : "No AIDs accepted in range");
  return out;
});

hfDes.command("signature", "Read the NXP originality signature (Read_Sig) -- prints the raw signature only, no ECDSA verification (needs a crypto library not available here)", [], async () => {
  await needReader();
  const r = await dfcSend(0x3C, [0x00]); // Read_Sig, native INS 0x3C
  if(!r.ok) return [" [!] Read_Sig failed: "+dfcStatusName(r.status)];
  return [
    " Signature (56 bytes): "+bhex(r.data).toUpperCase(),
    " [!] Not verified against NXP's public keys -- the real CLI's ECDSA (secp224r1)",
    "     check needs a crypto library this terminal doesn't have. Compare the bytes",
    "     against a known-genuine card's signature by hand, or use the Python CLI.",
  ];
});

// hf des chk/auth-trace/divkey/parse need host-side crypto/auth state this
// JS terminal doesn't implement -- not registered.

/* ================= hf 14a sniff ================= */
// Flags match HF14ASniff (chameleon_cli_unit.py) exactly; -o/--trace (write a
// pm3 .trace file) isn't ported -- this terminal has no filesystem.
hf14a.command("sniff", "Capture ISO14443A reader frames while CU acts as a tag", [
  {names:["--timeout"], takesValue:true, dest:"timeout"},
  {names:["--tap"], takesValue:false, dest:"tap"},
], async (a) => {
  await needReader();
  const timeout = Math.max(1, Math.min(30000, a.timeout!==undefined ? Number(a.timeout) : 5000));
  const f = await request(CU.HF14A_SNIFF, [...u16be(timeout), a.tap?1:0], Math.max(6000, timeout+3000));
  if(!OK_STATUSES.has(f.status)) return [" [!] No capture: "+stname(f.status)];
  const fr = parseFrames(f.data);
  const lines = [" - "+fr.length+" frame(s) captured"];
  for(const n of extractNonces(fr)){
    lines.push("   auth key"+n.key+" block "+n.block+" uid "+n.uid+" nt "+n.nt+" nr "+n.nr+" ar "+n.ar+(n.at?" at "+n.at:""));
  }
  fr.forEach((f2,i) => lines.push("   "+String(i).padStart(3)+"  "+(f2.tx?"card->rdr":"rdr->card")+"  "+String(f2.bits).padStart(4)+"b  "+hex(f2.data)));
  return lines;
});

/* ================= hf mf: key-recovery attacks (nonce acquisition only) =====
 * No crypto1 math runs here -- see the file header. Flags are copied from
 * cli_hf_mf.py's parsers, confirmed by reading each command's args_parser(),
 * not guessed. darkside in particular is NOT a flat opcode wrapper in the
 * real CLI: HFMFDarkside.recover_key hardcodes block 0x03/key A, loops up to
 * 255 acquisition rounds, and shells out to an external `darkside` binary to
 * decrypt each round -- so it takes no flags at all. This command does the
 * same single acquisition call (block 0x03, type A, first_recover=true,
 * sync_max=30, matching recover_key's own call) and prints the raw round for
 * your own offline solver, rather than attempting the retry loop or binary. */
function mf1KeytypeArgs(a){
  if(a.a && a.b) throw new ArgError("-a and -b are mutually exclusive");
  return a.b ? 0x61 : 0x60;
}
function mf1TargetKeytypeArgs(a){
  if(a.ta && a.tb) throw new ArgError("--ta/--tA and --tb/--tB are mutually exclusive");
  return a.tb ? 0x61 : 0x60;
}
function fmtNtRows(data, stride, uidAt){
  const u32 = (o) => (data[o]<<24|data[o+1]<<16|data[o+2]<<8|data[o+3])>>>0;
  const lines = [];
  let o = 0;
  if(uidAt !== undefined){ lines.push(" - uid: 0x"+u32(uidAt).toString(16)); o = uidAt+4; }
  for(; o+stride<=data.length; o+=stride){
    lines.push("   nt 0x"+u32(o).toString(16).padStart(8,"0")+" nt_enc 0x"+u32(o+4).toString(16).padStart(8,"0")+
      (stride>8 ? " par 0x"+data[o+8].toString(16) : ""));
  }
  return lines;
}
hfMf.command("nested", "Mifare Classic nested recover key (nonce acquisition; auto-picks static/weak-PRNG method, same as the real CLI's first step)", [
  {names:["--blk","--known-block"], takesValue:true, dest:"blk", required:true},
  {names:["-a","-A"], takesValue:false, dest:"a"},
  {names:["-b","-B"], takesValue:false, dest:"b"},
  {names:["-k","--key"], takesValue:true, dest:"key", required:true},
  {names:["--tblk","--target-block"], takesValue:true, dest:"tblk", required:true},
  {names:["--ta","--tA"], takesValue:false, dest:"ta"},
  {names:["--tb","--tB"], takesValue:false, dest:"tb"},
], async (a) => {
  await needReader();
  const keytype = mf1KeytypeArgs(a), targetKeytype = mf1TargetKeytypeArgs(a);
  const key = hexBytes(a.key, 6);
  if(key.length!==6) throw new ArgError("key must be 12 hex chars (6 bytes)");
  // recover_a_key's own first step (cli_hf_mf.py): detect PRNG, refuse hard.
  const prng = okOrThrow(await request(CU.MF1_DETECT_PRNG)).data[0];
  const lines = [" - NT vulnerable: "+["StaticNested","Nested","HardNested"][prng]];
  if(prng === 2) return [...lines, " [!] Use hf mf hardnested"];
  const args = [keytype, Number(a.blk), ...key, targetKeytype, Number(a.tblk)];
  if(prng === 0){
    const f = okOrThrow(await request(CU.MF1_STATIC_NESTED_ACQUIRE, args));
    return [...lines, ...fmtNtRows(f.data, 8, 0)];
  }
  const f = okOrThrow(await request(CU.MF1_NESTED_ACQUIRE, args));
  return [...lines, ...fmtNtRows(f.data, 9)];
});
const DARKSIDE_STATUS_T = {0:"OK",1:"can't fix nt (PRNG unpredictable)",2:"lucky auth (default key recovered directly)",3:"no NAK sent by tag",4:"tag changed mid-attack"};
hfMf.command("darkside", "Mifare Classic darkside recover key (single acquisition round against block 0x03 key A, matching the real CLI's fixed target; no retry loop or external solver here)", [], async () => {
  await needReader();
  // sync_max=30, as recover_key's own call -- can run up to 300s on-device.
  const f = okOrThrow(await request(CU.MF1_DARKSIDE_ACQUIRE, [0x60, 0x03, 1, 30], 305000));
  const ds = f.data[0];
  if(ds !== 0) return [" - Darkside: "+(DARKSIDE_STATUS_T[ds]||"status "+ds)];
  // !BIIQQII: status(1) uid(4) nt1(4) par(8) ks1(8) nr(4) ar(4) = 33 bytes
  const u32 = (o) => (f.data[o]<<24|f.data[o+1]<<16|f.data[o+2]<<8|f.data[o+3])>>>0;
  return [
    " - Darkside OK -- feed to an offline darkside solver:",
    "   uid 0x"+u32(1).toString(16)+" nt1 0x"+u32(5).toString(16),
    "   par 0x"+u64beHex(f.data,9)+" ks1 0x"+u64beHex(f.data,17),
    "   nr 0x"+u32(25).toString(16)+" ar 0x"+u32(29).toString(16),
  ];
});
hfMf.command("hardnested", "Mifare Classic hardnested recover key (single acquisition round; the real CLI's multi-attempt MSB-tracking loop + nonce-file hand-off to an external solver is not reproduced here)", [
  {names:["--blk","--known-block"], takesValue:true, dest:"blk", required:true},
  {names:["-a","-A"], takesValue:false, dest:"a"},
  {names:["-b","-B"], takesValue:false, dest:"b"},
  {names:["-k","--key"], takesValue:true, dest:"key", required:true},
  {names:["--tblk","--target-block"], takesValue:true, dest:"tblk", required:true},
  {names:["--ta","--tA"], takesValue:false, dest:"ta"},
  {names:["--tb","--tB"], takesValue:false, dest:"tb"},
  {names:["--slow"], takesValue:false, dest:"slow"},
], async (a) => {
  await needReader();
  const keytype = mf1KeytypeArgs(a), targetKeytype = mf1TargetKeytypeArgs(a);
  const key = hexBytes(a.key, 6);
  if(key.length!==6) throw new ArgError("key must be 12 hex chars (6 bytes)");
  // struct.pack('!BBB6sBB', slow, type_known, block_known, key_known, type_target, block_target)
  const f = okOrThrow(await request(CU.MF1_HARDNESTED_ACQUIRE,
    [a.slow?1:0, keytype, Number(a.blk), ...key, targetKeytype, Number(a.tblk)], 35000));
  return [" - "+f.data.length+" raw byte(s) (feed to an offline hardnested solver):", "   "+bhex(f.data)];
});
hfMf.command("senested", "Mifare Classic static encrypted nested recover key via backdoor", [
  {names:["-k","--key"], takesValue:true, dest:"key"},
  {names:["-s","--sectors"], takesValue:true, dest:"sectors"},
  {names:["--starting-sector"], takesValue:true, dest:"start"},
], async (a) => {
  await needReader();
  // Defaults match HFMFStaticEncryptedNested's set_defaults exactly.
  const key = hexBytes(a.key !== undefined ? a.key : "A396EFA4E24F", 6);
  if(key.length!==6) throw new ArgError("key must be 12 hex chars (6 bytes)");
  const sectors = a.sectors !== undefined ? Number(a.sectors) : 16;
  const start = a.start !== undefined ? Number(a.start) : 0;
  const f = await request(CU.MF1_ENC_NESTED_ACQUIRE, [...key, sectors, start], Math.max(6000, sectors*5000+5000));
  if(f.status === 0x01) return [" [!] No tag found."];
  okOrThrow(f);
  const uid = (f.data[0]<<24|f.data[1]<<16|f.data[2]<<8|f.data[3])>>>0;
  // reconstruct_full_nt's PRNG-successor unrolling isn't ported -- see header.
  return [" - uid 0x"+uid.toString(16), " - "+(f.data.length-4)+" raw byte(s) of a/b nonce pairs (feed to an offline senested solver):", "   "+bhex(f.data.slice(4))];
});

/* ================= hf seos ================= */
// Flags match HFSeosEView/ELoad/Keys (chameleon_cli_unit.py ~6201-6360).
// eload's HF14A anti-collision flags (--uid/--atqa/--sak/--ats, via
// HF14AAntiCollArgsUnit) aren't ported -- this terminal has no shared
// anti-coll arg mixin, and that's slot config, not SEOS data proper.
const hfSeos = hf.subgroup("seos", "SEOS emulation commands");
hfSeos.command("eview", "View SEOS emulator data", [], async () => {
  need();
  const f = okOrThrow(await request(CU.SEOS_READ_EMU_DATA));
  let o=0;
  const next = () => { const len=f.data[o]; const v=f.data.slice(o+1,o+1+len); o+=1+len; return v; };
  const data=next(), oid=next(), tag=next(), diversifier=next();
  return [
    " - Data: "+bhex(data), " - OID: "+bhex(oid), " - Tag: "+bhex(tag), " - Diversifier: "+bhex(diversifier),
  ];
});
hfSeos.command("eload", "Load SEOS emulator data (fields left out keep their current value)", [
  {names:["-d","--data"], takesValue:true, dest:"data"},
  {names:["-o","--oid"], takesValue:true, dest:"oid"},
  {names:["-t","--tag"], takesValue:true, dest:"tag"},
  {names:["--diversifier"], takesValue:true, dest:"diversifier"},
], async (a) => {
  need();
  if(a.data===undefined && a.oid===undefined && a.tag===undefined && a.diversifier===undefined)
    throw new ArgError("no changes requested -- pass at least one of -d/-o/-t/--diversifier");
  const cur = okOrThrow(await request(CU.SEOS_READ_EMU_DATA));
  let o=0;
  const next = () => { const len=cur.data[o]; const v=cur.data.slice(o+1,o+1+len); o+=1+len; return v; };
  const curData=next(), curOid=next(), curTag=next(), curDiv=next();
  const hashAlg=cur.data[o], encrAlg=cur.data[o+1]; // not configurable, per the real CLI
  const data = a.data!==undefined ? hexBytes(a.data) : curData;
  const oid = a.oid!==undefined ? hexBytes(a.oid) : curOid;
  const tag = a.tag!==undefined ? hexBytes(a.tag) : curTag;
  const diversifier = a.diversifier!==undefined ? hexBytes(a.diversifier) : curDiv;
  if(data.length<2||data.length>255) throw new ArgError("data must be 2-255 bytes");
  if(oid.length<1||oid.length>32) throw new ArgError("oid must be 1-32 bytes");
  if(tag.length<1||tag.length>2) throw new ArgError("tag must be 1-2 bytes");
  if(diversifier.length<1||diversifier.length>16) throw new ArgError("diversifier must be 1-16 bytes");
  const payload=[...lenPrefixed(data), ...lenPrefixed(oid), ...lenPrefixed(tag), ...lenPrefixed(diversifier), hashAlg, encrAlg];
  okOrThrow(await request(CU.SEOS_WRITE_EMU_DATA, payload));
  return [" - SEOS emulation data loaded."];
});
hfSeos.command("keys", "Load SEOS emulation keys (16 bytes each)", [
  {names:["-a","--auth"], takesValue:true, dest:"auth", required:true},
  {names:["-e","--privenc"], takesValue:true, dest:"privenc", required:true},
  {names:["-m","--privmac"], takesValue:true, dest:"privmac", required:true},
], async (a) => {
  need();
  const auth=hexBytes(a.auth,16), privenc=hexBytes(a.privenc,16), privmac=hexBytes(a.privmac,16);
  if(auth.length!==16) throw new ArgError("auth must be 16 bytes (32 hex chars)");
  if(privenc.length!==16) throw new ArgError("privenc must be 16 bytes (32 hex chars)");
  if(privmac.length!==16) throw new ArgError("privmac must be 16 bytes (32 hex chars)");
  okOrThrow(await request(CU.SEOS_WRITE_EMU_KEYS, [...auth,...privenc,...privmac]));
  return [" - SEOS emulation keys loaded."];
});

/* ================= hf st25ta ================= */
// Flags match HFSt25taInfo/EView/ELoad/EConfig (cli_hf_st25ta.py). eload
// mirrors the real command's framing exactly: body written at offset 2,
// length prefix written separately at offset 0 (ST25TA_CHUNK/4046 wire
// layout) -- not a flat offset+data passthrough. -f/--file and eview's
// -o/--output aren't ported (no filesystem).
const hfSt25ta = hf.subgroup("st25ta", "ST25TA (NFC Type 4) emulation commands");
const ST25TA_READ_ACCESS = {free:0x00, locked:0x80, forbidden:0xFE};
const ST25TA_WRITE_ACCESS = {free:0x00, locked:0x80, forbidden:0xFF};
function st25taAccessName(v, table){ return Object.keys(table).find(k=>table[k]===v) || ("unknown (0x"+v.toString(16).padStart(2,"0")+")"); }
async function st25taInfo(){
  const f = okOrThrow(await request(CU.ST25TA_GET_INFO));
  const ndefSize=(f.data[0]<<8)|f.data[1];
  return {ndefSize, cc:f.data.slice(2,17), pwdRead:f.data.slice(17,33), pwdWrite:f.data.slice(33,49)};
}
hfSt25ta.command("info", "Show ST25TA emulator configuration", [], async () => {
  need();
  const info = await st25taInfo();
  const lenBytes = okOrThrow(await request(CU.ST25TA_READ_NDEF, [...u16be(0), 2])).data;
  const msgLen = (lenBytes[0]<<8)|lenBytes[1];
  return [
    " - NDEF file size: "+info.ndefSize+" bytes", " - NDEF message: "+msgLen+" bytes",
    " - File type: 0x"+info.cc[7].toString(16).padStart(2,"0"),
    " - Read access: "+st25taAccessName(info.cc[13], ST25TA_READ_ACCESS),
    " - Write access: "+st25taAccessName(info.cc[14], ST25TA_WRITE_ACCESS),
    " - Read password: "+bhex(info.pwdRead), " - Write password: "+bhex(info.pwdWrite),
  ];
});
async function st25taReadChunked(offset, length){
  const out=[];
  while(length>0){
    const n=Math.min(length, ST25TA_CHUNK);
    const f = okOrThrow(await request(CU.ST25TA_READ_NDEF, [...u16be(offset), n]));
    out.push(...f.data); offset+=n; length-=n;
  }
  return out;
}
hfSt25ta.command("eview", "View NDEF data from ST25TA emulator memory", [
  {names:["--full"], takesValue:false, dest:"full"},
], async (a) => {
  need();
  const info = await st25taInfo();
  let data;
  if(a.full){
    data = await st25taReadChunked(0, info.ndefSize);
  } else {
    const len = await st25taReadChunked(0, 2);
    const msgLen = Math.min(((len[0]<<8)|len[1]), info.ndefSize-2);
    data = msgLen ? await st25taReadChunked(2, msgLen) : [];
  }
  return [" - "+data.length+" byte(s)"+(data.length?": "+bhex(data):"")];
});
hfSt25ta.command("eload", "Load an NDEF message into ST25TA emulator memory", [
  {names:["-d","--data"], takesValue:true, dest:"data"},
], async (a) => {
  need();
  if(a.data===undefined) throw new ArgError("no changes requested -- pass -d/--data");
  const msg = hexBytes(a.data);
  const info = await st25taInfo();
  if(msg.length+2 > info.ndefSize) throw new ArgError("message needs "+(msg.length+2)+" bytes, NDEF file is "+info.ndefSize+" (use econfig --size)");
  // Body first, length last -- matches HFSt25taELoad.on_exec exactly.
  for(let i=0;i<msg.length;i+=ST25TA_CHUNK){
    const chunk = msg.slice(i,i+ST25TA_CHUNK);
    okOrThrow(await request(CU.ST25TA_WRITE_NDEF, [...u16be(2+i), ...chunk]));
  }
  okOrThrow(await request(CU.ST25TA_WRITE_NDEF, [...u16be(0), (msg.length>>8)&255, msg.length&255]));
  okOrThrow(await request(CU.SLOT_DATA_CONFIG_SAVE)); // HFSt25taELoad.on_exec calls this too
  return [" - NDEF message loaded ("+msg.length+" bytes)."];
});
hfSt25ta.command("econfig", "Configure ST25TA emulator size, access rights and passwords (fields left out keep their current value)", [
  {names:["--size"], takesValue:true, dest:"size"},
  {names:["--read-access"], takesValue:true, dest:"readAccess", choices:Object.keys(ST25TA_READ_ACCESS)},
  {names:["--write-access"], takesValue:true, dest:"writeAccess", choices:Object.keys(ST25TA_WRITE_ACCESS)},
  {names:["--read-pwd"], takesValue:true, dest:"readPwd"},
  {names:["--write-pwd"], takesValue:true, dest:"writePwd"},
], async (a) => {
  need();
  if([a.size,a.readAccess,a.writeAccess,a.readPwd,a.writePwd].every(v=>v===undefined))
    throw new ArgError("no changes requested");
  const info = await st25taInfo();
  const size = a.size!==undefined ? Number(a.size) : info.ndefSize;
  if(size<2||size>7680) throw new ArgError("size must be 2-7680");
  const readAcc = a.readAccess!==undefined ? ST25TA_READ_ACCESS[a.readAccess] : info.cc[13];
  const writeAcc = a.writeAccess!==undefined ? ST25TA_WRITE_ACCESS[a.writeAccess] : info.cc[14];
  const pwdRead = a.readPwd!==undefined ? hexBytes(a.readPwd,16) : info.pwdRead;
  const pwdWrite = a.writePwd!==undefined ? hexBytes(a.writePwd,16) : info.pwdWrite;
  if(pwdRead.length!==16||pwdWrite.length!==16) throw new ArgError("passwords must be 16 bytes (32 hex chars)");
  okOrThrow(await request(CU.ST25TA_SET_CONFIG, [...u16be(size), readAcc, writeAcc, ...pwdRead, ...pwdWrite]));
  okOrThrow(await request(CU.SLOT_DATA_CONFIG_SAVE)); // HFSt25taEConfig.on_exec calls this too
  return [" - ST25TA config updated."];
});

/* ================= hf mfplus ================= */
// Flags match HFMfPlusInfo/WritePerso/CommitPerso (cli_hf_mfplus.py). -a/
// --addr's alias/sector-pair/raw-hex parsing ports _parse_addr() verbatim --
// NOT the same shape as this page's own GUI (addrHi/addrLo fields), because
// the real CLI command doesn't take raw address bytes.
const hfMfplus = hf.subgroup("mfplus", "MIFARE Plus SL0/SL3 perso commands");
const MFPLUS_ADDR_ALIASES = {master:[0x90,0x00], config:[0x90,0x01], l3switch:[0x90,0x03]};
function mfplusParseAddr(s){
  s = (s||"").trim();
  if(MFPLUS_ADDR_ALIASES[s.toLowerCase()]) return MFPLUS_ADDR_ALIASES[s.toLowerCase()];
  if(s.includes(":")){
    const [sectorStr, keytypeStr] = s.split(":",2);
    const sector = parseInt(sectorStr,10), keytype = keytypeStr.trim().toUpperCase()==="A" ? 0 : 1;
    const keyNum = 0x4000 + sector*2 + keytype;
    return [(keyNum>>8)&255, keyNum&255];
  }
  const keyNum = parseInt(s,16);
  if(!Number.isFinite(keyNum)) throw new ArgError("bad --addr: "+s);
  return [(keyNum>>8)&255, keyNum&255];
}
hfMfplus.command("info", "Show MIFARE Plus emulator state", [], async () => {
  need();
  const f = okOrThrow(await request(CU.MFPLUS_GET_INFO));
  const level = f.data[0], blockMax = f.data[1]|(f.data[2]<<8); // little-endian, matches chameleon_cmd.py
  const lines = [" - Security level: "+({0:"SL0 (not personalized)",3:"SL3 (AES)"}[level] || ("unknown ("+level+")")),
    " - Blocks: "+blockMax];
  if(level===0) lines.push(" - Use 'hf mfplus wrp' to write admin keys, then 'hf mfplus commitp' to switch to SL3.");
  return lines;
});
hfMfplus.command("wrp", "WritePerso: write one AES key into the MIFARE Plus key table (SL0 only)", [
  {names:["-a","--addr"], takesValue:true, dest:"addr", required:true},
  {names:["-k","--key"], takesValue:true, dest:"key", required:true},
], async (a) => {
  need();
  const [addrHi, addrLo] = mfplusParseAddr(a.addr);
  const key = hexBytes(a.key, 16);
  if(key.length!==16) throw new ArgError("key must be 16 bytes (32 hex chars, AES)");
  okOrThrow(await request(CU.MFPLUS_WRITE_PERSO, [addrHi, addrLo, ...key]));
  okOrThrow(await request(CU.SLOT_DATA_CONFIG_SAVE));
  return [" - WritePerso 0x"+addrHi.toString(16).padStart(2,"0")+addrLo.toString(16).padStart(2,"0")+" OK"];
});
hfMfplus.command("commitp", "CommitPerso: switch SL0 -> SL3 (requires the three admin keys written first; cannot be undone)", [
  {names:["--force"], takesValue:false, dest:"force"},
], async (a) => {
  need();
  if(!a.force) return [" - Pass --force to confirm: this switches SL0 -> SL3 and can't be undone."];
  okOrThrow(await request(CU.MFPLUS_COMMIT_PERSO));
  okOrThrow(await request(CU.SLOT_DATA_CONFIG_SAVE));
  return [" - Perso committed -- card is now SL3."];
});

/* ================= emv ================= */
const emv = ROOT.subgroup("emv", "EMV contactless payment card commands");

// BER-TLV walk, ported from EMVScan's tlv_find() (chameleon_cli_unit.py):
// recurses into constructed tags (bit 0x20 of the first tag byte) and
// tolerates truncated trailing TLV instead of aborting the whole parse.
function emvTlvFind(data, wantTags){
  const found = {}; for(const t of wantTags) found[t] = [];
  let i = 0;
  while(i < data.length){
    if(i+1 >= data.length) break;
    const b0 = data[i];
    const tl = (b0 & 0x1F) === 0x1F ? 2 : 1;
    if(i+tl > data.length) break;
    let tag = 0; for(let k=0;k<tl;k++) tag = (tag<<8) | data[i+k];
    i += tl;
    if(i >= data.length) break;
    const constructed = !!(b0 & 0x20);
    let vlen;
    if(data[i] & 0x80){
      const nb = data[i] & 0x7F; i++;
      if(i+nb > data.length) break;
      vlen = 0; for(let k=0;k<nb;k++) vlen = (vlen<<8) | data[i+k];
      i += nb;
    } else { vlen = data[i]; i++; }
    const truncated = i+vlen > data.length;
    const val = truncated ? data.slice(i) : data.slice(i, i+vlen);
    i = truncated ? data.length : i+vlen;
    if(wantTags.includes(tag) && !truncated) found[tag].push(val);
    if(constructed){ const sub = emvTlvFind(val, wantTags); for(const t of wantTags) found[t].push(...sub[t]); }
  }
  return found;
}
function emvTlvToDict(data){
  if(!data || !data.length) return {value:""};
  const tl = (data[0] & 0x1F) === 0x1F ? 2 : 1;
  let i = tl;
  if(i >= data.length) return {value:""};
  let vlen;
  if(data[i] & 0x80){ const nb = data[i]&0x7F; i++; vlen=0; for(let k=0;k<nb;k++) vlen=(vlen<<8)|data[i+k]; i+=nb; }
  else { vlen = data[i]; i++; }
  return {value: bhex(data.slice(i, i+vlen)).toUpperCase()};
}
function emvPanLuhn(panHex){
  const digits = panHex.split("").filter(c=>/[0-9]/.test(c)).map(Number).reverse();
  let total = 0;
  digits.forEach((d,i) => { if(i%2===0) total+=d; else { const d2=d*2; total += d2>9 ? d2-9 : d2; } });
  return total % 10 === 0;
}

emv.command("scan", "Full EMV contactless card scan (PPSE/SELECT AID/GPO/READ RECORD) in one firmware call -- like PM3 'emv scan -at' (-f/--file JSON output not ported -- no filesystem here)", [
  {names:["-s","--slot"], takesValue:true, dest:"slot"},
], async (a) => {
  need();
  const f = await request(CU.HF14A_4_EMV_SCAN);
  if(f.status !== 0x00 || !f.data.length) return [" [!] No card found or scan failed (status="+stname(f.status)+")"];
  const d = f.data; let off = 0;
  const uidLen = d[off++]; const uid = d.slice(off, off+uidLen); off += uidLen;
  const atqa = d.slice(off, off+2); off += 2;
  const sak = d[off++];
  const atsLen = d[off++]; const ats = d.slice(off, off+atsLen); off += atsLen;
  const out = [
    " UID : "+bhex(uid).toUpperCase(),
    " ATQA: "+bhex(atqa).toUpperCase()+"  SAK: "+sak.toString(16).padStart(2,"0").toUpperCase(),
    " ATS : "+bhex(ats).toUpperCase(),
  ];
  const numApdus = d[off++];
  const pairs = [];
  for(let n=0;n<numApdus;n++){
    const cl = d[off++]; const c = d.slice(off, off+cl); off += cl;
    const rl = d[off] | (d[off+1]<<8); off += 2;
    const r = d.slice(off, off+rl); off += rl;
    pairs.push([c, r]);
  }
  if(!pairs.length) { out.push(" [!] No APDU responses captured"); return out; }

  let allRecordData = [], extraData = [];
  if(pairs.length){
    const [, ppseResp] = pairs[0];
    const ppseBody = ppseResp.length>=2 ? ppseResp.slice(0,-2) : ppseResp;
    out.push("", " PPSE OK ("+ppseResp.length+"b)");
    extraData.push(...ppseBody);
  }
  if(pairs.length>=2){
    const [, selResp] = pairs[1];
    const selBody = selResp.length>=2 ? selResp.slice(0,-2) : selResp;
    out.push(" SELECT AID OK ("+selResp.length+"b)");
    extraData.push(...selBody);
  }
  if(pairs.length>=3){
    const [, gpoResp] = pairs[2];
    const gpoBody = gpoResp.length>=2 ? gpoResp.slice(0,-2) : gpoResp;
    out.push(" GPO OK ("+gpoResp.length+"b)");
    extraData.push(...gpoBody);
    for(const [cb, rb] of pairs.slice(3)){
      const sfiN = cb.length>=4 ? (cb[3]>>3)&0x1F : 0;
      const recN = cb.length>=3 ? cb[2] : 0;
      const rBody = rb.length>=2 ? rb.slice(0,-2) : rb;
      out.push(" READ RECORD SFI="+sfiN+" rec="+recN+" OK ("+rb.length+"b)");
      allRecordData.push(...rBody);
    }
  }

  const searchData = [...allRecordData, ...extraData];
  const tags = emvTlvFind(allRecordData, [0x5A, 0x57, 0x5F24, 0x5F20, 0x5F28]);
  const appTags = emvTlvFind(searchData, [0x9F12, 0x50]);

  out.push("", " -- Card Details --");
  const seenLabels = new Set();
  for(const v of appTags[0x50]){
    const lbl = bytesToAscii(v).trim();
    if(lbl && !seenLabels.has(lbl)){ seenLabels.add(lbl); out.push(" App Label     : "+lbl); }
  }

  let panHex = null;
  for(const v of tags[0x57]){
    const t2 = bhex(v).toUpperCase();
    const sep = t2.indexOf("D");
    if(sep > 0){ panHex = t2.slice(0, sep); break; }
  }
  if(!panHex && tags[0x5A].length){
    const raw = bhex(tags[0x5A][0]).toUpperCase();
    panHex = raw.endsWith("F") ? raw.replace(/F+$/,"") : raw;
  }
  if(panHex){
    const panFmt = panHex.match(/.{1,4}/g).join(" ");
    out.push(" PAN           : "+panFmt+"  Luhn: "+(emvPanLuhn(panHex)?"ok":"FAIL"));
  } else out.push(" PAN           : not found");

  let expiryFound = false;
  for(const v of tags[0x5F24]){
    if(v.length===3){ const exp=bhex(v).toUpperCase(); out.push(" Expiry        : 20"+exp.slice(0,2)+"/"+exp.slice(2,4)); expiryFound=true; }
  }
  if(!expiryFound && panHex){
    for(const v of tags[0x57]){
      const t2 = bhex(v).toUpperCase(); const sep = t2.indexOf("D");
      if(sep>0 && t2.length>=sep+5){
        const yymm = t2.slice(sep+1, sep+5);
        if(/^\d+$/.test(yymm)){ out.push(" Expiry        : 20"+yymm.slice(0,2)+"/"+yymm.slice(2,4)+" (from Track2)"); expiryFound=true; break; }
      }
    }
  }
  if(!expiryFound) out.push(" Expiry        : not found");

  for(const v of tags[0x5F20]){
    if(v.length && v.every(b=>b>=0x20 && b<=0x7E)){
      const name = bytesToAscii(v).trim();
      if(name) out.push(" Cardholder    : "+name);
    }
  }

  // -s/--slot (EMVScan.on_exec, chameleon_cli_unit.py): load the just-scanned
  // card straight into an emulation slot. Uses the in-memory uid/atqa/sak/ats
  // and full (cmd,resp) pairs already captured above -- no filesystem needed,
  // unlike -f/--file (PM3 JSON), which stays unported here for that reason.
  if(a.slot !== undefined){
    const slot = Number(a.slot);
    if(!(slot>=1 && slot<=8)) throw new ArgError("--slot must be 1-8");
    out.push("", " Loading into slot "+slot+"...");
    try{
      okOrThrow(await request(CU.SET_SLOT_TAG_TYPE, [slot-1, ...u16be(TAG_TYPE_BY_NAME.HF14A_4)]));
      okOrThrow(await request(CU.SET_SLOT_DATA_DEFAULT, [slot-1, ...u16be(TAG_TYPE_BY_NAME.HF14A_4)]));
      okOrThrow(await request(CU.SET_SLOT_ENABLE, [slot-1, 1, 1])); // 1 = HF
      okOrThrow(await request(CU.HF14A_4_SET_ANTI_COLL, [uid.length, ...uid, ...atqa, sak, ats.length, ...ats]));
      okOrThrow(await request(CU.HF14A_4_STATIC_RESP, [0])); // clear existing
      for(const [c, r] of pairs){ // full exchange, original SW -- matches as-captured
        okOrThrow(await request(CU.HF14A_4_STATIC_RESP, [c.length, ...c, ...u16be(r.length), ...r]));
      }
      okOrThrow(await request(CU.SLOT_DATA_CONFIG_SAVE));
      out.push(" Slot "+slot+" ready. Run: hw slot change -s "+slot+" && hw mode -e");
    }catch(e){
      out.push(" Slot load failed: "+e.message);
    }
  }

  return out;
});

emv.command("debug", "Show T=CL emulation debug counters (I-blocks rx/tx, last PCB, last static match)", [], async () => {
  need();
  const f = await request(CU.EMV_DEBUG);
  if(f.status !== 0x00 || !f.data || f.data.length < 4) return [" [!] Debug command failed"];
  const d = f.data;
  return [
    " I-blocks received : "+d[0],
    " I-blocks sent     : "+d[1],
    " Last rx PCB       : "+d[2].toString(16).padStart(2,"0")+"  (blk_num="+(d[2]&0x01)+", chain="+((d[2]>>5)&1)+", cid="+((d[2]>>4)&1)+")",
    " Last static match : "+(d[3] ? "yes" : "no"),
  ];
});

emv.command("load", "Load EMV APDU responses into the HF14A_4 slot for autonomous emulation (--file JSON mode not ported -- no filesystem here)", [
  {names:["--clear"], takesValue:false, dest:"clear"},
  {names:["--cmd"], takesValue:true, dest:"cmd"},
  {names:["--resp"], takesValue:true, dest:"resp"},
  {names:["--defaults"], takesValue:false, dest:"defaults"},
], async (a) => {
  need();
  if(a.clear){
    okOrThrow(await request(CU.HF14A_4_STATIC_RESP, [0]));
    return [" Static responses cleared."];
  }
  if(a.cmd && a.resp){
    const c = hexBytes(a.cmd), r = hexBytes(a.resp);
    okOrThrow(await request(CU.HF14A_4_STATIC_RESP, [c.length, ...c, ...u16be(r.length), ...r]));
    return [" Added: "+bhex(c).toUpperCase()+" -> "+bhex(r).toUpperCase()];
  }
  if(a.defaults){
    okOrThrow(await request(CU.HF14A_4_STATIC_RESP, [0]));
    const pairs = [
      [hexBytes("00a404000e325041592e5359532e4444463031"),
       hexBytes("6f23840e325041592e5359532e4444463031a511bf0c0e610c4f07a00000000410108701019000"),
       "SELECT PPSE"],
      [hexBytes("00a4040007a0000000041010"),
       hexBytes("6f1d8407a0000000041010a512500a4d6173746572436172648701019f38009000"),
       "SELECT Mastercard AID"],
      [hexBytes("80a80000"), hexBytes("6985"), "GPO (conditions not satisfied)"],
    ];
    const out = [];
    for(const [c,r,name] of pairs){
      const f = await request(CU.HF14A_4_STATIC_RESP, [c.length, ...c, ...u16be(r.length), ...r]);
      out.push((f.status===0x00?" Loaded: ":" Failed: ")+name);
    }
    out.push("", " Default responses loaded. Run: hw mode -e");
    return out;
  }
  return [" Specify --cmd/--resp, --clear, or --defaults (--file JSON mode needs a filesystem this terminal doesn't have)"];
});

// emv apdu is an interactive relay that waits for typed hex mid-command,
// which this request/response terminal can't do -- not registered.

/* The remaining real CLI groups below aren't ported here and so aren't
   registered; see the removal note further down for why. */
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

/* ================= lf sniff ================= */
// Flags match LFSniff (cli_lf.py); --out/--hex aren't ported (no filesystem;
// this always prints a hex preview, same as this page's own LF tab).
lf.command("sniff", "Capture raw LF field ADC samples (125kHz, 8us/sample)", [
  {names:["--timeout"], takesValue:true, dest:"timeout"},
  {names:["--passive"], takesValue:false, dest:"passive"},
], async (a) => {
  await needReader();
  const timeout = Math.max(1, Math.min(10000, a.timeout!==undefined ? Number(a.timeout) : 2000));
  const f = await request(CU.LF_SNIFF, [...u16be(timeout), a.passive?1:0], Math.max(6000, timeout+3000));
  if(!OK_STATUSES.has(f.status) || !f.data.length) return [" [!] No samples captured"];
  const d = f.data;
  let min=255, max=0, sum=0;
  for(const b of d){ if(b<min) min=b; if(b>max) max=b; sum+=b; }
  return [
    " - "+d.length+" ADC sample(s), min "+min+" max "+max+" mean "+(sum/d.length).toFixed(1),
    " - first 64 bytes: "+bhex(d.slice(0,64))+(d.length>64?" ...":""),
  ];
});

const lfEm = lf.subgroup("em", "EM commands");
const lfEm410x = lfEm.subgroup("410x", "EM410x commands");
// lf em 4x05 not ported -- not registered.

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

// *_econfig commands (cli_lf.py) get/set the emulated card id held in the
// active slot's emulator memory -- distinct from the T55xx write commands
// above, which target a physical tag. Several of them warn when the active
// slot's own LF tag type doesn't match; this reads GET_SLOT_INFO the same
// way `hw slot list` does (8 slots * {hf u16, lf u16}, big-endian).
async function lfSlotTypeWarnIfNot(expectedName){
  const info = okOrThrow(await request(CU.GET_SLOT_INFO));
  const active = await currentSlot1();
  const off = (active-1)*4;
  const lfType = (info.data[off+2]<<8)|info.data[off+3];
  if(lfType !== TAG_TYPE_BY_NAME[expectedName]) return "WARNING: Slot type not set to "+expectedName+".";
  return null;
}

lfEm410x.command("econfig", "Set/get the emulated em410x card id (in the active slot)", [
  {names:["--id"], takesValue:true, dest:"id"},
], async (a) => {
  need();
  if(a.id !== undefined){
    const id = hexBytes(a.id);
    if(id.length!==5 && id.length!==13) throw new ArgError("id must be 10 hex chars (5 bytes) or 26 hex chars (13 bytes, Electra)");
    okOrThrow(await request(CU.EM410X_SET_EMU_ID, id));
    return [" - Set em410x tag id success."];
  }
  const f = okOrThrow(await request(CU.EM410X_GET_EMU_ID));
  return [" - Get em410x tag id success.", "ID: "+bhex(f.data)];
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

lfHidProx.command("econfig", "Set/get the emulated hidprox card id (in the active slot)", [
  {names:["-f","--format"], takesValue:true, dest:"format", choices:Object.keys(HID_FORMAT_BY_NAME)},
  {names:["--fc"], takesValue:true, dest:"fc"},
  {names:["--cn"], takesValue:true, dest:"cn"},
  {names:["--il"], takesValue:true, dest:"il"},
  {names:["--oem"], takesValue:true, dest:"oem"},
], async (a) => {
  need();
  if(a.cn !== undefined){
    const warn = await lfSlotTypeWarnIfNot("HIDProx");
    const lines = warn ? [warn] : [];
    const format = a.format ? HID_FORMAT_BY_NAME[a.format] : HID_FORMAT_BY_NAME.H10301;
    const fc = a.fc!==undefined ? Number(a.fc) : 0, il = a.il!==undefined ? Number(a.il) : 0, oem = a.oem!==undefined ? Number(a.oem) : 0;
    const cn = Number(a.cn), cnHi = Math.floor(cn / 0x100000000), cnLo = cn >>> 0;
    const id = [format, ...u32be(fc), cnHi&0xFF, ...u32be(cnLo), il&0xFF, (oem>>8)&0xFF, oem&0xFF];
    okOrThrow(await request(CU.HIDPROX_SET_EMU_ID, id));
    lines.push(" - SET hidprox tag id success.");
    return lines;
  }
  const f = okOrThrow(await request(CU.HIDPROX_GET_EMU_ID));
  const d = f.data;
  const [format, fc, cn1, cn2, il, oem] = [d[0], (d[1]<<24|d[2]<<16|d[3]<<8|d[4])>>>0, d[5],
    (d[6]<<24|d[7]<<16|d[8]<<8|d[9])>>>0, d[10], (d[11]<<8|d[12])];
  const cn = cn1*0x100000000 + cn2;
  const lines = [" - GET hidprox tag id success.", "HIDProx/"+(HID_FORMAT_BY_VALUE[format]||format)];
  if(fc>0) lines.push(" FC: "+fc);
  if(il>0) lines.push(" IL: "+il);
  if(oem>0) lines.push(" OEM: "+oem);
  lines.push(" CN: "+cn);
  return lines;
});

// lf fdxb / lf generic / lf idteck / lf t55xx aren't ported -- not
// registered, so they're absent from help/tab-complete rather than stubbed.

/* ---- pm3-style LF decode/encode, ported from lf_info.py / cli_core.py ---- */
function vikingRaw(idb){ // pm3 getVikingBits(): F2 00 00 <id32> <chk>
  const chk = (idb[0]^idb[1]^idb[2]^idb[3]^0xF2^0xA8) & 0xFF;
  return [0xF2,0,0,...idb.slice(0,4),chk];
}
function jablotronRaw(full){ // pm3 getJablotronBits(): FFFF <5 byte code> <chk>
  const sum5 = full.slice(0,5).reduce((a,b)=>a+b,0) & 0xFF;
  return [0xFF,0xFF,...full.slice(0,5),(sum5^0x3A)&0xFF];
}
function jablotronCardId(raw){ // 5 raw bytes -> decimal via BCD
  let id = 0;
  for(const b of raw) id = id*100 + ((b>>4)*10) + (b&0x0F);
  return id;
}
function jablotronPrinted(full){ // 1410-nn-nnnn-nnnn
  const h = bhex(full.slice(0,5)).toUpperCase();
  return "1410-"+h.slice(0,2)+"-"+h.slice(2,6)+"-"+h.slice(6,10);
}
function indalaDecodeRaw(raw){ // 26-bit FC/CN from an 8-byte frame
  const bits=[];
  for(const b of raw) for(let i=7;i>=0;i--) bits.push((b>>i)&1);
  let fc=0;
  for(const [bi,sh] of [[57,7],[49,6],[44,5],[47,4],[48,3],[53,2],[39,1],[58,0]]) fc |= bits[bi]<<sh;
  let cn=0;
  for(const [bi,sh] of [[42,15],[45,14],[43,13],[40,12],[52,11],[36,10],[35,9],[51,8],
                         [46,7],[33,6],[37,5],[54,4],[56,3],[59,2],[50,1],[41,0]]) cn |= bits[bi]<<sh;
  return [fc,cn];
}
function indalaEncodeRaw(fc,cn){ // inverse of indalaDecodeRaw
  const bits = new Array(64).fill(0);
  bits[0]=1; bits[2]=1; bits[32]=1;
  for(const [bi,sh] of [[57,7],[49,6],[44,5],[47,4],[48,3],[53,2],[39,1],[58,0]]) bits[bi]=(fc>>sh)&1;
  for(const [bi,sh] of [[42,15],[45,14],[43,13],[40,12],[52,11],[36,10],[35,9],[51,8],
                         [46,7],[33,6],[37,5],[54,4],[56,3],[59,2],[50,1],[41,0]]) bits[bi]=(cn>>sh)&1;
  let chk=0;
  for(const sh of [14,12,9,8,6,5,2,0]) chk += (cn>>sh)&1;
  if(chk%2===0){ bits[62]=1; bits[63]=0; } else { bits[62]=0; bits[63]=1; }
  let p1=1,p2=1;
  for(let i=33;i<64;i++){ if(i%2) p1^=bits[i]; else p2^=bits[i]; }
  bits[34]=p1; bits[38]=p2;
  const raw=new Array(8).fill(0);
  for(let i=0;i<64;i++) if(bits[i]) raw[i>>3] |= 1<<(7-(i%8));
  return raw;
}
function indalaLines(raw, fc, cn){ // pm3 demodIndala() de-scramble patterns
  const bit = n => (raw[n>>3]>>(7-(n%8)))&1;
  const uid2 = (raw[4]<<24|raw[5]<<16|raw[6]<<8|raw[7])>>>0;
  let p1=0;
  for(const [n,sh] of [[3,8],[6,5],[8,4],[9,3],[11,1],[16,6],[19,7],[20,10],[21,2],[22,0],[24,9]]) p1 |= bit(32+n)<<sh;
  let heden=0;
  for(const [n,w] of [[8,1],[10,2],[14,4],[15,8],[12,16],[28,32],[3,64],[11,128],[19,256],
                       [26,512],[17,1024],[18,2048],[20,4096],[13,8192],[7,16384],[23,32768]])
    if(bit(31+n)) heden += w;
  return [
    "Indala (len 64)  Raw: "+bhex(raw).toUpperCase(),
    "Fmt 26 FC: "+fc+" Card: "+cn,
    "",
    "Possible de-scramble patterns",
    "  Printed....... __"+String(p1).padStart(4,"0")+"__  ( 0x"+p1.toString(16).toUpperCase()+" )",
    "  Internal ID... "+(uid2 & 0x7FFFFFFF),
    "  Heden-2L...... "+heden,
  ];
}
function pacEncodeRaw(cardId){ // 8-byte card ID -> 16-byte T55XX bitstream
  const payload = [0x02,0x32,0x30,...cardId];
  let xorCheck=0; for(const b of cardId) xorCheck ^= b;
  payload.push(xorCheck);
  const bits = new Array(8).fill(1); // 0xFF sync
  for(const byteVal of payload){
    bits.push(0); // start bit
    let ones=0;
    for(let i=0;i<7;i++){ const b=(byteVal>>i)&1; bits.push(b); ones+=b; }
    bits.push(ones&1 ? 0 : 1); // odd parity
    bits.push(1); // stop bit
  }
  const raw = new Array(16).fill(0);
  for(let i=0;i<128;i++) if(bits[i]) raw[i>>3] |= 1<<(7-(i&7));
  return raw;
}

const lfViking = lf.subgroup("viking", "Viking commands");
lfViking.command("read", "Scan Viking tag and print id", [], async () => {
  await needReader();
  const f = await request(CU.VIKING_SCAN);
  if(!OK_STATUSES.has(f.status)) return ["No tag: "+stname(f.status)];
  const id = f.data.slice(0,4);
  return ["Viking - Card "+bhex(id).toUpperCase()+", Raw: "+bhex(vikingRaw(id)).toUpperCase()];
});
lfViking.command("write", "Write Viking id to t55xx", [
  {names:["--id"], takesValue:true, dest:"id", required:true},
], async (a) => {
  await needReader();
  const id = hexBytes(a.id,4);
  if(id.length!==4) throw new ArgError("id must be 8 hex chars (4 bytes)");
  okOrThrow(await request(CU.VIKING_WRITE_TO_T55XX, t55xxPayload(id)));
  return [" - Viking ID(8H): "+a.id+" write done."];
});

lfViking.command("econfig", "Set/get the emulated Viking card id (in the active slot)", [
  {names:["--id"], takesValue:true, dest:"id"},
], async (a) => {
  need();
  if(a.id !== undefined){
    const warn = await lfSlotTypeWarnIfNot("Viking");
    const id = hexBytes(a.id,4);
    if(id.length!==4) throw new ArgError("id must be 8 hex chars (4 bytes)");
    okOrThrow(await request(CU.VIKING_SET_EMU_ID, id));
    return [...(warn?[warn]:[]), " - Set Viking tag id success."];
  }
  const f = okOrThrow(await request(CU.VIKING_GET_EMU_ID));
  return [" - Get Viking tag id success.", "ID: "+bhex(f.data).toUpperCase()];
});

const lfPac = lf.subgroup("pac", "PAC/Stanley commands");
lfPac.command("read", "Scan PAC/Stanley tag and print card ID", [], async () => {
  await needReader();
  const f = await request(CU.PAC_SCAN);
  if(!OK_STATUSES.has(f.status)) return ["No tag: "+stname(f.status)];
  const id = f.data.slice(0,8);
  const ascii = Array.from(id).map(b => (b>=0x20&&b<0x7F) ? String.fromCharCode(b) : ".").join("");
  return [" PAC/Stanley - CN: "+ascii+" | Raw: "+bhex(pacEncodeRaw(id)).toUpperCase()];
});
lfPac.command("write", "Write PAC/Stanley id to T55xx (--cn only here; --raw bitstream decode not ported)", [
  {names:["--cn"], takesValue:true, dest:"cn", required:true},
], async (a) => {
  await needReader();
  if(a.cn.length!==8) throw new ArgError("Card number must be exactly 8 characters");
  const id = Array.from(a.cn, c => c.charCodeAt(0));
  if(id.some(b => b>0x7F)) throw new ArgError("PAC card IDs are 7-bit only (each byte must be 0x00-0x7F)");
  okOrThrow(await request(CU.PAC_WRITE_TO_T55XX, t55xxPayload(id)));
  return [" - PAC/Stanley write done - CN: "+a.cn+" | Raw: "+bhex(pacEncodeRaw(id)).toUpperCase()];
});

lfPac.command("econfig", "Set/get the emulated PAC/Stanley card id (in the active slot; --cn only here, same as `lf pac write` -- --raw bitstream decode not ported)", [
  {names:["--cn"], takesValue:true, dest:"cn"},
], async (a) => {
  need();
  if(a.cn !== undefined){
    if(a.cn.length!==8) throw new ArgError("Card number must be exactly 8 characters");
    const id = Array.from(a.cn, c => c.charCodeAt(0));
    if(id.some(b => b>0x7F)) throw new ArgError("PAC card IDs are 7-bit only (each byte must be 0x00-0x7F)");
    const warn = await lfSlotTypeWarnIfNot("PAC");
    okOrThrow(await request(CU.PAC_SET_EMU_ID, id));
    return [...(warn?[warn]:[]), " - Set PAC/Stanley tag id success."];
  }
  const f = okOrThrow(await request(CU.PAC_GET_EMU_ID));
  const id = f.data;
  const ascii = Array.from(id).map(b => (b>=0x20&&b<0x7F) ? String.fromCharCode(b) : ".").join("");
  return [" - Get PAC/Stanley tag id success.", "CN: "+ascii+" | Raw: "+bhex(pacEncodeRaw(id)).toUpperCase()];
});

const lfJablotron = lf.subgroup("jablotron", "Jablotron commands");
lfJablotron.command("read", "Scan Jablotron tag and print id", [], async () => {
  await needReader();
  const f = await request(CU.JABLOTRON_SCAN);
  if(!OK_STATUSES.has(f.status)) return ["No tag: "+stname(f.status)];
  const code = f.data.slice(0,5);
  return [
    "Jablotron - Card: "+jablotronCardId(code)+", Raw: "+bhex(jablotronRaw(code)).toUpperCase(),
    "Printed: "+jablotronPrinted(code),
  ];
});
lfJablotron.command("write", "Write Jablotron id to t55xx", [
  {names:["--id"], takesValue:true, dest:"id", required:true},
], async (a) => {
  await needReader();
  const id = hexBytes(a.id,5);
  if(id.length!==5) throw new ArgError("id must be 10 hex chars (5 bytes)");
  okOrThrow(await request(CU.JABLOTRON_WRITE_TO_T55XX, t55xxPayload(id)));
  return [" - Jablotron ID: "+a.id.toUpperCase()+" write done."];
});

lfJablotron.command("econfig", "Set/get the emulated Jablotron card id (in the active slot)", [
  {names:["--id"], takesValue:true, dest:"id"},
], async (a) => {
  need();
  if(a.id !== undefined){
    const warn = await lfSlotTypeWarnIfNot("Jablotron");
    const id = hexBytes(a.id,5);
    if(id.length!==5) throw new ArgError("id must be 10 hex chars (5 bytes)");
    okOrThrow(await request(CU.JABLOTRON_SET_EMU_ID, id));
    return [...(warn?[warn]:[]), " - Set Jablotron tag id success."];
  }
  const f = okOrThrow(await request(CU.JABLOTRON_GET_EMU_ID));
  return [" - Get Jablotron tag id success.", "ID: "+bhex(f.data).toUpperCase(), "Card: "+jablotronCardId(f.data)];
});

const lfIndala = lf.subgroup("indala", "Indala commands");
lfIndala.command("read", "Scan for an Indala tag", [], async () => {
  await needReader();
  const f = await request(CU.INDALA_SCAN);
  if(!OK_STATUSES.has(f.status)) return ["Indala scan failed: "+stname(f.status)];
  const raw = f.data.slice(0,8);
  const [fc,cn] = indalaDecodeRaw(raw);
  return indalaLines(raw, fc, cn);
});
lfIndala.command("write", "Clone Indala tag to T55XX (use -r <hex>, or --fc <n> --cn <n>)", [
  {names:["-r","--raw"], takesValue:true, dest:"raw"},
  {names:["--fc"], takesValue:true, dest:"fc"},
  {names:["--cn"], takesValue:true, dest:"cn"},
], async (a) => {
  await needReader();
  let raw;
  if(a.raw!==undefined){
    if(a.fc!==undefined || a.cn!==undefined) throw new ArgError("-r/--raw and --fc/--cn are mutually exclusive");
    raw = hexBytes(a.raw,8);
    if(raw.length!==8) throw new ArgError("Raw 64-bit frame must be 16 hex chars");
  } else {
    if(a.fc===undefined || a.cn===undefined) throw new ArgError("--fc and --cn must be used together");
    const fc=Number(a.fc), cn=Number(a.cn);
    if(fc<0||fc>255) throw new ArgError("FC must be 0-255");
    if(cn<0||cn>65535) throw new ArgError("CN must be 0-65535");
    raw = indalaEncodeRaw(fc,cn);
  }
  okOrThrow(await request(CU.INDALA_WRITE_TO_T55XX, t55xxPayload(raw)));
  const [fc,cn] = indalaDecodeRaw(raw);
  return [...indalaLines(raw,fc,cn), " Write done. Verify with 'lf indala read'."];
});

lfIndala.command("econfig", "Get or set the Indala emulated frame on a slot (-r <hex>, or --fc/--cn)", [
  {names:["-r","--raw"], takesValue:true, dest:"raw"},
  {names:["--fc"], takesValue:true, dest:"fc"},
  {names:["--cn"], takesValue:true, dest:"cn"},
], async (a) => {
  need();
  if(a.raw!==undefined || a.fc!==undefined || a.cn!==undefined){
    let raw;
    if(a.raw!==undefined){
      if(a.fc!==undefined || a.cn!==undefined) throw new ArgError("-r/--raw and --fc/--cn are mutually exclusive");
      raw = hexBytes(a.raw,8);
      if(raw.length!==8) throw new ArgError("Raw 64-bit frame must be 16 hex chars");
    } else {
      if(a.fc===undefined || a.cn===undefined) throw new ArgError("--fc and --cn must be used together");
      const fc=Number(a.fc), cn=Number(a.cn);
      if(fc<0||fc>255) throw new ArgError("FC must be 0-255");
      if(cn<0||cn>65535) throw new ArgError("CN must be 0-65535");
      raw = indalaEncodeRaw(fc,cn);
    }
    const warn = await lfSlotTypeWarnIfNot("Indala");
    okOrThrow(await request(CU.INDALA_SET_EMU_ID, raw));
    return [...(warn?[warn]:[]), " - Indala emu frame set to "+bhex(raw).toUpperCase()+"."];
  }
  const f = okOrThrow(await request(CU.INDALA_GET_EMU_ID));
  const [fc,cn] = indalaDecodeRaw(f.data);
  return [" - Get Indala emu frame success.", ...indalaLines(f.data,fc,cn)];
});

const lfIoprox = lf.subgroup("ioprox", "ioProx commands");
lfIoprox.command("read", "Scan ioProx tag and print version, facility, card number and raw", [], async () => {
  await needReader();
  const f = await request(CU.IOPROX_SCAN);
  if(!OK_STATUSES.has(f.status)) return ["No tag: "+stname(f.status)];
  const d = f.data, ver=d[0], fc=d[1], cn=(d[2]<<8)|d[3], raw8=d.slice(4,12);
  return [
    "IO Prox - XSF("+String(ver).padStart(2,"0")+")"+fc.toString(16).padStart(2,"0")+":"+String(cn).padStart(5,"0")+", Raw: "+bhex(raw8),
    "   Facility: "+fc+" [0x"+fc.toString(16).padStart(2,"0").toUpperCase()+"]",
  ];
});
lfIoprox.command("write", "Write ioProx card data to t55xx", [
  {names:["--ver"], takesValue:true, dest:"ver"},
  {names:["--fc"], takesValue:true, dest:"fc"},
  {names:["--cn"], takesValue:true, dest:"cn"},
  {names:["--raw8"], takesValue:true, dest:"raw8"},
], async (a) => {
  await needReader();
  let resp;
  if(a.raw8!==undefined){
    const raw8 = hexBytes(a.raw8,8);
    if(raw8.length!==8) throw new ArgError("raw8 must be 16 hex chars (8 bytes)");
    resp = await request(CU.IOPROX_DECODE_RAW, raw8);
  } else {
    const ver = a.ver!==undefined?Number(a.ver):1, fc = a.fc!==undefined?Number(a.fc):0, cn = a.cn!==undefined?Number(a.cn):0;
    resp = await request(CU.IOPROX_COMPOSE_ID, [ver, fc, ...u16be(cn)]);
  }
  if(!OK_STATUSES.has(resp.status)) return ["error: "+stname(resp.status)];
  const d = resp.data, ver=d[0], fc=d[1], cn=(d[2]<<8)|d[3], raw8=d.slice(4,12);
  const payload16 = [ver, fc, ...u16be(cn), ...raw8, 0,0,0,0];
  okOrThrow(await request(CU.IOPROX_WRITE_TO_T55XX, t55xxPayload(payload16)));
  return [
    "ioProx XSF format",
    "   Version: "+ver,
    "   Facility: "+fc+" [0x"+fc.toString(16).padStart(2,"0").toUpperCase()+"]",
    "   ID: "+cn,
    "   Raw: "+bhex(raw8).toUpperCase(),
    "Write done.",
  ];
});

lfIoprox.command("econfig", "Set/get emulated ioProx card id (in the active slot)", [
  {names:["--ver"], takesValue:true, dest:"ver"},
  {names:["--fc"], takesValue:true, dest:"fc"},
  {names:["--cn"], takesValue:true, dest:"cn"},
  {names:["--raw8"], takesValue:true, dest:"raw8"},
], async (a) => {
  need();
  const doSet = a.cn!==undefined || a.raw8!==undefined || a.fc!==undefined || a.ver!==undefined;
  if(doSet){
    const warn = await lfSlotTypeWarnIfNot("ioProx");
    let ver = a.ver!==undefined?Number(a.ver):1, fc = a.fc!==undefined?Number(a.fc):0, cn = a.cn!==undefined?Number(a.cn):0, raw8;
    if(a.raw8!==undefined){
      const rawIn = hexBytes(a.raw8,8);
      if(rawIn.length!==8) throw new ArgError("raw8 must be 16 hex chars (8 bytes)");
      const resp = okOrThrow(await request(CU.IOPROX_DECODE_RAW, rawIn));
      ver=resp.data[0]; fc=resp.data[1]; cn=(resp.data[2]<<8)|resp.data[3]; raw8=resp.data.slice(4,12);
    } else {
      const resp = okOrThrow(await request(CU.IOPROX_COMPOSE_ID, [ver, fc, ...u16be(cn)]));
      raw8 = resp.data.slice(4,12);
    }
    const payload16 = [ver, fc, ...u16be(cn), ...raw8, 0,0,0,0];
    okOrThrow(await request(CU.IOPROX_SET_EMU_ID, payload16));
    return [...(warn?[warn]:[]), "ioProx XSF format", "   Version: "+ver,
      "   Facility: "+fc+" [0x"+fc.toString(16).padStart(2,"0").toUpperCase()+"]",
      "   ID: "+cn, "   Raw: "+bhex(raw8).toUpperCase()];
  }
  const f = okOrThrow(await request(CU.IOPROX_GET_EMU_ID));
  const d = f.data, ver=d[0], fc=d[1], cn=(d[2]<<8)|d[3], raw8=d.slice(4,12);
  return ["ioProx XSF format", "   Version: "+ver,
    "   Facility: "+fc+" [0x"+fc.toString(16).padStart(2,"0").toUpperCase()+"]",
    "   ID: "+cn, "   Raw: "+bhex(raw8).toUpperCase()];
});

// lf clone / lf sniff -- no equivalent anywhere on this page -- not
// registered. standalone -- ported as the page's own Standalone tab, not
// through this terminal -- not registered. data (PM3 waveform analysis;
// this page has no waveform capture) -- not registered.

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
      const label = s.positional ? "<"+s.dest+">" : s.names.join(", ")+(s.takesValue?" <value>":"");
      lines.push("  "+label+(s.required?"  (required)":""));
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
  // Not a registered command, not in help, not tab-completable. Known to
  // exactly one person who bothers to read this file.
  if(tokens[0]==="2600") return blueBox();

  let node = ROOT, i = 0;
  while(node instanceof Group){
    if(i >= tokens.length) return helpFor(node);
    const next = node.children.get(tokens[i]);
    if(!next) return ["error: unknown "+(node.name?"'"+node.name+"' subcommand":"command")+": "+tokens[i], ...helpFor(node)];
    node = next; i++;
  }
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

// 2600 Hz was the single-frequency tone AT&T's long-distance trunks used for
// on-hook/idle supervision. The toy whistle in boxes of Cap'n Crunch cereal
// happened to blow it dead-on, so a kid with a bowl of cereal and a payphone
// could seize an idle trunk for free -- John Draper took "Captain Crunch"
// from the whistle, and the scene around him took "phreak" (phone + freak).
// Phreak + byte. No request goes out over BLE for this; it's local only.
let blueBoxCtx = null;
async function blueBox(){
  try{
    blueBoxCtx = blueBoxCtx || new (window.AudioContext||window.webkitAudioContext)();
    const ctx = blueBoxCtx, o = ctx.createOscillator(), g = ctx.createGain();
    o.frequency.value = 2600; o.connect(g); g.connect(ctx.destination);
    const t = ctx.currentTime;
    g.gain.setValueAtTime(0.15, t);
    g.gain.exponentialRampToValueAtTime(0.0001, t+0.9);
    o.start(t); o.stop(t+0.9);
  }catch(e){ /* no audio output here; the text still tells the story */ }
  return [
    "",
    "   *** 2600 Hz ***",
    "   AT&T's trunks listened for one pure tone to mean \"idle, take me\".",
    "   A plastic whistle from a box of Cap'n Crunch sang it exactly --",
    "   blow it into a payphone and you owned an open trunk, operator-free.",
    "   John Draper became \"Captain Crunch\"; his scene became \"phreaks\".",
    "   Phreak + byte -- you're standing in the family tree.",
    "",
  ];
}

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
