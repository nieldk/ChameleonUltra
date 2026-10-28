"use strict";
/* ---------------------------------------------------------------------
 * fullcmd.js — device/slot/HF14A/MF1/LF/MF0-NTAG command surface.
 *
 * Loaded after canary.js in the same (non-module) page, so it reuses
 * canary.js's globals directly: request(), connected(), hex(), $(),
 * device, makeFrame, parseFrames, frameLabel, extractNonces.
 *
 * Every payload layout below is copied from software/script/chameleon_cmd.py
 * in NielDK/ChameleonUltra (the struct.pack('!...') calls there are
 * network/big-endian) — NOT the little-endian convention used by the
 * 7000-range STANDALONE_* commands in canary.js. Cross-check against that
 * file (and data_cmd.h for the opcodes) before relying on this for
 * anything you can't verify by hand against the device.
 * ------------------------------------------------------------------- */

const CU = {
  GET_APP_VERSION:1000, CHANGE_DEVICE_MODE:1001, GET_DEVICE_MODE:1002,
  SET_ACTIVE_SLOT:1003, SET_SLOT_TAG_TYPE:1004, SET_SLOT_DATA_DEFAULT:1005,
  SET_SLOT_ENABLE:1006, SET_SLOT_TAG_NICK:1007, GET_SLOT_TAG_NICK:1008,
  SLOT_DATA_CONFIG_SAVE:1009, ENTER_BOOTLOADER:1010, GET_DEVICE_CHIP_ID:1011,
  GET_DEVICE_ADDRESS:1012, SAVE_SETTINGS:1013, RESET_SETTINGS:1014,
  SET_ANIMATION_MODE:1015, GET_ANIMATION_MODE:1016, GET_GIT_VERSION:1017,
  GET_ACTIVE_SLOT:1018, GET_SLOT_INFO:1019, WIPE_FDS:1020,
  DELETE_SLOT_TAG_NICK:1021, GET_ENABLED_SLOTS:1023, DELETE_SLOT_SENSE_TYPE:1024,
  GET_BATTERY_INFO:1025, GET_ALL_SLOT_NICKS:1038,
  GET_BUTTON_PRESS_CONFIG:1026, SET_BUTTON_PRESS_CONFIG:1027,
  GET_LONG_BUTTON_PRESS_CONFIG:1028, SET_LONG_BUTTON_PRESS_CONFIG:1029,
  SET_BLE_PAIRING_KEY:1030, GET_BLE_PAIRING_KEY:1031, DELETE_ALL_BLE_BONDS:1032,
  GET_DEVICE_MODEL:1033, GET_DEVICE_SETTINGS:1034, GET_DEVICE_CAPABILITIES:1035,
  GET_BLE_PAIRING_ENABLE:1036, SET_BLE_PAIRING_ENABLE:1037,
  GET_SLEEP_TIMEOUT:1039, SET_SLEEP_TIMEOUT:1040,
  // 1041/1042 are reserved (RRG's GET/SET_LONG_PRESS_THRESHOLD, not
  // implemented by this firmware) -- GET_BOOTLOADER_VERSION/GET_FREE_MEMORY
  // moved to 1061/1062 (data_cmd.c). Using 1041/1042 here was stale and
  // made both read as "not supported by current firmware".
  GET_BLE_NAME:1043, SET_BLE_NAME:1044, RESET_DEVICE:1045,
  LOG_GET_STATUS:1047, LOG_SET_LEVEL:1048, LOG_READ:1049, LOG_CLEAR:1050,
  BL_INFO:1057, FDS_LIST:1058, FDS_READ:1059,
  GET_BOOTLOADER_VERSION:1061, GET_FREE_MEMORY:1062,

  HF14A_SCAN:2000, MF1_DETECT_SUPPORT:2001, MF1_DETECT_PRNG:2002,
  MF1_AUTH_ONE_KEY_BLOCK:2007, MF1_READ_ONE_BLOCK:2008, MF1_WRITE_ONE_BLOCK:2009,
  HF14A_RAW:2010, MF1_MANIPULATE_VALUE_BLOCK:2011, MF1_MAGIC_AUTH:4051,
  HF14A_4_APDU_RECV:6000, HF14A_4_APDU_SEND:6001, HF14A_4_SET_ANTI_COLL:6002, HF14A_4_STATIC_RESP:6003,
  MF1_CHECK_KEYS_OF_SECTORS:2012, MF1_CHECK_KEYS_ON_BLOCK:2015,
  HF14A_SCAN_KEEP:2016, HF14A_AUTH_TRACE:2017,
  HF14A_SET_FIELD_ON:2100, HF14A_SET_FIELD_OFF:2101,
  HF14A_GET_CONFIG:2200, HF14A_SET_CONFIG:2201,
  // Key-recovery nonce acquisition (chameleon_cmd.py mf1_*_acquire/mf1_detect_nt_dist) --
  // these collect data for an OFFLINE cracker (mfoc/mfcuk/proxmark-style darkside,
  // nested, hardnested), no crypto1 math reimplemented here.
  MF1_STATIC_NESTED_ACQUIRE:2003, MF1_DARKSIDE_ACQUIRE:2004, MF1_DETECT_NT_DIST:2005,
  MF1_NESTED_ACQUIRE:2006, MF1_HARDNESTED_ACQUIRE:2013, MF1_ENC_NESTED_ACQUIRE:2014,
  HF14A_SNIFF:2020,

  EM410X_SCAN:3000, EM410X_WRITE_TO_T55XX:3001, HIDPROX_SCAN:3002, HIDPROX_WRITE_TO_T55XX:3003,
  VIKING_SCAN:3004, VIKING_WRITE_TO_T55XX:3005, EM410X_ELECTRA_WRITE_TO_T55XX:3006,
  ADC_GENERIC_READ:3009,
  IOPROX_SCAN:3010, IOPROX_WRITE_TO_T55XX:3011, IOPROX_DECODE_RAW:3012, IOPROX_COMPOSE_ID:3013,
  PAC_SCAN:3014, PAC_WRITE_TO_T55XX:3015, LF_T55XX_WRITE:3016, LF_T55XX_READ:3017,
  IDTECK_WRITE_TO_T55XX:3018, JABLOTRON_SCAN:3019, JABLOTRON_WRITE_TO_T55XX:3020,
  FDXB_SCAN:3021, FDXB_WRITE_TO_T55XX:3022, EM4X05_SCAN:3030, LF_SNIFF:3031, LF_SEARCH:3033,
  INDALA_SCAN:3035, INDALA_WRITE_TO_T55XX:3036,
  // 3032 EM4X05_READSNIFF is a #define in firmware's data_cmd.c with no
  // app_cmd.c dispatch case and no chameleon_cmd.py wrapper -- not actually
  // implemented in this firmware, so no UI control for it (checked, not guessed).

  MF1_WRITE_EMU_BLOCK_DATA:4000, HF14A_SET_ANTI_COLL_DATA:4001,
  MF1_SET_DETECTION_ENABLE:4004, MF1_GET_DETECTION_COUNT:4005, MF1_GET_DETECTION_LOG:4006,
  MF1_READ_EMU_BLOCK_DATA:4008, MF1_GET_EMULATOR_CONFIG:4009,
  MF1_SET_GEN1A_MODE:4011, MF1_SET_GEN2_MODE:4013,
  MF1_SET_BLOCK_ANTI_COLL_MODE:4015, MF1_SET_WRITE_MODE:4017, HF14A_GET_ANTI_COLL_DATA:4018,
  MF0_NTAG_GET_UID_MAGIC_MODE:4019, MF0_NTAG_SET_UID_MAGIC_MODE:4020,
  MF0_NTAG_READ_EMU_PAGE_DATA:4021, MF0_NTAG_WRITE_EMU_PAGE_DATA:4022,
  MF0_NTAG_GET_VERSION_DATA:4023, MF0_NTAG_SET_VERSION_DATA:4024,
  MF0_NTAG_GET_SIGNATURE_DATA:4025, MF0_NTAG_SET_SIGNATURE_DATA:4026,
  MF0_NTAG_GET_COUNTER_DATA:4027, MF0_NTAG_SET_COUNTER_DATA:4028, MF0_NTAG_RESET_AUTH_CNT:4029,
  MF0_NTAG_GET_PAGE_COUNT:4030,
  MF0_NTAG_GET_WRITE_MODE:4031, MF0_NTAG_SET_WRITE_MODE:4032,
  MF0_NTAG_SET_DETECTION_ENABLE:4033, MF0_NTAG_GET_DETECTION_COUNT:4034,
  MF0_NTAG_GET_DETECTION_LOG:4035, MF0_NTAG_GET_DETECTION_ENABLE:4036,
  MF0_NTAG_GET_EMULATOR_CONFIG:4037,
  MF1_GET_FIELD_OFF_DO_RESET:4039, MF1_SET_FIELD_OFF_DO_RESET:4038,
  MF1_GET_PRNG_TYPE:4040, MF1_SET_PRNG_TYPE:4041,
  SEOS_READ_EMU_DATA:4042, SEOS_WRITE_EMU_DATA:4043, SEOS_WRITE_EMU_KEYS:4044,
  ST25TA_GET_INFO:4045, ST25TA_READ_NDEF:4046, ST25TA_WRITE_NDEF:4047, ST25TA_SET_CONFIG:4048,
  MFPLUS_GET_INFO:4049, MFPLUS_WRITE_PERSO:4050, MFPLUS_COMMIT_PERSO:4052,

  EM410X_SET_EMU_ID:5000, EM410X_GET_EMU_ID:5001, HIDPROX_SET_EMU_ID:5002, HIDPROX_GET_EMU_ID:5003,
  VIKING_SET_EMU_ID:5004, VIKING_GET_EMU_ID:5005, PAC_SET_EMU_ID:5006, PAC_GET_EMU_ID:5007,
  IOPROX_SET_EMU_ID:5008, IOPROX_GET_EMU_ID:5009, JABLOTRON_SET_EMU_ID:5010, JABLOTRON_GET_EMU_ID:5011,
  IDTECK_SET_EMU_ID:5012, IDTECK_GET_EMU_ID:5013, INDALA_SET_EMU_ID:5014, INDALA_GET_EMU_ID:5015,

  STANDALONE_GET_AVAILABLE:7011, STANDALONE_GET_RESULT_FOR:7012, STANDALONE_CLEAR_RESULT_FOR:7013,

  DESFIRE_SET_CREDENTIAL:6006, DESFIRE_GET_CREDENTIAL:6007, DESFIRE_GET_INFO:6008,
  DESFIRE_FACTORY_BLANK:6009, DESFIRE_GET_STATS:6011,
  DESFIRE_READER_AUTH_ISO7816:6012, DESFIRE_READER_GET_VERSION:6013,
  HF14A_4_READER_APDU:6004, HF14A_4_EMV_SCAN:6005,
};

/* TagSpecificType, from chameleon_enum.py — used only to label slot info. */
const TAG_TYPE_NAMES = {
  0:"undefined",
  1:"EM410X (old)",2:"MIFARE Mini (old)",3:"MIFARE 1K (old)",4:"MIFARE 2K (old)",
  5:"MIFARE 4K (old)",6:"NTAG213 (old)",7:"NTAG215 (old)",8:"NTAG216 (old)",
  100:"EM410X",101:"EM410X-16",102:"EM410X-32",103:"EM410X-64",104:"EM410X Electra",
  105:"FDX-B",150:"PAC/Stanley",170:"Viking",180:"Jablotron",
  200:"HID Prox",201:"ioProx",310:"IDTECK",311:"Indala",
  1000:"MIFARE Mini",1001:"MIFARE 1K",1002:"MIFARE 2K",1003:"MIFARE 4K",
  1004:"MIFARE Plus S2K (SL1)",1005:"MIFARE Plus S4K (SL1)",
  1006:"MIFARE Plus S2K (SL3)",1007:"MIFARE Plus S4K (SL3)",
  1100:"NTAG213",1101:"NTAG215",1102:"NTAG216",1103:"MF0ICU1",1104:"MF0ICU2",
  1105:"MF0UL11",1106:"MF0UL21",1107:"NTAG210",1108:"NTAG212",
  1300:"DESFire EV1 2K",1301:"DESFire EV1 4K",1302:"DESFire EV1 8K",
  1303:"DESFire EV2 2K",1304:"DESFire EV2 4K",1305:"DESFire EV2 8K",
  2000:"ST25TA",3000:"HF14A-4 (T=CL)",3001:"SEOS",
};
function tagTypeName(code){ return (TAG_TYPE_NAMES[code]||("type "+code))+" ("+code+")"; }

const STATUS_NAMES = {0x00:"HF_TAG_OK",0x01:"HF_TAG_NO",0x02:"HF_ERR_STAT",0x03:"HF_ERR_CRC",
  0x04:"HF_COLLISION",0x05:"HF_ERR_BCC",0x06:"MF_ERR_AUTH",0x07:"HF_ERR_PARITY",0x08:"HF_ERR_ATS",
  0x40:"LF_TAG_OK",0x41:"LF_TAG_NO_FOUND",0x60:"PAR_ERR",0x66:"DEVICE_MODE_ERROR",0x67:"INVALID_CMD",
  0x68:"SUCCESS",0x69:"NOT_IMPLEMENTED",0x70:"FLASH_WRITE_FAIL",0x71:"FLASH_READ_FAIL",0x72:"INVALID_SLOT_TYPE"};
const stname = s => STATUS_NAMES[s] || ("0x"+s.toString(16));
const OK_STATUSES = new Set([0x00,0x40,0x68]);

const NEW_KEY = [0x20,0x20,0x66,0x66];
const OLD_KEYS = [0x51,0x24,0x36,0x48, 0x19,0x92,0x04,0x27];
function t55xxPayload(idBytes){ return idBytes.concat(NEW_KEY, OLD_KEYS); }

/* ---- byte helpers ---- */
function hexBytes(str, padLen){
  let s = (str||"").replace(/[^0-9a-fA-F]/g,"");
  if(padLen){ s = s.length < padLen*2 ? s.padStart(padLen*2,"0") : s.slice(0,padLen*2); }
  const out=[];
  for(let i=0;i+1<s.length;i+=2) out.push(parseInt(s.substr(i,2),16)||0);
  return out;
}
function bhex(bytes){ return Array.from(bytes).map(x=>(x&255).toString(16).padStart(2,"0")).join(""); }
function u16be(v){ v=v&0xFFFF; return [(v>>8)&255, v&255]; }
function u32be(v){ v=v>>>0; return [(v>>24)&255,(v>>16)&255,(v>>8)&255,v&255]; }
function sbyte(v){ v=parseInt(v,10)||0; return v<0 ? (256+v) : v; }
function u64beHex(bytes, off){ let s=""; for(let i=0;i<8;i++) s+=(bytes[off+i]&255).toString(16).padStart(2,"0"); return s; }
function lenPrefixed(bytes){ if(bytes.length>255) throw new Error("field must be ≤255 bytes (1-byte length prefix)"); return [bytes.length, ...bytes]; }
function utf8Bytes(s){ return Array.from(new TextEncoder().encode(s||"")); }
function bytesToUtf8(a){ return new TextDecoder().decode(new Uint8Array(a)); }
function bytesToAscii(a){ return a.map(c=>String.fromCharCode(c)).join(""); }

function showResult(el, text, cls){
  if(!el) return;
  el.textContent = text;
  el.className = "result" + (cls ? " "+cls : "");
}
function okOrThrow(f, okSet){
  if(!(okSet||OK_STATUSES).has(f.status)) throw new Error("device status "+stname(f.status));
  return f;
}
function need(){ if(!connected()) throw new Error("Not connected. Press Connect first."); }

/* Wrap a button handler: disable while running, report errors to a result element. */
function wire(id, resultEl, fn){
  const btn = $(id);
  if(!btn) return;
  btn.addEventListener("click", async () => {
    try{
      need();
      btn.disabled = true;
      await fn();
    }catch(e){
      console.error(e);
      showResult(resultEl, "Failed: "+e.message, "err");
      if(!resultEl) alert("Failed: "+e.message);
    }finally{
      // A capability-gated button stays disabled after the click too --
      // see applyCapabilityGating(). Everything else re-enables as before.
      btn.disabled = btn.dataset.capGated === "1";
    }
  });
}
// Grey out (and tooltip-explain) every wire()-registered button whose
// opcode(s) this connected device's firmware doesn't declare support for
// (BUTTON_OPCODES, generated from these same wire() call bodies -- see
// button_capabilities.js). Called after deviceCommands is populated
// (canary.js's fetchDeviceCapabilities), both on direct BLE connect and on
// relay peer join. A button listing more than one opcode (a ternary pick
// between two commands) is left enabled if ANY of them is supported.
function applyCapabilityGating(){
  for(const [id, opNames] of Object.entries(BUTTON_OPCODES)){
    const btn = $(id);
    if(!btn) continue;
    const unsupported = deviceCommands.size>0 && !opNames.some(n => CU[n]!==undefined && deviceCommands.has(CU[n]));
    btn.disabled = unsupported;
    btn.dataset.capGated = unsupported ? "1" : "";
    btn.title = unsupported ? "Not supported by this device's firmware (opcode "+opNames.join(", ")+")" : "";
  }
}
function clearCapabilityGating(){
  for(const id of Object.keys(BUTTON_OPCODES)){
    const btn = $(id);
    if(!btn) continue;
    btn.disabled = false; btn.dataset.capGated = ""; btn.title = "";
  }
}

/* ---------------------------------------------------------------------
 * Tabs
 * ------------------------------------------------------------------- */
// Keep the sticky tab bar/quicknav pinned exactly below <nav>, not a guessed
// pixel offset — nav's rendered height varies with font metrics across
// browsers/zoom levels.
function setNavHeight(){
  const nav = document.querySelector("nav");
  const tabnav = document.querySelector(".tabnav");
  if(nav) document.documentElement.style.setProperty("--nav-h", nav.offsetHeight+"px");
  // Both nav and .tabnav are sticky and stack, so a quicknav jump-link target
  // needs scroll-margin-top covering both or the sticky bars cover it.
  if(nav && tabnav) document.documentElement.style.setProperty("--sticky-h", (nav.offsetHeight+tabnav.offsetHeight+12)+"px");
}
setNavHeight();
window.addEventListener("resize", setNavHeight);

// Build a row of jump-links from the active tab's own <h2> sections, so a
// long tab (Slots, HF14A, DESFire...) doesn't force scrolling past
// everything to find one control. IDs are derived once per h2 from its
// sec-num + heading text so repeat visits land on the same anchor.
function slugify(s){ return s.toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/(^-|-$)/g,""); }
function buildQuickNav(panel){
  const qn = $("quicknav");
  qn.innerHTML = "";
  const h2s = panel.querySelectorAll("h2");
  if(h2s.length < 2) return; // not worth a jump strip for a single-section tab
  h2s.forEach(h2=>{
    const secNum = h2.querySelector(".sec-num");
    const label = (secNum ? secNum.nextSibling && secNum.nextSibling.textContent : "") || h2.textContent;
    const id = "sec-"+slugify((secNum?secNum.textContent:"")+"-"+label);
    h2.id = id;
    const a = document.createElement("a");
    a.className = "qlink"; a.href = "#"+id;
    a.innerHTML = (secNum ? "<span class='sec-num'>"+secNum.textContent+"</span>" : "") + label.trim();
    qn.appendChild(a);
  });
}

document.querySelectorAll(".tabbtn").forEach(btn=>{
  btn.addEventListener("click", ()=>{
    document.querySelectorAll(".tabbtn").forEach(b=>b.classList.remove("active"));
    document.querySelectorAll(".tabpanel").forEach(p=>p.classList.remove("active"));
    btn.classList.add("active");
    const panel = $("tab-"+btn.dataset.tab);
    panel.classList.add("active");
    buildQuickNav(panel);
    setNavHeight(); // quicknav row count (and wrap) changed, so its height did too
  });
});
buildQuickNav($("tab-standalone")); // initial active tab on load
setNavHeight();

/* ---------------------------------------------------------------------
 * Standalone: 7011 GET_AVAILABLE / 7012 GET_RESULT_FOR / 7013 CLEAR_RESULT_FOR
 * ------------------------------------------------------------------- */
async function refreshAvailable(){
  const f = okOrThrow(await request(CU.STANDALONE_GET_AVAILABLE));
  const sel = $("availSel");
  sel.innerHTML = "";
  for(const [id, name] of Object.entries(MODES)){
    const m = Number(id);
    if(m === 0) continue; // "none"
    const avail = f.data[m] === 1;
    const opt = document.createElement("option");
    opt.value = String(m);
    opt.textContent = name + (avail ? "" : " (not built)");
    sel.appendChild(opt);
    // grey out the same mode in the standalone mode-select dropdown
    const mainOpt = document.querySelector('#modeSel option[value="'+m+'"]');
    if(mainOpt) mainOpt.textContent = name + (avail ? "" : " (unavailable)");
  }
  showResult($("availResult"), "Availability refreshed.", "ok");
}
wire("refreshAvail", $("availResult"), refreshAvailable);

wire("fetchFor", $("availResult"), async () => {
  const mode = Number($("availSel").value);
  const raw = [];
  for(let i=0;i<200;i++){
    const f = okOrThrow(await request(CU.STANDALONE_GET_RESULT_FOR, [mode]));
    const chunk = f.data.slice(4);
    if(!chunk.length) break;
    raw.push(...chunk);
  }
  showResult($("availResult"), raw.length
    ? raw.length+" raw byte(s) for "+(MODES[mode]||mode)+":\n"+bhex(raw)
    : "No stored result for "+(MODES[mode]||mode)+".");
});
wire("clearFor", $("availResult"), async () => {
  const mode = Number($("availSel").value);
  okOrThrow(await request(CU.STANDALONE_CLEAR_RESULT_FOR, [mode]));
  showResult($("availResult"), "Cleared stored result for "+(MODES[mode]||mode)+".", "ok");
});
// best-effort on connect; harmless if it fails before the link is up
$("btn").addEventListener("click", () => setTimeout(()=>{ if(connected()) refreshAvailable().catch(()=>{}); }, 800));

/* =======================================================================
 * DEVICE tab
 * ===================================================================== */
const dIdent = $("d_identResult");
wire("d_version", dIdent, async () => {
  const f = okOrThrow(await request(CU.GET_APP_VERSION));
  showResult(dIdent, "App version: "+f.data[0]+"."+f.data[1]);
});
wire("d_git", dIdent, async () => {
  const f = okOrThrow(await request(CU.GET_GIT_VERSION));
  showResult(dIdent, "Git version: "+bytesToUtf8(f.data));
});
wire("d_model", dIdent, async () => {
  const f = okOrThrow(await request(CU.GET_DEVICE_MODEL));
  showResult(dIdent, "Model: "+(f.data[0]===0?"Chameleon Ultra":f.data[0]===1?"Chameleon Lite":"unknown ("+f.data[0]+")"));
});
wire("d_chipid", dIdent, async () => {
  const f = okOrThrow(await request(CU.GET_DEVICE_CHIP_ID));
  showResult(dIdent, "Chip ID: "+bhex(f.data));
});
wire("d_addr", dIdent, async () => {
  const f = okOrThrow(await request(CU.GET_DEVICE_ADDRESS));
  showResult(dIdent, "BLE address: "+bhex(f.data));
});
wire("d_blver", dIdent, async () => {
  // cmd_processor_get_bootloader_version (app_cmd.c) always returns a
  // single big-endian u32 (dfuver_get's bl_v).
  const f = okOrThrow(await request(CU.GET_BOOTLOADER_VERSION));
  const v = ((f.data[0]<<24)|(f.data[1]<<16)|(f.data[2]<<8)|f.data[3])>>>0;
  showResult(dIdent, "Bootloader version: "+v);
});
wire("d_freemem", dIdent, async () => {
  const f = okOrThrow(await request(CU.GET_FREE_MEMORY));
  const free=(f.data[0]<<24|f.data[1]<<16|f.data[2]<<8|f.data[3])>>>0;
  const total=(f.data[4]<<24|f.data[5]<<16|f.data[6]<<8|f.data[7])>>>0;
  showResult(dIdent, "Free memory: "+free+" / "+total+" bytes");
});
wire("d_battery", dIdent, async () => {
  const f = okOrThrow(await request(CU.GET_BATTERY_INFO));
  const mv=(f.data[0]<<8)|f.data[1], pct=f.data[2];
  showResult(dIdent, "Battery: "+mv+" mV · "+pct+"%");
});
wire("d_mode", dIdent, async () => {
  const f = okOrThrow(await request(CU.GET_DEVICE_MODE));
  showResult(dIdent, "Current mode: "+(f.data[0] ? "Reader" : "Tag (emulate)"));
});
wire("d_caps", dIdent, async () => {
  const f = okOrThrow(await request(CU.GET_DEVICE_CAPABILITIES));
  const ids=[];
  for(let i=0;i+1<f.data.length;i+=2) ids.push((f.data[i]<<8)|f.data[i+1]);
  showResult(dIdent, ids.length+" command(s) supported:\n"+ids.join(", "));
});
wire("d_settings", dIdent, async () => {
  // DATA_CMD_GET_DEVICE_SETTINGS: version(1) animation(1) btnA_short(1) btnB_short(1)
  // btnA_long(1) btnB_long(1) ble_pairing_enable(1) ble_key[6] — cmd_processor_get_device_settings, app_cmd.c.
  const f = okOrThrow(await request(CU.GET_DEVICE_SETTINGS));
  const d = f.data;
  const anim = {0:"Full",1:"Minimal",2:"None"}[d[1]] ?? d[1];
  showResult(dIdent,
    "Settings version: "+d[0]+"\n"+
    "Animation mode: "+anim+"\n"+
    "Button A short press: "+(BUTTON_FN_NAMES[d[2]]||d[2])+"\n"+
    "Button B short press: "+(BUTTON_FN_NAMES[d[3]]||d[3])+"\n"+
    "Button A long press: "+(BUTTON_FN_NAMES[d[4]]||d[4])+"\n"+
    "Button B long press: "+(BUTTON_FN_NAMES[d[5]]||d[5])+"\n"+
    "BLE pairing required: "+(d[6] ? "yes" : "no")+"\n"+
    "BLE pairing key: "+bytesToAscii(d.slice(7,13)));
});

wire("d_setmode", $("d_modeResult"), async () => {
  const mode = Number($("d_modeSel").value);
  const f = okOrThrow(await request(CU.CHANGE_DEVICE_MODE, [mode]));
  showResult($("d_modeResult"), "Device mode changed.", "ok");
});

const dBle = $("d_bleResult");
wire("d_getname", dBle, async () => {
  const f = okOrThrow(await request(CU.GET_BLE_NAME));
  const name = bytesToUtf8(f.data).replace(/\0+$/,"");
  showResult(dBle, "BLE name: "+(name || "(firmware default)"));
});
wire("d_setname", dBle, async () => {
  const name = $("d_newname").value;
  const data = utf8Bytes(name);
  if(data.length>20) throw new Error("name must be ≤20 bytes utf-8");
  okOrThrow(await request(CU.SET_BLE_NAME, data));
  showResult(dBle, "BLE name set"+(name?"":" to firmware default")+". Reconnect to see the new advertised name.", "ok");
});
wire("d_getpair", dBle, async () => {
  const f = okOrThrow(await request(CU.GET_BLE_PAIRING_KEY));
  showResult(dBle, "Pairing key: "+bytesToAscii(f.data));
});
wire("d_setpair", dBle, async () => {
  const key = $("d_newpair").value.trim();
  if(key.length !== 6) throw new Error("pairing key must be exactly 6 digits/chars");
  okOrThrow(await request(CU.SET_BLE_PAIRING_KEY, utf8Bytes(key)));
  showResult(dBle, "Pairing key set.", "ok");
});
wire("d_delbonds", dBle, async () => {
  if(!confirm("Delete all BLE bonds on the device? You'll need to re-pair afterward.")) return;
  okOrThrow(await request(CU.DELETE_ALL_BLE_BONDS));
  showResult(dBle, "All BLE bonds deleted.", "ok");
});

const dBeh = $("d_behResult");
wire("d_getanim", dBeh, async () => {
  const f = okOrThrow(await request(CU.GET_ANIMATION_MODE));
  $("d_animSel").value = String(f.data[0]);
  showResult(dBeh, "Animation mode: "+f.data[0]);
});
wire("d_setanim", dBeh, async () => {
  okOrThrow(await request(CU.SET_ANIMATION_MODE, [Number($("d_animSel").value)]));
  showResult(dBeh, "Animation mode set.", "ok");
});
wire("d_getsleep", dBeh, async () => {
  const f = okOrThrow(await request(CU.GET_SLEEP_TIMEOUT));
  $("d_sleep").value = String(f.data[0]);
  showResult(dBeh, "Sleep timeout: "+f.data[0]+" s");
});
wire("d_setsleep", dBeh, async () => {
  okOrThrow(await request(CU.SET_SLEEP_TIMEOUT, [Number($("d_sleep").value)&0xFF]));
  showResult(dBeh, "Sleep timeout set.", "ok");
});

const BUTTON_FN_NAMES = {0:"Disabled",1:"Cycle slot +",2:"Cycle slot -",3:"Clone IC UID",4:"Show battery",5:"NFC field generator",6:"Disarm standalone mode"};
wire("d_getbtn", $("d_btnResult"), async () => {
  const type = $("d_btnSel").value.charCodeAt(0); // 'A' or 'B'
  const isLong = $("d_btnPress").value === "long";
  const f = okOrThrow(await request(isLong ? CU.GET_LONG_BUTTON_PRESS_CONFIG : CU.GET_BUTTON_PRESS_CONFIG, [type]));
  $("d_btnFn").value = String(f.data[0]);
  showResult($("d_btnResult"), "Button "+$("d_btnSel").value+" ("+$("d_btnPress").value+" press): "+(BUTTON_FN_NAMES[f.data[0]]||f.data[0]));
});
wire("d_setbtn", $("d_btnResult"), async () => {
  const type = $("d_btnSel").value.charCodeAt(0);
  const fn = Number($("d_btnFn").value);
  const isLong = $("d_btnPress").value === "long";
  okOrThrow(await request(isLong ? CU.SET_LONG_BUTTON_PRESS_CONFIG : CU.SET_BUTTON_PRESS_CONFIG, [type, fn]));
  showResult($("d_btnResult"), "Button "+$("d_btnSel").value+" ("+$("d_btnPress").value+" press) set to: "+BUTTON_FN_NAMES[fn], "ok");
});
wire("d_getpairreq", $("d_btnResult"), async () => {
  const f = okOrThrow(await request(CU.GET_BLE_PAIRING_ENABLE));
  $("d_pairreq").value = String(f.data[0]);
  showResult($("d_btnResult"), "BLE pairing: "+(f.data[0] ? "required" : "not required"));
});
wire("d_setpairreq", $("d_btnResult"), async () => {
  okOrThrow(await request(CU.SET_BLE_PAIRING_ENABLE, [Number($("d_pairreq").value)]));
  showResult($("d_btnResult"), "BLE pairing requirement updated.", "ok");
});

// Persistent debug log (DATA_CMD_LOG_*, cmd_processor_log_* in app_cmd.c).
const LOG_LEVEL_NAMES = {0:"Off",1:"Error",2:"Warning",3:"Info",4:"Debug"};
wire("d_logstatus", $("d_logResult"), async () => {
  // cmd_processor_log_get_status reply: level(1) failed(1) pages(1) reserved(1)
  // stored(4,BE) pending(4,BE) dropped(4,BE) boots(4,BE) err(4,BE) = 20 bytes.
  const f = okOrThrow(await request(CU.LOG_GET_STATUS));
  const d = f.data;
  const u32 = o => (d[o]<<24 | d[o+1]<<16 | d[o+2]<<8 | d[o+3]) >>> 0;
  $("d_loglevel").value = String(d[0]);
  showResult($("d_logResult"),
    "Level: "+(LOG_LEVEL_NAMES[d[0]]||d[0])+"\n"+
    "Flash write failed: "+(d[1] ? "yes" : "no")+"\n"+
    "Ring pages: "+d[2]+"\n"+
    "Bytes stored: "+u32(4)+"\n"+
    "Bytes pending flush: "+u32(8)+"\n"+
    "Dropped (ring overrun): "+u32(12)+"\n"+
    "Boot count: "+u32(16)+"\n"+
    "Error count: "+u32(20));
});
wire("d_logsetlevel", $("d_logResult"), async () => {
  okOrThrow(await request(CU.LOG_SET_LEVEL, [Number($("d_loglevel").value)]));
  showResult($("d_logResult"), "Log level set to "+LOG_LEVEL_NAMES[Number($("d_loglevel").value)]+".", "ok");
});
wire("d_logclear", $("d_logResult"), async () => {
  if(!confirm("Clear the persistent debug log?")) return;
  okOrThrow(await request(CU.LOG_CLEAR));
  $("d_logText").style.display = "none"; $("d_logText").textContent = "";
  showResult($("d_logResult"), "Log cleared.", "ok");
});
wire("d_logdump", $("d_logResult"), async () => {
  // LOG_READ in: offset(4,BE) len(2,BE); out: raw text slice, n<chunk means EOF.
  const CHUNK = 512;
  let offset = 0, text = "", guard = 0;
  while(guard++ < 2000){
    const f = okOrThrow(await request(CU.LOG_READ, [...u32be(offset), ...u16be(CHUNK)]));
    if(f.data.length === 0) break;
    text += bytesToUtf8(f.data);
    offset += f.data.length;
    if(f.data.length < CHUNK) break;
  }
  const el = $("d_logText");
  el.textContent = text || "(empty)";
  el.style.display = "block";
  showResult($("d_logResult"), "Fetched "+offset+" byte(s) of log text.", "ok");
});

// Flash diagnostics: BL_INFO (cmd_processor_bl_info) and FDS_LIST/FDS_READ
// (cmd_processor_fds_list/fds_read), all in app_cmd.c. BL_INFO's 31 leading
// words + CRC32 tail are the MCU's own native (little-endian) byte order —
// unlike the log-status struct, nothing here calls U32HTONL. Only the
// embedded 64-byte bootloader block (bl_info.h) is documented as LE too, so
// the whole payload is consistently little-endian.
function u32le(b,o){ return ((b[o] | b[o+1]<<8 | b[o+2]<<16 | b[o+3]<<24) >>> 0); }
// Named rdU16le, not u16le: canary.js already defines a u16le(arr,val) that
// APPENDS little-endian bytes to an array — same global scope, different
// job. A same-named `function` here would be a SyntaxError (duplicate
// declaration), not a silent shadow, and kills the whole script's load.
function rdU16le(b,o){ return (b[o] | b[o+1]<<8); }
const BL_FEAT_NAMES = [[1,"UF2"],[2,"CDC-DFU"],[4,"RAW_APP"]];
wire("d_blinfo", $("d_fdsResult"), async () => {
  const f = okOrThrow(await request(CU.BL_INFO));
  const d = f.data;
  if(d.length < 124+64+4) throw new Error("short BL_INFO reply ("+d.length+" bytes)");
  let lines = [];
  lines.push("NRFFW[0]: 0x"+u32le(d,0).toString(16).padStart(8,"0"));
  lines.push("NRFFW[1]: 0x"+u32le(d,4).toString(16).padStart(8,"0"));
  lines.push("Word @0xFF8: 0x"+u32le(d,8).toString(16).padStart(8,"0"));
  lines.push("Word @0xFFC: 0x"+u32le(d,12).toString(16).padStart(8,"0"));
  lines.push("REGOUT0: 0x"+u32le(d,16).toString(16).padStart(8,"0"));
  lines.push("Vector @0xF3000: 0x"+u32le(d,20).toString(16).padStart(8,"0"));
  lines.push("Vector @0xF3004: 0x"+u32le(d,24).toString(16).padStart(8,"0"));
  lines.push("");
  lines.push("ACL regions:");
  for(let i=0;i<8;i++){
    const o = 28 + i*12;
    const addr=u32le(d,o), size=u32le(d,o+4), perm=u32le(d,o+8);
    if(addr===0 && size===0 && perm===0) continue;
    lines.push("  ["+i+"] addr=0x"+addr.toString(16).padStart(8,"0")+" size=0x"+size.toString(16)+" perm=0x"+perm.toString(16));
  }
  // bl_info_t at offset 124: magic(4) layout(2) size(2) version(4) features(4) gcc[4] rev[24] reserved[20]
  const bo = 124;
  const magic = u32le(d,bo);
  lines.push("");
  lines.push("Bootloader info block:");
  lines.push("  magic: 0x"+magic.toString(16)+(magic===0x4E494C42?" (\"BLIN\", valid)":" (unexpected)"));
  lines.push("  layout: "+rdU16le(d,bo+4));
  lines.push("  size: "+rdU16le(d,bo+6));
  lines.push("  version: "+u32le(d,bo+8));
  const feat = u32le(d,bo+12);
  const featNames = BL_FEAT_NAMES.filter(([bit])=>feat&bit).map(([,n])=>n);
  lines.push("  features: 0x"+feat.toString(16)+" ("+(featNames.join(", ")||"none")+")");
  lines.push("  gcc: "+d[bo+16]+"."+d[bo+17]+"."+d[bo+18]);
  const rev = bytesToUtf8(Array.from(d.slice(bo+20,bo+44)).filter(b=>b!==0));
  lines.push("  git rev: "+(rev||"(none)"));
  lines.push("");
  lines.push("Bootloader region CRC32: 0x"+u32le(d,188).toString(16).padStart(8,"0"));
  showResult($("d_fdsResult"), lines.join("\n"));
});
wire("d_fdslist", $("d_fdsResult"), async () => {
  const f = okOrThrow(await request(CU.FDS_LIST));
  const rows = [];
  for(let i=0;i+5<f.data.length;i+=6){
    const fileId = (f.data[i]<<8)|f.data[i+1];
    const key = (f.data[i+2]<<8)|f.data[i+3];
    const len = (f.data[i+4]<<8)|f.data[i+5];
    rows.push({fileId,key,len});
  }
  const el = $("d_fdsResult");
  el.className = "result";
  if(rows.length===0){ el.textContent = "No (unprotected) FDS records found."; return; }
  const t=document.createElement("table"); t.className="tbl";
  t.innerHTML="<tr><th>File ID</th><th>Key</th><th>Length (bytes)</th></tr>"+
    rows.map(r=>`<tr><td>0x${r.fileId.toString(16).padStart(4,"0")}</td><td>0x${r.key.toString(16).padStart(4,"0")}</td><td>${r.len}</td></tr>`).join("");
  el.textContent = "";
  el.appendChild(document.createTextNode(rows.length+" record(s):"));
  el.appendChild(t);
});
wire("d_fdsread", $("d_fdsResult"), async () => {
  const fileId = hexBytes($("d_fdsfile").value, 2);
  const key = hexBytes($("d_fdskey").value, 2);
  const CHUNK = 240;
  let offset = 0, bytes = [], guard = 0;
  while(guard++ < 64){
    const f = await request(CU.FDS_READ, [...fileId, ...key, ...u16be(offset), ...u16be(CHUNK)]);
    if(!OK_STATUSES.has(f.status)){
      if(offset===0) throw new Error("device status "+stname(f.status)+" (record missing or protected)");
      break;
    }
    if(f.data.length === 0) break;
    bytes.push(...f.data);
    offset += f.data.length;
    if(f.data.length < CHUNK) break;
  }
  const el = $("d_fdsHex");
  if(bytes.length === 0){
    el.style.display = "none";
    showResult($("d_fdsResult"), "Record empty or not found.", "err");
    return;
  }
  const lineLen = 16;
  let out = "";
  for(let i=0;i<bytes.length;i+=lineLen){
    const chunk = bytes.slice(i,i+lineLen);
    out += i.toString(16).padStart(6,"0")+"  "+
      chunk.map(b=>b.toString(16).padStart(2,"0")).join(" ").padEnd(lineLen*3-1)+"  "+
      chunk.map(b=>(b>=32&&b<127)?String.fromCharCode(b):".").join("")+"\n";
  }
  el.textContent = out;
  el.style.display = "block";
  showResult($("d_fdsResult"), "Record: "+bytes.length+" byte(s).", "ok");
});

const dPwr = $("d_pwrResult");
wire("d_save", dPwr, async () => { okOrThrow(await request(CU.SAVE_SETTINGS)); showResult(dPwr,"Settings saved to flash.","ok"); });
wire("d_resetset", dPwr, async () => {
  if(!confirm("Reset all settings to firmware defaults?")) return;
  okOrThrow(await request(CU.RESET_SETTINGS)); showResult(dPwr,"Settings reset.","ok");
});
wire("d_wipe", dPwr, async () => {
  if(!confirm("Factory wipe (WIPE_FDS)? This erases slots, settings and standalone data, and the device will reboot and drop this connection.")) return;
  try{ await request(CU.WIPE_FDS); }catch(e){ /* device closes the link as part of the wipe */ }
  showResult(dPwr,"Wipe requested — device is rebooting; reconnect once it's back.","ok");
});
wire("d_resetdev", dPwr, async () => {
  if(!confirm("Reboot the device now? This drops the BLE connection.")) return;
  try{ await request(CU.RESET_DEVICE); }catch(e){}
  showResult(dPwr,"Reboot requested — reconnect once it's back.","ok");
});
wire("d_bootloader", dPwr, async () => {
  if(!confirm("Enter DFU bootloader mode? This drops the BLE connection; you'll need a DFU tool to get back to the application.")) return;
  try{ await request(CU.ENTER_BOOTLOADER); }catch(e){}
  showResult(dPwr,"Bootloader entry requested.","ok");
});

/* =======================================================================
 * SLOTS tab
 * ===================================================================== */
function sensePick(n){ return n===2 ? "HF" : n===1 ? "LF" : "?"; }

wire("s_info", null, async () => {
  const f = okOrThrow(await request(CU.GET_SLOT_INFO));
  const rows=[];
  for(let i=0;i<8 && i*4+3<f.data.length;i++){
    const o=i*4;
    rows.push({slot:i+1, hf:(f.data[o]<<8)|f.data[o+1], lf:(f.data[o+2]<<8)|f.data[o+3]});
  }
  renderSlotTable(rows);
});
wire("s_enabled", null, async () => {
  const f = okOrThrow(await request(CU.GET_ENABLED_SLOTS));
  const rows=[];
  for(let i=0;i<8 && i*2+1<f.data.length;i++) rows.push({slot:i+1, hfEn:f.data[i*2], lfEn:f.data[i*2+1]});
  const el = $("s_table"); el.innerHTML="";
  const t=document.createElement("table"); t.className="tbl";
  t.innerHTML="<tr><th>Slot</th><th>HF enabled</th><th>LF enabled</th></tr>"+
    rows.map(r=>`<tr><td>${r.slot}</td><td>${r.hfEn?"yes":"no"}</td><td>${r.lfEn?"yes":"no"}</td></tr>`).join("");
  el.appendChild(t);
});
wire("s_nicks", null, async () => {
  const f = okOrThrow(await request(CU.GET_ALL_SLOT_NICKS));
  const rows=[]; let i=0, slot=0;
  while(i<f.data.length && slot<8){
    let hfName="", lfName="";
    if(i<f.data.length){ const n=f.data[i]; i++; if(n>0 && i+n<=f.data.length){ hfName=bytesToUtf8(f.data.slice(i,i+n)); i+=n; } }
    if(i<f.data.length){ const n=f.data[i]; i++; if(n>0 && i+n<=f.data.length){ lfName=bytesToUtf8(f.data.slice(i,i+n)); i+=n; } }
    rows.push({slot:slot+1, hf:hfName, lf:lfName}); slot++;
  }
  const el = $("s_table"); el.innerHTML="";
  const t=document.createElement("table"); t.className="tbl";
  t.innerHTML="<tr><th>Slot</th><th>HF nick</th><th>LF nick</th></tr>"+
    rows.map(r=>`<tr><td>${r.slot}</td><td>${r.hf||"—"}</td><td>${r.lf||"—"}</td></tr>`).join("");
  el.appendChild(t);
});
wire("s_active", null, async () => {
  const f = okOrThrow(await request(CU.GET_ACTIVE_SLOT));
  const el = $("s_table"); el.innerHTML = "";
  const d = document.createElement("div"); d.className="det"; d.textContent = "Active slot: "+(f.data[0]+1);
  el.appendChild(d);
});
function renderSlotTable(rows){
  const el = $("s_table"); el.innerHTML="";
  const t=document.createElement("table"); t.className="tbl";
  t.innerHTML="<tr><th>Slot</th><th>HF type</th><th>LF type</th></tr>"+
    rows.map(r=>`<tr><td>${r.slot}</td><td>${tagTypeName(r.hf)}</td><td>${tagTypeName(r.lf)}</td></tr>`).join("");
  el.appendChild(t);
}

wire("s_setactivebtn", $("s_activeResult"), async () => {
  const slot = Number($("s_setactive").value);
  if(slot<1||slot>8) throw new Error("slot must be 1-8");
  okOrThrow(await request(CU.SET_ACTIVE_SLOT, [slot-1]));
  showResult($("s_activeResult"), "Active slot set to "+slot+".", "ok");
});

const sType = $("s_typeResult");
function slotArgs(){
  const slot = Number($("s_slot").value); if(slot<1||slot>8) throw new Error("slot must be 1-8");
  const sense = Number($("s_sense").value);
  return {slot, sense};
}
wire("s_settype", sType, async () => {
  const {slot} = slotArgs();
  const tagtype = Number($("s_tagtype").value);
  okOrThrow(await request(CU.SET_SLOT_TAG_TYPE, [slot-1, ...u16be(tagtype)]));
  showResult(sType, "Slot "+slot+" tag type set to "+tagtype+" (not written to flash until you save).", "ok");
});
wire("s_setdefault", sType, async () => {
  const {slot} = slotArgs();
  const tagtype = Number($("s_tagtype").value);
  okOrThrow(await request(CU.SET_SLOT_DATA_DEFAULT, [slot-1, ...u16be(tagtype)]));
  showResult(sType, "Slot "+slot+" data reset to default for type "+tagtype+" (written to flash).", "ok");
});
wire("s_setenable", sType, async () => {
  const {slot, sense} = slotArgs();
  const en = Number($("s_enflag").value);
  okOrThrow(await request(CU.SET_SLOT_ENABLE, [slot-1, sense, en]));
  showResult(sType, "Slot "+slot+" "+sensePick(sense)+" "+(en?"enabled":"disabled")+".", "ok");
});
wire("s_savecfg", sType, async () => {
  okOrThrow(await request(CU.SLOT_DATA_CONFIG_SAVE));
  showResult(sType, "Slot config + data saved to flash.", "ok");
});
wire("s_delsense", sType, async () => {
  const {slot, sense} = slotArgs();
  if(!confirm("Delete the "+sensePick(sense)+" tag data in slot "+slot+"? This can't be undone.")) return;
  okOrThrow(await request(CU.DELETE_SLOT_SENSE_TYPE, [slot-1, sense]));
  showResult(sType, "Slot "+slot+" "+sensePick(sense)+" data deleted.", "ok");
});

const sName = $("s_nameResult");
function nickArgs(){
  const slot = Number($("s_nslot").value); if(slot<1||slot>8) throw new Error("slot must be 1-8");
  const sense = Number($("s_nsense").value);
  return {slot, sense};
}
wire("s_getname", sName, async () => {
  const {slot, sense} = nickArgs();
  const f = okOrThrow(await request(CU.GET_SLOT_TAG_NICK, [slot-1, sense]));
  showResult(sName, "Nick: "+(bytesToUtf8(f.data) || "(none)"));
});
wire("s_setname", sName, async () => {
  const {slot, sense} = nickArgs();
  const data = utf8Bytes($("s_nname").value);
  if(data.length>32) throw new Error("nickname must be ≤32 bytes utf-8");
  okOrThrow(await request(CU.SET_SLOT_TAG_NICK, [slot-1, sense, ...data]));
  showResult(sName, "Nickname set.", "ok");
});
wire("s_delname", sName, async () => {
  const {slot, sense} = nickArgs();
  okOrThrow(await request(CU.DELETE_SLOT_TAG_NICK, [slot-1, sense]));
  showResult(sName, "Nickname deleted.", "ok");
});

/* =======================================================================
 * HF14A / MF1 tab
 * ===================================================================== */
function parseHf14aScan(data){
  const out=[]; let o=0;
  while(o<data.length){
    const uidlen=data[o]; o++;
    const uid=data.slice(o,o+uidlen); o+=uidlen;
    const atqa=data.slice(o,o+2); o+=2;
    const sak=data[o]; o++;
    const atslen=data[o]; o++;
    const ats=data.slice(o,o+atslen); o+=atslen;
    out.push({uid:bhex(uid), atqa:bhex(atqa), sak:bhex([sak]), ats:bhex(ats)});
  }
  return out;
}
function fmtTags(tags){
  if(!tags.length) return "No tag found.";
  return tags.map(t=>"uid "+t.uid+" · atqa "+t.atqa+" · sak "+t.sak+(t.ats?" · ats "+t.ats:"")).join("\n");
}

const hScan = $("h_scanResult");
wire("h_scan", hScan, async () => {
  const f = await request(CU.HF14A_SCAN);
  if(f.status !== 0x00){ showResult(hScan, "No tag: "+stname(f.status)); return; }
  showResult(hScan, fmtTags(parseHf14aScan(f.data)), "ok");
});
wire("h_scankeep", hScan, async () => {
  const f = await request(CU.HF14A_SCAN_KEEP);
  if(f.status !== 0x00){ showResult(hScan, "No tag: "+stname(f.status)); return; }
  showResult(hScan, fmtTags(parseHf14aScan(f.data))+"\n(field kept on)", "ok");
});
wire("h_fieldon", hScan, async () => { okOrThrow(await request(CU.HF14A_SET_FIELD_ON)); showResult(hScan,"Field on.","ok"); });
wire("h_fieldoff", hScan, async () => { okOrThrow(await request(CU.HF14A_SET_FIELD_OFF)); showResult(hScan,"Field off.","ok"); });
wire("h_support", hScan, async () => {
  const f = await request(CU.MF1_DETECT_SUPPORT);
  showResult(hScan, f.status===0x00 ? "MIFARE Classic: yes" : "MIFARE Classic: no ("+stname(f.status)+")");
});
wire("h_prng", hScan, async () => {
  const f = okOrThrow(await request(CU.MF1_DETECT_PRNG));
  showResult(hScan, "PRNG: "+["static","weak (vulnerable)","hard"][f.data[0]]+" ("+f.data[0]+")");
});

const hCfg = $("h_cfgResult");
wire("h_getcfg", hCfg, async () => {
  const f = okOrThrow(await request(CU.HF14A_GET_CONFIG));
  const sv = b => b>127 ? b-256 : b;
  const [bcc,cl2,cl3,rats] = f.data.map(sv);
  $("h_bcc").value=bcc; $("h_cl2").value=cl2; $("h_cl3").value=cl3; $("h_rats").value=rats;
  showResult(hCfg, `bcc=${bcc} cl2=${cl2} cl3=${cl3} rats=${rats}`, "ok");
});
wire("h_setcfg", hCfg, async () => {
  const data=[sbyte($("h_bcc").value), sbyte($("h_cl2").value), sbyte($("h_cl3").value), sbyte($("h_rats").value)];
  okOrThrow(await request(CU.HF14A_SET_CONFIG, data));
  showResult(hCfg, "Config set.", "ok");
});

const hRw = $("h_rwResult");
function mf1Args(blockEl, keytypeEl, keyEl){
  const block = Number($(blockEl).value);
  const keytype = parseInt($(keytypeEl).value, 16);
  const key = hexBytes($(keyEl).value, 6);
  if(key.length!==6) throw new Error("key must be 12 hex chars (6 bytes)");
  return {block, keytype, key};
}
wire("h_auth", hRw, async () => {
  const {block,keytype,key} = mf1Args("h_block","h_keytype","h_key");
  const f = await request(CU.MF1_AUTH_ONE_KEY_BLOCK, [keytype, block, ...key]);
  showResult(hRw, f.status===0x00 ? "Auth OK." : "Auth failed: "+stname(f.status), f.status===0x00?"ok":"err");
});
wire("h_read", hRw, async () => {
  const {block,keytype,key} = mf1Args("h_block","h_keytype","h_key");
  const f = okOrThrow(await request(CU.MF1_READ_ONE_BLOCK, [keytype, block, ...key]));
  showResult(hRw, "Block "+block+": "+bhex(f.data), "ok");
});
wire("h_write", hRw, async () => {
  const {block,keytype,key} = mf1Args("h_block","h_keytype","h_key");
  const wdata = hexBytes($("h_wdata").value, 16);
  if(wdata.length!==16) throw new Error("write data must be 32 hex chars (16 bytes)");
  okOrThrow(await request(CU.MF1_WRITE_ONE_BLOCK, [keytype, block, ...key, ...wdata]));
  showResult(hRw, "Block "+block+" written.", "ok");
});

const hCk = $("h_ckResult");
function parseKeyList(){
  const lines = $("h_ckkeys").value.split(/\r?\n/).map(l=>l.trim()).filter(Boolean);
  if(lines.length<1 || lines.length>83) throw new Error("need 1-83 keys");
  return lines.map(l=>{
    const k = hexBytes(l,6);
    if(k.length!==6) throw new Error("bad key: "+l+" (need 12 hex chars)");
    return k;
  });
}
wire("h_ckonblock", hCk, async () => {
  const block = Number($("h_ckblock").value);
  const keytype = parseInt($("h_ckkeytype").value,16);
  const keys = parseKeyList();
  const payload = [block, keytype, keys.length, ...keys.flat()];
  const f = await request(CU.MF1_CHECK_KEYS_ON_BLOCK, payload);
  if(f.status===0x00 && f.data.length===7 && f.data[0]){
    showResult(hCk, "Found: "+bhex(f.data.slice(1)), "ok");
  } else {
    showResult(hCk, "No match ("+stname(f.status)+").");
  }
});
wire("h_ckofsectors", hCk, async () => {
  const sectors = Math.max(1, Math.min(40, Number($("h_cksectors").value)||16));
  const keys = parseKeyList();
  // Mask bit semantics (mf1_toolbox_check_keys_of_sectors in firmware): a SET
  // bit SKIPS that sector/key, a CLEAR bit means check it. So to check only
  // the first N sectors, leave their bits 0 and set the bits for every
  // sector beyond that (both key A and key B) to skip them.
  const mask = [0,0,0,0,0,0,0,0,0,0];
  for(let s=sectors;s<40;s++){
    for(const bit of [s*2, s*2+1]){
      mask[bit>>3] |= (0x80 >> (bit & 7));
    }
  }
  const payload = [...mask, ...keys.flat()];
  const f = await request(CU.MF1_CHECK_KEYS_OF_SECTORS, payload);
  if(f.data.length===490){
    const found = f.data.slice(0,10);
    const rows=[];
    for(let bit=0; bit<80; bit++){
      if(found[bit>>3] & (0x80 >> (bit&7))){
        const sector = bit>>1, kt = bit&1 ? "B" : "A";
        rows.push("sector "+sector+" key"+kt+": "+bhex(f.data.slice(10+6*bit,16+6*bit)));
      }
    }
    showResult(hCk, rows.length ? rows.join("\n") : "No keys found.", "ok");
  } else {
    showResult(hCk, "Status: "+stname(f.status));
  }
});

wire("h_authtrace", $("h_atOut"), async () => {
  const block = Number($("h_atblock").value);
  const keytype = parseInt($("h_atkeytype").value,16);
  const key = hexBytes($("h_atkey").value,6);
  const timeout = Math.max(1, Math.min(30000, Number($("h_attimeout").value)||5000));
  const payload = [keytype, block, ...key, ...u16be(timeout)];
  const f = await request(CU.HF14A_AUTH_TRACE, payload);
  const out = $("h_atOut");
  if(f.status!==0x00){ out.innerHTML = '<div class="result err">No trace: '+stname(f.status)+"</div>"; return; }
  const fr = parseFrames(f.data);
  const ns = extractNonces(fr);
  let html = '<div class="det">'+fr.length+" frames.</div>";
  for(const n of ns){
    html += '<div class="nonce">Classic auth key'+n.key+' block '+n.block+' · uid '+n.uid+' · nt '+n.nt+' · nr '+n.nr+' · ar '+n.ar+(n.at?' · at '+n.at:'')+'</div>';
  }
  html += '<details><summary>Frames</summary><pre>'+fr.map((f2,i)=>String(i).padStart(3)+"  "+(f2.tx?"card→rdr":"rdr→card")+"  "+String(f2.bits).padStart(4)+"b  "+hex(f2.data).padEnd(40)+"  "+frameLabel(f2,fr[i-1])).join("\n")+'</pre></details>';
  out.innerHTML = html;
});

const hE = $("h_eResult");
wire("h_eread", hE, async () => {
  const start = Number($("h_eblock").value), count = Number($("h_ecount").value);
  const f = okOrThrow(await request(CU.MF1_READ_EMU_BLOCK_DATA, [start, count]));
  const rows=[];
  for(let i=0;i*16<f.data.length;i++) rows.push("block "+(start+i)+": "+bhex(f.data.slice(i*16,i*16+16)));
  showResult(hE, rows.join("\n"), "ok");
  $("h_edata").value = bhex(f.data);
});
wire("h_ewrite", hE, async () => {
  const start = Number($("h_eblock").value);
  const data = hexBytes($("h_edata").value);
  if(data.length===0 || data.length%16!==0) throw new Error("data must be a non-empty multiple of 16 bytes (32 hex chars)");
  okOrThrow(await request(CU.MF1_WRITE_EMU_BLOCK_DATA, [start, ...data]));
  showResult(hE, "Wrote "+(data.length/16)+" block(s) starting at "+start+".", "ok");
});

const hA = $("h_aResult");
wire("h_aget", hA, async () => {
  const f = okOrThrow(await request(CU.HF14A_GET_ANTI_COLL_DATA));
  if(!f.data.length){ showResult(hA, "No anti-collision data set."); return; }
  let o=0; const uidlen=f.data[o]; o++;
  const uid=f.data.slice(o,o+uidlen); o+=uidlen;
  const atqa=f.data.slice(o,o+2); o+=2;
  const sak=f.data[o]; o++;
  const atslen=f.data[o]; o++;
  const ats=f.data.slice(o,o+atslen);
  $("h_auid").value=bhex(uid); $("h_aatqa").value=bhex(atqa); $("h_asak").value=bhex([sak]); $("h_aats").value=bhex(ats);
  showResult(hA, "uid "+bhex(uid)+" · atqa "+bhex(atqa)+" · sak "+bhex([sak])+(ats.length?" · ats "+bhex(ats):""), "ok");
});
wire("h_aset", hA, async () => {
  const uid = hexBytes($("h_auid").value);
  const atqa = hexBytes($("h_aatqa").value,2);
  const sak = hexBytes($("h_asak").value,1);
  const ats = hexBytes($("h_aats").value);
  if(![4,7,10].includes(uid.length)) throw new Error("uid must be 4, 7 or 10 bytes");
  const payload = [uid.length, ...uid, ...atqa, ...sak, ats.length, ...ats];
  okOrThrow(await request(CU.HF14A_SET_ANTI_COLL_DATA, payload));
  showResult(hA, "Anti-collision data set.", "ok");
});

const hEmu = $("h_emuResult");
wire("h_getemu", hEmu, async () => {
  const f = okOrThrow(await request(CU.MF1_GET_EMULATOR_CONFIG));
  const [det,gen1a,gen2,bacm,wmode] = f.data;
  $("h_gen1a").value=gen1a?"1":"0"; $("h_gen2").value=gen2?"1":"0";
  $("h_bacm").value=bacm?"1":"0"; $("h_wmode").value=String(wmode); $("h_detect").value=det?"1":"0";
  showResult(hEmu, `detection=${!!det} gen1a=${!!gen1a} gen2=${!!gen2} block0AntiColl=${!!bacm} writeMode=${wmode}`, "ok");
});
wire("h_setgen1a", hEmu, async () => { okOrThrow(await request(CU.MF1_SET_GEN1A_MODE,[Number($("h_gen1a").value)])); showResult(hEmu,"Gen1a mode set.","ok"); });
wire("h_setgen2", hEmu, async () => { okOrThrow(await request(CU.MF1_SET_GEN2_MODE,[Number($("h_gen2").value)])); showResult(hEmu,"Gen2 mode set.","ok"); });
wire("h_setbacm", hEmu, async () => { okOrThrow(await request(CU.MF1_SET_BLOCK_ANTI_COLL_MODE,[Number($("h_bacm").value)])); showResult(hEmu,"Block0 anti-coll mode set.","ok"); });
wire("h_setwmode", hEmu, async () => { okOrThrow(await request(CU.MF1_SET_WRITE_MODE,[Number($("h_wmode").value)])); showResult(hEmu,"Write mode set.","ok"); });
wire("h_getprngtype", hEmu, async () => { const f=okOrThrow(await request(CU.MF1_GET_PRNG_TYPE)); $("h_prngtype").value=String(f.data[0]); showResult(hEmu,"PRNG type: "+f.data[0],"ok"); });
wire("h_setprngtype", hEmu, async () => { okOrThrow(await request(CU.MF1_SET_PRNG_TYPE,[Number($("h_prngtype").value)])); showResult(hEmu,"PRNG type set.","ok"); });
wire("h_setdetect", hEmu, async () => { okOrThrow(await request(CU.MF1_SET_DETECTION_ENABLE,[Number($("h_detect").value)])); showResult(hEmu,"Detection logging set.","ok"); });
wire("h_getfor", hEmu, async () => {
  const f = okOrThrow(await request(CU.MF1_GET_FIELD_OFF_DO_RESET));
  $("h_for").value = f.data[0] ? "1" : "0";
  showResult(hEmu, "Field-off resets card state: "+(!!f.data[0]), "ok");
});
wire("h_setfor", hEmu, async () => { okOrThrow(await request(CU.MF1_SET_FIELD_OFF_DO_RESET,[Number($("h_for").value)])); showResult(hEmu,"Field-off-reset behaviour set.","ok"); });

const hDet = $("h_detTable");
wire("h_detcount", null, async () => {
  const f = okOrThrow(await request(CU.MF1_GET_DETECTION_COUNT));
  const n=(f.data[0]<<24|f.data[1]<<16|f.data[2]<<8|f.data[3])>>>0;
  hDet.innerHTML = '<div class="det">'+n+" record(s) logged.</div>";
});
wire("h_detlog", null, async () => {
  const idx = Number($("h_detidx").value)||0;
  const f = okOrThrow(await request(CU.MF1_GET_DETECTION_LOG, u32be(idx)));
  const rows=[];
  for(let o=0;o+18<=f.data.length;o+=18){
    const block=f.data[o], bit=f.data[o+1];
    rows.push({block, type: bit&1?"B":"A", nested: !!(bit&2),
      uid:bhex(f.data.slice(o+2,o+6)), nt:bhex(f.data.slice(o+6,o+10)),
      nr:bhex(f.data.slice(o+10,o+14)), ar:bhex(f.data.slice(o+14,o+18))});
  }
  const t=document.createElement("table"); t.className="tbl";
  t.innerHTML="<tr><th>Block</th><th>Key</th><th>Nested</th><th>UID</th><th>Nt</th><th>Nr</th><th>Ar</th></tr>"+
    rows.map(r=>`<tr><td>${r.block}</td><td>${r.type}</td><td>${r.nested}</td><td>${r.uid}</td><td>${r.nt}</td><td>${r.nr}</td><td>${r.ar}</td></tr>`).join("");
  hDet.innerHTML=""; hDet.appendChild(t);
  if(!rows.length) hDet.innerHTML = '<div class="det">No records from index '+idx+'.</div>';
});

// HF14A_RAW (cmd_processor_hf14a_raw, app_cmd.c): options is one bitfield
// byte, fields listed LSB->MSB per the struct comment: reserved(2 bits,
// b0-1), check_response_crc(b2), keep_rf_field(b3), auto_select(b4),
// append_crc(b5), wait_response(b6), activate_rf_field(b7, MSB). Then
// resp_timeout(u16 BE), data_bitlength(u16 BE), raw data bytes.
wire("h_rawsend", $("h_rawResult"), async () => {
  const activate = Number($("h_rawfield").value);
  const autosel = Number($("h_rawautosel").value);
  const appendcrc = Number($("h_rawcrc").value);
  const waitresp = Number($("h_rawwait").value);
  const keepfield = Number($("h_rawkeep").value);
  const checkcrc = Number($("h_rawcheckcrc").value);
  const timeout = Math.max(0, Math.min(65535, Number($("h_rawtimeout").value)||0));
  const bytes = hexBytes($("h_rawdata").value);
  const optByte = (checkcrc<<2)|(keepfield<<3)|(autosel<<4)|(appendcrc<<5)|(waitresp<<6)|(activate<<7);
  const payload = [optByte, ...u16be(timeout), ...u16be(bytes.length*8), ...bytes];
  const f = await request(CU.HF14A_RAW, payload);
  if(!OK_STATUSES.has(f.status)){ showResult($("h_rawResult"), "Failed: "+stname(f.status), "err"); return; }
  showResult($("h_rawResult"), f.data.length+" byte(s): "+(bhex(f.data)||"(none)"), "ok");
});

// MF1_MANIPULATE_VALUE_BLOCK (cmd_processor_mf1_manipulate_value_block):
// auth src -> PICC_INCREMENT/DECREMENT/RESTORE on src block -> auth dst (if
// different from src) -> transfer result into dst block.
wire("h_vbrun", $("h_vbResult"), async () => {
  const srcBlock = Number($("h_vbsrc").value);
  const srcType = parseInt($("h_vbsrctype").value, 16);
  const srcKey = hexBytes($("h_vbsrckey").value, 6);
  if(srcKey.length!==6) throw new Error("source key must be 12 hex chars (6 bytes)");
  const op = parseInt($("h_vbop").value, 16);
  const operand = parseInt($("h_vboperand").value, 10) || 0;
  const dstBlock = Number($("h_vbdst").value);
  const dstType = parseInt($("h_vbdsttype").value, 16);
  const dstKey = hexBytes($("h_vbdstkey").value, 6);
  if(dstKey.length!==6) throw new Error("destination key must be 12 hex chars (6 bytes)");
  const payload = [srcType, srcBlock, ...srcKey, op, ...u32be(operand), dstType, dstBlock, ...dstKey];
  okOrThrow(await request(CU.MF1_MANIPULATE_VALUE_BLOCK, payload));
  showResult($("h_vbResult"), "Value block operation OK — block "+dstBlock+" now holds the result.", "ok");
});

// MF1_MAGIC_AUTH (cmd_processor_mf1_magic_auth): payload type(1) block(1)
// key[6] keep_field(1) = 9 bytes. Raw backdoor auth via auth_key_use_522_hw,
// bypassing normal MF1 authenticate — Ultra only (RC522 reader hardware).
wire("h_marun", $("h_maResult"), async () => {
  const type = parseInt($("h_maType").value, 16) & 0xFF;
  const block = Number($("h_maBlock").value) & 0xFF;
  const key = hexBytes($("h_maKey").value, 6);
  if(key.length!==6) throw new Error("key must be 12 hex chars (6 bytes)");
  const keep = Number($("h_maKeep").value);
  const payload = [type, block, ...key, keep];
  okOrThrow(await request(CU.MF1_MAGIC_AUTH, payload));
  showResult($("h_maResult"), "Magic auth OK on block "+block+".", "ok");
});

// HF14A-4 (ISO14443-4/T=CL) emulation, app_cmd.c cmd_processor_hf14a_4_*:
// STATIC_RESP cmd_len(1) cmd(n) resp_len_be16(2) resp(m), cmd_len=0 clears all.
// SET_ANTI_COLL uid_len(1) uid(n) atqa(2) sak(1) ats_len(1) ats(m).
// APDU_SEND len_be16(2) resp(n). APDU_RECV takes no payload.
wire("h4_setstatic", $("h4_Result"), async () => {
  const cmdBytes = hexBytes($("h4_cmd").value);
  if(cmdBytes.length===0){
    okOrThrow(await request(CU.HF14A_4_STATIC_RESP, [0]));
    showResult($("h4_Result"), "All static responses cleared.", "ok");
    return;
  }
  const respBytes = hexBytes($("h4_resp").value);
  const payload = [cmdBytes.length, ...cmdBytes, ...u16be(respBytes.length), ...respBytes];
  okOrThrow(await request(CU.HF14A_4_STATIC_RESP, payload));
  showResult($("h4_Result"), "Static response set for prefix "+bhex(cmdBytes)+".", "ok");
});
wire("h4_setanticoll", $("h4_Result"), async () => {
  const uid = hexBytes($("h4_uid").value);
  const atqa = hexBytes($("h4_atqa").value, 2);
  const sak = hexBytes($("h4_sak").value, 1);
  if(atqa.length!==2) throw new Error("ATQA must be 4 hex chars (2 bytes)");
  if(sak.length!==1) throw new Error("SAK must be 2 hex chars (1 byte)");
  const ats = hexBytes($("h4_ats").value);
  const payload = [uid.length, ...uid, ...atqa, ...sak, ats.length, ...ats];
  okOrThrow(await request(CU.HF14A_4_SET_ANTI_COLL, payload));
  showResult($("h4_Result"), "Anti-collision data set.", "ok");
});
wire("h4_recv", $("h4_Result"), async () => {
  const f = await request(CU.HF14A_4_APDU_RECV);
  if(f.status === 0x01){ showResult($("h4_Result"), "No pending APDU.", "warn"); return; }
  if(!OK_STATUSES.has(f.status)){ showResult($("h4_Result"), "Failed: "+stname(f.status), "err"); return; }
  showResult($("h4_Result"), "Pending APDU ("+f.data.length+" byte(s)): "+(bhex(f.data)||"(none)"), "ok");
});
wire("h4_send", $("h4_Result"), async () => {
  const resp = hexBytes($("h4_sendresp").value);
  const payload = [...u16be(resp.length), ...resp];
  okOrThrow(await request(CU.HF14A_4_APDU_SEND, payload));
  showResult($("h4_Result"), "Response pushed ("+resp.length+" byte(s)).", "ok");
});

/* ---- MF1 key-recovery attacks: nonce acquisition only, no crypto1 math here ----
 * request()'s own BLE round-trip timeout (canary.js, fixed at 6000ms) is
 * shorter than these commands can legitimately take -- mf1_darkside_acquire
 * waits up to sync_max*10 on the Python side, mf1_hard_nested_acquire/
 * mf1_static_encrypted_nested_acquire use a 30s budget there. A long-running
 * attack can hit that 6s client-side timeout and report "no reply" even
 * though the device is still working; this file can't fix that without
 * changing canary.js (out of scope here). */
const hAtk = $("h_atkResult");
function mf1KnownArgs(blockEl, typeEl, keyEl){
  const block = Number($(blockEl).value);
  const type = parseInt($(typeEl).value,16);
  const key = hexBytes($(keyEl).value,6);
  if(key.length!==6) throw new Error("key must be 12 hex chars (6 bytes)");
  return {block, type, key};
}
wire("h_ntdist", hAtk, async () => {
  const {block,type,key} = mf1KnownArgs("h_ndblock","h_ndtype","h_ndkey");
  const f = okOrThrow(await request(CU.MF1_DETECT_NT_DIST, [type, block, ...key]));
  const uid=(f.data[0]<<24|f.data[1]<<16|f.data[2]<<8|f.data[3])>>>0;
  const dist=(f.data[4]<<24|f.data[5]<<16|f.data[6]<<8|f.data[7])>>>0;
  showResult(hAtk, "uid 0x"+uid.toString(16)+" · nt distance "+dist, "ok");
});
const DARKSIDE_STATUS = {0:"OK",1:"can't fix nt (PRNG unpredictable)",2:"lucky auth (default key recovered directly)",3:"no NAK sent by tag",4:"tag changed mid-attack"};
wire("h_darkside", hAtk, async () => {
  const block = Number($("h_dsblock").value);
  const type = parseInt($("h_dstype").value,16);
  const firstRecover = Number($("h_dsfirst").value);
  const syncMax = Math.max(1, Math.min(255, Number($("h_dssync").value)||15));
  // sync_max rounds against a tag with an unstable nonce can take a while --
  // chameleon_cmd.py allows up to sync_max*10s; request()'s 6s default is too
  // short for anything but a lucky first auth.
  const f = okOrThrow(await request(CU.MF1_DARKSIDE_ACQUIRE, [type, block, firstRecover, syncMax], Math.max(6000, syncMax*10000+5000)));
  const ds = f.data[0];
  if(ds !== 0){ showResult(hAtk, "Darkside: "+(DARKSIDE_STATUS[ds]||"status "+ds), ds===2?"ok":""); return; }
  // !BIIQQII: status(1) uid(4) nt1(4) par(8) ks1(8) nr(4) ar(4) = 33 bytes
  const u32 = o => (f.data[o]<<24|f.data[o+1]<<16|f.data[o+2]<<8|f.data[o+3])>>>0;
  showResult(hAtk,
    "Darkside OK — feed these to an offline darkside solver:\n"+
    "uid 0x"+u32(1).toString(16)+" · nt1 0x"+u32(5).toString(16)+"\n"+
    "par 0x"+u64beHex(f.data,9)+" · ks1 0x"+u64beHex(f.data,17)+"\n"+
    "nr 0x"+u32(25).toString(16)+" · ar 0x"+u32(29).toString(16), "ok");
});
wire("h_nested", hAtk, async () => {
  const {block,type,key} = mf1KnownArgs("h_nkblock","h_nktype","h_nkkey");
  const targetBlock = Number($("h_ntblock").value), targetType = parseInt($("h_nttype").value,16);
  const f = okOrThrow(await request(CU.MF1_NESTED_ACQUIRE, [type, block, ...key, targetType, targetBlock]));
  const rows=[];
  for(let o=0;o+9<=f.data.length;o+=9){
    const nt=(f.data[o]<<24|f.data[o+1]<<16|f.data[o+2]<<8|f.data[o+3])>>>0;
    const ntEnc=(f.data[o+4]<<24|f.data[o+5]<<16|f.data[o+6]<<8|f.data[o+7])>>>0;
    rows.push("nt 0x"+nt.toString(16).padStart(8,"0")+" · nt_enc 0x"+ntEnc.toString(16).padStart(8,"0")+" · par 0x"+f.data[o+8].toString(16));
  }
  showResult(hAtk, rows.length+" nonce(s):\n"+rows.join("\n"), "ok");
});
wire("h_staticnested", hAtk, async () => {
  const {block,type,key} = mf1KnownArgs("h_snkblock","h_snktype","h_snkkey");
  const targetBlock = Number($("h_sntblock").value), targetType = parseInt($("h_snttype").value,16);
  const f = okOrThrow(await request(CU.MF1_STATIC_NESTED_ACQUIRE, [type, block, ...key, targetType, targetBlock]));
  const uid=(f.data[0]<<24|f.data[1]<<16|f.data[2]<<8|f.data[3])>>>0;
  const rows=[];
  for(let o=4;o+8<=f.data.length;o+=8){
    const nt=(f.data[o]<<24|f.data[o+1]<<16|f.data[o+2]<<8|f.data[o+3])>>>0;
    const ntEnc=(f.data[o+4]<<24|f.data[o+5]<<16|f.data[o+6]<<8|f.data[o+7])>>>0;
    rows.push("nt 0x"+nt.toString(16).padStart(8,"0")+" · nt_enc 0x"+ntEnc.toString(16).padStart(8,"0"));
  }
  showResult(hAtk, "uid 0x"+uid.toString(16)+" · "+rows.length+" nonce(s):\n"+rows.join("\n"), "ok");
});
wire("h_hardnested", hAtk, async () => {
  const {block,type,key} = mf1KnownArgs("h_hnkblock","h_hnktype","h_hnkkey");
  const targetBlock = Number($("h_hntblock").value), targetType = parseInt($("h_hnttype").value,16);
  const slow = Number($("h_hnslow").value);
  // struct.pack('!BBB6sBB', slow, type_known, block_known, key_known, type_target, block_target)
  // Hardnested can run 30s+ on-device; 6s default would time out mid-attack.
  const f = okOrThrow(await request(CU.MF1_HARDNESTED_ACQUIRE, [slow, type, block, ...key, targetType, targetBlock], 35000));
  showResult(hAtk, "Raw nonce data, "+f.data.length+" byte(s) (feed to an offline hardnested solver):\n"+bhex(f.data), "ok");
});
wire("h_encnested", hAtk, async () => {
  const backdoorKey = hexBytes($("h_enkey").value,6);
  if(backdoorKey.length!==6) throw new Error("backdoor key must be 12 hex chars (6 bytes)");
  const sectorCount = Number($("h_ensectors").value), startSector = Number($("h_enstart").value);
  // Scales with sectorCount -- give it room past the 6s default.
  const f = await request(CU.MF1_ENC_NESTED_ACQUIRE, [...backdoorKey, sectorCount, startSector], Math.max(6000, sectorCount*5000+5000));
  if(f.status === 0x01){ showResult(hAtk, "No tag found.", "err"); return; }
  okOrThrow(f);
  // Raw bytes only -- Python's own parsing (reconstruct_full_nt) runs the
  // weak-PRNG successor function to unroll each partial nonce, which is
  // attack-specific crypto1 math not ported here. Feed this to the same tool.
  const uid=(f.data[0]<<24|f.data[1]<<16|f.data[2]<<8|f.data[3])>>>0;
  showResult(hAtk, "uid 0x"+uid.toString(16)+" · "+(f.data.length-4)+" raw byte(s) of a/b nonce pairs:\n"+bhex(f.data.slice(4)), "ok");
});

const hSniff = $("h_sniffResult");
wire("h_sniff", hSniff, async () => {
  const timeout = Math.max(1, Math.min(30000, Number($("h_sftimeout").value)||5000));
  const tap = Number($("h_sftap").value);
  const f = await request(CU.HF14A_SNIFF, [...u16be(timeout), tap]);
  if(!OK_STATUSES.has(f.status)){ showResult(hSniff, "No capture: "+stname(f.status), "err"); return; }
  const fr = parseFrames(f.data);
  const ns = extractNonces(fr);
  let html = '<div class="det">'+fr.length+" frames.</div>";
  for(const n of ns){
    html += '<div class="nonce">Classic auth key'+n.key+' block '+n.block+' · uid '+n.uid+' · nt '+n.nt+' · nr '+n.nr+' · ar '+n.ar+(n.at?' · at '+n.at:'')+'</div>';
  }
  html += '<details><summary>Frames</summary><pre>'+fr.map((f2,i)=>String(i).padStart(3)+"  "+(f2.tx?"card→rdr":"rdr→card")+"  "+String(f2.bits).padStart(4)+"b  "+hex(f2.data).padEnd(40)+"  "+frameLabel(f2,fr[i-1])).join("\n")+'</pre></details>';
  hSniff.innerHTML = html;
});

/* =======================================================================
 * LF tab
 * ===================================================================== */
const lGen = $("l_genResult");
wire("l_search", lGen, async () => {
  const f = await request(CU.LF_SEARCH);
  if(f.status!==0x40){ showResult(lGen,"No LF tag found ("+stname(f.status)+")."); return; }
  const type=(f.data[0]<<8)|f.data[1];
  showResult(lGen, "Tag type "+type+" · id "+bhex(f.data.slice(2)), "ok");
});
wire("l_adc", lGen, async () => {
  const f = okOrThrow(await request(CU.ADC_GENERIC_READ,[]));
  showResult(lGen, bhex(f.data), "ok");
});

const lEm = $("l_emResult");
wire("l_em_scan", lEm, async () => {
  const f = await request(CU.EM410X_SCAN);
  if(f.status!==0x40){ showResult(lEm,"No tag: "+stname(f.status)); return; }
  const type=(f.data[0]<<8)|f.data[1];
  const id = f.data.slice(2);
  $("l_em_id").value = bhex(id);
  showResult(lEm, (type===104?"Electra":"EM410x")+" id: "+bhex(id), "ok");
});
wire("l_em_write", lEm, async () => {
  const id = hexBytes($("l_em_id").value);
  let cmd;
  if(id.length===5) cmd=CU.EM410X_WRITE_TO_T55XX;
  else if(id.length===13) cmd=CU.EM410X_ELECTRA_WRITE_TO_T55XX;
  else throw new Error("id must be 5 bytes (EM410x) or 13 bytes (Electra)");
  okOrThrow(await request(cmd, t55xxPayload(id)));
  showResult(lEm, "Written to T55xx.", "ok");
});
wire("l_em_getemu", lEm, async () => {
  const f = okOrThrow(await request(CU.EM410X_GET_EMU_ID));
  showResult(lEm, "Emulated id: "+bhex(f.data), "ok");
});
wire("l_em_setemu", lEm, async () => {
  const id = hexBytes($("l_em_id").value);
  if(![5,13].includes(id.length)) throw new Error("id must be 5 or 13 bytes (must match the active slot's LF type)");
  okOrThrow(await request(CU.EM410X_SET_EMU_ID, id));
  showResult(lEm, "Emulated id set.", "ok");
});

const lHid = $("l_hidResult");
wire("l_hid_scan", lHid, async () => {
  const fmt = Number($("l_hid_fmt").value)||0;
  const f = await request(CU.HIDPROX_SCAN, [fmt]);
  if(f.status!==0x40){ showResult(lHid,"No tag: "+stname(f.status)); return; }
  showResult(lHid, "Raw fields: "+bhex(f.data.slice(0,13))+"  (see hidprox_scan in chameleon_cmd.py for field layout)", "ok");
});
wire("l_hid_write", lHid, async () => {
  const id = hexBytes($("l_hid_id").value,13);
  if(id.length!==13) throw new Error("id must be 13 bytes");
  okOrThrow(await request(CU.HIDPROX_WRITE_TO_T55XX, t55xxPayload(id)));
  showResult(lHid, "Written to T55xx.", "ok");
});
wire("l_hid_getemu", lHid, async () => {
  const f = okOrThrow(await request(CU.HIDPROX_GET_EMU_ID));
  showResult(lHid, "Raw: "+bhex(f.data.slice(0,13)), "ok");
});
wire("l_hid_setemu", lHid, async () => {
  const id = hexBytes($("l_hid_id").value,13);
  if(id.length!==13) throw new Error("id must be 13 bytes");
  okOrThrow(await request(CU.HIDPROX_SET_EMU_ID, id));
  showResult(lHid, "Emulated id set.", "ok");
});

function decodeIoprox16(d){
  return {ver:d[0], fc:d[1], cn:(d[2]<<8)|d[3], raw8:d.slice(4,12)};
}
const lIo = $("l_ioResult");
wire("l_io_scan", lIo, async () => {
  const f = await request(CU.IOPROX_SCAN);
  if(f.status!==0x40){ showResult(lIo,"No tag: "+stname(f.status)); return; }
  $("l_io_id").value = bhex(f.data.slice(0,16));
  const d = decodeIoprox16(f.data);
  showResult(lIo, `ver=${d.ver} fc=${d.fc} cn=${d.cn} raw8=${bhex(d.raw8)}`, "ok");
});
wire("l_io_compose", lIo, async () => {
  const ver=Number($("l_io_ver").value), fc=Number($("l_io_fc").value), cn=Number($("l_io_cn").value);
  const f = okOrThrow(await request(CU.IOPROX_COMPOSE_ID, [ver, fc, ...u16be(cn)]));
  $("l_io_id").value = bhex(f.data.slice(0,16));
  const d = decodeIoprox16(f.data);
  showResult(lIo, "Composed: raw8="+bhex(d.raw8)+" (16-byte struct placed in the ID field above)", "ok");
});
wire("l_io_write", lIo, async () => {
  const id = hexBytes($("l_io_id").value,16);
  if(id.length!==16) throw new Error("id must be the 16-byte struct from Scan/Compose");
  okOrThrow(await request(CU.IOPROX_WRITE_TO_T55XX, t55xxPayload(id)));
  showResult(lIo, "Written to T55xx.", "ok");
});
wire("l_io_getemu", lIo, async () => {
  const f = okOrThrow(await request(CU.IOPROX_GET_EMU_ID));
  $("l_io_id").value = bhex(f.data.slice(0,16));
  const d = decodeIoprox16(f.data);
  showResult(lIo, `ver=${d.ver} fc=${d.fc} cn=${d.cn} raw8=${bhex(d.raw8)}`, "ok");
});
wire("l_io_setemu", lIo, async () => {
  const id = hexBytes($("l_io_id").value,16);
  if(id.length!==16) throw new Error("id must be the 16-byte struct from Scan/Compose");
  okOrThrow(await request(CU.IOPROX_SET_EMU_ID, id));
  showResult(lIo, "Emulated id set.", "ok");
});

const lMisc = $("l_miscResult");
function simpleLf(prefix, scanCmd, writeCmd, getCmd, setCmd, idInput, idLen){
  if(scanCmd !== null) wire(prefix+"_scan", lMisc, async () => {
    const f = await request(scanCmd);
    if(f.status!==0x40){ showResult(lMisc,"No tag: "+stname(f.status)); return; }
    $(idInput).value = bhex(f.data.slice(0,idLen));
    showResult(lMisc, "Scanned id: "+bhex(f.data.slice(0,idLen)), "ok");
  });
  wire(prefix+"_write", lMisc, async () => {
    const id = hexBytes($(idInput).value, idLen);
    if(id.length!==idLen) throw new Error("id must be "+idLen+" bytes");
    okOrThrow(await request(writeCmd, t55xxPayload(id)));
    showResult(lMisc, "Written to T55xx.", "ok");
  });
  wire(prefix+"_getemu", lMisc, async () => {
    const f = okOrThrow(await request(getCmd));
    showResult(lMisc, "Emulated id: "+bhex(f.data.slice(0,idLen)), "ok");
  });
  wire(prefix+"_setemu", lMisc, async () => {
    const id = hexBytes($(idInput).value, idLen);
    if(id.length!==idLen) throw new Error("id must be "+idLen+" bytes");
    okOrThrow(await request(setCmd, id));
    showResult(lMisc, "Emulated id set.", "ok");
  });
}
simpleLf("l_vk", CU.VIKING_SCAN, CU.VIKING_WRITE_TO_T55XX, CU.VIKING_GET_EMU_ID, CU.VIKING_SET_EMU_ID, "l_vk_id", 4);
simpleLf("l_pac", CU.PAC_SCAN, CU.PAC_WRITE_TO_T55XX, CU.PAC_GET_EMU_ID, CU.PAC_SET_EMU_ID, "l_pac_id", 8);
simpleLf("l_jb", CU.JABLOTRON_SCAN, CU.JABLOTRON_WRITE_TO_T55XX, CU.JABLOTRON_GET_EMU_ID, CU.JABLOTRON_SET_EMU_ID, "l_jb_id", 5);
simpleLf("l_in", CU.INDALA_SCAN, CU.INDALA_WRITE_TO_T55XX, CU.INDALA_GET_EMU_ID, CU.INDALA_SET_EMU_ID, "l_in_id", 8);
simpleLf("l_id", null, CU.IDTECK_WRITE_TO_T55XX, CU.IDTECK_GET_EMU_ID, CU.IDTECK_SET_EMU_ID, "l_id_id", 8);

const lFx = $("l_fxResult");
wire("l_fx_scan", lFx, async () => {
  const f = await request(CU.FDXB_SCAN);
  if(f.status!==0x40){ showResult(lFx,"No tag: "+stname(f.status)); return; }
  const type=(f.data[0]<<8)|f.data[1], frame=f.data.slice(2,15);
  $("l_fx_data").value = bhex(frame);
  showResult(lFx, "Tag type "+type+" · frame "+bhex(frame), "ok");
});
wire("l_fx_write", lFx, async () => {
  const data = hexBytes($("l_fx_data").value,13);
  if(data.length!==13) throw new Error("frame must be 13 bytes");
  okOrThrow(await request(CU.FDXB_WRITE_TO_T55XX, t55xxPayload(data)));
  showResult(lFx, "Written to T55xx.", "ok");
});
wire("l_em4_scan", lFx, async () => {
  const pwd = hexBytes($("l_em4_pwd").value,4);
  const f = await request(CU.EM4X05_SCAN, pwd.length===4?pwd:[0,0,0,0]);
  if(f.status!==0x40){ showResult(lFx,"No tag: "+stname(f.status)); return; }
  const config=bhex(f.data.slice(0,4)), uid=bhex(f.data.slice(4,8)), uidhi=bhex(f.data.slice(8,12)), is69=f.data[12], blk=f.data[13];
  showResult(lFx, `config=${config} uid=${uid} uid_hi=${uidhi} em4x69=${!!is69} uidBlock=${blk}`, "ok");
});
wire("l_t5_writeblk", lFx, async () => {
  const block = Number($("l_t5_block").value)&0xFF;
  const word = hexBytes($("l_t5_word").value,4);
  const pwdStr = $("l_t5_pwd").value.trim();
  const usePwd = pwdStr.length>0 ? 1 : 0;
  const pwd = usePwd ? hexBytes(pwdStr,4) : [0,0,0,0];
  const page1 = Number($("l_t5_page1").value);
  const payload = [block, ...word, usePwd, ...pwd, page1, 0 /* dl_mode: fixed */];
  okOrThrow(await request(CU.LF_T55XX_WRITE, payload));
  showResult(lFx, "T55xx block "+block+" written.", "ok");
});

wire("l_sniff", $("l_sniffResult"), async () => {
  // request()'s 6000ms timeout (canary.js) can be shorter than a long capture.
  const timeout = Math.max(1, Math.min(10000, Number($("l_sftimeout").value)||2000));
  const passive = Number($("l_sfpassive").value);
  const f = await request(CU.LF_SNIFF, [...u16be(timeout), passive]);
  if(!OK_STATUSES.has(f.status)){ showResult($("l_sniffResult"), "No capture: "+stname(f.status), "err"); return; }
  const d = f.data;
  let min=255, max=0, sum=0;
  for(const b of d){ if(b<min) min=b; if(b>max) max=b; sum+=b; }
  const mean = d.length ? (sum/d.length) : 0;
  showResult($("l_sniffResult"),
    d.length+" ADC sample(s) · min "+min+" · max "+max+" · mean "+mean.toFixed(1)+
    "\n(raw, ~0x80 = field on, lower = gap/no field — first 64 bytes: "+bhex(d.slice(0,64))+(d.length>64?" …":"")+")", "ok");
});

/* =======================================================================
 * MF0 / NTAG tab
 * ===================================================================== */
const mP = $("m_pResult");
wire("m_pagecount", mP, async () => {
  const f = okOrThrow(await request(CU.MF0_NTAG_GET_PAGE_COUNT));
  showResult(mP, "Pages: "+f.data[0], "ok");
});
wire("m_pread", mP, async () => {
  const start = Number($("m_pstart").value), count = Number($("m_pcount").value);
  const f = okOrThrow(await request(CU.MF0_NTAG_READ_EMU_PAGE_DATA, [start, count]));
  $("m_pdata").value = bhex(f.data);
  const rows=[];
  for(let i=0;i*4<f.data.length;i++) rows.push("page "+(start+i)+": "+bhex(f.data.slice(i*4,i*4+4)));
  showResult(mP, rows.join("\n"), "ok");
});
wire("m_pwrite", mP, async () => {
  const start = Number($("m_pstart").value);
  const data = hexBytes($("m_pdata").value);
  if(data.length===0 || data.length%4!==0) throw new Error("data must be a non-empty multiple of 4 bytes (8 hex chars)");
  const count = data.length/4;
  okOrThrow(await request(CU.MF0_NTAG_WRITE_EMU_PAGE_DATA, [start, count, ...data]));
  showResult(mP, "Wrote "+count+" page(s) starting at "+start+".", "ok");
});

const mMagic = $("m_magicResult");
wire("m_getmagic", mMagic, async () => {
  const f = okOrThrow(await request(CU.MF0_NTAG_GET_UID_MAGIC_MODE));
  $("m_magicsel").value = f.data[0] ? "1" : "0";
  showResult(mMagic, "UID magic mode: "+(!!f.data[0]), "ok");
});
wire("m_setmagic", mMagic, async () => {
  okOrThrow(await request(CU.MF0_NTAG_SET_UID_MAGIC_MODE, [Number($("m_magicsel").value)]));
  showResult(mMagic, "UID magic mode set.", "ok");
});
wire("m_getver", mMagic, async () => {
  const f = okOrThrow(await request(CU.MF0_NTAG_GET_VERSION_DATA));
  $("m_verdata").value = bhex(f.data.slice(0,8));
  showResult(mMagic, "Version data: "+bhex(f.data.slice(0,8)), "ok");
});
wire("m_setver", mMagic, async () => {
  const bytes = hexBytes($("m_verdata").value, 8);
  if(bytes.length!==8) throw new Error("version data must be 16 hex chars (8 bytes)");
  okOrThrow(await request(CU.MF0_NTAG_SET_VERSION_DATA, bytes));
  showResult(mMagic, "Version data set.", "ok");
});
wire("m_getsig", mMagic, async () => {
  const f = okOrThrow(await request(CU.MF0_NTAG_GET_SIGNATURE_DATA));
  $("m_sigdata").value = bhex(f.data.slice(0,32));
  showResult(mMagic, "Signature data: "+bhex(f.data.slice(0,32)), "ok");
});
wire("m_setsig", mMagic, async () => {
  const bytes = hexBytes($("m_sigdata").value, 32);
  if(bytes.length!==32) throw new Error("signature data must be 64 hex chars (32 bytes)");
  okOrThrow(await request(CU.MF0_NTAG_SET_SIGNATURE_DATA, bytes));
  showResult(mMagic, "Signature data set.", "ok");
});
wire("m_resetauth", mMagic, async () => {
  const f = okOrThrow(await request(CU.MF0_NTAG_RESET_AUTH_CNT));
  showResult(mMagic, "Auth counter reset. (raw reply: "+bhex(f.data)+")", "ok");
});

const mWm = $("m_wmResult");
wire("m_getemu", mWm, async () => {
  // cmd_processor_mf0_get_emulator_config: [detectionEnable, uidMode, writeMode]
  const f = okOrThrow(await request(CU.MF0_NTAG_GET_EMULATOR_CONFIG));
  const [det, uidMode, wmode] = f.data;
  $("m_detect").value = det ? "1" : "0";
  $("m_magicsel").value = uidMode ? "1" : "0";
  $("m_wmode").value = String(wmode);
  showResult(mWm, `detection=${!!det} uidMagic=${!!uidMode} writeMode=${wmode}`, "ok");
});
wire("m_getwmode", mWm, async () => {
  const f = okOrThrow(await request(CU.MF0_NTAG_GET_WRITE_MODE));
  $("m_wmode").value = String(f.data[0]);
  showResult(mWm, "Write mode: "+f.data[0], "ok");
});
wire("m_setwmode", mWm, async () => {
  okOrThrow(await request(CU.MF0_NTAG_SET_WRITE_MODE, [Number($("m_wmode").value)]));
  showResult(mWm, "Write mode set.", "ok");
});
wire("m_getdetect", mWm, async () => {
  const f = okOrThrow(await request(CU.MF0_NTAG_GET_DETECTION_ENABLE));
  $("m_detect").value = f.data[0] ? "1" : "0";
  showResult(mWm, "Detection enabled: "+(!!f.data[0]), "ok");
});
wire("m_setdetect", mWm, async () => {
  okOrThrow(await request(CU.MF0_NTAG_SET_DETECTION_ENABLE, [Number($("m_detect").value)]));
  showResult(mWm, "Detection logging set (log cleared).", "ok");
});

const mDet = $("m_detTable");
wire("m_detcount", null, async () => {
  const f = okOrThrow(await request(CU.MF0_NTAG_GET_DETECTION_COUNT));
  const n = (f.data[0]<<24|f.data[1]<<16|f.data[2]<<8|f.data[3])>>>0;
  mDet.innerHTML = '<div class="det">Detection log entries: '+n+'</div>';
});
wire("m_detlog", null, async () => {
  // nfc_tag_mf0_ntag_auth_log_t: pwd[4] — one attempted password per entry.
  const idx = Number($("m_detidx").value)||0;
  const f = okOrThrow(await request(CU.MF0_NTAG_GET_DETECTION_LOG, u32be(idx)));
  const rows = [];
  for(let o=0;o+4<=f.data.length;o+=4) rows.push(bhex(f.data.slice(o,o+4)));
  mDet.innerHTML = "";
  if(!rows.length){ mDet.innerHTML = '<div class="det">No records from index '+idx+'.</div>'; return; }
  const t = document.createElement("table"); t.className = "tbl";
  t.innerHTML = "<tr><th>#</th><th>Password tried</th></tr>"+
    rows.map((p,i)=>`<tr><td>${idx+i}</td><td>${p}</td></tr>`).join("");
  mDet.appendChild(t);
});

const mC = $("m_cResult");
wire("m_cget", mC, async () => {
  const idx = Number($("m_cidx").value);
  const f = okOrThrow(await request(CU.MF0_NTAG_GET_COUNTER_DATA, [idx]));
  const value = (f.data[2]<<16)|(f.data[1]<<8)|f.data[0];
  const tearing = f.data[3]===0xBD;
  $("m_cval").value=String(value);
  showResult(mC, "Counter "+idx+" = "+value+" · tearing flag intact: "+tearing, "ok");
});
wire("m_cset", mC, async () => {
  const idx = Number($("m_cidx").value)&0x7F;
  const value = Number($("m_cval").value)>>>0;
  const resetTear = Number($("m_ctear").value);
  const payload = [idx | (resetTear<<7), value&0xFF, (value>>8)&0xFF, (value>>16)&0xFF];
  okOrThrow(await request(CU.MF0_NTAG_SET_COUNTER_DATA, payload));
  showResult(mC, "Counter "+idx+" set to "+value+".", "ok");
});

/* =======================================================================
 * DESFire tab
 * ===================================================================== */
const DFC_ALGOS = { aes:[0x09,16], "2tdea":[0x02,16], "3tdea":[0x04,24] };
// chameleon_cmd.py uses 1024 (fine over USB-serial), but Web Bluetooth's
// writeValueWithoutResponse caps a single write at 512 bytes regardless of
// the negotiated ATT MTU. Our frame is 9B header + 6B (total/sent/len) +
// chunk + 1B checksum = 16 + chunk, so chunk must stay <= 496; leave margin.
const DESFIRE_CHUNK = 480;
let lastDfcb = null; // last downloaded credential, for the "save as .dfcb" button

// GET_INFO/GET_CREDENTIAL/FACTORY_BLANK all return PAR_ERR (0x60) when the
// active slot's live DESFire buffer (m_info) is unset — nfc_tag_desfire_get_credential()
// returns NULL and the handler bails before touching anything else. Setting the
// slot's tag type alone does not populate that buffer on a slot that never held
// DESFire data (load_data_by_tag_type() only reloads an *existing* flash record),
// and "Set slot data default" only writes the live buffer immediately if the slot
// is already active — see F0 above for the one-click fix.
function okOrDfcHint(f){
  if(f.status === 0x60) throw new Error("PAR_ERR — this slot's live DESFire buffer isn't populated. Use F0 \"Prepare slot\" above (set tag type -> make active -> set slot data default, in that order) before using this tab.");
  return okOrThrow(f);
}

const fPrep = $("f_prepResult");
wire("f_prepare", fPrep, async () => {
  const slot = Number($("f_prepslot").value);
  if(slot<1||slot>8) throw new Error("slot must be 1-8");
  const tagtype = Number($("f_preptype").value);
  // Order matters: tag type first, then make this the active slot (so the
  // firmware's "only reload live if already active" check in
  // tag_emulation_factory_data() passes), then set slot data default, which
  // both writes the factory record to flash AND reloads it into the live
  // buffer since the slot is now active.
  okOrThrow(await request(CU.SET_SLOT_TAG_TYPE, [slot-1, ...u16be(tagtype)]));
  okOrThrow(await request(CU.SET_ACTIVE_SLOT, [slot-1]));
  okOrThrow(await request(CU.SET_SLOT_DATA_DEFAULT, [slot-1, ...u16be(tagtype)]));
  showResult(fPrep, "Slot "+slot+" is now active, type "+tagtype+", and loaded with factory-default DESFire data. F1-F3 should work now.", "ok");
});

const fInfo = $("f_infoResult");
wire("f_info", fInfo, async () => {
  const f = okOrDfcHint(await request(CU.DESFIRE_GET_INFO));
  if(f.data.length < 20) throw new Error("short reply ("+f.data.length+" bytes)");
  const d = f.data;
  const uidLen = d[0], uid = d.slice(1, 1+uidLen);
  const numApps=d[8], numFiles=d[9];
  const poolUsed=(d[10]<<8)|d[11], poolSize=(d[12]<<8)|d[13], credSize=(d[14]<<8)|d[15];
  const maxApps=d[16], maxKeys=d[17], maxFiles=d[18], piccAuthCmd=d[19];
  showResult(fInfo,
    `uid: ${bhex(uid)}\napps: ${numApps}/${maxApps}  files: ${numFiles}/${maxFiles}  keys/app max: ${maxKeys}\n`+
    `pool: ${poolUsed}/${poolSize} bytes  credential size: ${credSize} bytes\npicc auth command: 0x${piccAuthCmd.toString(16)}`,
    "ok");
});
wire("f_stats", fInfo, async () => {
  const f = okOrThrow(await request(CU.DESFIRE_GET_STATS));
  if(f.data.length < 10) throw new Error("short reply ("+f.data.length+" bytes)");
  const d = f.data;
  const u16 = o => (d[o]<<8)|d[o+1];
  let text = `rx frames: ${u16(0)}  tx frames: ${u16(2)}  engine errors: ${u16(4)}\n`+
    `max handler: ${u16(6)} µs  entropy starvations: ${u16(8)}`;
  if(d.length >= 18){
    text += `\nactivations: ${u16(10)}  atqa tx: ${u16(12)}  fdt timeouts: ${u16(14)}  max reset: ${u16(16)} µs`;
  }
  showResult(fInfo, text, "ok");
});
wire("f_blank", fInfo, async () => {
  const uidStr = $("f_blankuid").value.trim();
  const uid = uidStr ? hexBytes(uidStr) : [];
  if(uidStr && uid.length===0) throw new Error("bad UID hex");
  if(!confirm("Factory-blank the active slot's DESFire credential? This overwrites whatever is loaded now.")) return;
  const payload = uid.length ? [uid.length, ...uid] : [];
  const f = okOrDfcHint(await request(CU.DESFIRE_FACTORY_BLANK, payload));
  showResult(fInfo, "Slot blanked. New uid: "+bhex(f.data), "ok");
});

const fCred = $("f_credResult");
wire("f_download", fCred, async () => {
  let total = null, offset = 0;
  const out = [];
  for(let i=0;i<200;i++){
    const f = okOrDfcHint(await request(CU.DESFIRE_GET_CREDENTIAL, u16be(offset)));
    if(f.data.length < 6) throw new Error("short reply");
    const gotTotal=(f.data[0]<<8)|f.data[1], gotOffset=(f.data[2]<<8)|f.data[3], chunkLen=(f.data[4]<<8)|f.data[5];
    if(gotOffset !== offset) throw new Error("device returned offset "+gotOffset+", expected "+offset);
    if(total === null) total = gotTotal;
    out.push(...f.data.slice(6, 6+chunkLen));
    offset += chunkLen;
    showResult(fCred, "Downloading… "+offset+"/"+total+" bytes", "ok");
    if(chunkLen === 0 || offset >= total) break;
  }
  lastDfcb = out;
  $("f_blob").value = bhex(out);
  showResult(fCred, "Downloaded "+out.length+" byte(s). Starts with 0x"+(out[0]||0).toString(16)+(out[0]===0x60?" (looks like a .dfcb)":" (does NOT look like a .dfcb — slot may be blank/non-DESFire)"), "ok");
});
wire("f_dlfile", fCred, async () => {
  const bytes = lastDfcb || hexBytes($("f_blob").value);
  if(!bytes.length) throw new Error("nothing to save — download or paste a credential first");
  const blob = new Blob([new Uint8Array(bytes)], {type:"application/octet-stream"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "credential.dfcb";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(url), 2000);
});
$("f_filepickbtn").addEventListener("click", () => $("f_filepick").click());
$("f_filepick").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if(!file) return;
  try{
    const buf = await file.arrayBuffer();
    const bytes = Array.from(new Uint8Array(buf));
    if(bytes[0] !== 0x60) showResult(fCred, "Loaded "+bytes.length+" byte(s) from "+file.name+" — warning: first byte is 0x"+(bytes[0]||0).toString(16)+", not 0x60, so this doesn't look like a .dfcb", "err");
    else showResult(fCred, "Loaded "+bytes.length+" byte(s) from "+file.name+".", "ok");
    $("f_blob").value = bhex(bytes);
    lastDfcb = bytes;
  }catch(err){
    showResult(fCred, "Could not read file: "+err.message, "err");
  }
  e.target.value = "";
});
wire("f_upload", fCred, async () => {
  const blob = hexBytes($("f_blob").value);
  if(!blob.length) throw new Error("paste or download a .dfcb credential first");
  if(blob[0] !== 0x60) throw new Error("not a .dfcb credential: first byte is 0x"+blob[0].toString(16)+", not 0x60");
  const total = blob.length;
  if(total > 0xFFFF) throw new Error("credential too large for the protocol ("+total+" bytes, max 65535)");
  let sent = 0;
  while(sent < total){
    const chunk = blob.slice(sent, sent + DESFIRE_CHUNK);
    const payload = [...u16be(total), ...u16be(sent), ...u16be(chunk.length), ...chunk];
    const f = await request(CU.DESFIRE_SET_CREDENTIAL, payload);
    if(f.status !== 0x68){
      const der = {1:"malformed", 2:"unsupported (this build lacks the feature)", 3:"too large for device"};
      const stages = {1:"decode", 2:"ATS-consistency", 3:"materialize/capacity", 4:"reload/bind_session"};
      let detail = "";
      if(f.data && f.data.length>=1) detail += " — "+(der[f.data[0]]||f.data[0]);
      if(f.data && f.data.length>=2) detail += " at stage "+(stages[f.data[1]]||f.data[1]);
      if(f.status === 0x69) detail += " — tag is emulating; pull it out of any reader field and retry";
      throw new Error("device rejected credential (status "+stname(f.status)+")"+detail);
    }
    sent += chunk.length;
    showResult(fCred, "Uploading… "+sent+"/"+total+" bytes", "ok");
  }
  showResult(fCred, "Uploaded "+total+" byte(s).", "ok");
});

const fReader = $("f_readerResult");
wire("f_auth", fReader, async () => {
  const keyNo = Number($("f_keyno").value);
  if(keyNo < 0 || keyNo > 31) throw new Error("key number must be 0-31");
  const alg = $("f_alg").value;
  const [algByte, wantLen] = DFC_ALGOS[alg];
  const key = hexBytes($("f_key").value, wantLen);
  if(key.length !== wantLen) throw new Error(alg+" key must be "+wantLen+" bytes");
  const aidStr = $("f_aid").value.trim();
  const hasAid = aidStr.length > 0;
  const aid = hasAid ? hexBytes(aidStr, 3) : [0,0,0];
  if(hasAid && aid.length !== 3) throw new Error("AID must be 3 bytes (6 hex chars)");
  const keyRef = (hasAid ? 0x80 : 0) | keyNo;
  const payload = [hasAid?1:0, ...aid, keyRef, algByte, wantLen, ...key];
  const f = await request(CU.DESFIRE_READER_AUTH_ISO7816, payload);
  if(f.status === 0x01){ showResult(fReader, "No card found."); return; }
  if(f.status !== 0x00){ showResult(fReader, "Request error: "+stname(f.status), "err"); return; }
  const rc = f.data[0];
  if(rc === 0){ showResult(fReader, "Authenticated.", "ok"); return; }
  if(rc === 6 && f.data.length >= 2){
    showResult(fReader, "Card rejected auth: native status 0x"+f.data[1].toString(16)+" (see DFC_STATUS_* in dfc_common.h)", "err");
    return;
  }
  showResult(fReader, "Reader status code: "+rc, "err");
});
// Decode tables ported from cli_hf_des.py's `hf des info` (_DESFIRE_VENDOR /
// _DESFIRE_HW_MAJOR / _DESFIRE_STORAGE / _DESFIRE_PROTOCOL /
// _DESFIRE_HW_MAJOR_TO_SW_MAJOR), not re-derived — same source of truth the
// user's own CLI output comes from.
const DESFIRE_VENDOR = {0x04:"NXP"};
const DESFIRE_HW_MAJOR = {0x00:"MF3ICD40 (D40)",0x01:"EV1",0x12:"EV2",0x30:"Light",0x33:"EV3"};
const DESFIRE_STORAGE = {0x16:"2 KB",0x18:"4 KB",0x1A:"8 KB"};
const DESFIRE_PROTOCOL = {0x03:"ISO 14443-3",0x04:"ISO 14443-4",0x05:"ISO 14443-3, 14443-4"};
const DESFIRE_HW_MAJOR_TO_SW_MAJOR = {0x01:1,0x12:2,0x30:3,0x33:3};
function fmtVer(maj,min){ return maj==null ? "?" : (maj.toString(16)+"."+(min?min.toString(16):"0")); }
function lut(table, val, fallbackPrefix){ return val==null ? "?" : (table[val] || (fallbackPrefix+"0x"+val.toString(16).padStart(2,"0").toUpperCase())); }

// blob layout (cmd_processor_desfire_get_version, app_cmd.c): num_frames(1),
// then per frame len(1) + bytes(len), bytes = payload + SW1 SW2. Strip the
// trailing 2 SW bytes per frame to get the actual payload (mirrors
// _split_version_frames in cli_hf_des.py — the earlier version here didn't
// strip them, corrupting the decoded fields by 2 bytes).
function splitVersionFrames(blob){
  const frames = [];
  if(!blob || !blob.length) return frames;
  const n = blob[0];
  let o = 1;
  for(let i=0;i<n && o<blob.length;i++){
    const len = blob[o]; o++;
    const chunk = blob.slice(o, o+len); o += len;
    frames.push(chunk.length>=2 ? chunk.slice(0,-2) : new Uint8Array());
  }
  return frames;
}

wire("f_getversion", fReader, async () => {
  const lines = [];
  try{
    const s = await request(CU.HF14A_SCAN);
    if(s.status !== 0x00){ showResult(fReader, "No tag: "+stname(s.status), "err"); return; }
    const tags = parseHf14aScan(s.data);
    if(!tags.length){ showResult(fReader, "No tag found.", "err"); return; }
    lines.push("UID : "+tags[0].uid, "SAK : "+tags[0].sak);
  }catch(e){ showResult(fReader, "Scan failed: "+e.message, "err"); return; }
  showResult(fReader, lines.join("\n"), "ok");

  try{
    const f = await request(CU.DESFIRE_READER_GET_VERSION);
    if(f.status !== 0x00) throw new Error(stname(f.status));
    const frames = splitVersionFrames(f.data);
    const hw = frames[0] || [], sw = frames[1] || [], uidf = frames[2] || [];
    const hwMaj = hw.length>=4 ? hw[3] : null, hwMin = hw.length>=5 ? hw[4] : null;
    let swMaj = sw.length>=4 ? sw[3] : null, swMin = sw.length>=5 ? sw[4] : null;
    let hwStor = hw.length>=6 ? hw[5] : null, swStor = sw.length>=6 ? sw[5] : (hwStor);
    let hwProto = hw.length>=7 ? hw[6] : null, swProto = sw.length>=7 ? sw[6] : (hwProto);
    if(swMaj==null && hwMaj!=null){ swMaj = DESFIRE_HW_MAJOR_TO_SW_MAJOR[hwMaj] ?? hwMaj; swMin = 0; }
    if(hw.length>=1) lines.push("Vendor : "+lut(DESFIRE_VENDOR, hw[0], ""));
    lines.push("HW version : "+fmtVer(hwMaj,hwMin)+"  ("+lut(DESFIRE_HW_MAJOR,hwMaj,"hw_major ")+")  storage: "+lut(DESFIRE_STORAGE,hwStor,""));
    lines.push("SW version : "+fmtVer(swMaj,swMin)+"  storage: "+lut(DESFIRE_STORAGE,swStor,""));
    lines.push("Protocol   : "+lut(DESFIRE_PROTOCOL,swProto,""));
    if(uidf.length>=7) lines.push("Card UID   : "+bhex(uidf.slice(0,7)));
    if(uidf.length>=12) lines.push("Batch no   : "+bhex(uidf.slice(7,12)));
    if(uidf.length>=14) lines.push("Production : week "+uidf[12].toString(16).padStart(2,"0").toUpperCase()+" / 20"+uidf[13].toString(16).padStart(2,"0").toUpperCase());
    lines.push("Version (raw frames): "+frames.map(bhex).join(" | "));
  }catch(e){ lines.push("GetVersion failed: "+e.message); }
  showResult(fReader, lines.join("\n"), "ok");

  try{
    const apps = await dfcSend(DFC_INS.GET_APPLICATION_IDS);
    if(!apps.ok) throw new Error(dfcStatusName(apps.status));
    const aids = [];
    for(let o=0;o+3<=apps.data.length;o+=3) aids.push(apps.data.slice(o,o+3));
    lines.push("\nApplications : "+(aids.length ? aids.length+" found" : "none"));
    for(const aid of aids) lines.push("  AID: "+bhex(aid));
  }catch(e){ lines.push("\nGetApplicationIDs failed: "+e.message); }
  showResult(fReader, lines.join("\n"), "ok");
});

/* ---- F4: real-card reader mode, generic native DESFire commands ----
 * Native INS bytes, the 90/INS/00/00/[Lc data]/00 ISO7816 wrapping, and the
 * 0x91/0xAF "more frames" continuation all come straight from this fork's
 * own reader-side encoder (dfc_command.c / dfc_common.h) — the same shape
 * cmd_processor_desfire_get_version (app_cmd.c) already uses for GetVersion,
 * generalized here to any command via HF14A_4_READER_APDU (6004). Requires
 * the device itself in Reader mode (Device tab), independent of slot prep. */
const DFC_INS = {
  GET_APPLICATION_IDS:0x6A, SELECT_APPLICATION:0x5A, GET_FILE_IDS:0x6F,
  GET_FILE_SETTINGS:0xF5, READ_DATA:0xBD, GET_VALUE:0x6C, READ_RECORDS:0xBB,
  ADDITIONAL_FRAME:0xAF,
};
const DFC_FILE_TYPES = {0:"Standard Data",1:"Backup Data",2:"Value",3:"Linear Record",4:"Cyclic Record"};
const DFC_STATUS_NAMES = {0x00:"OK",0x0C:"NO_CHANGES",0x0E:"OUT_OF_EEPROM",0x1C:"ILLEGAL_COMMAND_CODE",
  0x1E:"INTEGRITY_ERROR",0x40:"NO_SUCH_KEY",0x7E:"LENGTH_ERROR",0x9D:"PERMISSION_DENIED",
  0x9E:"PARAMETER_ERROR",0xA0:"APPLICATION_NOT_FOUND",0xAE:"AUTHENTICATION_ERR",
  0xBE:"BOUNDARY_ERROR",0xCA:"COMMAND_ABORTED",0xF0:"FILE_NOT_FOUND"};
function dfcStatusName(s){ return DFC_STATUS_NAMES[s] || ("0x"+(s==null?0:s).toString(16)); }
function u24le(n){ return [n&0xFF,(n>>8)&0xFF,(n>>16)&0xFF]; }

// Send one native command. cmd_processor_hf14a_4_reader_apdu (app_cmd.c) does
// a full antenna-off/reset/scan_auto on EVERY call — it's a one-shot
// select-then-one-APDU primitive, not a session that survives across calls.
// So a 0x91/0xAF ("more frames follow") here can NOT be continued by sending
// another HF14A_4_READER_APDU: that call re-selects the card from scratch,
// drops its mid-exchange state, and a stray 0x90 0xAF 00 00 00 then gets
// legitimately rejected as ILLEGAL_COMMAND_CODE. Only the firmware's own
// dedicated DESFIRE_READER_GET_VERSION (F3 "Reader GetVersion") keeps one
// continuous field session across GetVersion's 3 frames — there's no generic
// multi-frame reader command exposed, so we surface this instead of hiding it.
// Returns {ok, status, data}: data is this single frame's payload (SW bytes
// stripped), status is its native DESFire status byte.
async function dfcSend(ins, data=[]){
  const apdu = data.length ? [0x90, ins, 0x00, 0x00, data.length, ...data, 0x00]
                           : [0x90, ins, 0x00, 0x00, 0x00];
  const f = await request(CU.HF14A_4_READER_APDU, apdu);
  if(f.status !== 0x00) throw new Error("reader error: "+stname(f.status));
  const d = f.data;
  if(d.length < 2) throw new Error("short APDU reply ("+d.length+" bytes)");
  const sw1 = d[d.length-2], sw2 = d[d.length-1];
  const out = d.slice(0, d.length-2);
  if(sw1 !== 0x91) throw new Error("not a DESFire-over-ISO7816 reply (SW1=0x"+sw1.toString(16)+")");
  if(sw2 === 0xAF) throw new Error("reply needs a continuation frame (0x91 0xAF) — "+
    out.length+" byte(s) received so far, but HF14A_4_READER_APDU re-selects the card on "+
    "every call and can't continue a multi-frame exchange. Use F3 \"Reader GetVersion\" for "+
    "GetVersion; for ReadData/ReadRecords, request a shorter length/count so the reply fits one frame.");
  return {ok: sw2===0x00, status: sw2, data: out};
}

const fRaw = $("f_rawResult");
wire("f_rawsend", fRaw, async () => {
  const ins = Number("0x"+$("f_rawins").value.trim());
  if(isNaN(ins) || ins<0 || ins>255) throw new Error("INS must be a hex byte, e.g. 6A");
  const dataStr = $("f_rawdata").value.trim();
  const data = dataStr ? hexBytes(dataStr) : [];
  const r = await dfcSend(ins, data);
  showResult(fRaw,
    "native status: 0x"+(r.status==null?0:r.status).toString(16)+" ("+dfcStatusName(r.status)+")\n"+
    "data ("+r.data.length+" bytes): "+bhex(r.data),
    r.ok?"ok":"err");
});

const fDump = $("f_dumpResult");
wire("f_dump", fDump, async () => {
  const lines = [];
  showResult(fDump, "Reading application list…", "ok");
  const apps = await dfcSend(DFC_INS.GET_APPLICATION_IDS);
  if(!apps.ok) throw new Error("GetApplicationIDs failed: native status "+dfcStatusName(apps.status));
  const aids = [];
  for(let o=0;o+3<=apps.data.length;o+=3) aids.push(apps.data.slice(o,o+3));
  lines.push(aids.length+" application(s): "+(aids.length?aids.map(bhex).join(", "):"(none — PICC level only)"));

  for(const aid of aids){
    lines.push("\nAID "+bhex(aid)+":");
    showResult(fDump, lines.join("\n"), "ok");
    const sel = await dfcSend(DFC_INS.SELECT_APPLICATION, aid);
    if(!sel.ok){ lines.push("  SelectApplication failed: "+dfcStatusName(sel.status)); continue; }
    const fids = await dfcSend(DFC_INS.GET_FILE_IDS);
    if(!fids.ok){ lines.push("  GetFileIDs failed: "+dfcStatusName(fids.status)); continue; }
    if(!fids.data.length){ lines.push("  (no files)"); continue; }
    for(const fileNo of fids.data){
      const fs = await dfcSend(DFC_INS.GET_FILE_SETTINGS, [fileNo]);
      if(!fs.ok){ lines.push("  file "+fileNo+": GetFileSettings failed: "+dfcStatusName(fs.status)); continue; }
      const d = fs.data;
      const type = d[0], comm = d[1], rights = d[2]|(d[3]<<8);
      const typeName = DFC_FILE_TYPES[type] || ("type 0x"+type.toString(16));
      let sizeInfo = "";
      if(type===2){ // value file: lowerLimit(4) upperLimit(4) value(4) limitedCreditEnabled(1), all LE int32
        const lo=(d[4]|(d[5]<<8)|(d[6]<<16)|(d[7]<<24))|0, hi=(d[8]|(d[9]<<8)|(d[10]<<16)|(d[11]<<24))|0, val=(d[12]|(d[13]<<8)|(d[14]<<16)|(d[15]<<24))|0;
        sizeInfo = "limits "+lo+".."+hi+", value "+val;
      } else if(type===3||type===4){ // record file: recordSize(3) maxRecords(3) currentRecords(3)
        const recSize=d[4]|(d[5]<<8)|(d[6]<<16), maxRec=d[7]|(d[8]<<8)|(d[9]<<16), curRec=d[10]|(d[11]<<8)|(d[12]<<16);
        sizeInfo = recSize+"B/record, "+curRec+"/"+maxRec+" records";
      } else { // standard/backup data file: fileSize(3)
        sizeInfo = (d[4]|(d[5]<<8)|(d[6]<<16))+" bytes";
      }
      lines.push("  file "+fileNo+": "+typeName+", comm=0x"+comm.toString(16)+", rights=0x"+rights.toString(16).padStart(4,"0")+", "+sizeInfo);
      if(comm !== 0x00){
        lines.push("    (comm_settings not plain — skipping read, needs secure messaging)");
        showResult(fDump, lines.join("\n"), "ok");
        continue;
      }
      try{
        if(type===2){
          const v = await dfcSend(DFC_INS.GET_VALUE, [fileNo]);
          lines.push(v.ok ? "    value: "+((v.data[0]|(v.data[1]<<8)|(v.data[2]<<16)|(v.data[3]<<24))|0) : "    GetValue failed: "+dfcStatusName(v.status));
        } else if(type===3||type===4){
          const rr = await dfcSend(DFC_INS.READ_RECORDS, [fileNo, ...u24le(0), ...u24le(0)]);
          lines.push(rr.ok ? "    records ("+rr.data.length+" bytes): "+bhex(rr.data) : "    ReadRecords failed: "+dfcStatusName(rr.status));
        } else {
          const rd = await dfcSend(DFC_INS.READ_DATA, [fileNo, ...u24le(0), ...u24le(0)]);
          lines.push(rd.ok ? "    data ("+rd.data.length+" bytes): "+bhex(rd.data) : "    ReadData failed: "+dfcStatusName(rd.status));
        }
      }catch(e){ lines.push("    read error: "+e.message); }
      showResult(fDump, lines.join("\n"), "ok");
    }
  }
  showResult(fDump, lines.join("\n"), "ok");
});

/* =======================================================================
 * Other tags tab: SEOS emulation, ST25TA (NFC Type 4) emulation, MIFARE Plus perso.
 * Payload layouts cross-checked against app_cmd.c's cmd_processor_seos_,
 * cmd_processor_st25ta_, cmd_processor_mfplus_ (not just chameleon_cmd.py).
 * ===================================================================== */
const oSeos = $("o_seosResult");
wire("o_seosread", oSeos, async () => {
  const f = okOrThrow(await request(CU.SEOS_READ_EMU_DATA));
  let o=0;
  const next = () => { const len=f.data[o]; const v=f.data.slice(o+1,o+1+len); o+=1+len; return v; };
  const data=next(), oid=next(), tag=next(), diversifier=next();
  const hashAlg=f.data[o], encrAlg=f.data[o+1];
  showResult(oSeos,
    "data ("+data.length+"B): "+bhex(data)+"\n"+
    "oid: "+bhex(oid)+"\ntag: "+bhex(tag)+"\ndiversifier: "+bhex(diversifier)+"\n"+
    "hash_alg: "+hashAlg+" · encr_alg: "+encrAlg, "ok");
  $("o_seosdata").value=bhex(data); $("o_seosoid").value=bhex(oid);
  $("o_seostag").value=bhex(tag); $("o_seosdiv").value=bhex(diversifier);
  $("o_seoshash").value=String(hashAlg); $("o_seosencr").value=String(encrAlg);
});
wire("o_seoswrite", oSeos, async () => {
  const data=hexBytes($("o_seosdata").value), oid=hexBytes($("o_seosoid").value),
        tag=hexBytes($("o_seostag").value), diversifier=hexBytes($("o_seosdiv").value);
  const hashAlg=Number($("o_seoshash").value), encrAlg=Number($("o_seosencr").value);
  const payload=[...lenPrefixed(data), ...lenPrefixed(oid), ...lenPrefixed(tag), ...lenPrefixed(diversifier), hashAlg, encrAlg];
  if(payload.length>4096) throw new Error("payload too large (>4096 bytes)");
  okOrThrow(await request(CU.SEOS_WRITE_EMU_DATA, payload));
  showResult(oSeos, "SEOS emulation data written.", "ok");
});
wire("o_seoskeys", oSeos, async () => {
  const auth=hexBytes($("o_seosauth").value,16), privenc=hexBytes($("o_seosprivenc").value,16), privmac=hexBytes($("o_seosprivmac").value,16);
  // cmd_processor_seos_write_emu_keys (app_cmd.c) requires exactly 16*3 bytes.
  if(auth.length!==16||privenc.length!==16||privmac.length!==16) throw new Error("auth/privenc/privmac must each be 32 hex chars (16 bytes)");
  okOrThrow(await request(CU.SEOS_WRITE_EMU_KEYS, [...auth,...privenc,...privmac]));
  showResult(oSeos, "SEOS emulation keys written.", "ok");
});

const oSt = $("o_stResult");
wire("o_stinfo", oSt, async () => {
  const f = okOrThrow(await request(CU.ST25TA_GET_INFO));
  const ndefSize=(f.data[0]<<8)|f.data[1];
  const cc=f.data.slice(2,17), pwdRead=f.data.slice(17,33), pwdWrite=f.data.slice(33,49);
  showResult(oSt, "ndef_size: "+ndefSize+"\ncc: "+bhex(cc)+"\npwd_read: "+bhex(pwdRead)+"\npwd_write: "+bhex(pwdWrite), "ok");
  $("o_stndefsize").value=String(ndefSize); $("o_stpwdread").value=bhex(pwdRead); $("o_stpwdwrite").value=bhex(pwdWrite);
});
const ST25TA_CHUNK = 240; // matches chameleon_cmd.py's ST25TA_CHUNK
wire("o_stread", oSt, async () => {
  let offset=Number($("o_stoffset").value)||0, length=Number($("o_stlen").value)||0;
  const out=[];
  while(length>0){
    const n=Math.min(length, ST25TA_CHUNK);
    const f = okOrThrow(await request(CU.ST25TA_READ_NDEF, [...u16be(offset), n]));
    out.push(...f.data); offset+=n; length-=n;
  }
  showResult(oSt, out.length+" byte(s): "+bhex(out), "ok");
});
wire("o_stwrite", oSt, async () => {
  let offset=Number($("o_stoffset").value)||0;
  const data=hexBytes($("o_stwdata").value);
  for(let i=0;i<data.length;i+=ST25TA_CHUNK){
    const chunk=data.slice(i,i+ST25TA_CHUNK);
    okOrThrow(await request(CU.ST25TA_WRITE_NDEF, [...u16be(offset+i), ...chunk]));
  }
  okOrThrow(await request(CU.SLOT_DATA_CONFIG_SAVE)); // HFSt25taELoad.on_exec calls this too
  showResult(oSt, data.length+" byte(s) written.", "ok");
});
wire("o_stconfig", oSt, async () => {
  const ndefSize=Number($("o_stndefsize").value)||0;
  const readAccess=Number($("o_stra").value), writeAccess=Number($("o_stwa").value);
  const pwdRead=hexBytes($("o_stpwdread").value,16), pwdWrite=hexBytes($("o_stpwdwrite").value,16);
  if(pwdRead.length!==16||pwdWrite.length!==16) throw new Error("passwords must each be 32 hex chars (16 bytes)");
  okOrThrow(await request(CU.ST25TA_SET_CONFIG, [...u16be(ndefSize), readAccess, writeAccess, ...pwdRead, ...pwdWrite]));
  okOrThrow(await request(CU.SLOT_DATA_CONFIG_SAVE)); // HFSt25taEConfig.on_exec calls this too
  showResult(oSt, "ST25TA config set.", "ok");
});

const oMfp = $("o_mfpResult");
wire("o_mfpinfo", oMfp, async () => {
  const f = okOrThrow(await request(CU.MFPLUS_GET_INFO));
  const level=f.data[0];
  const blockMax=f.data[1]|(f.data[2]<<8); // little-endian, unlike the rest of this file -- matches chameleon_cmd.py exactly
  showResult(oMfp, "Security level: SL"+level+(level===0?" (not personalized)":level===3?" (AES)":"")+"\nblock_max: "+blockMax, "ok");
});
wire("o_mfpperso", oMfp, async () => {
  const addrHi=sbyte($("o_mfpaddrhi").value), addrLo=sbyte($("o_mfpaddrlo").value);
  const key=hexBytes($("o_mfpkey").value,16);
  if(key.length!==16) throw new Error("MIFARE Plus key must be 32 hex chars (16 bytes AES)");
  okOrThrow(await request(CU.MFPLUS_WRITE_PERSO, [addrHi, addrLo, ...key]));
  okOrThrow(await request(CU.SLOT_DATA_CONFIG_SAVE)); // HFMfPlusWritePerso.on_exec calls this too
  showResult(oMfp, "WritePerso sent for addr 0x"+addrHi.toString(16).padStart(2,"0")+addrLo.toString(16).padStart(2,"0")+".", "ok");
});
wire("o_mfpcommit", oMfp, async () => {
  if(!confirm("Commit perso: switches the card from SL0 to SL3. Make sure all three mandatory admin keys (0x9000/0x9001/0x9003) are written first — this can't be undone.")) return;
  okOrThrow(await request(CU.MFPLUS_COMMIT_PERSO));
  okOrThrow(await request(CU.SLOT_DATA_CONFIG_SAVE)); // HFMfPlusCommitPerso.on_exec calls this too
  showResult(oMfp, "Perso committed — card is now SL3.", "ok");
});

/* =========================================================================
 * EMV tab — ported from cli_hf_des.py's sibling `emv scan` command in
 * chameleon_cli_unit.py, which runs on the firmware's single-call
 * HF14A_4_EMV_SCAN (6005): the whole PPSE/SELECT AID/GPO/READ RECORD
 * sequence happens inside one firmware call with the field held
 * continuously, so (unlike the generic DESFire reader path) there's no
 * per-call reselect to worry about. Response layout, straight from the
 * Python wrapper's own docstring (chameleon_cmd.py hf14a_4_emv_scan):
 *   uid_len(1) uid(n) atqa(2) sak(1) ats_len(1) ats(m) num_apdus(1)
 *   then per pair: cmd_len(1) cmd(n) resp_len_le(2) resp(m)
 * ===================================================================== */
const ISO3166_NUMERIC={4:"Afghanistan",8:"Albania",10:"Antarctica",12:"Algeria",16:"American Samoa",20:"Andorra",24:"Angola",28:"Antigua and Barbuda",31:"Azerbaijan",32:"Argentina",36:"Australia",40:"Austria",44:"Bahamas",48:"Bahrain",50:"Bangladesh",51:"Armenia",52:"Barbados",56:"Belgium",60:"Bermuda",64:"Bhutan",68:"Bolivia",70:"Bosnia and Herzegovina",72:"Botswana",74:"Bouvet Island",76:"Brazil",84:"Belize",86:"British Indian Ocean Territory",90:"Solomon Islands",92:"Virgin Islands, British",96:"Brunei Darussalam",100:"Bulgaria",104:"Myanmar",108:"Burundi",112:"Belarus",116:"Cambodia",120:"Cameroon",124:"Canada",132:"Cabo Verde",136:"Cayman Islands",140:"Central African Republic",144:"Sri Lanka",148:"Chad",152:"Chile",156:"China",158:"Taiwan",162:"Christmas Island",166:"Cocos (Keeling) Islands",170:"Colombia",174:"Comoros",175:"Mayotte",178:"Congo",180:"Congo, The Democratic Republic of the",184:"Cook Islands",188:"Costa Rica",191:"Croatia",192:"Cuba",196:"Cyprus",203:"Czechia",204:"Benin",208:"Denmark",212:"Dominica",214:"Dominican Republic",218:"Ecuador",222:"El Salvador",226:"Equatorial Guinea",231:"Ethiopia",232:"Eritrea",233:"Estonia",234:"Faroe Islands",238:"Falkland Islands (Malvinas)",239:"South Georgia and the South Sandwich Islands",242:"Fiji",246:"Finland",248:"\u00c5land Islands",250:"France",254:"French Guiana",258:"French Polynesia",260:"French Southern Territories",262:"Djibouti",266:"Gabon",268:"Georgia",270:"Gambia",275:"Palestine, State of",276:"Germany",288:"Ghana",292:"Gibraltar",296:"Kiribati",300:"Greece",304:"Greenland",308:"Grenada",312:"Guadeloupe",316:"Guam",320:"Guatemala",324:"Guinea",328:"Guyana",332:"Haiti",334:"Heard Island and McDonald Islands",336:"Holy See (Vatican City State)",340:"Honduras",344:"Hong Kong",348:"Hungary",352:"Iceland",356:"India",360:"Indonesia",364:"Iran",368:"Iraq",372:"Ireland",376:"Israel",380:"Italy",384:"C\u00f4te d'Ivoire",388:"Jamaica",392:"Japan",398:"Kazakhstan",400:"Jordan",404:"Kenya",408:"North Korea",410:"South Korea",414:"Kuwait",417:"Kyrgyzstan",418:"Laos",422:"Lebanon",426:"Lesotho",428:"Latvia",430:"Liberia",434:"Libya",438:"Liechtenstein",440:"Lithuania",442:"Luxembourg",446:"Macao",450:"Madagascar",454:"Malawi",458:"Malaysia",462:"Maldives",466:"Mali",470:"Malta",474:"Martinique",478:"Mauritania",480:"Mauritius",484:"Mexico",492:"Monaco",496:"Mongolia",498:"Moldova",499:"Montenegro",500:"Montserrat",504:"Morocco",508:"Mozambique",512:"Oman",516:"Namibia",520:"Nauru",524:"Nepal",528:"Netherlands",531:"Cura\u00e7ao",533:"Aruba",534:"Sint Maarten (Dutch part)",535:"Bonaire, Sint Eustatius and Saba",540:"New Caledonia",548:"Vanuatu",554:"New Zealand",558:"Nicaragua",562:"Niger",566:"Nigeria",570:"Niue",574:"Norfolk Island",578:"Norway",580:"Northern Mariana Islands",581:"United States Minor Outlying Islands",583:"Micronesia, Federated States of",584:"Marshall Islands",585:"Palau",586:"Pakistan",591:"Panama",598:"Papua New Guinea",600:"Paraguay",604:"Peru",608:"Philippines",612:"Pitcairn",616:"Poland",620:"Portugal",624:"Guinea-Bissau",626:"Timor-Leste",630:"Puerto Rico",634:"Qatar",638:"R\u00e9union",642:"Romania",643:"Russian Federation",646:"Rwanda",652:"Saint Barth\u00e9lemy",654:"Saint Helena, Ascension and Tristan da Cunha",659:"Saint Kitts and Nevis",660:"Anguilla",662:"Saint Lucia",663:"Saint Martin (French part)",666:"Saint Pierre and Miquelon",670:"Saint Vincent and the Grenadines",674:"San Marino",678:"Sao Tome and Principe",682:"Saudi Arabia",686:"Senegal",688:"Serbia",690:"Seychelles",694:"Sierra Leone",702:"Singapore",703:"Slovakia",704:"Vietnam",705:"Slovenia",706:"Somalia",710:"South Africa",716:"Zimbabwe",724:"Spain",728:"South Sudan",729:"Sudan",732:"Western Sahara",740:"Suriname",744:"Svalbard and Jan Mayen",748:"Eswatini",752:"Sweden",756:"Switzerland",760:"Syria",762:"Tajikistan",764:"Thailand",768:"Togo",772:"Tokelau",776:"Tonga",780:"Trinidad and Tobago",784:"United Arab Emirates",788:"Tunisia",792:"T\u00fcrkiye",795:"Turkmenistan",796:"Turks and Caicos Islands",798:"Tuvalu",800:"Uganda",804:"Ukraine",807:"North Macedonia",818:"Egypt",826:"United Kingdom",831:"Guernsey",832:"Jersey",833:"Isle of Man",834:"Tanzania",840:"United States",850:"Virgin Islands, U.S.",854:"Burkina Faso",858:"Uruguay",860:"Uzbekistan",862:"Venezuela",876:"Wallis and Futuna",882:"Samoa",887:"Yemen",894:"Zambia"};

// Recursive BER-TLV search: returns {tag: [value,...]} for each tag in wantTags,
// descending into constructed (0x20-bit) tags. Mirrors tlv_find in
// chameleon_cli_unit.py exactly (same truncation-tolerant behavior).
function tlvFind(data, wantTags){
  const found = {}; wantTags.forEach(t=>found[t]=[]);
  let i=0;
  while(i<data.length){
    if(i+1>=data.length) break;
    const b0=data[i];
    const tl=(b0&0x1F)===0x1F?2:1;
    if(i+tl>data.length) break;
    let tag=0; for(let k=0;k<tl;k++) tag=(tag<<8)|data[i+k];
    i+=tl;
    if(i>=data.length) break;
    const constructed = !!(b0&0x20);
    let vlen;
    if(data[i]&0x80){
      const nb=data[i]&0x7F; i++;
      if(i+nb>data.length) break;
      vlen=0; for(let k=0;k<nb;k++) vlen=(vlen<<8)|data[i+k];
      i+=nb;
    } else { vlen=data[i]; i++; }
    const truncated = (i+vlen>data.length);
    const val = truncated ? data.slice(i) : data.slice(i,i+vlen);
    i = truncated ? data.length : i+vlen;
    if(found[tag] && !truncated) found[tag].push(val);
    if(constructed){
      const sub = tlvFind(val, wantTags);
      wantTags.forEach(t=>found[t].push(...sub[t]));
    }
  }
  return found;
}
// Decode one top-level TLV into {tag,length,value} for the PM3-style JSON.
function tlvToDict(data){
  if(!data || !data.length) return null;
  const tl=(data[0]&0x1F)===0x1F?2:1;
  const tagHex = bhex(data.slice(0,tl)).replace(/ /g,"");
  let i=tl;
  if(i>=data.length) return null;
  let vlen;
  if(data[i]&0x80){ const nb=data[i]&0x7F; i++; vlen=0; for(let k=0;k<nb;k++) vlen=(vlen<<8)|data[i+k]; i+=nb; }
  else { vlen=data[i]; i++; }
  const val = data.slice(i, i+vlen);
  return {tag:tagHex, length:vlen.toString(16).padStart(2,"0").toUpperCase(), value:bhex(val)};
}
function panLuhn(panHex){
  const digits = panHex.split("").filter(c=>/[0-9]/.test(c)).map(Number).reverse();
  let total=0;
  digits.forEach((d,i)=>{ if(i%2===0) total+=d; else { const dd=d*2; total += dd>9?dd-9:dd; } });
  return total%10===0;
}

let lastEmvResult = null;
const eCard = $("e_cardResult"), eApdu = $("e_apduResult");

wire("e_scan", eCard, async () => {
  showResult(eCard, "Scanning… place card on antenna.", "ok");
  showResult(eApdu, "", "ok");
  const f = await request(CU.HF14A_4_EMV_SCAN);
  if(f.status !== 0x00 || !f.data.length){ showResult(eCard, "No card found or scan failed: "+stname(f.status), "err"); return; }
  const d = f.data;
  let o=0;
  const uidLen=d[o]; o++;
  const uid=d.slice(o,o+uidLen); o+=uidLen;
  const atqa=d.slice(o,o+2); o+=2;
  const sak=d[o]; o++;
  const atsLen=d[o]; o++;
  const ats=d.slice(o,o+atsLen); o+=atsLen;
  const numApdus=d[o]; o++;
  const pairs=[];
  for(let i=0;i<numApdus;i++){
    const cl=d[o]; o++;
    const c=d.slice(o,o+cl); o+=cl;
    const rl=d[o]|(d[o+1]<<8); o+=2;
    const r=d.slice(o,o+rl); o+=rl;
    pairs.push({cmd:c,resp:r});
  }
  showResult(eApdu, pairs.map((p,i)=>"#"+i+" -> "+bhex(p.cmd)+"\n   <- "+bhex(p.resp)).join("\n\n"), "ok");

  const lines = [];
  lines.push("UID  : "+bhex(uid));
  lines.push("ATQA : "+bhex(atqa)+"  SAK: "+bhex([sak]));
  lines.push("ATS  : "+bhex(ats));
  if(!pairs.length){ lines.push("\nNo APDU responses captured."); showResult(eCard, lines.join("\n"), "err"); return; }

  const result = {File:{Created:"chameleonultra.html emv scan"},
    Card:{Contactless:{Communication:"iso14443-4a", UID:bhex(uid), ATQA:bhex(atqa), SAK:bhex([sak]), ATS:bhex(ats)}}};

  const ppseResp = pairs[0].resp;
  const ppseBody = ppseResp.length>=2 ? ppseResp.slice(0,-2) : ppseResp;
  result.PPSE = {AID:"32 50 41 59 2E 53 59 53 2E 44 44 46 30 31", FCITemplate: tlvToDict(ppseBody)};
  lines.push("\nPPSE OK ("+ppseResp.length+"b)");

  const extraData=[];
  if(pairs.length>=2){
    const selResp = pairs[1].resp, selCmd = pairs[1].cmd;
    const selBody = selResp.length>=2 ? selResp.slice(0,-2) : selResp;
    const aidBytes = selCmd.length>6 ? selCmd.slice(5,-1) : [];
    result.Application = {AID: bhex(aidBytes), FCITemplate: tlvToDict(selBody)};
    const aidKnown = lookupIsoAid(aidBytes);
    lines.push("SELECT AID OK ("+selResp.length+"b)  AID "+bhex(aidBytes)+(aidKnown ? "  ("+aidKnown[0]+": "+aidKnown[1]+")" : ""));
    if(result.Application.FCITemplate) extraData.push(...hexBytes(result.Application.FCITemplate.value));
  }
  const allRecordData=[];
  if(pairs.length>=3 && result.Application){
    const gpoResp = pairs[2].resp;
    const gpoBody = gpoResp.length>=2 ? gpoResp.slice(0,-2) : gpoResp;
    result.Application.GPO = tlvToDict(gpoBody);
    lines.push("GPO OK ("+gpoResp.length+"b)");
    if(result.Application.GPO) extraData.push(...hexBytes(result.Application.GPO.value));
    const records=[];
    for(let i=3;i<pairs.length;i++){
      const cb=pairs[i].cmd, rb=pairs[i].resp;
      const sfiN = cb.length>=4 ? ((cb[3]>>3)&0x1F) : 0;
      const recN = cb.length>=3 ? cb[2] : 0;
      const rBody = rb.length>=2 ? rb.slice(0,-2) : rb;
      lines.push("READ RECORD SFI="+sfiN+" rec="+recN+" OK ("+rb.length+"b)");
      const dict = tlvToDict(rBody);
      records.push({SFI:sfiN.toString(16).padStart(2,"0").toUpperCase(), RecordNum:recN.toString(16).padStart(2,"0").toUpperCase(), Offline:"01", Data:dict});
      if(dict) allRecordData.push(...hexBytes(dict.value));
    }
    result.Application.Records = records;
  }

  const tags = tlvFind(allRecordData, [0x5A,0x57,0x5F24,0x5F20,0x5F28]);
  const appTags = tlvFind([...allRecordData, ...extraData], [0x9F12,0x50]);

  lines.push("\n── Card Details ──────────────────────");
  const seenLabels=new Set();
  [...(tags[0x50]||[]), ...(appTags[0x50]||[])].forEach(v=>{
    const lbl=bytesToAscii(v).trim();
    if(lbl && !seenLabels.has(lbl)){ seenLabels.add(lbl); lines.push("App Label     : "+lbl); }
  });

  let panHex=null;
  for(const v of (tags[0x57]||[])){
    const t2=bhex(v).replace(/ /g,"");
    const sep=t2.indexOf("D");
    if(sep>0){ panHex=t2.slice(0,sep); break; }
  }
  if(!panHex){
    for(const v of (tags[0x5A]||[])){
      const raw=bhex(v).replace(/ /g,"");
      panHex = raw.endsWith("F") ? raw.replace(/F+$/,"") : raw;
      break;
    }
  }
  if(panHex){
    const panFmt = (panHex.match(/.{1,4}/g)||[panHex]).join(" ");
    lines.push("PAN           : "+panFmt+"  Luhn: "+(panLuhn(panHex)?"OK":"FAIL"));
    (result.Decoded = result.Decoded||{}).PAN = panHex;
  } else lines.push("PAN           : not found");

  let expiryFound=false;
  for(const v of (tags[0x5F24]||[])){
    if(v.length===3){
      const exp=bhex(v).replace(/ /g,"");
      const expFmt = "20"+exp.slice(0,2)+"/"+exp.slice(2,4);
      lines.push("Expiry        : "+expFmt);
      (result.Decoded=result.Decoded||{}).Expiry=expFmt;
      expiryFound=true;
    }
  }
  if(!expiryFound && panHex){
    for(const v of (tags[0x57]||[])){
      const t2=bhex(v).replace(/ /g,"");
      const sep=t2.indexOf("D");
      if(sep>0 && t2.length>=sep+5){
        const yymm=t2.slice(sep+1,sep+5);
        if(/^\d{4}$/.test(yymm)){
          const expFmt="20"+yymm.slice(0,2)+"/"+yymm.slice(2,4);
          lines.push("Expiry        : "+expFmt+" (from Track2)");
          (result.Decoded=result.Decoded||{}).Expiry=expFmt;
          expiryFound=true;
          break;
        }
      }
    }
  }
  if(!expiryFound) lines.push("Expiry        : not found");

  for(const v of (tags[0x5F20]||[])){
    if(v.length && v.every(b=>b>=0x20&&b<=0x7E)){
      const name=bytesToAscii(v).trim();
      if(name){ lines.push("Cardholder    : "+name); (result.Decoded=result.Decoded||{}).CardholderName=name; }
    }
  }

  for(const v of (tags[0x5F28]||[])){
    const country = (bhex(v).replace(/ /g,"").replace(/^0+/,"")) || "0";
    const name = ISO3166_NUMERIC[parseInt(country,10)];
    lines.push("Issuer Country: "+country+(name?" ("+name+")":""));
    const dec = result.Decoded = result.Decoded||{};
    dec.IssuerCountry = country;
    if(name) dec.IssuerCountryName = name;
  }

  for(const v of (appTags[0x9F12]||[])){
    const name=bytesToAscii(v).trim();
    if(name && !seenLabels.has(name)) lines.push("App Name      : "+name);
  }

  lines.push("──────────────────────────────────────");
  lastEmvResult = result;
  showResult(eCard, lines.join("\n"), "ok");
});

wire("e_savejson", eCard, async () => {
  if(!lastEmvResult) throw new Error("scan a card first");
  const blob = new Blob([JSON.stringify(lastEmvResult, null, 2)], {type:"application/json"});
  const url = URL.createObjectURL(blob);
  const a=document.createElement("a"); a.href=url; a.download="emv-scan.json";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(url), 2000);
});

/* ---------------------------------------------------------------------
 * Shell tab (#tab-shell): one raw DATA_CMD_* frame per Send, shown as a
 * scrolling log. Command accepts a CU name, decimal id, or 0x-hex -- same
 * three forms terminal.js's "hw raw" parses, kept consistent on purpose.
 * Up/Down recall previous command+payload pairs like a real shell.
 * ------------------------------------------------------------------- */
(function(){
  const shCmd = $("sh_cmd"), shData = $("sh_data"), shLog = $("sh_log"),
        shList = $("sh_cmdlist"), shSend = $("sh_send"), shClear = $("sh_clear");
  if(!shCmd || !shData || !shLog || !shSend) return; // Shell tab not present in this build

  if(shList){
    for(const name of Object.keys(CU).sort()){
      const opt = document.createElement("option");
      opt.value = name;
      shList.appendChild(opt);
    }
  }

  function parseCmdId(s){
    s = (s||"").trim();
    if(!s) throw new Error("command is required");
    if(/^0x[0-9a-f]+$/i.test(s)) return parseInt(s, 16);
    if(/^-?\d+$/.test(s)) return parseInt(s, 10);
    const up = s.toUpperCase();
    if(up in CU) return CU[up];
    throw new Error("unknown command: "+s);
  }

  function logLine(text, cls){
    const row = document.createElement("div");
    if(cls) row.className = cls;
    row.textContent = text;
    shLog.appendChild(row);
    shLog.scrollTop = shLog.scrollHeight;
  }

  const history = []; // {cmd, data}
  let histIdx = 0;

  async function send(){
    const cmdStr = shCmd.value, dataStr = shData.value;
    let cmdId;
    try{ cmdId = parseCmdId(cmdStr); }
    catch(e){ logLine("error: "+e.message, "sh-err"); return; }
    const payload = hexBytes(dataStr);
    logLine("> "+cmdStr+(dataStr?" "+dataStr:"")+"  (cmd "+cmdId+")", "sh-tx");
    history.push({cmd:cmdStr, data:dataStr});
    histIdx = history.length;
    try{
      need();
      const f = await request(cmdId, payload);
      logLine("status: 0x"+f.status.toString(16).padStart(2,"0")+" "+stname(f.status),
               OK_STATUSES.has(f.status) ? "sh-ok" : "sh-err");
      logLine("data: "+((f.data && f.data.length) ? bhex(f.data) : "(none)"), "sh-meta");
    }catch(e){
      logLine("error: "+e.message, "sh-err");
    }
  }

  shSend.addEventListener("click", () => { shSend.disabled = true; send().finally(()=>{ shSend.disabled = false; }); });
  if(shClear) shClear.addEventListener("click", () => { shLog.textContent = ""; });

  function recall(dir){
    if(history.length===0) return;
    histIdx = Math.max(0, Math.min(history.length, histIdx+dir));
    const h = history[histIdx] || {cmd:"", data:""};
    shCmd.value = h.cmd; shData.value = h.data;
  }
  for(const el of [shCmd, shData]){
    el.addEventListener("keydown", (ev) => {
      if(ev.key === "Enter"){ ev.preventDefault(); send(); }
      else if(ev.key === "ArrowUp"){ ev.preventDefault(); recall(-1); }
      else if(ev.key === "ArrowDown"){ ev.preventDefault(); recall(1); }
    });
  }
})();
