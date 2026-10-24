"use strict";
const NUS = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
const NUS_TX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e";
const NUS_RX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e";
const CMD_GET_RESULT = 7004, STATUS_OK = 0x68;
const CMD_SET_MODE = 7001, CMD_CLEAR = 7005, MODE_EMUL = 6, CMD_GET_MODE = 7000, CMD_TRIGGER = 7006, CMD_DISARM = 7009, MODE_CANARY = 9;
const STATES = ["disarmed","armed, waiting","mode select","armed, running"];
const MODES = {0:"none",1:"autoclone",2:"read_replay",3:"authtrace",4:"slot_cycle",5:"dict_check",6:"emul_trace",7:"relay",8:"hf14a_tap_sniff",9:"nfc_canary",10:"gdb_gateway",11:"u2f"};
const CMD_EVENT = 7010;
const CMD_GET_CONFIG = 7002, CMD_SET_CONFIG = 7003, CMD_GET_SIZES = 7007, CMD_RELAY_DIAG = 7008;
const MODE_AUTHTRACE = 3, MODE_SLOT = 4, MODE_RELAY = 7, MODE_TAP = 8;
const MODE_AUTOCLONE = 1, MODE_READ_REPLAY = 2, MODE_DICT = 5, MODE_GDB = 10, MODE_U2F = 11;
const ACTION_MODES = [MODE_READ_REPLAY, MODE_AUTOCLONE, MODE_DICT];  /* trigger-driven reader modes */
/* gdb_gateway sets writes_slot, so the firmware gates it behind host opt-in too */
const OPTIN_MODES = [MODE_AUTOCLONE, MODE_READ_REPLAY, MODE_GDB];
const FLAG_OPTIN = 0x01;
const SESSION_MODES = [MODE_EMUL, MODE_AUTHTRACE, MODE_TAP];  /* identical session-record format */
const LEVELS = ["field","poll","select","engage"];
const TYPES = {1:"Alert",2:"Window ended",3:"Test"};
const FLAGS = {1:"forced close",2:"disarmed"};
const $ = id => document.getElementById(id);

/* ---- command names (mirrors software/script/canary_cmd.py) ---- */
const NAMES = {0x7A:"Apple MagSafe WUPA variant (7-bit)",0x7B:"Apple MagSafe WUPA variant (7-bit)",0x7C:"Apple MagSafe WUPA variant (7-bit)",0x7D:"Apple MagSafe WUPA variant (7-bit)",
0x78:"Topaz RID (NFC Type 1 poll)",0x00:"00: Topaz RALL, or noise / non-Type-A signal",0x05:"REQB/WUPB (Type B poll)",0x26:"REQA",0x52:"WUPA",0x93:"SEL CL1",0x95:"SEL CL2",0x97:"SEL CL3",0x50:"HLTA",0xE0:"RATS",
0x6A:"ECP (Apple Enhanced Contactless Polling)",0x40:"magic wake (Gen1, 7-bit)",0x43:"magic wake (Gen1, step 2)",
0x60:"AUTH-A (Classic) / GET_VERSION (UL/NTAG)",0x61:"AUTH-B (Classic)",0xA0:"WRITE (Classic)",0xC0:"DECREMENT",
0xC1:"INCREMENT",0xC2:"RESTORE (Classic) / ISO-DEP DESELECT",0xB0:"TRANSFER",0x30:"READ",0x3A:"FAST_READ",
0x39:"READ_CNT",0x3C:"READ_SIG",0x1A:"AUTH (UL-C)",0x1B:"PWD_AUTH (NTAG/UL EV1)",0xA2:"WRITE (UL/NTAG)"};

function cmdName(level, c){
  if(level===0) return "-";
  if(NAMES[c]) return NAMES[c];
  if((c&0xE2)===0x02) return "ISO-DEP I-block (APDU)";
  if((c&0xE6)===0xA2) return "ISO-DEP R(ACK)";
  if((c&0xE6)===0xB2) return "ISO-DEP R(NAK)";
  if((c&0xF7)===0xC2) return "ISO-DEP DESELECT";
  if((c&0xF7)===0xF2) return "ISO-DEP WTX";
  if((c&0xF0)===0xD0) return "PPS";
  return "unknown";
}

/* ---- Chameleon data-frame parser (same as canary_listen.py) ---- */
const lrc = a => (0x100 - a.reduce((s,x)=>s+x,0)) & 0xFF;
function makeFrame(cmd,data=[]){    // request frame, optional payload
  const h=[0x11,0,(cmd>>8)&255,cmd&255,0,0,(data.length>>8)&255,data.length&255,0];
  h[1]=lrc(h.slice(0,1)); h[8]=lrc(h.slice(0,8));
  return new Uint8Array([...h,...data,lrc(data)]);
}

class Parser{
  constructor(){this.b=[];}
  feed(bytes){
    this.b.push(...bytes);
    const out=[], b=this.b;
    for(;;){
      while(b.length && b[0]!==0x11) b.shift();
      if(b.length<9) break;
      if(b[1]!==lrc(b.slice(0,1)) || b[8]!==lrc(b.slice(0,8))){ b.shift(); continue; }
      const n=(b[6]<<8)|b[7], total=9+n+1;
      if(b.length<total) break;
      const data=b.slice(9,9+n), ck=b[9+n], b0s=b.slice(0,9);
      const cmd=(b[2]<<8)|b[3];
      b.splice(0,total);
      if(ck===lrc(data)) out.push({cmd,status:(b0s[4]<<8)|b0s[5],data});
    }
    return out;
  }
}

/* ---- state ---- */
let device=null, tx=null, rx=null, pending=null, parser=new Parser(), lastSeq=null, wake=null, wantConn=false, retry=null;
let events=[];

function setStatus(kind, title, sub){
  $("lamp").className="lamp "+kind;
  $("st").textContent=title; $("stsub").textContent=sub||"";
}
function showErr(t){ $("err").textContent=t||""; $("err").classList.toggle("show",!!t); }

/* ---- decode a 10-byte event payload (little-endian, see nfc_canary_core.h) ---- */
function decode(p){
  const u16=(i)=>p[i]|(p[i+1]<<8);
  return {type:p[0], level:p[1], cmd:p[2], seq:p[3], dur:u16(4), fields:p[6], flags:p[7], frames:u16(8), t:Date.now()};
}

/* ---- alerting ---- */
let actx=null;
function beep(level){
  if(!$("oSound").checked) return;
  try{
    actx=actx||new (window.AudioContext||window.webkitAudioContext)();
    const n = level>=3?3:level>=2?2:1;
    for(let i=0;i<n;i++){
      const o=actx.createOscillator(), g=actx.createGain();
      o.frequency.value=level>=3?880:660; o.connect(g); g.connect(actx.destination);
      const t=actx.currentTime+i*0.22; g.gain.setValueAtTime(0.2,t); g.gain.exponentialRampToValueAtTime(0.001,t+0.18);
      o.start(t); o.stop(t+0.2);
    }
  }catch(e){}
}
function alertUser(ev,text){
  beep(ev.level);
  if($("oVib").checked && navigator.vibrate) navigator.vibrate(ev.level>=3?[300,100,300,100,300]:[200]);
  if($("oNotif").checked && "Notification" in window && Notification.permission==="granted"){
    try{ new Notification("NFC canary: "+text); }catch(e){}
  }
  $("lamp").classList.add("alert"); setTimeout(()=>$("lamp").classList.remove("alert"),3200);
}

/* ---- log rendering ---- */
function fmtTime(t){ return new Date(t).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"}); }
function render(){
  const ul=$("log"); ul.textContent="";
  $("empty").style.display=events.length?"none":"block";
  for(const e of events){
    const li=document.createElement("li");
    li.className="ev"+(e.type===3?" test":" l"+e.level);
    const top=document.createElement("div"); top.className="top";
    const s=document.createElement("strong");
    s.textContent = e.type===3 ? "Test event" : (TYPES[e.type]||"Event")+": "+LEVELS[e.level];
    const tm=document.createElement("time"); tm.textContent=fmtTime(e.t);
    top.append(s,tm); li.append(top);
    if(e.type!==3){
      const d=document.createElement("div"); d.className="det";
      let t = e.level>0 ? "command 0x"+e.cmd.toString(16).padStart(2,"0")+" – "+cmdName(e.level,e.cmd) : "reader field detected";
      t += " · window "+e.dur+" s";
      if(e.type===2){ t += " · "+e.fields+" field-ons · "+e.frames+" frames"; const f=Object.keys(FLAGS).filter(b=>e.flags&b).map(b=>FLAGS[b]); if(f.length) t+=" · "+f.join(", "); }
      d.textContent=t; li.append(d);
    }
    if(e.missed){ const g=document.createElement("div"); g.className="gap"; g.textContent=e.missed+" event(s) missed before this one – see the device log."; li.append(g); }
    ul.append(li);
  }
}
function save(){ try{ localStorage.setItem("canaryEvents", JSON.stringify(events.slice(0,100))); }catch(e){} }
function load(){ try{ events=JSON.parse(localStorage.getItem("canaryEvents")||"[]"); }catch(e){ events=[]; } }

function onPayload(p){
  if(p.length!==10) return;
  const ev=decode(p);
  // seq restarts at 0 every time the device is armed, so a 0 (unless it follows 255)
  // means a fresh arm, not a gap.
  ev.missed = (lastSeq===null || (ev.seq===0 && lastSeq!==255)) ? 0 : (ev.seq-lastSeq-1)&0xFF;
  lastSeq=ev.seq;
  events.unshift(ev); events=events.slice(0,100); save(); render();
  if(ev.type===1) alertUser(ev, LEVELS[ev.level]+(ev.level>0?" ("+cmdName(ev.level,ev.cmd)+")":""));
  if(ev.type===3){ beep(1); if($("oVib").checked&&navigator.vibrate) navigator.vibrate(100); }
}

/* ---- Bluetooth ---- */
function onNotify(e){
  const v=new Uint8Array(e.target.value.buffer);
  for(const f of parser.feed(Array.from(v))){
    if(f.cmd===CMD_EVENT) onPayload(f.data);
    else if(pending && f.cmd===pending.cmd){ const p=pending; pending=null; p.resolve(f); }
  }
}
async function openLink(){
  setStatus("wait","Connecting…",device.name||"");
  const server=await device.gatt.connect();
  const svc=await server.getPrimaryService(NUS);
  tx=await svc.getCharacteristic(NUS_TX);
  rx=await svc.getCharacteristic(NUS_RX);
  parser=new Parser(); lastSeq=null;
  tx.addEventListener("characteristicvaluechanged", onNotify);
  await tx.startNotifications();
  setStatus("on","Listening",(device.name||"Chameleon")+" · alerts will appear below");
  $("btn").textContent="Disconnect";
  showErr("");
  readState().catch(()=>{});
  await keepAwake();
}
async function connect(){
  showErr("");
  if(!navigator.bluetooth){ showErr("Web Bluetooth isn't available here. Use Chrome or Edge on Android/desktop, or the Bluefy browser on iOS, and open this page over HTTPS."); return; }
  try{
    if(!device){
      device=await navigator.bluetooth.requestDevice({
        filters:[{namePrefix:"Chameleon"},{services:[NUS]}], optionalServices:[NUS]});
      device.addEventListener("gattserverdisconnected", onDrop);
    }
    wantConn=true;
    if($("oNotif").checked && "Notification" in window && Notification.permission==="default") Notification.requestPermission();
    await openLink();
  }catch(e){
    if(e.name==="NotFoundError"){ setStatus("","Not connected","No device chosen."); return; }
    showErr("Could not connect: "+e.message+" If pairing is enabled on the device, pair it in your system Bluetooth settings first (key: hw settings blepair).");
    setStatus("","Not connected","");
    scheduleRetry();
  }
}
function onDrop(){
  $("btn").textContent="Connect";
  if(pending){ pending.reject(new Error("connection lost")); pending=null; }
  if(wantConn && $("oRe").checked){ setStatus("wait","Connection lost","Reconnecting…"); alertUser({level:3},"connection to the canary was lost"); scheduleRetry(); }
  else setStatus("","Not connected","");
}
function scheduleRetry(){
  if(!wantConn || !$("oRe").checked || !device) return;
  clearTimeout(retry);
  retry=setTimeout(async()=>{
    try{ await openLink(); }catch(e){ setStatus("wait","Reconnecting…",e.message); scheduleRetry(); }
  },5000);
}
function disconnect(){
  wantConn=false; clearTimeout(retry);
  if(device&&device.gatt.connected) device.gatt.disconnect();
  releaseWake(); setStatus("","Not connected",""); $("btn").textContent="Connect";
}
async function keepAwake(){
  if(!$("oWake").checked || !("wakeLock" in navigator)) return;
  try{ wake=await navigator.wakeLock.request("screen"); }catch(e){}
}
function releaseWake(){ if(wake){ wake.release().catch(()=>{}); wake=null; } }
document.addEventListener("visibilitychange",()=>{ if(document.visibilityState==="visible" && wantConn) keepAwake(); });

// Nordic UART RX is a raw byte pipe: data_frame_receive() (dataframe.c) just
// appends whatever arrives into its parser buffer, byte-stream style, the
// same as USB-serial bytes trickling in — one logical frame does not need to
// land in a single GATT write. That matters because a single write must fit
// in one ATT PDU (MTU-3): this firmware's own max MTU is 247B (sdk_config.h),
// so a write over ~244B needs splitting. writeValueWithoutResponse is a
// "Write Command": its promise resolves once the OS has queued the packet,
// not once it's actually gone over the air, so back-to-back calls give no
// real backpressure — on BlueZ in particular this reliably overruns the
// controller's write queue and surfaces as "GATT Error Unknown", even with
// small chunks and even though each await "succeeded". writeValueWithResponse
// is a "Write Request": it only resolves once the peripheral ATT-acks the
// write, so each fragment is paced by the actual link and buffer overflow
// can't happen. The NUS RX characteristic advertises both write_wo_resp and
// write properties (ble_nus.c), so this is supported by the firmware.
const BLE_WRITE_CHUNK = 180;
async function rawWrite(bytes){
  for(let o=0;o<bytes.length;o+=BLE_WRITE_CHUNK){
    await rx.writeValueWithResponse(bytes.slice(o, o+BLE_WRITE_CHUNK));
  }
}

/* ---- fetch the device's saved log (GET_RESULT 7004, repeated until an empty chunk) ---- */
function request(cmd,data=[]){
  return new Promise(async (resolve,reject)=>{
    const t=setTimeout(()=>{ pending=null; reject(new Error("no reply over Bluetooth. If a USB serial session (the CLI, a terminal) is open, the device sends its answer there instead. Close it and try again.")); },6000);
    pending={cmd,resolve:f=>{clearTimeout(t);resolve(f);},reject:e=>{clearTimeout(t);reject(e);}};
    try{ await rawWrite(makeFrame(cmd,data)); }
    catch(e){ clearTimeout(t); pending=null; reject(e); }
  });
}
function parseRecords(raw){
  const out=[];
  for(let o=0;o+16<=raw.length;o+=16){
    const r=raw.slice(o,o+16); if(r[0]!==1) continue;
    out.push({level:r[1],cmd:r[2],epoch:r[3],start:(r[4]|(r[5]<<8)|(r[6]<<16)|(r[7]<<24))>>>0,
      dur:r[8]|(r[9]<<8),fields:r[10]|(r[11]<<8),frames:r[12]|(r[13]<<8),flags:r[14]});
  }
  return out;
}
async function fetchSaved(){
  const btn=$("fetch"), st=$("fstat");
  if(!(device&&device.gatt.connected&&rx)){ st.textContent="Not connected. Press Connect first."; return; }
  btn.disabled=true; st.textContent="Fetching…";
  try{
    await readState();
    const raw=[];
    for(let i=0;i<200;i++){
      const f=await request(CMD_GET_RESULT);
      console.log("GET_RESULT reply",i,"status",f.status,"bytes",f.data.length);
      if(f.status!==STATUS_OK) throw new Error("device returned status 0x"+f.status.toString(16)+" (is nfc_canary the active standalone mode?)");
      const chunk=f.data.slice(4);
      if(!chunk.length) break;
      raw.push(...chunk);
    }
    if(SESSION_MODES.includes(devMode)){
      const ss=parseSessions(raw); renderSessions(ss);
      st.textContent = ss.length ? ss.length+" captured session(s) (oldest first)." : "No sessions captured yet.";
    } else if(devMode===MODE_RELAY){
      const ss=parseRelay(raw); renderRelay(ss);
      st.textContent = ss.length ? ss.length+" relay session(s) (oldest first)." : "No relay sessions stored.";
    } else if(devMode===MODE_SLOT){
      $("saved").textContent=""; st.textContent="slot_cycle keeps no log.";
    } else if(devMode===MODE_GDB){
      $("saved").textContent=""; st.textContent="gdb_gateway keeps no log; it serves GDB over USB-CDC.";
    } else if(devMode===MODE_U2F){
      $("saved").textContent=""; st.textContent="u2f keeps no log; it runs passively over NFC.";
    } else if(devMode===MODE_READ_REPLAY){
      const recs=parseReadReplay(raw); renderReadReplay(recs);
      st.textContent = recs.length ? recs.length+" clone(s) stored." : "No clones stored.";
    } else if(devMode===MODE_AUTOCLONE){
      const recs=parseAutoclone(raw); renderAutoclone(recs);
      st.textContent = recs.length ? recs.length+" autoclone attempt(s) stored." : "No autoclone attempts stored.";
    } else if(devMode===MODE_DICT){
      const recs=parseDict(raw); renderDict(recs);
      const found=recs.filter(r=>r.foundA||r.foundB).length;
      st.textContent = recs.length ? found+"/"+recs.length+" sector(s) with a known key." : "No sectors checked.";
    } else {
      const recs=parseRecords(raw);
      renderSaved(recs);
      st.textContent = recs.length ? recs.length+" window(s) stored on the device, newest first. Start is seconds after that arm." : "The device log is empty.";
    }
  }catch(e){ st.textContent="Could not fetch: "+e.message; }
  btn.disabled=false;
}
function stripParity(raw,bits){
  if(bits>=8 && bits%9===0){
    const n=bits/9, out=[], all=[];
    for(const b of raw) for(let i=0;i<8;i++) all.push((b>>i)&1);
    for(let k=0;k<n;k++){ let v=0; for(let i=0;i<8;i++) v|=all[k*9+i]<<i; out.push(v); }
    return {data:out,bits:n*8};
  }
  return {data:Array.from(raw),bits};
}
function parseFrames(t){
  const fr=[]; let o=0;
  while(o+2<=t.length){
    const hdr=(t[o]<<8)|t[o+1], tx=!!(hdr&0x8000), bits=hdr&0x7FFF, nb=(bits+7)>>3; o+=2;
    if(o+nb>t.length) break;
    const s=stripParity(t.slice(o,o+nb),bits); fr.push({tx,bits:s.bits,data:s.data}); o+=nb;
  }
  return fr;
}
function parseSessions(raw){
  const out=[]; let o=0;
  while(o+4<=raw.length){
    const len=raw[o+2]|(raw[o+3]<<8); const t=raw.slice(o+4,o+4+len);
    out.push({num:raw[o],status:raw[o+1],frames:parseFrames(t)}); o+=4+len;
  }
  return out;
}
const hex=a=>a.map(x=>x.toString(16).padStart(2,"0")).join("");
function frameLabel(f,prev){
  const d=f.data;
  // Classic auth exchange: AUTH cmd -> nt (card) -> nr+ar (reader) -> at (card)
  if(!f.tx && f.bits===64 && prev && prev.tx && prev.bits===32) return "nr + ar (reader answer)";
  if(f.tx && f.bits===32 && prev){
    if(!prev.tx && prev.bits===32 && (prev.data[0]===0x60||prev.data[0]===0x61)) return "nt (card nonce)";
    if(!prev.tx && prev.bits===64) return "at (card answer)";
  }
  if(!f.tx){
    if(f.bits===7) return cmdName(1,d[0]);
    if(d[0]===0x93||d[0]===0x95||d[0]===0x97) return d[1]===0x70?"SELECT":"anticollision";
    return d.length>1?cmdName(3,d[0]):"";
  }
  if(f.bits===16) return "ATQA";
  if(f.bits===40||(d.length===5&&f.bits===40)) return "UID + BCC";
  if(f.bits===24) return "SAK";
  if(d.length===4) return "nonce / answer";
  return "";
}
function extractNonces(fr){
  const out=[]; let uid=null;
  fr.forEach((f,i)=>{
    const d=f.data; if(!d.length) return;
    if(!f.tx && (d[0]===0x93||d[0]===0x95||d[0]===0x97) && d.length>=6 && d[1]===0x70 && !(d[0]===0x93&&d[2]===0x88)) uid=hex(d.slice(2,6));
    if(f.tx && f.bits===40 && d.length===5 && uid===null && (d[0]^d[1]^d[2]^d[3])===d[4]) uid=hex(d.slice(0,4));
    if(!f.tx && (d[0]===0x60||d[0]===0x61) && d.length>=2){
      const a=fr[i+1], b=fr[i+2], c=fr[i+3];
      if(!a||!a.tx||a.data.length!==4||!b||b.tx||b.data.length!==8) return;
      out.push({uid:uid||"00000000",block:d[1],key:d[0]===0x60?"A":"B",nt:hex(a.data),nr:hex(b.data.slice(0,4)),ar:hex(b.data.slice(4)),at:(c&&c.tx&&c.data.length===4)?hex(c.data):null});
    }
  });
  return out;
}
function renderSessions(ss){
  const ul=$("saved"); ul.textContent="";
  for(const s of ss){
    const li=document.createElement("li"); li.className="ev l2";
    const rd=s.frames.filter(f=>!f.tx).length, cd=s.frames.length-rd;
    const top=document.createElement("div"); top.className="top";
    const st=document.createElement("strong"); st.textContent="Session "+s.num;
    const tm=document.createElement("time"); tm.textContent=s.status===0?"complete":"partial (cut short)";
    top.append(st,tm);
    const d=document.createElement("div"); d.className="det"; d.textContent=s.frames.length+" frames: "+rd+" reader→card, "+cd+" card→reader";
    li.append(top,d);
    const ns=extractNonces(s.frames);
    for(const n of ns){
      const e=document.createElement("div"); e.className="nonce";
      e.textContent="Classic auth key"+n.key+" block "+n.block+" · uid "+n.uid+" · nt "+n.nt+" · nr "+n.nr+" · ar "+n.ar+(n.at?" · at "+n.at:"");
      li.append(e);
    }
    const dt=document.createElement("details"), sm=document.createElement("summary"); sm.textContent="Frames";
    const pre=document.createElement("pre");
    pre.textContent=s.frames.map((f,i)=>String(i).padStart(3)+"  "+(f.tx?"card→rdr":"rdr→card")+"  "+String(f.bits).padStart(4)+"b  "+hex(f.data).padEnd(40)+"  "+frameLabel(f,s.frames[i-1])).join("\n");
    dt.append(sm,pre); li.append(dt); ul.append(li);
  }
}
function renderSaved(recs){
  const ul=$("saved"); ul.textContent="";
  for(const r of recs.slice().reverse()){
    const li=document.createElement("li"); li.className="ev l"+Math.min(r.level,3);
    const top=document.createElement("div"); top.className="top";
    const s=document.createElement("strong"); s.textContent=(LEVELS[r.level]||"level "+r.level);
    const tm=document.createElement("time"); tm.textContent="arm "+r.epoch+" · start "+r.start+" s";
    top.append(s,tm);
    const d=document.createElement("div"); d.className="det";
    let t=(r.level>0?"command 0x"+r.cmd.toString(16).padStart(2,"0")+" – "+cmdName(r.level,r.cmd)+" · ":"")+
      r.dur+" s · "+r.fields+" field-ons · "+r.frames+" frames";
    const f=Object.keys(FLAGS).filter(b=>r.flags&b).map(b=>FLAGS[b]); if(f.length) t+=" · "+f.join(", ");
    d.textContent=t; li.append(top,d); ul.append(li);
  }
}
/* ---- relay result records (16-byte header, see mode_relay.c) ---- */
function parseRelay(raw){
  const out=[]; let o=0;
  while(o+16<=raw.length){
    const r=raw.slice(o,o+16), len=r[12]|(r[13]<<8), t=raw.slice(o+16,o+16+len);
    out.push({role:r[0],status:r[1],uidLen:r[2],uid:hex(r.slice(3,3+Math.min(4,r[2]))),
      atqa:hex(r.slice(7,9)),sak:r[9],fc:r[10]|(r[11]<<8),frames:parseFrames(t)});
    o+=16+len;
  }
  return out;
}
const RELAY_ROLE=["card","reader"], RELAY_RST=["ok","timeout","disconnect"];
function renderRelay(ss){
  const ul=$("saved"); ul.textContent="";
  for(const s of ss){
    const li=document.createElement("li"); li.className="ev l2";
    const top=document.createElement("div"); top.className="top";
    const t1=document.createElement("strong"); t1.textContent=(RELAY_ROLE[s.role]||"role "+s.role)+" session";
    const tm=document.createElement("time"); tm.textContent=RELAY_RST[s.status]||"status "+s.status;
    top.append(t1,tm);
    const d=document.createElement("div"); d.className="det";
    d.textContent=(s.uidLen?"uid "+s.uid+" \u00b7 atqa "+s.atqa+" \u00b7 sak "+s.sak.toString(16).padStart(2,"0")+" \u00b7 ":"")+s.fc+" frames";
    li.append(top,d);
    for(const n of extractNonces(s.frames)){
      const e=document.createElement("div"); e.className="nonce";
      e.textContent="Classic auth key"+n.key+" block "+n.block+" \u00b7 uid "+n.uid+" \u00b7 nt "+n.nt+" \u00b7 nr "+n.nr+" \u00b7 ar "+n.ar+(n.at?" \u00b7 at "+n.at:""); li.append(e);
    }
    const dt=document.createElement("details"), sm=document.createElement("summary"); sm.textContent="Frames";
    const pre=document.createElement("pre");
    pre.textContent=s.frames.map((f,i)=>String(i).padStart(3)+"  "+(f.tx?"card\u2192rdr":"rdr\u2192card")+"  "+String(f.bits).padStart(4)+"b  "+hex(f.data).padEnd(40)+"  "+frameLabel(f,s.frames[i-1])).join("\n");
    dt.append(sm,pre); li.append(dt); ul.append(li);
  }
}

/* ---- per-mode config (GET_CONFIG 7002 / SET_CONFIG 7003), little-endian cfg_t ---- */
const u16le=(a,v)=>{ a.push(v&255,(v>>8)&255); };
const CFG={
  [MODE_READ_REPLAY]:{  // 4B: ver, read_blocks, rsvd[2]
    fields:[["read_blocks","Read blocks (on/off)","on"]],
    enc(g){ return [1, (g.read_blocks||"on").toLowerCase().startsWith("on")?1:0, 0,0]; },
    dec(d){ return {read_blocks:d[1]?"on":"off"}; }},
  [MODE_AUTOCLONE]:{  // 4B: ver, also_slot, rsvd[2]
    fields:[["also_slot","Also clone to slot (on/off)","off"]],
    enc(g){ return [1, (g.also_slot||"off").toLowerCase().startsWith("on")?1:0, 0,0]; },
    dec(d){ return {also_slot:d[1]?"on":"off"}; }},
  [MODE_DICT]:{  // 4B: ver, sectors, rsvd[2]
    fields:[["sectors","Sectors (1-16)","16"]],
    enc(g){ return [1, Math.min(16,Math.max(1,+g.sectors||16)), 0,0]; },
    dec(d){ return {sectors:d[1]}; }},
  [MODE_AUTHTRACE]:{  // 16B: ver,type,block,rsvd,timeout(u16),key[6],rsvd[4]
    fields:[["type","Auth (0x60 A / 0x61 B)","0x60"],["block","Block","4"],["timeout","Timeout ms","3000"],["key","Key (12 hex)","FFFFFFFFFFFF"]],
    enc(g){ const t=parseInt(g.type,16)||0x60, bl=+g.block||0, to=+g.timeout||3000;
      const k=(g.key||"").replace(/[^0-9a-f]/gi,"").padStart(12,"F").slice(0,12);
      const a=[1,t,bl,0]; u16le(a,to); for(let i=0;i<6;i++) a.push(parseInt(k.substr(i*2,2),16)); a.push(0,0,0,0); return a; },
    dec(d){ return {type:"0x"+(d[1]||0).toString(16),block:d[2],timeout:d[4]|(d[5]<<8),key:hex(Array.from(d.slice(6,12)))}; }},
  [MODE_SLOT]:{  // 6B: ver,slot_mask,start_slot,rsvd,interval(u16). 100..60000ms
    fields:[["mask","Slots (e.g. 12345678)","12345678"],["start","Start slot (1-8)","1"],["interval","Interval ms","1000"]],
    enc(g){ let m=0; (g.mask||"").replace(/[^1-8]/g,"").split("").forEach(c=>m|=1<<(+c-1));
      const a=[1,m||0xFF,(+g.start||1)-1,0]; u16le(a,Math.min(60000,Math.max(100,+g.interval||1000))); return a; },
    dec(d){ let s=""; for(let i=0;i<8;i++) if(d[1]&(1<<i)) s+=(i+1); return {mask:s,start:d[2]+1,interval:d[4]|(d[5]<<8)}; }},
  [MODE_TAP]:{  // 8B: ver,rsvd,timeout(u16),rsvd[4]
    fields:[["timeout","Timeout ms","5000"]],
    enc(g){ const a=[1,0]; u16le(a,+g.timeout||5000); a.push(0,0,0,0); return a; },
    dec(d){ return {timeout:d[2]|(d[3]<<8)}; }},
  [MODE_RELAY]:{  // u32 wtx_ms
    fields:[["wtx","WTX ms","2000"]],
    enc(g){ const w=(+g.wtx||2000)>>>0; return [w&255,(w>>8)&255,(w>>16)&255,(w>>24)&255]; },
    dec(d){ return {wtx:d.length>=4?((d[0]|(d[1]<<8)|(d[2]<<16)|(d[3]<<24))>>>0):2000}; }},
};
function renderCfg(mode){
  const box=$("cfg"), spec=CFG[mode]; box.textContent="";
  if(!spec){ box.style.display="none"; return; }
  box.style.display="";
  for(const [k,label,def] of spec.fields){
    const w=document.createElement("label"); w.className="cfgf";
    const sp=document.createElement("span"); sp.textContent=label;
    const inp=document.createElement("input"); inp.id="cfg_"+k; inp.value=def;
    w.append(sp,inp); box.append(w);
  }
  const ld=document.createElement("button"); ld.className="ghost"; ld.textContent="Load"; ld.onclick=()=>guarded(()=>loadCfg(mode));
  const sv=document.createElement("button"); sv.textContent="Save config"; sv.onclick=()=>guarded(()=>saveCfg(mode));
  box.append(ld,sv);
}
async function loadCfg(mode){
  const f=await request(CMD_GET_CONFIG,[mode]);
  if(f.status!==STATUS_OK) throw new Error("status 0x"+f.status.toString(16));
  const cfg=f.data.slice(2); if(!cfg.length){ cmsg("No stored config; showing defaults."); return; }
  const g=CFG[mode].dec(cfg); for(const k in g){ const el=$("cfg_"+k); if(el) el.value=g[k]; }
  cmsg("Loaded stored config.");
}
async function saveCfg(mode){
  const g={}; for(const [k] of CFG[mode].fields) g[k]=$("cfg_"+k).value.trim();
  const f=await request(CMD_SET_CONFIG,[mode,...CFG[mode].enc(g)]);
  if(f.status!==STATUS_OK) throw new Error("status 0x"+f.status.toString(16));
  cmsg("Config saved. Set mode, then Arm, to apply.");
}
$("modeSel").addEventListener("change",()=>renderCfg(Number($("modeSel").value)));

/* ---- relay live diagnostics (RELAY_DIAG 7008) ---- */
const RELAY_SUB=["linking","waiting","card found","relaying","done"];
let relayTimer=null;
function relayDiagToggle(){
  $("rdwrap").style.display = devMode===MODE_RELAY ? "" : "none";
  const on = devMode===MODE_RELAY && devState!==0 && connected();
  if(on && !relayTimer) relayTimer=setInterval(relayDiag,1000);
  if(!on && relayTimer){ clearInterval(relayTimer); relayTimer=null; }
}
async function relayDiag(){
  if(!connected()) return;
  try{
    const f=await request(CMD_RELAY_DIAG);
    if(f.status!==STATUS_OK) return;
    const d=f.data, u32=i=>(d[i]|(d[i+1]<<8)|(d[i+2]<<16)|(d[i+3]<<24))>>>0, ul=d[13];
    $("rdiag").textContent="adv "+u32(0)+" \u00b7 hits "+u32(4)+" \u00b7 ble "+d[8]+"/"+d[9]+" \u00b7 "+(RELAY_SUB[d[10]]||"sub "+d[10])
      +(d[11]?" \u00b7 card found":"")+(d[12]?" \u00b7 identity rx":"")+(ul?" \u00b7 uid "+hex(Array.from(d.slice(14,14+ul))):"");
  }catch(e){}
}

/* ---- read_replay / autoclone / dict_check result records (see mode_*.c) ---- */

function parseReadReplay(raw){  // 13B: uid_len, uid[7], atqa[2], sak, read, total

  const out=[];

  for(let o=0;o+13<=raw.length;o+=13){ const r=raw.slice(o,o+13);

    out.push({uid:hex(r.slice(1,1+Math.min(r[0],7))),atqa:hex(r.slice(8,10)),sak:r[10],read:r[11],total:r[12]}); }

  return out;

}

function renderReadReplay(recs){

  const ul=$("saved"); ul.textContent="";

  recs.forEach(r=>{

    const li=document.createElement("li"); li.className="ev l2";

    const top=document.createElement("div"); top.className="top";

    const s=document.createElement("strong"); s.textContent="uid "+r.uid;

    const tm=document.createElement("time"); tm.textContent="sectors "+r.read+"/"+r.total;

    top.append(s,tm);

    const d=document.createElement("div"); d.className="det";

    d.textContent="atqa "+r.atqa+" \u00b7 sak "+r.sak.toString(16).padStart(2,"0");

    li.append(top,d); ul.append(li);

  });

}

const AC_RES=["ok","no source","no target","write fail"];

function parseAutoclone(raw){  // 11B: result, uid_len, uid[7], blocks_written (+pad)

  const out=[];

  for(let o=0;o+11<=raw.length;o+=11){ const r=raw.slice(o,o+11);

    out.push({result:r[0],name:AC_RES[r[0]]||("?"+r[0]),uid:hex(r.slice(2,2+Math.min(r[1],7))),written:r[9]}); }

  return out;

}

function renderAutoclone(recs){

  const ul=$("saved"); ul.textContent="";

  recs.forEach(r=>{

    const li=document.createElement("li"); li.className="ev "+(r.result===0?"l1":"l3");

    const top=document.createElement("div"); top.className="top";

    const s=document.createElement("strong"); s.textContent=r.name;

    const tm=document.createElement("time"); tm.textContent="blocks "+r.written;

    top.append(s,tm);

    const d=document.createElement("div"); d.className="det"; d.textContent="uid "+(r.uid||"-");

    li.append(top,d); ul.append(li);

  });

}

function parseDict(raw){  // 15B: sector, found_a, keyA[6], found_b, keyB[6]

  const out=[];

  for(let o=0;o+15<=raw.length;o+=15){ const r=raw.slice(o,o+15);

    out.push({sector:r[0],foundA:!!r[1],keyA:hex(r.slice(2,8)),foundB:!!r[8],keyB:hex(r.slice(9,15))}); }

  return out;

}

function renderDict(recs){

  const ul=$("saved"); ul.textContent="";

  recs.forEach(r=>{

    const li=document.createElement("li"); li.className="ev "+((r.foundA||r.foundB)?"l1":"");

    const top=document.createElement("div"); top.className="top";

    const s=document.createElement("strong"); s.textContent="sector "+r.sector;

    top.append(s);

    const d=document.createElement("div"); d.className="det";

    d.textContent="A "+(r.foundA?r.keyA:"--")+" \u00b7 B "+(r.foundB?r.keyB:"--");

    li.append(top,d); ul.append(li);

  });

}



$("fetch").addEventListener("click",fetchSaved);

/* ---- arm / disarm / test (7000 GET_MODE, 7006 TRIGGER, 7009 DISARM) ---- */
let devState=null, devMode=null, devFlags=0;
const connected=()=>!!(device&&device.gatt.connected&&rx);
function cmsg(t){ $("cstat").textContent=t; }
async function readState(){
  const f=await request(CMD_GET_MODE);
  if(f.status!==STATUS_OK||f.data.length<2) throw new Error("status 0x"+f.status.toString(16));
  devState=f.data[0]; devMode=f.data[1]; devFlags=f.data[2]||0;
  cmsg("Device is "+(STATES[devState]||"state "+devState)+" · active mode: "+(MODES[devMode]||devMode)+(devMode===MODE_CANARY?"":(devMode===MODE_GDB?" · GDB gateway runs over USB-CDC; connect gdb there":(devMode===MODE_U2F?" · authenticator runs passively over NFC; nothing to fetch":" · no live alerts in this mode, use Fetch saved events"))));
  $("test").textContent = devMode===MODE_EMUL ? "Commit session now" : (ACTION_MODES.includes(devMode) ? "Trigger" : "Send test event");
  $("test").style.display = (devMode===MODE_CANARY||devMode===MODE_EMUL||ACTION_MODES.includes(devMode)) ? "" : "none";
  if(MODES[devMode]) $("modeSel").value=String(devMode);
  renderCfg(devMode); relayDiagToggle();
}
async function guarded(fn){
  if(!connected()){ cmsg("Not connected. Press Connect first."); return; }
  for(const id of ["arm","disarm","test","refresh","setmode","clrdev"]) $(id).disabled=true;
  try{ await fn(); }catch(e){ cmsg("Failed: "+e.message); }
  for(const id of ["arm","disarm","test","refresh","setmode","clrdev"]) $(id).disabled=false;
}
$("refresh").addEventListener("click",()=>guarded(readState));

/* ---- Standalone mode switcher (7001 SET_MODE) ---- */

async function changeHardwareStandaloneMode(targetMode) {
  // 7001 SET_MODE needs exactly 2 bytes: [mode, flags]. The mode is saved to flash.
  // If the device is armed in a different mode, the firmware exits that mode itself.
  const flags = OPTIN_MODES.includes(targetMode) ? (devFlags | FLAG_OPTIN) : devFlags;
  const res = await request(CMD_SET_MODE, [targetMode, flags]);
  if (res.status !== STATUS_OK)
    throw new Error("mode switch rejected: 0x" + res.status.toString(16));
}

$("setmode").addEventListener("click", () => guarded(async () => {
  // Read the dropdown BEFORE readState(): readState() resets the dropdown to the
  // device's current mode, which would make every choice look "already set".
  const selectedMode = Number($("modeSel").value);
  await readState();

  if (devMode === selectedMode) {
    cmsg("Device is already in mode " + (MODES[selectedMode] || selectedMode));
    return;
  }

  cmsg("Writing new mode (0x0" + selectedMode.toString(16) + ") to device flash...");
  
  await changeHardwareStandaloneMode(selectedMode);

  // Clear UI logs
  $("saved").textContent = "";

  // Refresh hardware state
  await readState();

  if (devMode === selectedMode) {
    cmsg("Successfully switched device mode to " + (MODES[devMode] || devMode) + "!");
  } else {
    cmsg("Mode update sent, but device reported active mode 0x0" + devMode.toString(16) + 
         ". (Requires reconnect or manual slot button press to trigger reload).");
  }
}));

$("clrdev").addEventListener("click",()=>guarded(async()=>{
  await readState();
  if(!confirm("Delete the saved log of the active mode ("+(MODES[devMode]||devMode)+") from the device? This cannot be undone.")) return;
  const f=await request(CMD_CLEAR);
  if(f.status!==STATUS_OK) throw new Error("status 0x"+f.status.toString(16));
  $("saved").textContent=""; cmsg("Device log cleared.");
}));
$("arm").addEventListener("click",()=>guarded(async()=>{
  await readState();
  if(![MODE_CANARY,MODE_EMUL,MODE_AUTHTRACE,MODE_SLOT,MODE_RELAY,MODE_TAP,MODE_READ_REPLAY,MODE_AUTOCLONE,MODE_DICT,MODE_GDB,MODE_U2F].includes(devMode)){ cmsg("Active mode "+(MODES[devMode]||devMode)+" can't be armed from here."); return; }
  if(devState!==0){ cmsg("Already armed."); return; }
  lastSeq=null;
  const f=await request(CMD_TRIGGER);
  if(f.status!==STATUS_OK) throw new Error("device refused to arm (status 0x"+f.status.toString(16)+")");
  await readState();
}));
$("disarm").addEventListener("click",()=>guarded(async()=>{
  lastSeq=null;
  const f=await request(CMD_DISARM);
  if(f.status!==STATUS_OK) throw new Error("status 0x"+f.status.toString(16));
  cmsg("Disarming… (the device saves its log first)");
  for(let i=0;i<6;i++){ await new Promise(r=>setTimeout(r,1000)); await readState(); if(devState===0) break; }
  if(devState===0) cmsg("Disarmed. The log was saved. Note: the device can now go to sleep and drop this connection.");
}));
$("test").addEventListener("click",()=>guarded(async()=>{
  await readState();
  if(devState===0){ cmsg("Not armed. Arm first."); return; }
  const f=await request(CMD_TRIGGER);
  if(f.status!==STATUS_OK) throw new Error("status 0x"+f.status.toString(16));
  cmsg(devMode===MODE_EMUL ? "Commit requested. Press Fetch saved events to see the session." : ACTION_MODES.includes(devMode) ? "Triggered. Press Fetch saved events to see the result." : "Test event sent. It should appear in the live list.");
}));
$("btn").addEventListener("click",()=>{ (wantConn||(device&&device.gatt.connected)) ? disconnect() : connect(); });
$("clr").addEventListener("click",()=>{ events=[]; save(); render(); });
load(); render();