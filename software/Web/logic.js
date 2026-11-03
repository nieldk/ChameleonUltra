"use strict";
/* logic.js - `hw logic` for the web console: arm / stop / download, decode
 * and VCD export. Port of software/script/cli_hw_logic.py; uses request(),
 * CU, okOrThrow() from canary.js / fullcmd.js (looked up when called). */
(function(){

const RATES = {16:0, 8:1, 4:2, 2:3, 1:4};            // MHz -> prescaler
const NAMED = {hf_cs:0x00, field_led:0x01, spi:0x02};
const EV_CHUNK = 90, SPI_CHUNK = 400, SPI_MAXDATA = 24;

// RC522 register names, from firmware rc522.h
const REGS = {
  0x00:"RFU00", 0x01:"CommandReg", 0x02:"ComIEnReg", 0x03:"DivlEnReg", 0x04:"ComIrqReg",
  0x05:"DivIrqReg", 0x06:"ErrorReg", 0x07:"Status1Reg", 0x08:"Status2Reg", 0x09:"FIFODataReg",
  0x0A:"FIFOLevelReg", 0x0B:"WaterLevelReg", 0x0C:"Control522Reg", 0x0D:"BitFramingReg",
  0x0E:"CollReg", 0x0F:"RFU0F", 0x10:"RFU10", 0x11:"ModeReg", 0x12:"TxModeReg",
  0x13:"RxModeReg", 0x14:"TxControlReg", 0x15:"TxAutoReg", 0x16:"TxSelReg", 0x17:"RxSelReg",
  0x18:"RxThresholdReg", 0x19:"DemodReg", 0x1A:"RFU1A", 0x1B:"RFU1B", 0x1C:"MfTxReg",
  0x1D:"MfRxReg", 0x1E:"RFU1E", 0x1F:"SerialSpeedReg", 0x20:"RFU20", 0x21:"CRCResultRegM",
  0x22:"CRCResultRegL", 0x23:"RFU23", 0x24:"ModWidthReg", 0x25:"RFU25", 0x26:"RFCfgReg",
  0x27:"GsNReg", 0x28:"CWGsCfgReg", 0x29:"ModGsCfgReg", 0x2A:"TModeReg", 0x2B:"TPrescalerReg",
  0x2C:"TReloadRegH", 0x2D:"TReloadRegL", 0x2E:"TCounterValueRegH", 0x2F:"TCounterValueRegL",
  0x30:"RFU30", 0x31:"TestSel1Reg", 0x32:"TestSel2Reg", 0x33:"TestPinEnReg",
  0x34:"TestPinValueReg", 0x35:"TestBusReg", 0x36:"AutoTestReg", 0x37:"VersionReg",
  0x38:"AnalogTestReg", 0x39:"TestDAC1Reg", 0x3A:"TestDAC2Reg", 0x3B:"TestADCReg", 0x3C:"RFU3C",
  0x3D:"RFU3D", 0x3E:"RFU3E", 0x3F:"RFU3F",
};
// CommandReg low nibble, from rc522.h PCD_*
const CMDS = {0x00:"Idle", 0x03:"CalcCRC", 0x04:"Transmit", 0x08:"Receive", 0x0C:"Transceive", 0x0E:"Authent", 0x0F:"SoftReset"};

let session = null;   // set by arm(), consumed by finish()
let last = null;      // last model, for plot/decode

const u16 = (d, o) => (d[o] << 8) | d[o + 1];
const u32 = (d, o) => ((d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) >>> 0;
const regName = r => REGS[r] || ("reg" + r.toString(16).toUpperCase().padStart(2, "0"));

function parseSrc(tok){
  const t = tok.toLowerCase();
  if(t in NAMED) return NAMED[t];
  const m = /^p([01])\.(\d+)$/.exec(t);
  if(m){
    const port = +m[1], pin = +m[2];
    if(pin < (port === 0 ? 32 : 16)) return 0x40 | (port << 5) | pin;
  }
  throw new Error("bad source '" + tok + "' (use " + Object.keys(NAMED).join(", ") + " or Px.yy)");
}

async function arm(sources, rateMHz, mergeUs){
  const presc = RATES[rateMHz === undefined ? 1 : rateMHz];
  if(presc === undefined) throw new Error("rate must be 1, 2, 4, 8 or 16 (MHz)");
  const src = sources.map(parseSrc);
  const ticks = Math.min(0xFFFF, Math.round((mergeUs || 0) * (16000000 >> presc) / 1e6));
  const payload = [presc, src.length, ...src];
  if(ticks) payload.push(ticks >> 8, ticks & 255);
  const f = okOrThrow(await request(CU.LOGIC_ARM, payload));
  const hz = u32(f.data, 1);
  const rev = Object.fromEntries(Object.entries(NAMED).map(([k, v]) => [v, k]));
  session = {n: src.length, hz, names: src.map((x, i) => rev[x] || ("ch" + i))};
  return {init: f.data[0], hz};
}

async function download(){
  const events = [];
  let total = null, init = 0, overflow = false;
  while(total === null || events.length < total){
    const f = okOrThrow(await request(CU.LOGIC_READ, [(events.length >> 8) & 255, events.length & 255, 0, EV_CHUNK]));
    const d = f.data;
    overflow = !!d[1]; init = d[2]; total = u16(d, 3);
    const body = d.slice(5);
    if(body.length < 5) break;
    for(let i = 0; i + 5 <= body.length; i += 5) events.push({t: u32(body, i), ch: body[i + 4] & 0x7F, lvl: body[i + 4] >> 7});
  }
  return {init, overflow, events};
}

async function downloadSpi(){
  const raw = [];
  let total = null, over = false, drops = 0;
  while(total === null || raw.length < total){
    const f = okOrThrow(await request(CU.LOGIC_SPI_READ, [(raw.length >> 8) & 255, raw.length & 255, SPI_CHUNK >> 8, SPI_CHUNK & 255]));
    const d = f.data;
    over = !!d[0]; drops = u16(d, 1); total = u16(d, 3);
    if(d.length <= 5) break;
    for(let i = 5; i < d.length; i++) raw.push(d[i]);
  }
  return {over, drops, raw};
}

/* packed SPI log -> entries (see firmware logic_spi_slow) */
function parseSpi(raw){
  const out = [];
  let i = 0;
  while(i + 6 <= raw.length){
    const hdr = raw[i + 4];
    const e = {ts: u32(raw, i), rd: !!(hdr & 0x80), reg: hdr & 0x3F, burst: !!(hdr & 0x40), rep: 0};
    if(e.burst){
      const ln = raw[i + 5], n = Math.min(ln, SPI_MAXDATA);
      if(i + 6 + n > raw.length) break;
      e.len = ln; e.data = raw.slice(i + 6, i + 6 + n);
      i += 6 + n;
    } else {
      if(i + 7 > raw.length) break;
      e.len = 1; e.data = [raw[i + 5]]; e.rep = raw[i + 6];
      i += 7;
    }
    out.push(e);
  }
  return out;
}

const hx = (b, sep) => Array.from(b, x => x.toString(16).padStart(2, "0")).join(sep || "");

function spiText(e, nextTs, us){
  const name = regName(e.reg), d = e.data, rw = e.rd ? "R" : "W";
  if(e.burst){
    const more = e.len > d.length ? " (+" + (e.len - d.length) + " more)" : "";
    return rw + "  " + name + " " + (e.rd ? "->" : "<-") + " " + hx(d, " ") + more + "  [" + e.len + " B]";
  }
  let t = rw + "  " + name + " = 0x" + d[0].toString(16).padStart(2, "0").toUpperCase();
  if(!e.rd && e.reg === 0x01) t += " (" + (CMDS[d[0] & 0x0F] || "cmd 0x" + (d[0] & 0x0F).toString(16).toUpperCase()) + ")";
  if(e.rep){
    const span = nextTs !== null ? (nextTs - e.ts) * us : 0;
    t += "  x" + (e.rep + 1) + (span ? " over " + (span / 1000).toFixed(3) + " ms" : "");
  }
  return t;
}

// short label for the graph's SPI lane
function spiShort(e){
  const n = regName(e.reg).replace(/Reg$/, ""), d = e.data;
  if(e.burst) return n + (e.rd ? " > " : " < ") + hx(d.slice(0, 6)) + (e.len > 6 ? ".." : "");
  if(!e.rd && e.reg === 0x01) return "Cmd " + (CMDS[d[0] & 0x0F] || "0x" + (d[0] & 15).toString(16));
  return (e.rd ? "R " : "W ") + n + " " + d[0].toString(16).padStart(2, "0") + (e.rep ? " x" + (e.rep + 1) : "");
}

/* stop, download and build the model (ticks since the first edge / SPI access) */
async function finish(){
  if(!session) throw new Error("No capture armed - run 'hw logic start' first");
  const s = session;
  session = null;
  const f = okOrThrow(await request(CU.LOGIC_STOP));
  const d = f.data;
  const stop = {overflow: !!d[0], total: u16(d, 1), calls: u16(d, 3)};
  const ed = await download();
  let spi = [], spiOver = false, drops = 0;
  if(s.names.includes("spi")){
    const sd = await downloadSpi();
    spiOver = sd.over; drops = sd.drops;
    spi = parseSpi(sd.raw);
  }
  const unwrap = list => {
    let base = 0, prev = 0;
    for(const x of list){ const k = x.ts !== undefined ? "ts" : "t"; base += (x[k] - prev) >>> 0; prev = x[k]; x[k] = base; }
  };
  unwrap(ed.events); unwrap(spi);
  const firsts = [];
  if(ed.events.length) firsts.push(ed.events[0].t);
  if(spi.length) firsts.push(spi[0].ts);
  const t0 = firsts.length ? Math.min(...firsts) : 0;
  const vis = s.names.map((n, i) => i).filter(i => s.names[i] !== "spi");
  const remap = Object.fromEntries(vis.map((o, k) => [o, k]));
  const us = 1e6 / s.hz;
  const model = {
    names: vis.map(i => s.names[i]), hz: s.hz,
    init: vis.reduce((a, o, k) => a | (((ed.init >> o) & 1) << k), 0),
    ev: ed.events.filter(e => e.ch in remap).map(e => ({t: e.t - t0, ch: remap[e.ch], lvl: e.lvl})),
    spi: spi.map((e, i) => {
      const ts = e.ts - t0;
      return {...e, t: ts, rd: e.rd, short: spiShort(e), text: spiText({...e, ts}, i + 1 < spi.length ? spi[i + 1].ts - t0 : null, us)};
    }),
    overflow: ed.overflow, spiOver, drops, calls: stop.calls, total: stop.total,
    hasEdges: vis.length > 0,
  };
  last = model;
  return model;
}

function intervals(steps, end){
  const out = [];
  let low = null, cur = steps[0].l;
  if(cur === 0) low = 0;
  for(const p of steps.slice(1)){
    if(p.l === cur) continue;
    cur = p.l;
    if(cur === 0) low = p.t;
    else if(low !== null){ out.push([low, p.t, false]); low = null; }
  }
  if(low !== null) out.push([low, end, true]);
  return out;
}

/* text timeline: field, chip-select bursts, SPI accesses. Same rules as _decode() in cli_hw_logic.py */
function decode(m, gapUs){
  gapUs = gapUs || 100;
  const us = 1e6 / m.hz;
  const steps = m.names.map((_, i) => [{t: 0, l: (m.init >> i) & 1}]);
  for(const e of m.ev) steps[e.ch].push({t: e.t, l: e.lvl});
  let end = 1;
  for(const e of m.ev) end = Math.max(end, e.t);
  for(const e of m.spi) end = Math.max(end, e.t);
  const iv = name => { const i = m.names.indexOf(name); return i < 0 ? [] : intervals(steps[i], end).map(([a, b, o]) => [a * us, b * us, o]); };
  const cs = iv("hf_cs").map(([a, b]) => [a, b]);
  const field = iv("field_led");
  const fieldAt = t => field.some(([a, b]) => a <= t && t <= b);
  const bursts = [];
  for(const [a, b] of cs){
    const lb = bursts.length ? bursts[bursts.length - 1] : null;
    const prev = lb ? lb[lb.length - 1] : null;
    if(b - a < gapUs && prev && a - prev[1] <= gapUs && prev[1] - prev[0] < gapUs) lb.push([a, b]);
    else bursts.push([[a, b]]);
  }
  const rows = [];
  for(const [a, b, open] of field){
    rows.push([a, "FIELD ON   " + ((b - a) / 1000).toFixed(3) + " ms" + (open ? " (until capture end)" : "")]);
    if(!open) rows.push([b, "FIELD OFF"]);
  }
  for(const bu of bursts){
    const a = bu[0][0], b = bu[bu.length - 1][1], cnt = bu.length;
    let tag = "CS  " + cnt + " access(es), span " + (b - a).toFixed(0) + " us";
    const lows = bu.map(([x, y]) => y - x);
    if(cnt === 1 && lows[0] >= gapUs) tag = "CS  held low " + (lows[0] / 1000).toFixed(3) + " ms (one access or merged polling)";
    else if(cnt >= 8){
      const per = bu.slice(1).map((p, i) => p[0] - bu[i][0]).sort((x, y) => x - y);
      const med = per[per.length >> 1];
      if(per[per.length / 10 | 0] > 0.7 * med && per[per.length - 1 - (per.length / 10 | 0)] < 1.3 * med)
        tag = "CS  poll loop: " + cnt + " accesses, period ~" + med.toFixed(1) + " us, " + ((b - a) / 1000).toFixed(3) + " ms";
    }
    rows.push([a, tag + (fieldAt(a) ? "  [field on]" : "  [field off]")]);
  }
  for(const e of m.spi) rows.push([e.t * us, "SPI " + e.text]);
  rows.sort((x, y) => x[0] - y[0]);
  const lines = [" " + "t (ms)".padStart(10) + "  event"];
  for(const [t, txt] of rows) lines.push(" " + (t / 1000).toFixed(3).padStart(10) + "  " + txt);
  if(cs.length) lines.push(" - " + bursts.length + " CS burst(s), CS low " + (cs.reduce((s, [a, b]) => s + b - a, 0) / 1000).toFixed(3) + " ms of " + (end * us / 1000).toFixed(3) + " ms");
  if(field.length) lines.push(" - field on " + (field.reduce((s, [a, b]) => s + b - a, 0) / 1000).toFixed(3) + " ms");
  if(m.spi.length) lines.push(" - " + m.spi.length + " SPI entries, " + m.spi.reduce((s, e) => s + e.rep + 1, 0) + " register accesses");
  return lines;
}

function vcd(m){
  const ids = m.names.map((_, i) => String.fromCharCode(33 + i));
  const L = ["$timescale 1 ps $end", "$scope module chameleon $end"];
  m.names.forEach((n, i) => L.push("$var wire 1 " + ids[i] + " " + n + " $end"));
  L.push("$upscope $end", "$enddefinitions $end", "#0", "$dumpvars");
  m.names.forEach((_, i) => L.push(((m.init >> i) & 1) + ids[i]));
  L.push("$end");
  let lastPs = -1;
  for(const e of m.ev){
    const ps = Math.round(e.t * 1e12 / m.hz);
    if(ps !== lastPs){ L.push("#" + ps); lastPs = ps; }
    L.push(e.lvl + ids[e.ch]);
  }
  return L.join("\n") + "\n";
}

function saveVcd(m, name){
  const text = vcd(m);
  CUPlot.save(new Blob([text], {type: "text/plain"}), name || "capture.vcd", text);
}

window.CULogic = {
  RATES, NAMED, REGS, parseSrc, arm, finish, parseSpi, spiText, decode, vcd, saveVcd,
  armed: () => !!session, last: () => last,
};

})();
