"use strict";
/* spectrum_plot.js - result viewer for the `spectrum` standalone mode
 * (STANDALONE_MODE_SPECTRUM, mode 14). Ported from software/script/
 * cli_spectrum.py (_parse, classify_peaks, summarize) and built on plot.js's
 * CUPlot.viewer() the same way CUPlot.waveform() is -- see plot.js.
 *
 * Both views' Y-axis / color-scale "autozoom" to the currently-visible
 * (zoomed) frequency range on every redraw, per the explicit requirement
 * that this console always autoscale (the Python CLI only autoscales when
 * --vmax is omitted; this console has no --vmax flag at all, so it always
 * autoscales).
 *
 * No IIFE here, deliberately: canary.js calls renderSpectrumResult(),
 * onStandaloneModeUIChange() and spectrumWaitAndFetch() by bare name via a
 * typeof check (same cross-file convention canary.js itself documents for
 * fullcmd.js/applyCapabilityGating), which only works if they're top-level
 * globals, not closed over an IIFE the way plot.js's internals are.
 */

/* ---------------------------------------------------------------------
 * Result parsing (mirrors cli_spectrum.py's _parse): u8 version=2, u16
 * start_mhz LE, u8 count, then `count` raw EDSAMPLE bytes.
 * ------------------------------------------------------------------- */
function parseSpectrumResult(raw){
  if(raw.length<4 || raw[0]!==2) return null;
  const start = raw[1] | (raw[2]<<8);
  const count = raw[3];
  const vals = raw.slice(4, 4+count);
  if(vals.length !== count) return null;
  const freqs = [];
  for(let i=0;i<vals.length;i++) freqs.push(start+i);
  return {freqs, vals};
}

/* ---------------------------------------------------------------------
 * Peak classification -- host-side only heuristic, same channel plans and
 * thresholding as cli_spectrum.py's classify_peaks()/_classify_one().
 * ------------------------------------------------------------------- */
const WIFI_CHANNELS = {}; for(let ch=1; ch<=13; ch++) WIFI_CHANNELS[ch] = 2412 + 5*(ch-1);
const ZIGBEE_CHANNELS = {}; for(let ch=11; ch<=26; ch++) ZIGBEE_CHANNELS[ch] = 2405 + 5*(ch-11);
const BLE_ADV_CHANNELS = {37:2402, 38:2426, 39:2480};

function nearestChannel(table, center){
  let bestCh=null, bestF=null, bestD=Infinity;
  for(const ch in table){ const f=table[ch], d=Math.abs(f-center); if(d<bestD){ bestD=d; bestCh=+ch; bestF=f; } }
  return {ch:bestCh, f:bestF, d:bestD};
}
function classifyOne(center, width){
  if(width>=15){
    const r=nearestChannel(WIFI_CHANNELS, center);
    if(r.d<=11) return "WiFi ch"+r.ch+" (~"+r.f+" MHz)";
    return "wideband (WiFi-shaped, channel unclear)";
  }
  if(width<=4){
    let r=nearestChannel(ZIGBEE_CHANNELS, center);
    if(r.d<=2) return "Zigbee ch"+r.ch+" (~"+r.f+" MHz)";
    r=nearestChannel(BLE_ADV_CHANNELS, center);
    if(r.d<=2) return "BLE advertising ch"+r.ch+" (~"+r.f+" MHz)";
    return "narrowband (BT/BLE-shaped)";
  }
  return "mid-width (unclassified)";
}
function median(a){ const s=a.slice().sort((x,y)=>x-y), n=s.length; return n%2 ? s[(n-1)/2] : (s[n/2-1]+s[n/2])/2; }
function classifyPeaks(freqs, vals){
  if(!vals.length) return [];
  const baseline = median(vals);
  const threshold = baseline + Math.max(1, (Math.max(...vals)-baseline)*0.3);
  const runs=[]; let startI=null;
  for(let i=0;i<vals.length;i++){
    if(vals[i] >= threshold){ if(startI===null) startI=i; }
    else if(startI!==null){ runs.push([startI,i-1]); startI=null; }
  }
  if(startI!==null) runs.push([startI, vals.length-1]);
  const peaks=[];
  for(const [s,e] of runs){
    const fStart=freqs[s], fEnd=freqs[e];
    const width=fEnd-fStart+1, center=(fStart+fEnd)/2;
    let peak=-Infinity; for(let i=s;i<=e;i++) if(vals[i]>peak) peak=vals[i];
    peaks.push({start:fStart, end:fEnd, center, width, peak, label:classifyOne(center,width)});
  }
  return peaks;
}
function summarizeSpectrum(freqs, vals){
  let busiest=0; for(let i=1;i<vals.length;i++) if(vals[i]>vals[busiest]) busiest=i;
  const mean = vals.reduce((s,x)=>s+x,0) / vals.length;
  const base = vals.length+" point(s), "+freqs[0]+"-"+freqs[freqs.length-1]+" MHz — "+
    "min="+Math.min(...vals)+" max="+vals[busiest]+" (at "+freqs[busiest]+" MHz) mean="+mean.toFixed(1)+
    " (raw EDSAMPLE, uncalibrated)";
  const peaks = classifyPeaks(freqs, vals);
  if(!peaks.length) return base;
  return base + "\n  peaks: " + peaks.map(p=>p.label+" @"+Math.round(p.center)+"MHz").join("; ");
}

/* ---------------------------------------------------------------------
 * Shared drawing bits (colors echo plot.js's COL; niceStepMhz mirrors
 * plot.js's internal niceStep, not exported, so reimplemented here).
 * ------------------------------------------------------------------- */
const COL = {bg:"#080c14", grid:"rgba(255,255,255,0.07)", axis:"#a0b4cc", dim:"#5d6b85",
  trace:"#39ff14", peak:"#d9534f", peakText:"#e08080",
  wifi:"rgba(58,124,165,0.5)", zigbee:"rgba(90,158,90,0.45)", ble:"rgba(208,143,42,0.6)"};
const FONT = "11px 'JetBrains Mono', monospace";

function niceStepMhz(span, target){
  const raw = span / Math.max(1,target);
  const p = Math.pow(10, Math.floor(Math.log10(Math.max(raw,1e-9))));
  const f = raw / p;
  return (f<1.5?1 : f<3.5?2 : f<7.5?5 : 10) * p;
}
function drawChannelRefs(ctx, L, R, T, bottom, w, view){
  ctx.save(); ctx.font = FONT; ctx.textAlign = "center";
  const px = f => L + (f - view.x0) / (view.x1 - view.x0) * (w - L - R);
  for(const ch in WIFI_CHANNELS){
    const f = WIFI_CHANNELS[ch]; if(f<view.x0 || f>view.x1) continue;
    const x = px(f);
    ctx.strokeStyle = COL.wifi; ctx.setLineDash([4,3]); ctx.beginPath(); ctx.moveTo(x,T); ctx.lineTo(x,bottom); ctx.stroke(); ctx.setLineDash([]);
  }
  for(const ch in ZIGBEE_CHANNELS){
    const f = ZIGBEE_CHANNELS[ch]; if(f<view.x0 || f>view.x1) continue;
    const x = px(f);
    ctx.strokeStyle = COL.zigbee; ctx.setLineDash([1,3]); ctx.beginPath(); ctx.moveTo(x,T); ctx.lineTo(x,bottom); ctx.stroke(); ctx.setLineDash([]);
  }
  for(const ch in BLE_ADV_CHANNELS){
    const f = BLE_ADV_CHANNELS[ch]; if(f<view.x0 || f>view.x1) continue;
    const x = px(f);
    ctx.strokeStyle = COL.ble; ctx.lineWidth=1.3; ctx.beginPath(); ctx.moveTo(x,T); ctx.lineTo(x,bottom); ctx.stroke(); ctx.lineWidth=1;
  }
  ctx.restore();
}

/* ---------------------------------------------------------------------
 * Line plot: Y axis autoscaled every draw() call to the min/max of only
 * the samples currently inside view.x0..view.x1 -- the "autozoom" the
 * spectrum graphs are required to have (there is no --vmax escape hatch
 * here, unlike the Python CLI's plot/waterfall commands).
 * ------------------------------------------------------------------- */
function spectrumPlotView(freqs, vals){
  const n = freqs.length;
  const peaks = classifyPeaks(freqs, vals);
  const L=46, R=12, T=22, B=28, H=260;
  const domain = [freqs[0], freqs[n-1]+1];
  return CUPlot.viewer({
    title: n+" point(s), "+freqs[0]+"-"+freqs[n-1]+" MHz (raw EDSAMPLE, Y autoscaled to view)",
    file: "spectrum",
    domain, height: H, L, R, minSpan: 2,
    draw(ctx, w, h, view, hx){
      const pw = w-L-R, ph = h-T-B;
      let i0 = freqs.findIndex(f=>f>=view.x0); if(i0<0) i0=0;
      let i1 = n-1; for(let i=n-1;i>=0;i--){ if(freqs[i]<=view.x1){ i1=i; break; } }
      if(i1<i0) i1=i0;
      let lo=Infinity, hi=-Infinity;
      for(let i=i0;i<=i1;i++){ if(vals[i]<lo) lo=vals[i]; if(vals[i]>hi) hi=vals[i]; }
      if(!isFinite(lo)){ lo=0; hi=1; }
      if(hi===lo) hi=lo+1;
      const pad=(hi-lo)*0.15;
      const yMin=Math.max(0,lo-pad), yMax=hi+pad*2;   // extra headroom above for peak labels
      const y = v => T + (1-(v-yMin)/(yMax-yMin))*ph;
      const px = f => L + (f-view.x0)/(view.x1-view.x0)*pw;

      drawChannelRefs(ctx, L, R, T, h-B, w, view);

      // Y grid (dynamic, autoscaled range)
      ctx.font=FONT; ctx.textAlign="right"; ctx.textBaseline="middle";
      const ystep = niceStepMhz(yMax-yMin, 4);
      for(let v=Math.ceil(yMin/ystep)*ystep; v<=yMax; v+=ystep){
        ctx.strokeStyle=COL.grid; ctx.beginPath(); ctx.moveTo(L,y(v)); ctx.lineTo(w-R,y(v)); ctx.stroke();
        ctx.fillStyle=COL.axis; ctx.fillText(Math.round(v), L-6, y(v));
      }
      // X grid (MHz)
      const xstep = niceStepMhz(view.x1-view.x0, Math.max(3,pw/90));
      ctx.textAlign="center"; ctx.textBaseline="top";
      for(let f=Math.ceil(view.x0/xstep)*xstep; f<=view.x1; f+=xstep){
        const x=px(f);
        ctx.strokeStyle=COL.grid; ctx.beginPath(); ctx.moveTo(x,T); ctx.lineTo(x,h-B); ctx.stroke();
        ctx.fillStyle=COL.axis; ctx.fillText(Math.round(f), x, h-B+4);
      }
      ctx.textAlign="right"; ctx.fillStyle=COL.dim; ctx.fillText("MHz", w-R, h-B+4+12);

      ctx.save(); ctx.beginPath(); ctx.rect(L,T,pw,ph); ctx.clip();
      // peak shading
      for(const p of peaks){
        if(p.end<view.x0 || p.start>view.x1) continue;
        const a=Math.max(L,px(p.start)), b=Math.min(w-R,px(p.end+1));
        ctx.fillStyle="rgba(217,83,79,0.12)"; ctx.fillRect(a,T,Math.max(1,b-a),ph);
      }
      // trace + fill
      ctx.beginPath();
      for(let i=i0;i<=i1;i++){ const x=px(freqs[i]), yy=y(vals[i]); i===i0?ctx.moveTo(x,yy):ctx.lineTo(x,yy); }
      ctx.strokeStyle=COL.trace; ctx.lineWidth=1.5; ctx.stroke(); ctx.lineWidth=1;
      ctx.lineTo(px(freqs[i1]), T+ph); ctx.lineTo(px(freqs[i0]), T+ph); ctx.closePath();
      ctx.fillStyle="rgba(57,255,20,0.12)"; ctx.fill();
      if(hx!==null){ ctx.strokeStyle="rgba(255,255,255,0.35)"; ctx.beginPath(); ctx.moveTo(hx,T); ctx.lineTo(hx,T+ph); ctx.stroke(); }
      ctx.restore();

      // peak labels (clamped inside the plot area; not a full anti-collision
      // layout like matplotlib's annotate() -- labels for very close peaks
      // may overlap)
      ctx.font=FONT; ctx.textAlign="center"; ctx.textBaseline="top"; ctx.fillStyle=COL.peakText;
      for(const p of peaks){
        if(p.end<view.x0 || p.start>view.x1) continue;
        const x=Math.max(L+20,Math.min(w-R-20,px(p.center)));
        ctx.fillText(p.label, x, T+2);
      }
    },
    hover(t){
      let idx=0, bd=Infinity;
      for(let i=0;i<n;i++){ const d=Math.abs(freqs[i]-t); if(d<bd){ bd=d; idx=i; } }
      return "f="+freqs[idx]+" MHz   EDSAMPLE="+vals[idx]+(idx<n ? " (0x"+vals[idx].toString(16).padStart(2,"0")+")" : "");
    },
  });
}

/* ---------------------------------------------------------------------
 * Waterfall: accumulates successive sweeps (newest row on top, like
 * cli_spectrum.py's SpectrumWaterfall). Color intensity autoscales every
 * draw() call to the min/max of only the rows' samples inside the
 * currently-visible frequency range -- same "autozoom" principle as the
 * line plot's Y axis, applied to the color scale instead.
 * ------------------------------------------------------------------- */
const VIRIDIS_STOPS = [[68,1,84],[59,82,139],[33,145,140],[94,201,98],[253,231,37]];   // viridis-like, not exact
function viridisColor(t){
  t = Math.max(0, Math.min(1, t));
  const n = VIRIDIS_STOPS.length-1, seg = t*n, i = Math.min(n-1, Math.floor(seg)), f = seg-i;
  const a=VIRIDIS_STOPS[i], b=VIRIDIS_STOPS[i+1];
  const r=Math.round(a[0]+(b[0]-a[0])*f), g=Math.round(a[1]+(b[1]-a[1])*f), bl=Math.round(a[2]+(b[2]-a[2])*f);
  return "rgb("+r+","+g+","+bl+")";
}

let wfFreqs = null, wfRows = [];   // rows[0] = newest sweep
const WF_MAX_ROWS = 60;
let wfRepaint = null;

function wfPushSweep(freqs, vals){
  if(!wfFreqs || wfFreqs.length!==freqs.length || wfFreqs[0]!==freqs[0]){
    wfFreqs = freqs.slice(); wfRows = [];   // range changed (reconfigured) -- start a fresh grid
  }
  wfRows.unshift(vals.slice());
  if(wfRows.length > WF_MAX_ROWS) wfRows.length = WF_MAX_ROWS;
  if(wfRepaint) try{ wfRepaint(); }catch(e){}
}

function spectrumWaterfallView(){
  const L=46, R=12, T=22, B=28, H=300;
  const rowsVisible = WF_MAX_ROWS;
  const rowH = () => Math.max(2, 1);   // computed from h at draw time instead (see draw())
  return CUPlot.viewer({
    title: "Frequency-vs-time waterfall (color autoscaled to the visible range)",
    file: "spectrum-waterfall",
    domain: wfFreqs ? [wfFreqs[0], wfFreqs[wfFreqs.length-1]+1] : [2400,2484],
    height: H, L, R, minSpan: 2,
    onReady(repaint){ wfRepaint = repaint; },
    draw(ctx, w, h, view, hx){
      const pw = w-L-R, ph = h-T-B;
      if(!wfFreqs || !wfRows.length){
        ctx.font=FONT; ctx.fillStyle=COL.dim; ctx.textAlign="center"; ctx.textBaseline="middle";
        ctx.fillText("No sweeps yet -- press Start waterfall.", L+pw/2, T+ph/2);
        return;
      }
      const n = wfFreqs.length;
      let i0 = wfFreqs.findIndex(f=>f>=view.x0); if(i0<0) i0=0;
      let i1 = n-1; for(let i=n-1;i>=0;i--){ if(wfFreqs[i]<=view.x1){ i1=i; break; } }
      if(i1<i0) i1=i0;
      let vmax=0;
      for(const row of wfRows) for(let i=i0;i<=i1;i++) if(row[i]>vmax) vmax=row[i];
      vmax = Math.max(1, vmax*1.1);
      const rowH = ph / rowsVisible;
      const px = f => L + (f-view.x0)/(view.x1-view.x0)*pw;
      ctx.save(); ctx.beginPath(); ctx.rect(L,T,pw,ph); ctx.clip();
      for(let r=0;r<wfRows.length;r++){
        const row=wfRows[r], y0=T+r*rowH, y1=T+(r+1)*rowH;
        for(let i=i0;i<=i1;i++){
          const x0=Math.max(L,px(wfFreqs[i])), x1=Math.min(w-R, i+1<n?px(wfFreqs[i+1]):px(wfFreqs[i])+(pw/n));
          ctx.fillStyle = viridisColor(row[i]/vmax);
          ctx.fillRect(x0, y0, Math.max(1,x1-x0), rowH+0.5);
        }
      }
      drawChannelRefs(ctx, L, R, T, T+ph, w, view);
      if(hx!==null){ ctx.strokeStyle="rgba(255,255,255,0.5)"; ctx.beginPath(); ctx.moveTo(hx,T); ctx.lineTo(hx,T+ph); ctx.stroke(); }
      ctx.restore();
      // X axis (MHz)
      ctx.font=FONT; ctx.textAlign="center"; ctx.textBaseline="top"; ctx.fillStyle=COL.axis;
      const xstep = niceStepMhz(view.x1-view.x0, Math.max(3,pw/90));
      for(let f=Math.ceil(view.x0/xstep)*xstep; f<=view.x1; f+=xstep){
        const x=px(f);
        ctx.fillText(Math.round(f), x, T+ph+4);
      }
      ctx.textAlign="left"; ctx.fillStyle=COL.dim; ctx.fillText("rows: sweeps ago (newest on top) · color 0-"+Math.round(vmax)+" EDSAMPLE (visible range)", L, T-10);
    },
    hover(t, view, pwArg){
      const n=wfFreqs ? wfFreqs.length : 0;
      if(!n) return "";
      let idx=0, bd=Infinity;
      for(let i=0;i<n;i++){ const d=Math.abs(wfFreqs[i]-t); if(d<bd){ bd=d; idx=i; } }
      const latest = wfRows.length ? wfRows[0][idx] : null;
      return "f="+wfFreqs[idx]+" MHz"+(latest!=null ? "   latest EDSAMPLE="+latest : "")+"   "+wfRows.length+" sweep(s) kept";
    },
  });
}

/* ---------------------------------------------------------------------
 * Wiring into canary.js (fetchSaved() dispatch, mode-switch UI, Trigger
 * button) and phreakbyte.html (#spectrumWrap / #specHost / view buttons).
 * ------------------------------------------------------------------- */
let curView = "plot";   // "plot" | "waterfall"
let lastParsed = null;  // {freqs, vals} from the last single-sweep fetch

function host(){ return document.getElementById("specHost"); }
function paintCurrentView(){
  const h = host(); if(!h) return;
  h.textContent = "";
  if(curView === "waterfall"){
    h.appendChild(spectrumWaterfallView());
  } else if(lastParsed){
    h.appendChild(spectrumPlotView(lastParsed.freqs, lastParsed.vals));
  } else {
    const d = document.createElement("div"); d.className = "det";
    d.textContent = "No sweep result yet. Arm spectrum, then press Trigger (or Fetch saved events).";
    h.appendChild(d);
  }
}

// Called by canary.js's fetchSaved() for mode 14 with the drained result
// bytes; returns a status-line string for fetchSaved()'s own $("fstat"),
// or null/"" to let it fall back to its default "no result" message.
function renderSpectrumResult(raw){
  const parsed = parseSpectrumResult(raw);
  const wrap = document.getElementById("spectrumWrap");
  if(wrap) wrap.style.display = "";
  const savedUl = document.getElementById("saved");
  if(savedUl) savedUl.style.display = "none";
  if(!parsed){ lastParsed = null; paintCurrentView(); return null; }
  lastParsed = parsed;
  wfPushSweep(parsed.freqs, parsed.vals);
  curView = "plot";
  paintCurrentView();
  const peaksEl = document.getElementById("specPeaks");
  if(peaksEl){
    const peaks = classifyPeaks(parsed.freqs, parsed.vals);
    peaksEl.textContent = peaks.length
      ? "Peaks (heuristic, not a decode): " + peaks.map(p=>p.start+"-"+p.end+" MHz peak="+p.peak+" "+p.label).join(" | ")
      : "No clear peaks above baseline.";
  }
  return summarizeSpectrum(parsed.freqs, parsed.vals);
}

// Called by canary.js's renderCfg(mode) on every mode read/switch -- swaps
// the saved-events list for the spectrum containers and back.
function onStandaloneModeUIChange(mode){
  const isSpec = mode === MODE_SPECTRUM;
  const wrap = document.getElementById("spectrumWrap");
  const savedUl = document.getElementById("saved");
  if(wrap) wrap.style.display = isSpec ? "" : "none";
  if(savedUl) savedUl.style.display = isSpec ? "none" : "";
  if(isSpec) paintCurrentView();
}

// Called by canary.js's "test"/Trigger button after it has already sent
// CMD_TRIGGER for a spectrum sweep: polls GET_STATUS (7014) for the
// "sweep=" field cli_spectrum.py's _trigger_and_wait() polls, same wording
// ("done ..." vs "running ..."), then auto-fetches/plots the result instead
// of making the user press Fetch saved events too.
async function spectrumWaitAndFetch(timeoutMs, pollMs){
  timeoutMs = timeoutMs || 30000; pollMs = pollMs || 250;
  const deadline = Date.now() + timeoutMs;
  while(Date.now() < deadline){
    try{
      const pairs = await getStandaloneStatus();
      const sweep = pairs.find(([k]) => k === "sweep");
      if(sweep && sweep[1].split(" ")[0] === "done") break;
    }catch(e){ /* transient -- keep polling until timeout */ }
    await new Promise(r=>setTimeout(r, pollMs));
  }
  await fetchSaved();
}

/* ---- waterfall start/stop loop: repeatedly (trigger + wait + drain), like
 * calling `standalone trigger` + `spectrum plot` in a loop, same as
 * cli_spectrum.py's SpectrumWaterfall. ---- */
let wfRunning = false;
async function waterfallTick(){
  if(!wfRunning) return;
  try{
    const t = await request(CMD_TRIGGER);
    if(t.status === STATUS_OK){
      const deadline = Date.now() + 30000;
      let done = false;
      while(wfRunning && Date.now() < deadline){
        const pairs = await getStandaloneStatus();
        const sweep = pairs.find(([k]) => k === "sweep");
        if(sweep && sweep[1].split(" ")[0] === "done"){ done = true; break; }
        await new Promise(r=>setTimeout(r, 250));
      }
      if(done){
        const raw = [];
        for(let i=0;i<50;i++){
          const f = await request(CMD_GET_RESULT);
          if(f.status !== STATUS_OK) break;
          const chunk = f.data.slice(4);
          if(!chunk.length) break;
          raw.push(...chunk);
        }
        const parsed = parseSpectrumResult(raw);
        if(parsed){ lastParsed = parsed; wfPushSweep(parsed.freqs, parsed.vals); }
      }
    }
  }catch(e){ /* transient (busy/blocked) -- keep looping until Stop */ }
  if(wfRunning) setTimeout(waterfallTick, 150);
}
function startWaterfall(){
  if(wfRunning) return;
  wfRunning = true;
  curView = "waterfall"; paintCurrentView();
  const startBtn=document.getElementById("specWaterfallStart"), stopBtn=document.getElementById("specWaterfallStop");
  if(startBtn) startBtn.style.display = "none";
  if(stopBtn) stopBtn.style.display = "";
  waterfallTick();
}
function stopWaterfall(){
  wfRunning = false;
  const startBtn=document.getElementById("specWaterfallStart"), stopBtn=document.getElementById("specWaterfallStop");
  if(startBtn) startBtn.style.display = "";
  if(stopBtn) stopBtn.style.display = "none";
}

// This script tag loads at the end of <body> (same convention as canary.js),
// so the DOM it queries already exists -- no DOMContentLoaded needed, same
// as canary.js's own top-level $("fetch").addEventListener(...).
(function wireButtons(){
  const byId = id => document.getElementById(id);
  const viewPlot = byId("specViewPlot"), viewWf = byId("specViewWaterfall");
  const wfStart = byId("specWaterfallStart"), wfStop = byId("specWaterfallStop");
  if(viewPlot) viewPlot.addEventListener("click", ()=>{ curView="plot"; paintCurrentView(); });
  if(viewWf) viewWf.addEventListener("click", ()=>{ curView="waterfall"; paintCurrentView(); });
  if(wfStart) wfStart.addEventListener("click", ()=>{ if(typeof connected==="function" && connected()) startWaterfall(); else if(typeof cmsg==="function") cmsg("Not connected. Press Connect first."); });
  if(wfStop) wfStop.addEventListener("click", stopWaterfall);
})();

// Exposed for debugging / potential reuse elsewhere on the page.
window.CUSpectrum = {parseSpectrumResult, classifyPeaks, summarizeSpectrum};
// renderSpectrumResult, onStandaloneModeUIChange and spectrumWaitAndFetch
// are plain top-level function statements above, so canary.js's typeof
// checks see them directly -- same cross-file convention as the rest of
// this console (classic <script> tags share one global scope, see
// canary.js's own comment on applyCapabilityGating/fullcmd.js).
