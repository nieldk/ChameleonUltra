"use strict";
/* plot.js - canvas graphs for the console (no dependencies).
 *   CUPlot.waveform(samples, {periodUs, title})  ADC samples vs time
 *   CUPlot.logic(model, {buttons})               digital traces + SPI lane
 * Wheel = zoom at cursor, drag = pan, double-click = reset.
 * Both return a DOM node; append it anywhere. */
(function(){

const COL = {
  bg:"#080c14", grid:"rgba(255,255,255,0.07)", axis:"#a0b4cc", dim:"#5d6b85",
  trace:["#39ff14", "#ffb020", "#b388ff", "#7fd4ff", "#ff3d57"],
  wr:"#ffb020", rd:"#7fd4ff", field:"rgba(57,255,20,0.06)", mean:"#ffb020",
};
const FONT = "11px 'JetBrains Mono', monospace";

function el(tag, css, text){
  const e = document.createElement(tag);
  if(css) e.style.cssText = css;
  if(text !== undefined) e.textContent = text;
  return e;
}

/* Full-screen fallback for browsers that cannot download a script-made file
 * (e.g. iOS web views): an image to long-press, or text to copy. */
function overlay(blob, name, text){
  const o = el("div", "position:fixed;inset:0;background:rgba(0,0,0,0.9);z-index:10000;display:flex;flex-direction:column;align-items:center;gap:10px;padding:14px;overflow:auto;");
  const msg = el("div", "color:#dde8f5;font:14px sans-serif;text-align:center;",
    text !== undefined ? name + ": select all, copy and paste it into a file" : name + ": long-press the image to save it");
  o.appendChild(msg);
  if(text !== undefined){
    const ta = el("textarea", "width:100%;max-width:700px;height:55vh;background:#080c14;color:#a0b4cc;font:11px monospace;");
    ta.readOnly = true; ta.value = text;
    const cp = el("button", "font:14px sans-serif;padding:8px 18px;", "Copy");
    cp.onclick = async () => {
      try{ await navigator.clipboard.writeText(text); cp.textContent = "Copied"; }
      catch(e){ ta.focus(); ta.select(); document.execCommand("copy"); cp.textContent = "Copied"; }
    };
    o.appendChild(ta); o.appendChild(cp);
  } else {
    const img = el("img", "max-width:100%;background:#080c14;");
    img.src = URL.createObjectURL(blob);
    o.appendChild(img);
  }
  const x = el("button", "font:14px sans-serif;padding:8px 18px;", "Close");
  x.onclick = () => o.remove();
  o.appendChild(x);
  document.body.appendChild(o);
}

/* Save a Blob: share sheet if the browser has one for files, else a normal
 * download (anchor attached to the page), plus the overlay on touch devices.
 * text: optional string version, shown in the overlay instead of an image. */
async function save(blob, name, text){
  const file = typeof File !== "undefined" ? new File([blob], name, {type: blob.type}) : null;
  if(file && navigator.canShare && navigator.canShare({files: [file]})){
    try{ await navigator.share({files: [file], title: name}); return; }
    catch(e){ if(e && e.name === "AbortError") return; }
  }
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1500);
  if(window.matchMedia && matchMedia("(pointer: coarse)").matches) overlay(blob, name, text);
}

function fmtUs(us, unit){
  if(unit === "s") return (us/1e6).toFixed(3)+" s";
  if(unit === "ms") return (us/1e3).toFixed(3)+" ms";
  return us.toFixed(1)+" us";
}
function pickUnit(span){ return span >= 2e6 ? "s" : span >= 2000 ? "ms" : "us"; }

function niceStep(span, target){
  const raw = span / target;
  const p = Math.pow(10, Math.floor(Math.log10(raw)));
  const f = raw / p;
  return (f < 1.5 ? 1 : f < 3.5 ? 2 : f < 7.5 ? 5 : 10) * p;
}

/* Time axis along the bottom of the plot area, vertical grid lines through it. */
function timeAxis(ctx, x0, x1, L, R, top, bottom){
  const unit = pickUnit(x1 - x0);
  const div = unit === "s" ? 1e6 : unit === "ms" ? 1e3 : 1;
  const step = niceStep(x1 - x0, Math.max(3, (R - L) / 110));
  ctx.font = FONT; ctx.textAlign = "center"; ctx.textBaseline = "top";
  for(let t = Math.ceil(x0 / step) * step; t <= x1; t += step){
    const x = L + (t - x0) / (x1 - x0) * (R - L);
    ctx.strokeStyle = COL.grid; ctx.beginPath(); ctx.moveTo(x, top); ctx.lineTo(x, bottom); ctx.stroke();
    ctx.fillStyle = COL.axis;
    ctx.fillText((t / div).toFixed(div === 1 ? 0 : 3).replace(/\.?0+$/, ""), x, bottom + 4);
  }
  ctx.textAlign = "right";
  ctx.fillStyle = COL.dim;
  ctx.fillText(unit, R, bottom + 4 + 12);
  return unit;
}

/* Shared zoom/pan/hover frame. cfg: {height, domain:[a,b], draw(ctx,w,h,view,hoverX), hover(x,view,w)->string, buttons} */
function viewer(cfg){
  const wrap = el("div", "width:100%;margin:6px 0;");
  const bar = el("div", "display:flex;gap:8px;align-items:center;font:11px 'JetBrains Mono',monospace;color:#a0b4cc;margin-bottom:4px;");
  const title = el("span", "flex:1", cfg.title || "");
  bar.appendChild(title);
  const canvas = el("canvas", "display:block;width:100%;background:"+COL.bg+";border:1px solid #1a2236;border-radius:4px;cursor:crosshair;touch-action:none;");
  const readout = el("div", "font:11px 'JetBrains Mono',monospace;color:#a0b4cc;min-height:1.5em;margin-top:3px;",
    "wheel: zoom   drag: pan   double-click: reset");
  const ctx = canvas.getContext("2d");
  const full = {x0: cfg.domain[0], x1: Math.max(cfg.domain[1], cfg.domain[0] + 1)};
  let view = {x0: full.x0, x1: full.x1};
  let hoverX = null, w = 800, dpr = 1, drag = null;

  function btn(label, fn){
    const b = el("button", "font:11px 'JetBrains Mono',monospace;padding:2px 8px;cursor:pointer;background:#0f1624;color:#a0b4cc;border:1px solid #1e2a40;border-radius:3px;", label);
    b.addEventListener("click", ev => {
      try{ fn(ev); }catch(e){ readout.textContent = label + " failed: " + e.message; console.error(e); }
    });
    bar.appendChild(b);
  }
  btn("Reset", () => { view = {x0: full.x0, x1: full.x1}; paint(); });
  btn("+", () => zoom(0.6, (cfg.L + w - cfg.R) / 2));
  btn("-", () => zoom(1.6, (cfg.L + w - cfg.R) / 2));
  btn("PNG", () => canvas.toBlob(b => {
    if(!b){ readout.textContent = "PNG failed: canvas gave no data"; return; }
    save(b, (cfg.file || "plot") + ".png");
  }));
  for(const b of (cfg.buttons || [])) btn(b.label, b.run);
  wrap.appendChild(bar); wrap.appendChild(canvas); wrap.appendChild(readout);

  function paint(){
    dpr = window.devicePixelRatio || 1;
    const h = cfg.height;
    canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
    canvas.style.height = h + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.fillStyle = COL.bg; ctx.fillRect(0, 0, w, h);
    cfg.draw(ctx, w, h, view, hoverX);
  }
  function xToT(px){ return view.x0 + (px - cfg.L) / (w - cfg.L - cfg.R) * (view.x1 - view.x0); }
  function zoom(f, px){
    const t = xToT(px);
    let a = t - (t - view.x0) * f, b = t + (view.x1 - t) * f;
    const minSpan = cfg.minSpan || 1;
    if(b - a < minSpan){ const m = (a + b) / 2; a = m - minSpan / 2; b = m + minSpan / 2; }
    if(b - a > full.x1 - full.x0){ a = full.x0; b = full.x1; }
    view = {x0: a, x1: b}; paint();
  }
  const guard = fn => ev => {
    try{ fn(ev); }catch(e){ readout.textContent = "plot error: " + e.message; console.error(e); }
  };
  canvas.addEventListener("wheel", guard(ev => {
    ev.preventDefault();
    const r = canvas.getBoundingClientRect();
    zoom(ev.deltaY < 0 ? 0.8 : 1.25, ev.clientX - r.left);
  }), {passive: false});
  const ptrs = new Map();            // active pointers: id -> {x, y}
  let pinch = null, lastTap = null;
  const dist = () => { const [p, q] = [...ptrs.values()]; return Math.hypot(p.x - q.x, p.y - q.y); };
  const startPan = () => { const p = [...ptrs.values()][0]; drag = {x: p.x, v: {...view}}; };
  canvas.addEventListener("pointerdown", guard(ev => {
    ptrs.set(ev.pointerId, {x: ev.clientX, y: ev.clientY});
    canvas.setPointerCapture(ev.pointerId);
    if(ptrs.size === 1){ startPan(); pinch = null; }
    else if(ptrs.size === 2){
      const [p, q] = [...ptrs.values()], r = canvas.getBoundingClientRect();
      pinch = {d: dist(), v: {...view}, cx: (p.x + q.x) / 2 - r.left};
      drag = null;
    }
  }));
  canvas.addEventListener("pointermove", guard(ev => {
    const r = canvas.getBoundingClientRect();
    const px = ev.clientX - r.left;
    if(ptrs.has(ev.pointerId)) ptrs.set(ev.pointerId, {x: ev.clientX, y: ev.clientY});
    if(pinch && ptrs.size === 2){
      // pinch: scale the span, keep the time under the fingers fixed
      const span0 = pinch.v.x1 - pinch.v.x0, frac = (pinch.cx - cfg.L) / (w - cfg.L - cfg.R);
      const tc = pinch.v.x0 + frac * span0;
      const span = Math.min(full.x1 - full.x0, Math.max(cfg.minSpan || 1, span0 * pinch.d / Math.max(dist(), 1)));
      view = {x0: tc - frac * span, x1: tc - frac * span + span};
    } else if(drag){
      const dt = (ev.clientX - drag.x) / (w - cfg.L - cfg.R) * (drag.v.x1 - drag.v.x0);
      view = {x0: drag.v.x0 - dt, x1: drag.v.x1 - dt};
    }
    hoverX = px >= cfg.L && px <= w - cfg.R ? px : null;
    readout.textContent = hoverX === null ? "" : cfg.hover(xToT(px), view, w - cfg.L - cfg.R);
    paint();
  }));
  const release = guard(ev => {
    const p = ptrs.get(ev.pointerId);
    ptrs.delete(ev.pointerId);
    pinch = null; drag = null;
    if(ptrs.size === 1) startPan();
    // double-tap (touch) resets the view
    if(ev.pointerType === "touch" && ptrs.size === 0 && p){
      const now = Date.now();
      if(lastTap && now - lastTap.t < 350 && Math.hypot(p.x - lastTap.x, p.y - lastTap.y) < 30){
        view = {x0: full.x0, x1: full.x1}; paint(); lastTap = null;
      } else lastTap = {t: now, x: p.x, y: p.y};
    }
  });
  canvas.addEventListener("pointerup", release);
  canvas.addEventListener("pointercancel", release);
  canvas.addEventListener("pointerleave", () => { hoverX = null; paint(); });
  canvas.addEventListener("dblclick", () => { view = {x0: full.x0, x1: full.x1}; paint(); });
  if(typeof ResizeObserver !== "undefined"){
    new ResizeObserver(() => {
      const nw = Math.floor(canvas.getBoundingClientRect().width);
      if(nw > 50 && nw !== w){ w = nw; paint(); }
    }).observe(canvas);
  }
  paint();
  return wrap;
}

/* ---------------- ADC waveform ---------------- */

function waveform(samples, o){
  o = o || {};
  const per = o.periodUs || 8;
  const n = samples.length;
  let sum = 0;
  for(let i = 0; i < n; i++) sum += samples[i];
  const mean = n ? sum / n : 0;
  const L = 54, R = 12, T = 8, B = 28;
  const H = 230;
  return viewer({
    title: (o.title || "ADC samples") + "  -  " + n + " samples, " + (1000 / per).toFixed(0) + " kHz, mean 0x" + Math.round(mean).toString(16),
    file: "lf-sniff",
    domain: [0, n * per], height: H, L, R, minSpan: per * 8,
    draw(ctx, w, h, view, hx){
      const pw = w - L - R, ph = h - T - B;
      const y = v => T + (1 - v / 255) * ph;
      ctx.font = FONT; ctx.textAlign = "right"; ctx.textBaseline = "middle";
      for(const v of [0, 64, 128, 192, 255]){
        ctx.strokeStyle = COL.grid; ctx.beginPath(); ctx.moveTo(L, y(v)); ctx.lineTo(w - R, y(v)); ctx.stroke();
        ctx.fillStyle = COL.axis; ctx.fillText("0x" + v.toString(16).padStart(2, "0"), L - 6, y(v));
      }
      timeAxis(ctx, view.x0, view.x1, L, w - R, T, h - B);
      ctx.save(); ctx.beginPath(); ctx.rect(L, T, pw, ph); ctx.clip();
      ctx.strokeStyle = COL.mean; ctx.setLineDash([5, 4]); ctx.beginPath();
      ctx.moveTo(L, y(mean)); ctx.lineTo(w - R, y(mean)); ctx.stroke(); ctx.setLineDash([]);
      const i0 = Math.max(0, Math.floor(view.x0 / per) - 1), i1 = Math.min(n - 1, Math.ceil(view.x1 / per) + 1);
      const px = i => L + (i * per - view.x0) / (view.x1 - view.x0) * pw;
      ctx.strokeStyle = COL.trace[0]; ctx.lineWidth = 1.2; ctx.beginPath();
      if(i1 - i0 > pw * 2){
        // more samples than pixels: one min/max column per pixel
        for(let c = 0; c < pw; c++){
          const a = Math.max(i0, Math.floor((view.x0 + c / pw * (view.x1 - view.x0)) / per));
          const b = Math.min(i1, Math.floor((view.x0 + (c + 1) / pw * (view.x1 - view.x0)) / per));
          let lo = 255, hi = 0;
          for(let i = a; i <= Math.max(a, b); i++){ const s = samples[i]; if(s < lo) lo = s; if(s > hi) hi = s; }
          ctx.moveTo(L + c + 0.5, y(lo)); ctx.lineTo(L + c + 0.5, y(hi));
        }
      } else {
        for(let i = i0; i <= i1; i++){ const x = px(i), yy = y(samples[i]); i === i0 ? ctx.moveTo(x, yy) : ctx.lineTo(x, yy); }
      }
      ctx.stroke(); ctx.lineWidth = 1;
      if(hx !== null){
        ctx.strokeStyle = "rgba(255,255,255,0.35)"; ctx.beginPath(); ctx.moveTo(hx, T); ctx.lineTo(hx, T + ph); ctx.stroke();
      }
      ctx.restore();
    },
    hover(t){
      const i = Math.max(0, Math.min(n - 1, Math.round(t / per)));
      return "t=" + fmtUs(i * per, "us") + "   sample " + i + "   0x" + (samples[i] || 0).toString(16).padStart(2, "0") + " (" + (samples[i] || 0) + ")";
    },
  });
}

/* ---------------- logic traces ----------------
 * model: {names[], hz, init(bitmask), ev:[{t,ch,lvl}] (ticks), spi:[{t, rd, short, text}] (ticks)}
 */
function logic(m, o){
  o = o || {};
  const us = 1e6 / m.hz;
  const nch = m.names.length;
  const steps = m.names.map((_, i) => [{t: 0, l: (m.init >> i) & 1}]);
  for(const e of m.ev) steps[e.ch].push({t: e.t * us, l: e.lvl});
  const spi = (m.spi || []).map(e => ({...e, t: e.t * us}));
  let end = 1;
  for(const s of steps) end = Math.max(end, s[s.length - 1].t);
  for(const e of spi) end = Math.max(end, e.t);
  end *= 1.02;
  const fi = m.names.indexOf("field_led");
  const L = 86, R = 12, T = 8, LANE = 38, SPI_H = spi.length ? 70 : 0, B = 28;
  const H = T + nch * LANE + SPI_H + B;

  function levelAt(s, t){ let lo = 0, hi = s.length - 1; while(lo < hi){ const mid = (lo + hi + 1) >> 1; if(s[mid].t <= t) lo = mid; else hi = mid - 1; } return s[lo]; }

  return viewer({
    title: o.title || "Logic capture", file: "logic",
    domain: [0, end], height: H, L, R, minSpan: 2, buttons: o.buttons,
    draw(ctx, w, h, view, hx){
      const pw = w - L - R, X = t => L + (t - view.x0) / (view.x1 - view.x0) * pw;
      const bottom = T + nch * LANE + SPI_H;
      timeAxis(ctx, view.x0, view.x1, L, w - R, T, bottom);
      ctx.save(); ctx.beginPath(); ctx.rect(L, T, pw, bottom - T); ctx.clip();
      if(fi >= 0){
        // shade where the field is on (LED low)
        const s = steps[fi];
        ctx.fillStyle = COL.field;
        for(let k = 0; k < s.length; k++){
          if(s[k].l) continue;
          const a = X(s[k].t), b = X(k + 1 < s.length ? s[k + 1].t : end);
          ctx.fillRect(Math.max(L, a), T, Math.min(w - R, b) - Math.max(L, a), bottom - T);
        }
      }
      for(let c = 0; c < nch; c++){
        const s = steps[c], top = T + c * LANE + 6, lo = T + c * LANE + LANE - 8;
        const yy = l => l ? top : lo;
        ctx.strokeStyle = COL.trace[c % COL.trace.length]; ctx.lineWidth = 1.5; ctx.beginPath();
        let cur = levelAt(s, view.x0);
        ctx.moveTo(L, yy(cur.l));
        for(const p of s){
          if(p.t <= view.x0) continue;
          if(p.t > view.x1) break;
          const x = X(p.t);
          ctx.lineTo(x, yy(cur.l)); ctx.lineTo(x, yy(p.l)); cur = p;
        }
        ctx.lineTo(w - R, yy(cur.l)); ctx.stroke(); ctx.lineWidth = 1;
      }
      if(spi.length){
        const base = T + nch * LANE;
        ctx.strokeStyle = COL.grid; ctx.beginPath(); ctx.moveTo(L, base); ctx.lineTo(w - R, base); ctx.stroke();
        ctx.font = FONT; ctx.textAlign = "left"; ctx.textBaseline = "middle";
        const ends = [-1e9, -1e9, -1e9];   // right edge of the last label in each row
        for(const e of spi){
          if(e.t < view.x0 || e.t > view.x1) continue;
          const x = X(e.t);
          ctx.strokeStyle = e.rd ? COL.rd : COL.wr;
          ctx.beginPath(); ctx.moveTo(x, base + 4); ctx.lineTo(x, base + 14); ctx.stroke();
          const row = ends.findIndex(v => x > v + 6);
          if(row < 0) continue;
          ctx.fillStyle = e.rd ? COL.rd : COL.wr;
          ctx.fillText(e.short, x + 2, base + 24 + row * 14);
          ends[row] = x + 2 + ctx.measureText(e.short).width;
        }
      }
      if(hx !== null){
        ctx.strokeStyle = "rgba(255,255,255,0.35)"; ctx.beginPath(); ctx.moveTo(hx, T); ctx.lineTo(hx, bottom); ctx.stroke();
      }
      ctx.restore();
      ctx.font = FONT; ctx.textAlign = "right"; ctx.textBaseline = "middle";
      for(let c = 0; c < nch; c++){
        ctx.fillStyle = COL.trace[c % COL.trace.length];
        ctx.fillText(m.names[c], L - 8, T + c * LANE + LANE / 2);
      }
      if(spi.length){ ctx.fillStyle = COL.axis; ctx.fillText("spi", L - 8, T + nch * LANE + 22); }
    },
    hover(t, view, pw){
      const parts = ["t=" + fmtUs(t, pickUnit(view.x1 - view.x0))];
      for(let c = 0; c < nch; c++) parts.push(m.names[c] + "=" + levelAt(steps[c], t).l);
      if(spi.length){
        let best = null, bd = 1e18;
        for(const e of spi){ const d = Math.abs(e.t - t); if(d < bd){ bd = d; best = e; } }
        const tol = 6 / pw * (view.x1 - view.x0);
        if(best && bd <= tol) parts.push("| " + best.text);
      }
      return parts.join("  ");
    },
  });
}

window.CUPlot = {waveform, logic, save};

})();
