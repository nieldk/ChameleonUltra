"use strict";
/* logic_tab.js - wires the Logic tab (arm / stop / capture) to CULogic and CUPlot.
 * Loaded after fullcmd.js for $(), wire(), showResult(). */
(function(){

function sources(){
  const s = [];
  if($("g_spi").checked) s.push("spi");
  if($("g_cs").checked) s.push("hf_cs");
  if($("g_field").checked) s.push("field_led");
  if(!s.length) throw new Error("Select at least one source");
  return s;
}

async function arm(){
  const r = await CULogic.arm(sources(), Number($("g_rate").value), Number($("g_merge").value) || 0);
  showResult($("g_result"), "Armed at " + (r.hz / 1e6) + " MHz. Run your command, then press Stop & show.", "ok");
}

async function show(){
  const m = await CULogic.finish();
  const msg = [];
  if(m.hasEdges) msg.push(m.total + " edge(s)" + (m.overflow ? " (buffer full, truncated)" : ""));
  if(m.spi.length) msg.push(m.spi.length + " SPI entries" + (m.spiOver ? " (log full, truncated)" : ""));
  showResult($("g_result"), msg.join(" · ") || "Nothing recorded", "ok");
  $("g_text").textContent = CULogic.decode(m).join("\n");
  const box = $("g_plot");
  box.replaceChildren();
  if(m.hasEdges || m.spi.length){
    box.appendChild(CUPlot.logic(m, {buttons: m.hasEdges ? [{label: "VCD", run: () => CULogic.saveVcd(m)}] : []}));
  }
}

wire("g_arm", $("g_result"), arm);
wire("g_stop", $("g_result"), show);
wire("g_cap", $("g_result"), async () => {
  await arm();
  await new Promise(r => setTimeout(r, Math.max(1, Number($("g_ms").value) || 1000)));
  await show();
});

})();
