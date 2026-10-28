#!/usr/bin/env node
/*
 * remote-session-server.js -- generic WebSocket room relay for
 * phreakbyte.html's remote-session feature (sharing a connected device with
 * other browsers; not to be confused with the device's own nfc "relay"
 * standalone mode -- different thing, same page). Zero device/protocol
 * knowledge: it just binds
 * one "host" connection and any number of "peer" connections per session
 * id, and fans out messages between them. All CLI/RSP framing, parsing and
 * command logic stays in the browser (canary.js); this only moves bytes.
 *
 * No auth (by design, for now): anyone who knows/guesses a session id can
 * join as a peer. Run this behind something you trust (private network,
 * a reverse proxy with its own auth, etc.) if that's not acceptable.
 *
 * Protocol per session: one text "hello" frame on connect
 *   {"role":"host"|"peer"}
 * then arbitrary binary frames, forwarded verbatim:
 *   host -> peers : device_rx bytes (what the real device sent)
 *   peer -> host  : device_tx bytes (what that peer wants written)
 * A peer that joins after the host already has one connected is rejected
 * (one host per session); multiple peers are fine.
 *
 * Connection log: every join/leave is appended to LOG_FILE (JSON lines,
 * default ./rsess-log.jsonl) with a timestamp, the peer's IP, the Origin
 * header their browser sent, and whether that Origin matches ALLOWED_ORIGIN
 * ("sameOrigin" -- did this come from a page actually loaded off your own
 * site, vs. something else speaking this wire protocol directly at the
 * relay). IP alone is behind a reverse proxy: set TRUST_PROXY=1 to read it
 * from X-Forwarded-For instead of the raw socket address. Read the log back
 * with GET /log?session=<id>&key=<LOG_KEY> -- disabled (404) unless LOG_KEY
 * is set.
 *
 * Public stats: GET /?session=<id>&stats=1 returns aggregate counts only
 * (no IP, origin, or UA) -- join counts in the last 24h/1h and whether the
 * host is currently online. No key needed; safe to show on the page itself.
 *
 * Usage: ALLOWED_ORIGIN=https://sec1.dk LOG_KEY=... node remote-session-server.js [port]
 *   (default port 8787; both env vars are optional -- without ALLOWED_ORIGIN
 *   every entry logs sameOrigin:false, without LOG_KEY /log is disabled)
 */
const { WebSocketServer } = require("ws");
const http = require("http");
const url = require("url");
const fs = require("fs");

const PORT = Number(process.argv[2]) || 8787;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "";
const LOG_KEY = process.env.LOG_KEY || "";
const LOG_FILE = process.env.LOG_FILE || "./rsess-log.jsonl";
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const LOG_CAP = 200;

const sessions = new Map();   // sessionId -> {host, peers:Set}

function session(id){
  let s = sessions.get(id);
  if(!s){ s = {host:null, peers:new Set()}; sessions.set(id, s); }
  return s;
}
function sendPeerCount(s){
  if(s.host && s.host.readyState===1) s.host.send(JSON.stringify({type:"peer_count", count:s.peers.size}));
}
function clientIp(req){
  if(TRUST_PROXY){
    const xf = (req.headers["x-forwarded-for"]||"").split(",")[0].trim();
    if(xf) return xf;
  }
  return req.socket.remoteAddress || "";
}
function recordLog(id, event, meta){
  const origin = meta.origin || "";
  const entry = { ts:new Date().toISOString(), session:id, event,
    ip:meta.ip||"", origin, sameOrigin: !!ALLOWED_ORIGIN && origin===ALLOWED_ORIGIN, ua:meta.ua||"" };
  try{ fs.appendFileSync(LOG_FILE, JSON.stringify(entry)+"\n"); }catch(e){}
  console.log(`[${id}] ${event} ip=${entry.ip} origin=${origin||"(none)"} sameOrigin=${entry.sameOrigin}`);
}
function readLog(id){
  let lines;
  try{ lines = fs.readFileSync(LOG_FILE, "utf8").trim().split("\n").filter(Boolean); }
  catch(e){ return []; }
  const out = [];
  for(const line of lines){
    try{ const e = JSON.parse(line); if(e.session===id) out.push(e); }catch(e){}
  }
  return out.slice(-LOG_CAP);
}
// Public, anonymous, no key: counts only, nothing that identifies a visitor.
function computeStats(id){
  const entries = readLog(id);
  const now = Date.now();
  const HOUR = 3600000, DAY = 86400000;
  const since = (e,ms) => now - new Date(e.ts).getTime() <= ms;
  const s = sessions.get(id);
  return {
    peerJoins24h: entries.filter(e=>e.event==="peer_join" && since(e,DAY)).length,
    hostJoins24h: entries.filter(e=>e.event==="host_join" && since(e,DAY)).length,
    peerJoins1h: entries.filter(e=>e.event==="peer_join" && since(e,HOUR)).length,
    hostOnline: !!(s && s.host),
    peersNow: s ? s.peers.size : 0,
  };
}

const server = http.createServer((req,res)=>{
  const { pathname, query } = url.parse(req.url, true);
  if(pathname === "/log"){
    const id = (query.session||"").trim();
    if(!LOG_KEY || query.key !== LOG_KEY || !id){ res.writeHead(404); res.end("not found"); return; }
    res.writeHead(200, {"content-type":"application/json"});
    res.end(JSON.stringify(readLog(id), null, 2));
    return;
  }
  if(pathname === "/" && query.stats === "1"){
    const id = (query.session||"").trim();
    if(!id){ res.writeHead(400); res.end("missing session"); return; }
    // Fetched cross-origin from the page with plain fetch() (unlike the
    // WebSocket traffic, which isn't subject to CORS at all) -- needs this
    // header explicitly. Body is aggregate counts only, so open CORS is fine.
    res.writeHead(200, {"content-type":"application/json","cache-control":"no-store","access-control-allow-origin":"*"});
    res.end(JSON.stringify(computeStats(id)));
    return;
  }
  res.writeHead(200); res.end("phreakbyte relay\n");
});
const wss = new WebSocketServer({ server });

wss.on("connection", (ws, req) => {
  const { query } = url.parse(req.url, true);
  const id = (query.session||"").trim();
  if(!id){ ws.close(1008, "missing session id"); return; }
  const s = session(id);
  let role = null;
  const meta = { ip: clientIp(req), origin: req.headers.origin || "", ua: (req.headers["user-agent"]||"").slice(0,160) };

  ws.once("message", (msg) => {
    let hello;
    try{ hello = JSON.parse(msg.toString()); }catch(e){ ws.close(1008,"bad hello"); return; }
    role = hello.role;
    if(role === "host"){
      if(s.host){ ws.close(1008, "session already has a host"); return; }
      s.host = ws;
      recordLog(id, "host_join", meta);
      for(const p of s.peers) p.send(JSON.stringify({type:"host_online"}));
      sendPeerCount(s);
    } else if(role === "peer"){
      s.peers.add(ws);
      recordLog(id, "peer_join", meta);
      ws.send(JSON.stringify({type: s.host ? "host_online" : "host_offline"}));
      sendPeerCount(s);
    } else {
      ws.close(1008, "bad role"); return;
    }

    ws.on("message", (data, isBinary) => {
      if(!isBinary) return;   // only the hello is text; everything else is raw device bytes
      if(role === "host"){
        for(const p of s.peers) if(p.readyState===1) p.send(data, {binary:true});
      } else if(s.host && s.host.readyState===1){
        s.host.send(data, {binary:true});
      }
    });

    ws.on("close", () => {
      if(role === "host"){
        s.host = null;
        recordLog(id, "host_leave", meta);
        for(const p of s.peers) if(p.readyState===1) p.send(JSON.stringify({type:"host_offline"}));
      } else {
        s.peers.delete(ws);
        recordLog(id, "peer_leave", meta);
        sendPeerCount(s);
      }
      if(!s.host && s.peers.size===0) sessions.delete(id);
    });
  });
});

server.listen(PORT, () => console.log(`relay listening on :${PORT}`));
