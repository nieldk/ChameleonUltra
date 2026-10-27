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
 * Usage: node remote-session-server.js [port]   (default 8787)
 */
const { WebSocketServer } = require("ws");
const http = require("http");
const url = require("url");

const PORT = Number(process.argv[2]) || 8787;
const sessions = new Map();   // sessionId -> {host, peers:Set}

function session(id){
  let s = sessions.get(id);
  if(!s){ s = {host:null, peers:new Set()}; sessions.set(id, s); }
  return s;
}

const server = http.createServer((req,res)=>{ res.writeHead(200); res.end("phreakbyte relay\n"); });
const wss = new WebSocketServer({ server });

wss.on("connection", (ws, req) => {
  const { query } = url.parse(req.url, true);
  const id = (query.session||"").trim();
  if(!id){ ws.close(1008, "missing session id"); return; }
  const s = session(id);
  let role = null;

  ws.once("message", (msg) => {
    let hello;
    try{ hello = JSON.parse(msg.toString()); }catch(e){ ws.close(1008,"bad hello"); return; }
    role = hello.role;
    if(role === "host"){
      if(s.host){ ws.close(1008, "session already has a host"); return; }
      s.host = ws;
      console.log(`[${id}] host connected`);
      for(const p of s.peers) p.send(JSON.stringify({type:"host_online"}));
    } else if(role === "peer"){
      s.peers.add(ws);
      console.log(`[${id}] peer joined (${s.peers.size} total)`);
      ws.send(JSON.stringify({type: s.host ? "host_online" : "host_offline"}));
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
        console.log(`[${id}] host disconnected`);
        for(const p of s.peers) if(p.readyState===1) p.send(JSON.stringify({type:"host_offline"}));
      } else {
        s.peers.delete(ws);
        console.log(`[${id}] peer left (${s.peers.size} left)`);
      }
      if(!s.host && s.peers.size===0) sessions.delete(id);
    });
  });
});

server.listen(PORT, () => console.log(`relay listening on :${PORT}`));
