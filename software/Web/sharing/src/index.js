/*
 * Cloudflare Workers / Durable Objects port of remote-session-server.js.
 * Same wire protocol, so canary.js needs no changes -- only the relayUrl
 * points at this Worker's wss:// URL instead of a self-run Node process.
 * One Durable Object instance per phreakbyte session id (the DO name IS
 * the session id), so "one host per session" falls out of the DO model for
 * free. Zero device/protocol knowledge: still just moves bytes.
 *
 * Protocol (unchanged from remote-session-server.js):
 *   connect to wss://<worker>?session=<id>
 *   first message (text): {"role":"host"|"peer"}
 *   then binary frames, forwarded verbatim:
 *     host -> peers : device bytes the real device sent
 *     peer -> host  : device bytes that peer wants written
 *   peer also gets a control text frame on join/host-drop:
 *     {"type":"host_online"} / {"type":"host_offline"}
 *
 * No auth, by design (matches remote-session-server.js): anyone who knows
 * a session id can join as a peer. Put Cloudflare Access or your own token
 * check in front of this Worker if that's not acceptable.
 */
import { DurableObject } from "cloudflare:workers";

export class RsessRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.host = null;
    this.peers = new Set();
    this.roleOf = new Map();   // ws -> "host" | "peer"
    this.pendingHello = new Set();   // ws connected, no role yet

    // The DO's plain fields above are lost on hibernation; its WebSockets
    // aren't. Rebuild role tracking from each socket's own attachment.
    for (const ws of this.ctx.getWebSockets()) {
      const att = ws.deserializeAttachment();
      if (!att) continue;
      this.roleOf.set(ws, att.role);
      if (att.role === "host") this.host = ws;
      else if (att.role === "peer") this.peers.add(ws);
    }
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected a websocket upgrade", { status: 426 });
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
    this.pendingHello.add(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    if (this.pendingHello.has(ws)) {
      this.pendingHello.delete(ws);
      let hello = null;
      if (typeof message === "string") {
        try { hello = JSON.parse(message); } catch (e) { /* bad hello below */ }
      }
      const role = hello && hello.role;
      if (role === "host") {
        if (this.host) { ws.close(1008, "session already has a host"); return; }
        this.host = ws;
        this.roleOf.set(ws, "host");
        ws.serializeAttachment({ role: "host" });
        for (const p of this.peers) this.safeSend(p, JSON.stringify({ type: "host_online" }));
        this.sendPeerCount();
      } else if (role === "peer") {
        this.peers.add(ws);
        this.roleOf.set(ws, "peer");
        ws.serializeAttachment({ role: "peer" });
        this.safeSend(ws, JSON.stringify({ type: this.host ? "host_online" : "host_offline" }));
        this.sendPeerCount();
      } else {
        ws.close(1008, "bad role");
      }
      return;
    }
    if (typeof message === "string") return;   // only the hello is text; ignore stray text after
    const role = this.roleOf.get(ws);
    if (role === "host") {
      for (const p of this.peers) this.safeSend(p, message);
    } else if (role === "peer" && this.host) {
      this.safeSend(this.host, message);
    }
  }

  async webSocketClose(ws) { this.cleanup(ws); }
  async webSocketError(ws) { this.cleanup(ws); }

  cleanup(ws) {
    const role = this.roleOf.get(ws);
    this.roleOf.delete(ws);
    this.pendingHello.delete(ws);
    if (role === "host" && this.host === ws) {
      this.host = null;
      for (const p of this.peers) this.safeSend(p, JSON.stringify({ type: "host_offline" }));
    } else if (role === "peer") {
      this.peers.delete(ws);
      this.sendPeerCount();
    }
  }

  sendPeerCount() {
    if (this.host) this.safeSend(this.host, JSON.stringify({ type: "peer_count", count: this.peers.size }));
  }

  safeSend(ws, data) { try { ws.send(data); } catch (e) { /* socket is gone; its close/error handler cleans up */ } }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const id = (url.searchParams.get("session") || "").trim();
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("phreakbyte remote-session relay (Cloudflare Worker)\n");
    }
    if (!id) return new Response("missing ?session=", { status: 400 });
    const stub = env.RSESS_ROOM.getByName(id);
    return stub.fetch(request);
  },
};
