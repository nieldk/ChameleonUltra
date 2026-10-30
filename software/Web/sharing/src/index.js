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
 *
 * Connection log: each hello (host or peer join) and disconnect is recorded
 * -- timestamp, CF-Connecting-IP, the Origin header the browser sent, and
 * whether that Origin matches env.ALLOWED_ORIGIN ("sameOrigin"). Origin is
 * the standard way to tell "a page loaded from my own site" apart from
 * anything else that speaks this wire protocol at the relay directly --
 * CF-Connecting-IP is still logged alongside it since Origin is just a
 * header the client sends and isn't itself a trust proof. Read it back with
 * GET /?session=<id>&log=1&key=<LOG_KEY> (set via `wrangler secret put
 * LOG_KEY`; without a configured LOG_KEY the endpoint is disabled, not
 * left open). Last 200 entries per session, persisted via DO storage so
 * hibernation/eviction between requests doesn't lose them.
 *
 * Public stats: GET /?session=<id>&stats=1 returns aggregate counts only
 * (no IP, origin, or UA) -- join counts in the last 24h/1h and whether the
 * host is currently online. No key needed; nothing in the response can
 * identify a visitor, so it's safe to show on the page itself.
 */
import { DurableObject } from "cloudflare:workers";

const LOG_CAP = 200;

export class RsessRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    // Assigned explicitly rather than relied on from the base class, since
    // the Durable Object docs don't confirm this.env is set automatically.
    this.env = env;
    this.host = null;
    this.peers = new Set();
    this.roleOf = new Map();    // ws -> "host" | "peer"
    this.pendingHello = new Map();   // ws -> {ip, origin, ua} captured at fetch() time, role not known yet
    this.log = [];

    // The DO's plain fields above are lost on hibernation; its WebSockets
    // aren't. Rebuild role tracking from each socket's own attachment.
    // blockConcurrencyWhile delays handling any request until the async
    // storage read finishes, so the log is loaded before anything touches it.
    ctx.blockConcurrencyWhile(async () => {
      this.log = (await ctx.storage.get("log")) || [];
      for (const ws of this.ctx.getWebSockets()) {
        const att = ws.deserializeAttachment();
        if (!att) continue;
        this.roleOf.set(ws, att.role);
        if (att.role === "host") this.host = ws;
        else if (att.role === "peer") this.peers.add(ws);
      }
    });
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.searchParams.get("log") === "1") return this.serveLog(url, request);
    if (url.searchParams.get("stats") === "1") return this.serveStats();
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected a websocket upgrade", { status: 426 });
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
    this.pendingHello.set(server, {
      ip: request.headers.get("CF-Connecting-IP") || "",
      origin: request.headers.get("Origin") || "",
      ua: (request.headers.get("User-Agent") || "").slice(0, 160),
    });
    return new Response(null, { status: 101, webSocket: client });
  }

  serveLog(url, request) {
    const key = this.env.LOG_KEY;
    if (!key || url.searchParams.get("key") !== key) {
      return new Response("not found", { status: 404 });
    }
    return new Response(JSON.stringify(this.log, null, 2), { headers: { "content-type": "application/json" } });
  }

  // Public, anonymous, no key: counts only, nothing that identifies a visitor.
  serveStats() {
    const now = Date.now();
    const HOUR = 3600000, DAY = 86400000;
    const since = (e, ms) => now - new Date(e.ts).getTime() <= ms;
    const stats = {
      peerJoins24h: this.log.filter((e) => e.event === "peer_join" && since(e, DAY)).length,
      hostJoins24h: this.log.filter((e) => e.event === "host_join" && since(e, DAY)).length,
      peerJoins1h: this.log.filter((e) => e.event === "peer_join" && since(e, HOUR)).length,
      hostOnline: !!this.host,
      peersNow: this.peers.size,
    };
    return new Response(JSON.stringify(stats), {
      // Fetched cross-origin from the page (sec1.dk -> this Worker's own
      // subdomain) with plain fetch(), unlike the WebSocket traffic, which
      // isn't subject to CORS at all -- so this needs the header explicitly.
      // The body is aggregate counts only, so an open CORS policy is fine.
      headers: { "content-type": "application/json", "cache-control": "no-store", "access-control-allow-origin": "*" },
    });
  }

  recordLog(event, meta) {
    const origin = meta.origin || "";
    const entry = {
      ts: new Date().toISOString(),
      event,                      // "host_join" | "peer_join" | "host_leave" | "peer_leave"
      ip: meta.ip || "",
      origin,
      sameOrigin: !!this.env.ALLOWED_ORIGIN && origin === this.env.ALLOWED_ORIGIN,
      ua: meta.ua || "",
    };
    this.log.push(entry);
    if (this.log.length > LOG_CAP) this.log.splice(0, this.log.length - LOG_CAP);
    this.ctx.storage.put("log", this.log).catch(() => {});
  }

  async webSocketMessage(ws, message) {
    if (this.pendingHello.has(ws)) {
      const meta = this.pendingHello.get(ws);
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
        ws.serializeAttachment({ role: "host", meta });
        this.recordLog("host_join", meta);
        for (const p of this.peers) this.safeSend(p, JSON.stringify({ type: "host_online" }));
        this.sendPeerCount();
      } else if (role === "peer") {
        this.peers.add(ws);
        this.roleOf.set(ws, "peer");
        ws.serializeAttachment({ role: "peer", meta });
        this.recordLog("peer_join", meta);
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
    const att = ws.deserializeAttachment();
    const meta = (att && att.meta) || {};
    this.roleOf.delete(ws);
    this.pendingHello.delete(ws);
    if (role === "host" && this.host === ws) {
      this.host = null;
      this.recordLog("host_leave", meta);
      for (const p of this.peers) this.safeSend(p, JSON.stringify({ type: "host_offline" }));
    } else if (role === "peer") {
      this.peers.delete(ws);
      this.recordLog("peer_leave", meta);
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
    const isMeta = url.searchParams.get("log") === "1" || url.searchParams.get("stats") === "1";
    if (request.headers.get("Upgrade") !== "websocket" && !isMeta) {
      return new Response("phreakbyte remote-session relay (Cloudflare Worker)\n");
    }
    if (!id) return new Response("missing ?session=", { status: 400 });
    const stub = env.RSESS_ROOM.getByName(id);
    return stub.fetch(request);
  },
};
