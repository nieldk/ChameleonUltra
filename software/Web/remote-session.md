# Remote session (device sharing) — setup

Lets other browsers drive a device connected to one browser's Web Bluetooth
link — full access to every tab (Device, Slots, HF14A/MF1, LF, MF0/NTAG,
DESFire, EMV, Shell, Terminal, `hw gdb`). One host holds the real BLE
connection; any number of peers join over a WebSocket relay that only moves
bytes. No login — anyone with the join link gets full control.

Not to be confused with `MODE_RELAY`, the device's own NFC relay-attack
standalone mode. Same word, unrelated feature.

## Components

| File | Role |
|---|---|
| `phreakbyte.html` | adds the "Remote session" status box + Share/Stop controls |
| `canary.js` | `rsessConnect`/`rsessShare`/`rsessStop` + `withDeviceLock`, `handleDeviceBytes`, `rawWrite`, `connected()` made peer-aware |
| `terminal.js` | `rspSend` (used by `hw gdb`) serialized through the same `withDeviceLock` |
| `remote-session-server.js` | relay backend, Node (`ws` package) — for self-hosting |
| `cloudflare-relay/` | same relay backend, as a Cloudflare Worker + Durable Object — for simply.com, which can't run a port-listening process |

Both relay backends speak the identical wire protocol, so `canary.js` needs
no changes regardless of which one you point it at.

## 1. Deploy a relay backend

Pick one.

### Cloudflare Workers (recommended for simply.com hosting)

```
cd cloudflare-relay
npm install
npx wrangler login
npx wrangler deploy
```

If `npm install` warns that `esbuild`/`workerd` postinstall scripts were
blocked (`npm warn install-scripts`), approve and reinstall first:

```
npm install-scripts approve esbuild
npm install-scripts approve workerd
npm install
```

`wrangler deploy` prints the Worker's URL, e.g.
`https://phreakbyte-rsess-relay.<subdomain>.workers.dev`. The relay address
to use on the page is the same host with `wss://` instead of `https://`:

```
wss://phreakbyte-rsess-relay.<subdomain>.workers.dev
```

### Self-hosted Node

```
node remote-session-server.js [port]   # default 8787
```

Relay address: `ws://<host>:<port>` (or `wss://` behind your own TLS
termination).

## 2. Allow the relay through CSP

If the page is served with a `Content-Security-Policy` header (simply.com
site here uses one via `.htaccess`), add the relay's origin to
`connect-src` — that's the directive the browser checks for both the
WebSocket connection and the plain HTTPS stats fetch (§7), so list both
schemes rather than relying on a browser's scheme-matching for a bare host:

```apache
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; connect-src 'self' https://infosec.exchange wss://phreakbyte-rsess-relay.<subdomain>.workers.dev https://phreakbyte-rsess-relay.<subdomain>.workers.dev; img-src 'self' data: https://media.infosec.exchange; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com"
```

Without this the browser silently blocks the connection and the console
shows a CSP `connect-src` violation.

## 3. Upload the page files

Upload `phreakbyte.html`, `canary.js`, `terminal.js`, `fullcmd.js` to the
site, overwriting the existing ones. Hard-refresh (Ctrl+Shift+R) to clear
any cached copy.

## 4. Share a device

1. Connect to the device over Bluetooth as normal (Connect button).
2. In the **Remote session** box (below the Connection options, above the
   tab bar), enter the relay address (`wss://...`) and click
   **Share this device**.
3. On success the status line reads `Sharing · N peer(s) connected` and the
   box shows the join link
   (`https://<site>/phreakbyte.html?rsess=<id>&rsrelay=<url>`). Send that
   link to whoever you're sharing with.
4. **Stop sharing** ends the session; closing the host tab/browser also
   drops it (peers get `host_offline`).

## 5. Join a session

Open the join link. The page replaces the Connection box with a plain
status line (`Joining…` → `Joined (live)`) — there's no real BLE connection
on this side, every tab talks through the host instead. Works exactly like
a local connection otherwise.

## 6. Connection log

There's no auth, so the relay keeps a log of who joins/leaves each session —
timestamp, IP, the `Origin` header their browser sent, and whether that
origin matches your own site (`sameOrigin`). `Origin` is what tells apart a
peer that actually loaded `phreakbyte.html` from your site versus something
else speaking the wire protocol directly at the relay; IP is logged
alongside it since `Origin` is just a header the client sends, not a trust
proof — a stranger can send any origin value they like, so treat `IP` as
the harder signal and `sameOrigin` as a filter for the common case.

**Cloudflare**: set a secret once (without it the log endpoint is disabled,
not left open):

```
cd cloudflare-relay
npx wrangler secret put LOG_KEY
```

`ALLOWED_ORIGIN` in `wrangler.jsonc` (defaults to `https://sec1.dk`) is what
`sameOrigin` is checked against — update and redeploy if the site ever
moves. Read the log:

```
curl "https://phreakbyte-rsess-relay.<subdomain>.workers.dev/?session=<id>&log=1&key=<LOG_KEY>"
```

**Self-hosted Node**: set env vars before starting it —
`ALLOWED_ORIGIN=https://sec1.dk LOG_KEY=... node remote-session-server.js`.
Entries append to `./rsess-log.jsonl` (override with `LOG_FILE`). Behind a
reverse proxy, add `TRUST_PROXY=1` so the logged IP comes from
`X-Forwarded-For` instead of the proxy's own address. Read the log:

```
curl "http://<host>:8787/log?session=<id>&key=<LOG_KEY>"
```

Both cap at the last 200 entries per session.

## 7. On-page stats (anonymous)

The page itself shows a small line under the Remote session box: peer/host
join counts in the last 24h and 1h, and whether a host is currently online.
No key, no IP, origin, or UA in the response — just counts — polled every
60s from `canary.js` (`rsessFetchStats`) for whoever has a relay + session
id configured, host or peer side. Backed by:

- **Cloudflare**: `GET /?session=<id>&stats=1` on the Worker.
- **Node**: `GET /?session=<id>&stats=1` on the HTTP server.

Both derive the stats URL from the same `wss://`/`ws://` relay address
(swapping the scheme for `https://`/`http://`), so nothing new to configure
beyond the CSP entry in §2.

## Notes

- No authentication by design. Anyone who has (or guesses) the join link's
  `rsess` id gets full read/write control of the device for as long as the
  host keeps sharing. Don't post join links anywhere public.
- Commands from the host and any number of peers are serialized onto the
  single physical BLE link — concurrent requests queue, they don't race or
  cross-wire replies.
- If the Worker's subdomain ever changes (different Cloudflare account,
  renamed Worker), update both the relay address you type into the page
  and the CSP `connect-src` entry to match.
