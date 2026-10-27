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
`connect-src` — that's the directive the browser checks for WebSocket
connections, not a separate one:

```apache
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; connect-src 'self' https://infosec.exchange wss://phreakbyte-rsess-relay.<subdomain>.workers.dev; img-src 'self' data: https://media.infosec.exchange; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com"
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
