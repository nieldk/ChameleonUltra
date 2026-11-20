"""cli_zigbee - host-side commands for the `zigbee` standalone mode (standalone zigbee ...).

The mode must be armed first (`standalone set-mode zigbee`, then trigger/arm).
Receive only; frames are parsed here, not on the device.
"""

import argparse
import struct
import sys
import time
from collections import defaultdict

import zb_parse as zp
from chameleon_enum import StandaloneMode, StandaloneState, Status

# The Zigbee HA/ZLL "default" Trust Center link key, used by many consumer
# devices that don't provision their own. Public: documented in the Zigbee
# specification and shipped as a built-in default in Wireshark.
ZIGBEE_DEFAULT_KEY = bytes.fromhex("5a6967426565416c6c69616e63653039")

# Zigbee Light Link (ZLL/"touchlink") keys. Public, but narrower in scope than the
# HA default key above:
#  - Master key: leaked publicly (Twitter, March 2015); used to key-transport the ZLL
#    link key during touchlink commissioning.
#  - Certification keys: Silicon Labs' public zll-types.h; only ever used by
#    manufacturers' own certification-lab test devices, included here for completeness.
ZLL_MASTER_KEY = bytes.fromhex("9f5595f10257c8a96573ab53ee2d4c0d")
ZLL_CERT_ENC_KEY = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
ZLL_CERT_LINK_KEY = bytes.fromhex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf")

# Candidate Trust Center link keys for decrypting an APS Transport-Key command seen
# during a device's join (the correct way to recover a network's real, random NWK
# key -- see ZigbeeDump's "found Transport Key" handling below). ZigBeeAlliance09 is
# the one that matters in practice; the ZLL keys are included in case a touchlink/ZLL
# device is joining instead of a HA one.
APS_JOIN_KEYS = [
    ("ZigBeeAlliance09 (HA default TC link key)", ZIGBEE_DEFAULT_KEY),
    ("ZLL master key", ZLL_MASTER_KEY),
    ("ZLL certification link key", ZLL_CERT_LINK_KEY),
]
from cli_core import ArgumentParserNoExit, DeviceRequiredUnit, standalone, color_string, CG, CR, CY, CC, C0, _box


def _group():
    for c in standalone.children:
        if c.name == "zigbee":
            return c
    return standalone.subgroup("zigbee", "Result data for the zigbee mode")


zb = _group()


def _collect(cmd, seconds, on_tick=None):
    """Drain the log for `seconds`, return a list of (channel, lqi, frame).
    on_tick(total, elapsed, remaining) is called each poll."""
    recs = []
    start = time.time()
    end = start + seconds
    while True:
        recs.extend(zp.parse_records(cmd.standalone_drain_result_for(StandaloneMode.ZIGBEE)))
        if on_tick is not None:
            on_tick(len(recs), time.time() - start, max(0.0, end - time.time()))
        if time.time() >= end:
            break
        time.sleep(0.5)
    return recs


def _live_status():
    """A one-line in-place '... Ns left, M frame(s)' status, TTY only.
    Returns (tick, done): tick(total, elapsed, remaining), done() ends the line."""
    on = sys.stdout.isatty()
    drawn = {"v": False}

    def tick(total, elapsed, remaining):
        if not on:
            return
        sys.stdout.write(f"\r\033[2K  scanning... {remaining:4.0f}s left, {total} frame(s)")
        sys.stdout.flush()
        drawn["v"] = True

    def done():
        if on and drawn["v"]:
            sys.stdout.write("\n")
            sys.stdout.flush()

    return tick, done


def _time_arg(parser, default):
    parser.add_argument("-t", "--time", type=float, default=default, metavar="<sec>",
                        help=f"capture duration in seconds (default {default:g})")
    return parser


@zb.command("scan")
class ZigbeeScan(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = ("Passively list Zigbee networks seen in beacons and traffic, per channel. "
                         "Arm the mode with channel 0 (hop) to cover 11-26: "
                         "`standalone config zigbee --channel 0`.")
        return _time_arg(p, 30)

    def on_exec(self, args: argparse.Namespace):
        nets = {}   # (channel, pan) -> info
        total = 0
        tick, done = _live_status()
        recs = _collect(self.cmd, args.time, on_tick=tick)
        done()
        for ch, lqi, f in recs:
            total += 1
            m = zp.parse_mac(f)
            if not m or not m["ok"]:
                continue
            pan = m["dst_pan"] if m["dst_pan"] is not None else m["src_pan"]
            if pan is None or pan == 0xFFFF:
                continue
            n = nets.setdefault((ch, pan), {"frames": 0, "beacon": None, "devs": set()})
            n["frames"] += 1
            if m["src"] is not None and m["src_mode"] == 2:
                n["devs"].add(m["src"])
            b = zp.parse_beacon(f, m)
            if b:
                n["beacon"] = b
        if not nets:
            if total:
                print(f" - {total} frame(s) captured but none with a usable PAN (acks, unparsed headers). Use `standalone zigbee dump`.")
            else:
                print(" - No frames. Is the mode armed (standalone status)? Beacons only appear when routers answer a beacon request or send them.")
            return
        print(f"  {'ch':>3} {'PAN':>6} {'frames':>6} {'short addrs':>11}  beacon")
        for (ch, pan), n in sorted(nets.items()):
            b = n["beacon"]
            bs = "-"
            if b:
                bs = (f"EPID {zp.fmt_ieee(b['epid'])} profile={b['stack_profile']} depth={b['depth']} "
                      f"permit_join={'yes' if b['permit_join'] else 'no'}")
            print(f"  {ch:>3} {pan:#06x} {n['frames']:>6} {len(n['devs']):>11}  {bs}")


@zb.command("devices")
class ZigbeeDevices(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = ("Device inventory per PAN from cleartext MAC/NWK headers: short addresses, "
                         "any IEEE addresses seen, frame counts and LQI (raw, uncompensated).")
        return _time_arg(p, 30)

    def on_exec(self, args: argparse.Namespace):
        devs = defaultdict(lambda: {"tx": 0, "lqi": [], "ieee": None})
        total = 0
        tick, done = _live_status()
        recs = _collect(self.cmd, args.time, on_tick=tick)
        done()
        for ch, lqi, f in recs:
            total += 1
            m = zp.parse_mac(f)
            if not m or not m["ok"] or m["src"] is None:
                continue
            pan = m["src_pan"]
            if m["src_mode"] == 3:
                key, ieee = (ch, pan, "ext"), m["src"]
                d = devs[(ch, pan, ieee)]
                d["ieee"] = ieee
            else:
                d = devs[(ch, pan, m["src"])]
            n = zp.parse_nwk(f, m)
            if n and m["src_mode"] == 2 and n["src"] == m["src"]:
                ie = n["src_ieee"]
                if ie is None and n.get("aux"):
                    ie = n["aux"]["src_ieee"]
                if ie is not None:
                    d["ieee"] = ie
            d["tx"] += 1
            d["lqi"].append(lqi)
        if not devs:
            print(f" - {total} frame(s) captured, none with a source address. Use `standalone zigbee dump`." if total
                  else " - No frames captured.")
            return
        print(f"  {'ch':>3} {'PAN':>6} {'address':>20} {'tx':>5} {'lqi raw avg':>11}")
        for (ch, pan, a), d in sorted(devs.items(), key=lambda kv: (kv[0][0], kv[0][1] or 0, str(kv[0][2]))):
            addr = zp.fmt_ieee(a) if isinstance(a, int) and a > 0xFFFF else f"{a:#06x}"
            extra = f"  ieee={zp.fmt_ieee(d['ieee'])}" if d["ieee"] is not None and addr != zp.fmt_ieee(d["ieee"]) else ""
            if d["ieee"] is not None:
                vendor = zp.oui_vendor(d["ieee"])
                if vendor:
                    extra += f" ({vendor})"
            pan_s = f"{pan:#06x}" if pan is not None else "  -   "
            print(f"  {ch:>3} {pan_s:>6} {addr:>20} {d['tx']:>5} {sum(d['lqi']) / len(d['lqi']):>11.0f}{extra}")


@zb.command("dump")
class ZigbeeDump(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = ("Print each captured frame decoded (MAC, beacon, NWK) plus hex. NWK payloads stay "
                         "opaque unless you give the network key of your own network with -k.")
        p.add_argument("-k", "--key", metavar="<hex32>", default=None,
                       help="16-byte NWK key (32 hex chars) to decrypt NWK payloads (AES-CCM*, MIC-32). "
                            "If omitted, the well-known Zigbee HA/ZLL default key is tried automatically.")
        p.add_argument("--no-default-key", action="store_true",
                       help="don't fall back to the well-known default/ZLL keys when -k is not given or fails "
                            "(these are key-transport keys, not real network keys -- a MIC-ok hit here means "
                            "the device non-compliantly reused one as its actual NWK key)")
        return _time_arg(p, 10)

    def on_exec(self, args: argparse.Namespace):
        keys = []
        if args.key:
            try:
                user_key = bytes.fromhex(args.key)
            except ValueError:
                user_key = b""
            if len(user_key) != 16:
                print(" - Key must be 32 hex characters (16 bytes).")
                return
            keys.append(("given key", user_key))
        if not args.no_default_key:
            keys.append(("default key (ZigBeeAlliance09)", ZIGBEE_DEFAULT_KEY))
            keys.append(("ZLL master key", ZLL_MASTER_KEY))
            keys.append(("ZLL certification link key", ZLL_CERT_LINK_KEY))
        count, found_keys = 0, 0
        tick, done = _live_status()
        recs = _collect(self.cmd, args.time, on_tick=tick)
        done()
        for ch, lqi, f in recs:
            count += 1
            m = zp.parse_mac(f)
            n = zp.parse_nwk(f, m) if m else None
            print(f"{zp.describe_frame(ch, lqi, f)}\n      {f.hex()}")
            if keys and n and n.get("aux"):
                for label, key in keys:
                    try:
                        r = zp.nwk_decrypt(f, m, n, key)
                    except ImportError:
                        print(" - Decrypting needs the 'cryptography' package: pip install cryptography")
                        keys = []
                        break
                    if r:
                        tag = "MIC ok" if r[1] else "MIC FAIL"
                        print(f"      nwk payload [{label}, {tag}]: {r[0].hex()}")
                        if r[1]:
                            break
            # Join-time key recovery: an APS Transport-Key command travels as NWK data
            # that's cleartext at the NWK layer (the joining device has no NWK key yet)
            # but secured at the APS layer under a TC link key. Decrypting that reveals
            # this network's real, random NWK key.
            if n is not None and n["ftype"] == 0 and not n["security"] and n.get("hdr_len") is not None:
                aps_payload = f[m["payload_off"] + n["hdr_len"]:]
                a = zp.parse_aps(aps_payload)
                if a and a["ftype"] == 1 and a["security"] and a.get("aux"):
                    for label, key in APS_JOIN_KEYS:
                        try:
                            r = zp.aps_decrypt(aps_payload, a, key)
                        except ImportError:
                            break
                        if r and r[0] and r[0][0] == zp.APS_CMD_TRANSPORT_KEY:
                            tk = zp.parse_transport_key(r[0])
                            tag = "MIC ok" if r[1] else "MIC FAIL"
                            print(f"      *** APS Transport Key [{label}, {tag}] type={tk['key_type_name']} ***")
                            if tk["decoded"]:
                                print(f"          network key: {tk['key'].hex()}  seq={tk['seq']} "
                                      f"dst={zp.fmt_ieee(tk['dst_ieee'])} src={zp.fmt_ieee(tk['src_ieee'])}")
                                if r[1]:
                                    found_keys += 1
                            else:
                                print(f"          (key type not decoded) raw={tk['raw'].hex()}")
                            if r[1]:
                                break
        print(f" {count} frame(s)" + (f", {found_keys} network key(s) recovered via Transport Key" if found_keys else ""))


def _poll_channel_arrays(cmd, seconds, poll_interval=1.0, on_update=None):
    """Poll standalone_get_status() for `seconds`, return the last-seen
    rx11-26/ed11-26 arrays (16 ints each, channel 11 first), or None for
    either that never appeared. on_update(rx, ed) is called each poll."""
    rx = ed = None
    end = time.time() + seconds
    while True:
        try:
            extra = dict(cmd.standalone_get_status())
        except Exception:
            extra = {}
        if 'rx11-26' in extra:
            rx = [int(x) for x in extra['rx11-26'].split(',')]
        if 'ed11-26' in extra:
            ed = [int(x) for x in extra['ed11-26'].split(',')]
        remaining = max(0.0, end - time.time())
        if on_update is not None:
            on_update(rx, ed, remaining)
        if remaining <= 0:
            break
        time.sleep(min(poll_interval, remaining))
    return rx, ed


def _channel_graph_lines(rx, ed, prev_ed=None, elapsed=None, total=None, width=30):
    """Stable channel-order (11-26) energy-detect bar chart with rx counts,
    rendered in the shared rounded box. Bars scale to the current max ed so
    the busiest channel fills the row. Each row is coloured by the change
    since the previous frame (green + rising, red - falling, plain steady) so
    small deltas are visible even when the bar length barely moves. Fixed min
    width so the live redraw doesn't jiggle."""
    maxed = max(ed) if ed and max(ed) > 0 else 1
    rows = [f"{'ch':>3} {'rx':>6} {'ed':>6}    energy"]
    for i in range(16):
        n = int(round(width * ed[i] / maxed))
        prev = prev_ed[i] if prev_ed else ed[i]
        if ed[i] > prev:
            col, mark = CG, f"{CG}+{C0}"
        elif ed[i] < prev:
            col, mark = CR, f"{CR}-{C0}"
        else:
            col, mark = CG, " "  # steady: green base, never white
        rows.append(f"{11 + i:>3} {rx[i]:>6} {ed[i]:>6} {mark}  {col}{'█' * n}{C0}")
    if total:
        done = int(round(width * min(elapsed or 0, total) / total))
        rows.append("")
        rows.append(f"{'scan':>14} {elapsed or 0:4.0f}/{total:.0f}s  "
                    f"{CC}{'█' * done}{C0}{'·' * (width - done)}")
    return _box("Zigbee channel energy", rows, color=CC, min_width=21 + width)


def _zigbee_decode_cfg(cfg):
    """Return (chan_mask, dwell_ms) for a zigbee config blob (v1 or v2),
    defaulting to (channel 11 only, 500 ms) when cfg is missing/short."""
    if cfg and len(cfg) >= 6 and cfg[0] == 2:
        mask = int.from_bytes(cfg[4:6], 'little') or 1
        dwell = int.from_bytes(cfg[2:4], 'little') if len(cfg) >= 4 else 500
        return mask, dwell
    if cfg and len(cfg) >= 2:
        ch = cfg[1]
        mask = 0xFFFF if ch == 0 else (1 << (ch - 11)) if 11 <= ch <= 26 else 1
        dwell = int.from_bytes(cfg[2:4], 'little') if len(cfg) >= 4 else 500
        return mask, dwell
    return 1, 500


@zb.command("hunt")
class ZigbeeHunt(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = (
            "Scan all channels (11-26) for activity -- rx frame counts and "
            "energy-detect peaks -- rank them, and optionally lock the mode "
            "onto the result. --lock locks a single channel (--rank N picks "
            "the Nth busiest, default 1 = busiest); --lock-top N instead hops "
            "only over the N busiest channels (less dwell time per channel "
            "than a single lock, but covers more than one).\n\n"
            "Requires zigbee already armed and hopping: "
            "`standalone config zigbee --channel 0` (or --channels) then "
            "`standalone trigger`."
        )
        p.add_argument("-t", "--time", type=float, default=120, metavar="<sec>",
                        help="scan duration in seconds (default 120)")
        p.add_argument("--lock", action="store_true",
                        help="after scanning, reconfigure the armed mode onto the ranked channel(s)")
        lock_grp = p.add_mutually_exclusive_group()
        lock_grp.add_argument("--rank", type=int, default=1, metavar="<N>",
                              help="with --lock, lock onto the Nth busiest channel (default 1 = busiest)")
        lock_grp.add_argument("--lock-top", type=int, default=None, metavar="<N>",
                              help="with --lock, hop only over the N busiest channels "
                                   "instead of locking a single one")
        return p

    def on_exec(self, args: argparse.Namespace):
        state, mode, flags, fds = self.cmd.standalone_get_mode()
        if mode != StandaloneMode.ZIGBEE:
            print(" - Not in zigbee mode. Run `standalone set-mode zigbee` first.")
            return
        if state == StandaloneState.DISARMED:
            print(" - Zigbee mode is disarmed. Run `standalone trigger` to arm it.")
            return
        cfg = self.cmd.standalone_get_config(mode)
        mask, dwell = _zigbee_decode_cfg(cfg)
        if bin(mask).count('1') <= 1:
            locked_ch = 11 + (mask.bit_length() - 1 if mask else 0)
            print(f" - Locked to channel {locked_ch}, not hopping -- a scan needs every channel covered.\n"
                  f"   Run `standalone config zigbee --channel 0` (or --channels) first "
                  f"(applies live, no re-arm needed).")
            return

        print(f"Scanning {args.time:g}s across channels 11-26 ...")
        # live energy-detect bar graph, redrawn in place each poll (TTY only)
        live = sys.stdout.isatty()
        drawn = {"n": 0, "prev": None}

        def _draw(rx_now, ed_now, remaining):
            if not live:
                return
            ed_cur = ed_now or [0] * 16
            frame = _channel_graph_lines(
                rx_now or [0] * 16, ed_cur, prev_ed=drawn["prev"],
                elapsed=args.time - remaining, total=args.time)
            drawn["prev"] = list(ed_cur)
            if drawn["n"]:
                sys.stdout.write(f"\033[{drawn['n']}A")
            for ln in frame:
                sys.stdout.write("\033[2K" + ln + "\n")
            sys.stdout.flush()
            drawn["n"] = len(frame)

        rx, ed = _poll_channel_arrays(self.cmd, args.time, on_update=_draw)
        if live and drawn["n"]:
            print()  # separate the live graph from the final ranking
        if rx is None and ed is None:
            print(" - No rx11-26/ed11-26 in status -- older firmware, or still on the first hop pass.")
            return
        rx = rx or [0] * 16
        ed = ed or [0] * 16

        ranking = sorted(range(16), key=lambda i: (rx[i], ed[i]), reverse=True)
        print(f"  {'ch':>3} {'rx':>6} {'ed':>6}")
        for i in ranking:
            ch = 11 + i
            quiet = "  (quiet)" if not rx[i] and not ed[i] else ""
            print(f"  {ch:>3} {rx[i]:>6} {ed[i]:>6}{quiet}")

        active = [11 + i for i in ranking if rx[i] or ed[i]]
        if len(active) > 1 and args.lock_top is None:
            print(color_string((CY,
                f" {len(active)} channels show activity ({', '.join(map(str, active))}); "
                f"re-run with --lock-top {len(active)} to hop only over those, "
                f"or --lock --rank N to pick one.")))

        if args.lock and args.lock_top is not None:
            if not (1 <= args.lock_top <= 16):
                print(" - --lock-top must be 1..16")
                return
            top_idxs = ranking[:args.lock_top]
            new_mask = 0
            for i in top_idxs:
                new_mask |= 1 << i
            chans = ','.join(str(11 + i) for i in top_idxs)
            if not any(rx[i] or ed[i] for i in top_idxs):
                print(color_string((CY, f" - None of {{{chans}}} showed activity; locking anyway.")))
            resp = self.cmd.standalone_set_config(mode, struct.pack('<BBHH', 2, 0, dwell, new_mask))
            if resp.status == Status.SUCCESS:
                print(color_string((CG, f"locked onto hop set {{{chans}}} (applied immediately)")))
            else:
                print(color_string((CR, f"set-config failed: status={resp.status}")))
            return

        if args.lock:
            if not (1 <= args.rank <= 16):
                print(" - --rank must be 1..16")
                return
            idx = ranking[args.rank - 1]
            target = 11 + idx
            if not rx[idx] and not ed[idx]:
                print(color_string((CY,
                    f" - Channel {target} (rank {args.rank}) showed no activity; locking anyway.")))
            resp = self.cmd.standalone_set_config(mode, struct.pack('<BBH', 1, target, dwell))
            if resp.status == Status.SUCCESS:
                print(color_string((CG, f"locked onto channel {target} (applied immediately)")))
            else:
                print(color_string((CR, f"set-config failed: status={resp.status}")))
