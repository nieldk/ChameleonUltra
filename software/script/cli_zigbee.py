"""cli_zigbee - host-side commands for the `zigbee` standalone mode (standalone zigbee ...).

The mode must be armed first (`standalone set-mode zigbee`, then trigger/arm).
Receive only; frames are parsed here, not on the device.
"""

import argparse
import time
from collections import defaultdict

import zb_parse as zp
from chameleon_enum import StandaloneMode

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
from cli_core import ArgumentParserNoExit, DeviceRequiredUnit, standalone


def _group():
    for c in standalone.children:
        if c.name == "zigbee":
            return c
    return standalone.subgroup("zigbee", "Result data for the zigbee mode")


zb = _group()


def _collect(cmd, seconds):
    """Drain the log for `seconds`, return a list of (channel, lqi, frame)."""
    recs = []
    end = time.time() + seconds
    while True:
        recs.extend(zp.parse_records(cmd.standalone_drain_result_for(StandaloneMode.ZIGBEE)))
        if time.time() >= end:
            break
        time.sleep(0.5)
    return recs


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
                         "`standalone config -m zigbee --channel 0`.")
        return _time_arg(p, 30)

    def on_exec(self, args: argparse.Namespace):
        nets = {}   # (channel, pan) -> info
        total = 0
        for ch, lqi, f in _collect(self.cmd, args.time):
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
        for ch, lqi, f in _collect(self.cmd, args.time):
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
        for ch, lqi, f in _collect(self.cmd, args.time):
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
