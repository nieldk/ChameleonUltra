"""cli_hw_logic - edge logic analyser on internal nets (hw logic ...)."""

import argparse
import time

from cli_core import ArgumentParserNoExit, DeviceRequiredUnit, hw

hw_logic = hw.subgroup("logic", "Edge logic analyser (internal nets / raw pins, VCD export)")

NAMED = {"hf_cs": 0x00, "field_led": 0x01, "spi": 0x02}
RATES = {16: 0, 8: 1, 4: 2, 2: 3, 1: 4}  # MHz -> prescaler
CHUNK = 90
SPI_CHUNK = 400
SPI_MAXDATA = 24

# RC522 register names, from firmware rc522.h
RC522_REGS = {
    0x00: "RFU00",
    0x01: "CommandReg",
    0x02: "ComIEnReg",
    0x03: "DivlEnReg",
    0x04: "ComIrqReg",
    0x05: "DivIrqReg",
    0x06: "ErrorReg",
    0x07: "Status1Reg",
    0x08: "Status2Reg",
    0x09: "FIFODataReg",
    0x0A: "FIFOLevelReg",
    0x0B: "WaterLevelReg",
    0x0C: "Control522Reg",
    0x0D: "BitFramingReg",
    0x0E: "CollReg",
    0x0F: "RFU0F",
    0x10: "RFU10",
    0x11: "ModeReg",
    0x12: "TxModeReg",
    0x13: "RxModeReg",
    0x14: "TxControlReg",
    0x15: "TxAutoReg",
    0x16: "TxSelReg",
    0x17: "RxSelReg",
    0x18: "RxThresholdReg",
    0x19: "DemodReg",
    0x1A: "RFU1A",
    0x1B: "RFU1B",
    0x1C: "MfTxReg",
    0x1D: "MfRxReg",
    0x1E: "RFU1E",
    0x1F: "SerialSpeedReg",
    0x20: "RFU20",
    0x21: "CRCResultRegM",
    0x22: "CRCResultRegL",
    0x23: "RFU23",
    0x24: "ModWidthReg",
    0x25: "RFU25",
    0x26: "RFCfgReg",
    0x27: "GsNReg",
    0x28: "CWGsCfgReg",
    0x29: "ModGsCfgReg",
    0x2A: "TModeReg",
    0x2B: "TPrescalerReg",
    0x2C: "TReloadRegH",
    0x2D: "TReloadRegL",
    0x2E: "TCounterValueRegH",
    0x2F: "TCounterValueRegL",
    0x30: "RFU30",
    0x31: "TestSel1Reg",
    0x32: "TestSel2Reg",
    0x33: "TestPinEnReg",
    0x34: "TestPinValueReg",
    0x35: "TestBusReg",
    0x36: "AutoTestReg",
    0x37: "VersionReg",
    0x38: "AnalogTestReg",
    0x39: "TestDAC1Reg",
    0x3A: "TestDAC2Reg",
    0x3B: "TestADCReg",
    0x3C: "RFU3C",
    0x3D: "RFU3D",
    0x3E: "RFU3E",
    0x3F: "RFU3F",
}
# CommandReg low nibble, from rc522.h PCD_*
RC522_CMDS = {0x00: "Idle", 0x03: "CalcCRC", 0x04: "Transmit", 0x08: "Receive",
              0x0C: "Transceive", 0x0E: "Authent", 0x0F: "SoftReset"}


def _parse_src(tok: str) -> int:
    t = tok.lower()
    if t in NAMED:
        return NAMED[t]
    if t.startswith("p") and "." in t:  # P1.13
        port, pin = t[1:].split(".")
        port, pin = int(port), int(pin)
        if port in (0, 1) and 0 <= pin < (32 if port == 0 else 16):
            return 0x40 | (port << 5) | pin
    raise argparse.ArgumentTypeError(f"bad source '{tok}' (use {', '.join(NAMED)} or Px.yy)")


def _download(cmd):
    events, total = [], None
    while total is None or len(events) < total:
        running, overflow, init, total, ev = cmd.logic_read(len(events), CHUNK)
        if not ev:
            break
        events += ev
    return init, overflow, events


def _unwrap(events):
    """Stamps are ticks since arm; unwrap the 32-bit counter."""
    out, base, prev = [], 0, 0
    for ts, ch, lvl in events:
        base += (ts - prev) & 0xFFFFFFFF
        prev = ts
        out.append((base, ch, lvl))
    return out


_session = {}
_last = {}


def _download_spi(cmd):
    raw, total, over, drops = b"", None, False, 0
    while total is None or len(raw) < total:
        over, drops, total, data = cmd.logic_spi_read(len(raw), SPI_CHUNK)
        if not data:
            break
        raw += data
    return over, drops, raw


def _parse_spi(raw):
    """Packed SPI log -> list of dicts (see firmware logic_spi_slow)."""
    out, i = [], 0
    while i + 6 <= len(raw):
        ts, hdr = int.from_bytes(raw[i:i + 4], "big"), raw[i + 4]
        e = dict(ts=ts, rd=bool(hdr & 0x80), reg=hdr & 0x3F, burst=bool(hdr & 0x40), rep=0)
        if e["burst"]:
            ln = raw[i + 5]
            n = min(ln, SPI_MAXDATA)
            if i + 6 + n > len(raw):
                break
            e.update(len=ln, data=bytes(raw[i + 6:i + 6 + n]))
            i += 6 + n
        else:
            if i + 7 > len(raw):
                break
            e.update(len=1, data=bytes([raw[i + 5]]), rep=raw[i + 6])
            i += 7
        out.append(e)
    return out


def _spi_text(e, next_ts, us):
    name = RC522_REGS.get(e["reg"], f"reg{e['reg']:02X}")
    d = e["data"]
    if e["burst"]:
        more = f" (+{e['len'] - len(d)} more)" if e["len"] > len(d) else ""
        arrow = "->" if e["rd"] else "<-"
        return f"{'R' if e['rd'] else 'W'}  {name} {arrow} {d.hex(' ')}{more}  [{e['len']} B]"
    v = d[0]
    txt = f"{'R' if e['rd'] else 'W'}  {name} = 0x{v:02X}"
    if not e["rd"] and e["reg"] == 0x01:
        txt += f" ({RC522_CMDS.get(v & 0x0F, 'cmd 0x%X' % (v & 0x0F))})"
    if e["rep"]:
        span = (next_ts - e["ts"]) * us if next_ts is not None else 0
        txt += f"  x{e['rep'] + 1}" + (f" over {span / 1000:.3f} ms" if span else "")
    return txt


def _report(cmd, vcd, plot=False, ascii_only=False, decode=False):
    n, hz = _session.pop("n", 0), _session.pop("hz", 1_000_000)
    names = _session.pop("names", [f"ch{i}" for i in range(n)])
    overflow, total, calls, cc = cmd.logic_stop()
    init, _, events = _download(cmd)
    ev = _unwrap(events)
    spi, spi_over, spi_drops = [], False, 0
    if "spi" in names:
        spi_over, spi_drops, raw = _download_spi(cmd)
        spi = _parse_spi(raw)
        base, prev = 0, 0
        for e in spi:
            base += (e["ts"] - prev) & 0xFFFFFFFF
            prev = e["ts"]
            e["ts"] = base
    firsts = ([ev[0][0]] if ev else []) + ([spi[0]["ts"]] if spi else [])
    t0 = min(firsts) if firsts else 0  # zero at first edge / access
    for e in spi:
        e["ts"] -= t0
    vis = [i for i, nm in enumerate(names) if nm != "spi"]
    remap = {o: k for k, o in enumerate(vis)}
    names_v = [names[i] for i in vis]
    init_v = sum(((init >> o) & 1) << k for k, o in enumerate(vis))
    ev = [(t - t0, remap[c], l) for t, c, l in ev if c in remap]
    _last.update(n=len(vis), hz=hz, init=init_v, ev=ev, names=names_v, spi=spi)
    if vis and total == 0:
        print(f" - diag: handler calls={calls}, PPI captures={cc[:n]} (0 = no edge seen)")
    if vis:
        print(f" - {total} edge(s){' (buffer full, capture truncated)' if overflow else ''}")
    if spi_over or spi_drops:
        print(f" - SPI log {'full, truncated' if spi_over else ''} {'(%d dropped)' % spi_drops if spi_drops else ''}")
    if vcd and vis:
        _write_vcd(vcd, names_v, init_v, hz, ev)
        print(f" - Wrote {vcd}")
    if decode or spi:
        _decode()
    if plot:
        _plot(ascii_only)


def _levels(n, init, ev):
    """Per-channel step lists [(t, level)] starting at t=0."""
    ch = [[(0, (init >> i) & 1)] for i in range(n)]
    for t, c, lvl in ev:
        ch[c].append((t, lvl))
    return ch


def _intervals(steps, end):
    """Level steps [(t, lvl)] -> [(start, stop, open)] where level is 0; open = still low at capture end."""
    out, low_at, cur = [], None, steps[0][1]
    if cur == 0:
        low_at = 0
    for t, lvl in steps[1:]:
        if lvl == cur:
            continue
        cur = lvl
        if lvl == 0:
            low_at = t
        elif low_at is not None:
            out.append((low_at, t, False))
            low_at = None
    if low_at is not None:
        out.append((low_at, end, True))
    return out


def _decode(burst_gap_us=100):
    """Summarise the last capture: field, RC522 chip select and register accesses."""
    if not _last:
        print(" No capture in buffer - run 'hw logic stop' or 'hw logic capture' first")
        return
    n, hz, init, ev, names = _last["n"], _last["hz"], _last["init"], _last["ev"], _last["names"]
    spi = _last.get("spi", [])
    us = 1e6 / hz
    end = max([t for t, _, _ in ev] + [e["ts"] for e in spi] + [1])
    lv = _levels(n, init, ev)
    cs, field = [], []
    if "hf_cs" in names:
        cs = [(a * us, b * us) for a, b, _ in _intervals(lv[names.index("hf_cs")], end)]
    if "field_led" in names:
        field = [(a * us, b * us, o) for a, b, o in _intervals(lv[names.index("field_led")], end)]

    def field_at(t):
        return any(a <= t <= b for a, b, _ in field)

    bursts = []
    for a, b in cs:
        short = b - a < burst_gap_us
        if short and bursts and a - bursts[-1][-1][1] <= burst_gap_us and bursts[-1][-1][1] - bursts[-1][-1][0] < burst_gap_us:
            bursts[-1].append((a, b))
        else:
            bursts.append([(a, b)])

    rows = []
    for a, b, still_on in field:
        rows.append((a, f"FIELD ON   {(b - a) / 1000:.3f} ms" + (" (until capture end)" if still_on else "")))
        if not still_on:
            rows.append((b, "FIELD OFF"))
    for bu in bursts:
        a, b = bu[0][0], bu[-1][1]
        cnt = len(bu)
        lows = [y - x for x, y in bu]
        tag = f"CS  {cnt} access(es), span {b - a:.0f} us"
        if cnt == 1 and lows[0] >= burst_gap_us:
            tag = f"CS  held low {lows[0] / 1000:.3f} ms (one access or merged polling)"
        elif cnt >= 8:
            per = sorted(bu[i + 1][0] - bu[i][0] for i in range(cnt - 1))
            med = per[len(per) // 2]
            if per[len(per) // 10] > 0.7 * med and per[-1 - len(per) // 10] < 1.3 * med:
                tag = f"CS  poll loop: {cnt} accesses, period ~{med:.1f} us, {(b - a) / 1000:.3f} ms"
        rows.append((a, tag + ("  [field on]" if field_at(a) else "  [field off]")))
    for i, e in enumerate(spi):
        nxt = spi[i + 1]["ts"] if i + 1 < len(spi) else None
        rows.append((e["ts"] * us, "SPI " + _spi_text(e, nxt, us)))
    rows.sort(key=lambda r: r[0])
    print(f" {'t (ms)':>10}  event")
    for t, txt in rows:
        print(f" {t / 1000:10.3f}  {txt}")
    if cs:
        print(f" - {len(bursts)} CS burst(s), CS low {sum(b - a for a, b in cs) / 1000:.3f} ms of {end * us / 1000:.3f} ms")
    if field:
        print(f" - field on {sum(b - a for a, b, _ in field) / 1000:.3f} ms")
    if spi:
        print(f" - {len(spi)} SPI entries, {sum(e['rep'] + 1 for e in spi)} register accesses")


def _plot_ascii(n, hz, init, ev, width=100):
    end = max([t for t, _, _ in ev] + [1])
    ch = _levels(n, init, ev)
    print(f" 0 .. {end * 1e6 / hz:.1f} us, {end / width * 1e6 / hz:.2f} us/col")
    names = _last.get("names", [])
    for i, steps in enumerate(ch):
        row, k, cur = "", 0, steps[0][1]
        for col in range(width):
            hi = (col + 1) * end / width
            edge = False
            while k + 1 < len(steps) and steps[k + 1][0] <= hi:
                k += 1
                edge = True
                cur = steps[k][1]
            row += "|" if edge else ("\u203e" if cur else "_")
        print(f" {names[i] if i < len(names) else i:>9} {row}")


def _plot_mpl(n, hz, init, ev, png):
    import matplotlib
    if png:
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    end = max([t for t, _, _ in ev] + [1])
    fig, ax = plt.subplots(figsize=(14, 1.2 + 0.9 * n))
    for i, steps in enumerate(_levels(n, init, ev)):
        xs = [t * 1e6 / hz for t, _ in steps] + [end * 1e6 / hz]
        ys = [l + 1.5 * (n - 1 - i) for _, l in steps]
        ax.step(xs, ys + [ys[-1]], where="post")
    ax.set_yticks([1.5 * (n - 1 - i) + 0.5 for i in range(n)])
    ax.set_yticklabels(_last.get("names", [f"ch{i}" for i in range(n)]))
    ax.set_xlabel("time (us)")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    if png:
        fig.savefig(png)
        print(f" - Wrote {png}")
    else:
        plt.show()


def _plot(ascii_only=False, png=None):
    if not _last:
        print(" No capture in buffer - run 'hw logic stop' or 'hw logic capture' first")
        return
    n, hz, init, ev = _last["n"], _last["hz"], _last["init"], _last["ev"]
    if n == 0:
        print(" No edge channels in the last capture")
        return
    if not ascii_only:
        try:
            _plot_mpl(n, hz, init, ev, png)
            return
        except ImportError:
            print(" matplotlib not installed, using ASCII")
    _plot_ascii(n, hz, init, ev)


_NAME_OF = {v: k for k, v in NAMED.items()}


def _arm(cmd, sources, rate, merge_us=0):
    ticks = round(merge_us * (16_000_000 >> RATES[rate]) / 1e6)
    init, hz = cmd.logic_arm(sources, RATES[rate], min(ticks, 0xFFFF))
    _session.update(n=len(sources), hz=hz, names=[_NAME_OF.get(x, f"ch{i}") for i, x in enumerate(sources)])
    print(f" - Armed {len(sources)} channel(s) at {hz / 1e6:g} MHz, initial levels 0b{init:b}")


def _write_vcd(path, names, init, tick_hz, events):
    ids = [chr(33 + i) for i in range(len(names))]
    with open(path, "w") as f:
        f.write("$timescale 1 ps $end\n$scope module chameleon $end\n")
        for i, n in enumerate(names):
            f.write(f"$var wire 1 {ids[i]} {n} $end\n")
        f.write("$upscope $end\n$enddefinitions $end\n#0\n$dumpvars\n")
        for i in range(len(names)):
            f.write(f"{(init >> i) & 1}{ids[i]}\n")
        f.write("$end\n")
        last = -1
        for t, ch, lvl in events:
            ps = round(t * 1_000_000_000_000 / tick_hz)
            if ps != last:
                f.write(f"#{ps}\n")
                last = ps
            f.write(f"{lvl}{ids[ch]}\n")


@hw_logic.command("start")
class HWLogicStart(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = ("Arm edge capture, run other commands, then 'hw logic stop'. "
                         "Up to 4 sources, 1024 edges max. hf_cs and field_led are logged where the "
                         "firmware drives them; raw pins rely on GPIOTE events.")
        p.add_argument("sources", nargs="+", type=_parse_src,
                       help="hf_cs (RC522 chip select), field_led (low = field on), "
                            "spi (RC522 register accesses with values)")
        p.add_argument("--rate", type=int, choices=sorted(RATES), default=1,
                       help="tick rate in MHz (default 1; the 32-bit stamp wraps after 2^32 ticks)")
        p.add_argument("--merge", type=int, default=0, metavar="US",
                       help="merge pulses closer than US us (hides polling storms)")
        return p

    def on_exec(self, args: argparse.Namespace):
        _arm(self.cmd, args.sources, args.rate, args.merge)


@hw_logic.command("stop")
class HWLogicStop(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = "Stop capture, download edges, print them and optionally write VCD"
        p.add_argument("--vcd", metavar="FILE", help="write VCD (opens in PulseView/GTKWave)")
        p.add_argument("--plot", action="store_true", help="plot the capture")
        p.add_argument("--ascii", action="store_true", help="ASCII plot instead of a window")
        p.add_argument("--decode", action="store_true", help="summarise field and RC522 activity")
        return p

    def on_exec(self, args: argparse.Namespace):
        _report(self.cmd, args.vcd, args.plot or args.ascii, args.ascii, args.decode)


@hw_logic.command("capture")
class HWLogicCapture(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = "Arm, wait, stop and dump in one go"
        p.add_argument("sources", nargs="+", type=_parse_src, help="see 'hw logic start'")
        p.add_argument("--rate", type=int, choices=sorted(RATES), default=1)
        p.add_argument("--ms", type=int, default=1000, help="capture time (default 1000)")
        p.add_argument("--merge", type=int, default=0, metavar="US",
                       help="merge pulses closer than US us (hides polling storms)")
        p.add_argument("--vcd", metavar="FILE")
        p.add_argument("--plot", action="store_true", help="plot the capture")
        p.add_argument("--ascii", action="store_true", help="ASCII plot instead of a window")
        p.add_argument("--decode", action="store_true", help="summarise field and RC522 activity")
        return p

    def on_exec(self, args: argparse.Namespace):
        _arm(self.cmd, args.sources, args.rate, args.merge)
        time.sleep(args.ms / 1000)
        _report(self.cmd, args.vcd, args.plot or args.ascii, args.ascii, args.decode)


@hw_logic.command("plot")
class HWLogicPlot(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = "Plot the last logic capture (matplotlib, ASCII fallback)"
        p.add_argument("--ascii", action="store_true", help="ASCII plot instead of a window")
        p.add_argument("--png", metavar="FILE", help="save a PNG instead of opening a window")
        return p

    def on_exec(self, args: argparse.Namespace):
        _plot(args.ascii, args.png)


@hw_logic.command("decode")
class HWLogicDecode(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = "Summarise the last capture: field on/off, CS bursts, polling loops"
        p.add_argument("--gap", type=int, default=100, metavar="US",
                       help="CS pulses closer than this belong to one burst (default 100)")
        return p

    def on_exec(self, args: argparse.Namespace):
        _decode(args.gap)
