"""cli_hw_logic - edge logic analyser on internal nets (hw logic ...)."""

import argparse
import time

from cli_core import ArgumentParserNoExit, DeviceRequiredUnit, hw

hw_logic = hw.subgroup("logic", "Edge logic analyser (internal nets / raw pins, VCD export)")

NAMED = {"hf_cs": 0x00, "field_led": 0x01}
RATES = {16: 0, 8: 1, 4: 2, 2: 3, 1: 4}  # MHz -> prescaler
CHUNK = 90


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


def _report(cmd, vcd, plot=False, ascii_only=False):
    n, hz = _session.pop("n", 0), _session.pop("hz", 1_000_000)
    overflow, total, calls, cc = cmd.logic_stop()
    init, _, events = _download(cmd)
    ev = _unwrap(events)
    t0 = ev[0][0] if ev else 0
    ev = [(t - t0, c, l) for t, c, l in ev]  # zero at first edge
    _last.update(n=n, hz=hz, init=init, ev=ev)
    if total == 0:
        print(f" - diag: handler calls={calls}, PPI captures={cc[:n]} (0 = no edge seen)")
    print(f" - {total} edge(s){' (buffer full, capture truncated)' if overflow else ''}")
    for t, ch, lvl in ev[:200]:
        print(f"   {t * 1e6 / hz:12.2f} us  ch{ch}={lvl}")
    if len(ev) > 200:
        print(f"   ... {len(ev) - 200} more (use --vcd)")
    if vcd:
        _write_vcd(vcd, [f"ch{i}" for i in range(n)], init, hz, ev)
        print(f" - Wrote {vcd}")
    if plot:
        _plot(ascii_only)


def _levels(n, init, ev):
    """Per-channel step lists [(t, level)] starting at t=0."""
    ch = [[(0, (init >> i) & 1)] for i in range(n)]
    for t, c, lvl in ev:
        ch[c].append((t, lvl))
    return ch


def _plot_ascii(n, hz, init, ev, width=100):
    end = max([t for t, _, _ in ev] + [1])
    ch = _levels(n, init, ev)
    print(f" 0 .. {end * 1e6 / hz:.1f} us, {end / width * 1e6 / hz:.2f} us/col")
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
        print(f" ch{i} {row}")


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
    ax.set_yticklabels([f"ch{i}" for i in range(n)])
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
    if not ascii_only:
        try:
            _plot_mpl(n, hz, init, ev, png)
            return
        except ImportError:
            print(" matplotlib not installed, using ASCII")
    _plot_ascii(n, hz, init, ev)


def _arm(cmd, sources, rate, merge_us=0):
    ticks = round(merge_us * (16_000_000 >> RATES[rate]) / 1e6)
    init, hz = cmd.logic_arm(sources, RATES[rate], min(ticks, 0xFFFF))
    _session.update(n=len(sources), hz=hz)
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
                            "or raw Px.yy (GPIOTE based, experimental)")
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
        return p

    def on_exec(self, args: argparse.Namespace):
        _report(self.cmd, args.vcd, args.plot or args.ascii, args.ascii)


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
        return p

    def on_exec(self, args: argparse.Namespace):
        _arm(self.cmd, args.sources, args.rate, args.merge)
        time.sleep(args.ms / 1000)
        _report(self.cmd, args.vcd, args.plot or args.ascii, args.ascii)


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
