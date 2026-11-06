"""cli_spectrum - host-side commands for the `spectrum` standalone mode.

One-shot 2.4 GHz ISM energy-detect sweep (1 MHz steps; full 2400-2483 MHz /
84 points by default, or a configured subrange -- see `standalone config
spectrum --start/--end`). Arm the mode, `standalone trigger` starts a sweep,
then `standalone spectrum plot` reads and plots it. Result format: u8
version=2, u16 start_mhz LE, u8 count, then `count` raw EDSAMPLE bytes (point
i == start_mhz+i MHz) -- see sa_radio.c / mode_spectrum.c.
"""

import argparse

from chameleon_enum import StandaloneMode

from cli_core import ArgumentParserNoExit, DeviceRequiredUnit, standalone, color_string, CG

START_MHZ = 2400     # default full-band start, used only as a display fallback
POINT_COUNT = 84      # default full-band count


def _group():
    for c in standalone.children:
        if c.name == "spectrum":
            return c
    return standalone.subgroup("spectrum", "Result data for the spectrum mode")


sa = _group()


def _parse(raw: bytes):
    """Returns (freqs_mhz, values) or (None, None) if raw isn't a valid record.

    Self-describing (version=2): start_mhz/count come from the record itself,
    so this works for a full-band sweep or a configured subrange alike.
    """
    if len(raw) < 4 or raw[0] != 2:
        return None, None
    start = raw[1] | (raw[2] << 8)
    count = raw[3]
    vals = list(raw[4:4 + count])
    if len(vals) != count:
        return None, None
    freqs = [start + i for i in range(len(vals))]
    return freqs, vals


@sa.command("plot")
class SpectrumPlot(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = ("Plot the last 2.4 GHz ISM sweep (matplotlib). Run `standalone "
                         "trigger` first to capture one; this only reads/plots the result.")
        p.add_argument("-o", "--out", metavar="<path.png>", default=None,
                       help="save to a file instead of opening an interactive window")
        p.add_argument("--raw", action="store_true", help="print raw values instead of plotting")
        return p

    def on_exec(self, args: argparse.Namespace):
        raw = self.cmd.standalone_drain_result_for(StandaloneMode.SPECTRUM)
        freqs, vals = _parse(raw)
        if freqs is None:
            print(" - No sweep result. Arm the mode and run `standalone trigger` first.")
            return
        if args.raw:
            for f, v in zip(freqs, vals):
                print(f"  {f:>4} MHz  {v:>3}")
            return
        try:
            import matplotlib
            if args.out:
                matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            print(" - Plotting needs matplotlib: pip install matplotlib")
            print("   Use --raw to print the values instead.")
            return
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.plot(freqs, vals, color="#3a7ca5", linewidth=1.5, marker=".", markersize=4)
        ax.fill_between(freqs, vals, color="#3a7ca5", alpha=0.15)
        ax.set_xlabel("Frequency (MHz)")
        ax.set_ylabel("Energy-detect level (raw EDSAMPLE, uncalibrated)")
        ax.set_title("2.4 GHz ISM sweep")
        ax.set_xlim(freqs[0] - 1, freqs[-1] + 1)
        fig.tight_layout()
        if args.out:
            fig.savefig(args.out, dpi=150)
            print(color_string((CG, f"-> {args.out}")))
        else:
            plt.show()


def summarize(freqs, vals) -> str:
    """Shared by chameleon_cli_unit.py's generic get-result dispatch for this mode."""
    busiest = max(range(len(vals)), key=lambda i: vals[i])
    return (f"{len(vals)} point(s), {freqs[0]}-{freqs[-1]} MHz -- "
            f"min={min(vals)} max={vals[busiest]} (at {freqs[busiest]} MHz) "
            f"mean={sum(vals) / len(vals):.1f} "
            "(raw EDSAMPLE, uncalibrated; `standalone spectrum plot` for the shape)")
