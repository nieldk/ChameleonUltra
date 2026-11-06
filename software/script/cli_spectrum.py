"""cli_spectrum - host-side commands for the `spectrum` standalone mode.

One-shot 2.4 GHz ISM energy-detect sweep (1 MHz steps; full 2400-2483 MHz /
84 points by default, or a configured subrange -- see `standalone config
spectrum --start/--end`). Arm the mode, `standalone trigger` starts a sweep,
then `standalone spectrum plot` reads and plots it. Result format: u8
version=2, u16 start_mhz LE, u8 count, then `count` raw EDSAMPLE bytes (point
i == start_mhz+i MHz) -- see sa_radio.c / mode_spectrum.c.

Peak classification (classify_peaks) is host-side only -- the firmware never
demodulates anything, it's pure energy-detect. Peaks are labeled by width and
center frequency against known channel plans (WiFi ~20MHz blocks, Zigbee
2MHz-wide channels every 5MHz, BLE advertising channels) -- a heuristic
guess, not a decode. Two real signals can still collide into one peak or one
signal can split into two if it dips mid-band; treat labels as a hint, not
ground truth.
"""

import argparse
import statistics
import time

from chameleon_enum import StandaloneMode, Status

from cli_core import ArgumentParserNoExit, DeviceRequiredUnit, standalone, color_string, CG, CY, CR

START_MHZ = 2400     # default full-band start, used only as a display fallback
POINT_COUNT = 84      # default full-band count

# 2.4 GHz channel plans used for peak classification (center frequencies, MHz).
WIFI_CHANNELS = {ch: 2412 + 5 * (ch - 1) for ch in range(1, 14)}      # 1-13, 20MHz nominal width
ZIGBEE_CHANNELS = {ch: 2405 + 5 * (ch - 11) for ch in range(11, 27)}  # 11-26, 2MHz occupied width
BLE_ADV_CHANNELS = {37: 2402, 38: 2426, 39: 2480}                    # advertising channels only


def _classify_one(center: float, width: int) -> str:
    """Width-first heuristic: wide -> WiFi-shaped, narrow -> Zigbee/BLE-shaped."""
    if width >= 15:
        ch, f = min(WIFI_CHANNELS.items(), key=lambda kv: abs(kv[1] - center))
        if abs(f - center) <= 11:
            return f"WiFi ch{ch} (~{f} MHz)"
        return "wideband (WiFi-shaped, channel unclear)"
    if width <= 4:
        ch, f = min(ZIGBEE_CHANNELS.items(), key=lambda kv: abs(kv[1] - center))
        if abs(f - center) <= 2:
            return f"Zigbee ch{ch} (~{f} MHz)"
        ch, f = min(BLE_ADV_CHANNELS.items(), key=lambda kv: abs(kv[1] - center))
        if abs(f - center) <= 2:
            return f"BLE advertising ch{ch} (~{f} MHz)"
        return "narrowband (BT/BLE-shaped)"
    return "mid-width (unclassified)"


def _draw_channel_refs(ax, f_lo, f_hi):
    """Static WiFi/Zigbee/BLE-adv channel markers, independent of peak detection."""
    from matplotlib.lines import Line2D
    for ch, f in WIFI_CHANNELS.items():
        if f_lo <= f <= f_hi:
            ax.axvline(f, color="#3a7ca5", alpha=0.25, linewidth=0.8, linestyle="--")
            ax.text(f, 1.0, str(ch), transform=ax.get_xaxis_transform(),
                    ha="center", va="bottom", fontsize=6, color="#3a7ca5")
    for ch, f in ZIGBEE_CHANNELS.items():
        if f_lo <= f <= f_hi:
            ax.axvline(f, color="#5a9e5a", alpha=0.2, linewidth=0.6, linestyle=":")
            ax.text(f, -0.06, str(ch), transform=ax.get_xaxis_transform(),
                    ha="center", va="top", fontsize=6, color="#5a9e5a", rotation=90)
    for ch, f in BLE_ADV_CHANNELS.items():
        if f_lo <= f <= f_hi:
            ax.axvline(f, color="#d08f2a", alpha=0.4, linewidth=1.0, linestyle="-")
    handles = [
        Line2D([0], [0], color="#3a7ca5", linestyle="--", linewidth=0.8, label="WiFi ch (top)"),
        Line2D([0], [0], color="#5a9e5a", linestyle=":", linewidth=0.6, label="Zigbee ch (bottom)"),
        Line2D([0], [0], color="#d08f2a", linestyle="-", linewidth=1.0, label="BLE adv"),
    ]
    ax.legend(handles=handles, loc="upper right", fontsize=7, framealpha=0.7)


def classify_peaks(freqs, vals):
    """Finds contiguous above-threshold runs and labels each by width/center.

    Threshold is the median (resists being pulled up by the peaks themselves)
    plus a margin scaled to how far above baseline the busiest point is.
    Returns a list of dicts: start, end, center, width (MHz), peak (raw
    EDSAMPLE), label. Empty list if nothing clears the threshold.
    """
    if not vals:
        return []
    baseline = statistics.median(vals)
    threshold = baseline + max(1, (max(vals) - baseline) * 0.3)
    runs = []
    start_i = None
    for i, v in enumerate(vals):
        if v >= threshold:
            if start_i is None:
                start_i = i
        elif start_i is not None:
            runs.append((start_i, i - 1))
            start_i = None
    if start_i is not None:
        runs.append((start_i, len(vals) - 1))

    peaks = []
    for s, e in runs:
        f_start, f_end = freqs[s], freqs[e]
        width = f_end - f_start + 1
        center = (f_start + f_end) / 2
        peaks.append({
            "start": f_start, "end": f_end, "center": center, "width": width,
            "peak": max(vals[s:e + 1]), "label": _classify_one(center, width),
        })
    return peaks


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
        peaks = classify_peaks(freqs, vals)
        if args.raw:
            for f, v in zip(freqs, vals):
                print(f"  {f:>4} MHz  {v:>3}")
            _print_peaks(peaks)
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
        _draw_channel_refs(ax, freqs[0], freqs[-1])
        ax.plot(freqs, vals, color="#3a7ca5", linewidth=1.5, marker=".", markersize=4)
        ax.fill_between(freqs, vals, color="#3a7ca5", alpha=0.15)
        ymax = max(vals) if vals else 1
        for p in peaks:
            ax.axvspan(p["start"], p["end"], color="#d9534f", alpha=0.12)
            ax.annotate(p["label"], xy=(p["center"], p["peak"]),
                        xytext=(p["center"], ymax * 1.08),
                        ha="center", va="bottom", fontsize=8, color="#a33",
                        arrowprops=dict(arrowstyle="-", color="#a33", alpha=0.6))
        ax.set_xlabel("Frequency (MHz)")
        ax.set_ylabel("Energy-detect level (raw EDSAMPLE, uncalibrated)")
        ax.set_title("2.4 GHz ISM sweep")
        ax.set_xlim(freqs[0] - 1, freqs[-1] + 1)
        ax.set_ylim(top=ymax * 1.25)
        fig.tight_layout()
        if args.out:
            fig.savefig(args.out, dpi=150)
            print(color_string((CG, f"-> {args.out}")))
        else:
            plt.show()
        _print_peaks(peaks)


def _trigger_and_wait(cmd, timeout_s=30.0, poll_s=0.05):
    """Fires one sweep and blocks until the firmware reports it done.

    `standalone trigger` only starts the sweep (sa_radio_sweep_start() is
    non-blocking, chained across radio timeslots) -- completion has to be
    polled via `standalone_get_status()`'s "sweep=" field, same thing the
    CLI's own `standalone status` shows. A sweep's wall-clock time depends on
    point count *and* `repeat` (see --repeat / sa_radio_set_repeat): each
    extra repeat adds a full EDSTART/EDEND cycle per point, and each radio
    timeslot (SLOT_US) can itself be delayed or bumped by BLE/USB scheduling
    (see "canceled"/"blocked" in `standalone status`) -- so a high-repeat,
    full-band (84-point) sweep can comfortably take several seconds, well
    past a naive few-second timeout. Default here is deliberately generous;
    raise it further (SpectrumWaterfall's --sweep-timeout) for repeat>~15.

    Returns (freqs, vals, None) on success, or (None, None, reason) where
    reason is "trigger failed" (busy/error status from the trigger call
    itself) or "timed out" (sweep never reported done within timeout_s).
    """
    resp = cmd.standalone_trigger()
    if resp.status != Status.SUCCESS:
        return None, None, f"trigger failed (status={resp.status})"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = dict(cmd.standalone_get_status())
        # standalone_get_status() splits each status line on the *first* '='
        # only, so the "sweep" key's value is the whole rest of that line --
        # "done range=2400-2483 points=84/84 repeat=1 slots=2 blocked=0
        # canceled=0" -- not just "done" (see get_status() in mode_spectrum.c,
        # one STATUS_KV line). Match the leading word, not the full value.
        if status.get("sweep", "").split(" ", 1)[0] == "done":
            break
        time.sleep(poll_s)
    else:
        return None, None, f"timed out after {timeout_s:.0f}s waiting for sweep to finish"
    raw = cmd.standalone_drain_result_for(StandaloneMode.SPECTRUM)
    freqs, vals = _parse(raw)
    if freqs is None:
        return None, None, "sweep reported done but result didn't parse"
    return freqs, vals, None


@sa.command("waterfall")
class SpectrumWaterfall(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = ("Live frequency-vs-time waterfall: repeatedly fires sweeps "
                         "(like calling `standalone trigger` + `spectrum plot` in a "
                         "loop) and scrolls them into a heatmap, newest row on top. "
                         "Needs the mode already armed. Close the window or Ctrl+C "
                         "to stop.")
        p.add_argument("--rows", type=int, default=60,
                       help="sweep history kept on screen (default 60)")
        p.add_argument("--max-sweeps", type=int, default=None,
                       help="stop after N sweeps instead of running until closed/interrupted "
                            "(default: unlimited live, 30 when saving with --out)")
        p.add_argument("--sweep-timeout", type=float, default=30.0,
                       help="seconds to wait for each sweep to finish before giving up "
                            "(default 30; raise this if `standalone config spectrum --repeat` "
                            "is set high -- more repeats means a slower sweep)")
        p.add_argument("-o", "--out", metavar="<path.gif>", default=None,
                       help="save the session as an animated GIF instead of a live window")
        p.add_argument("--vmax", type=float, default=None,
                       help="pin the color scale's top to this raw EDSAMPLE value instead of "
                            "autoscaling to the loudest point seen so far. Real readings rarely "
                            "get near the 0-255 theoretical ceiling -- a quiet room is often "
                            "single digits -- so autoscale (the default) is what keeps weak "
                            "signals visible instead of washed out to near-black.")
        return p

    def on_exec(self, args: argparse.Namespace):
        try:
            import matplotlib
            if args.out:
                matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import matplotlib.animation as animation
            import numpy as np
        except ImportError:
            print(" - Waterfall needs matplotlib and numpy: pip install matplotlib numpy")
            return

        max_sweeps = args.max_sweeps if args.max_sweeps is not None else (30 if args.out else None)

        freqs, vals, err = _trigger_and_wait(self.cmd, timeout_s=args.sweep_timeout)
        if freqs is None:
            print(color_string((CR, f" - No sweep: {err}. Check the mode is armed "
                                    "(`standalone status`); if it's a high --repeat config, "
                                    "try a larger --sweep-timeout.")))
            return

        rows = max(2, args.rows)
        grid = np.full((rows, len(freqs)), np.nan)
        grid[0] = vals

        def clim_for(g):
            if args.vmax is not None:
                return 0, args.vmax
            peak = np.nanmax(g) if not np.all(np.isnan(g)) else 1
            return 0, max(1.0, peak * 1.15)

        fig, ax = plt.subplots(figsize=(10, 5))
        vmin0, vmax0 = clim_for(grid)
        im = ax.imshow(grid, aspect="auto", cmap="viridis", vmin=vmin0, vmax=vmax0,
                       extent=[freqs[0], freqs[-1], rows, 0], interpolation="nearest")
        _draw_channel_refs(ax, freqs[0], freqs[-1])
        ax.set_xlabel("Frequency (MHz)")
        ax.set_ylabel("Sweeps ago")
        ax.set_title("2.4 GHz ISM waterfall (live)")
        cbar = fig.colorbar(im, ax=ax, label="Energy-detect level (raw EDSAMPLE, uncalibrated "
                                              "-- color scale autoscaled unless --vmax)")
        fig.tight_layout()

        def update(_frame):
            f2, v2, _err = _trigger_and_wait(self.cmd, timeout_s=args.sweep_timeout)
            if f2 is None:
                return [im]   # transient busy/timeout -- skip this frame, keep showing last
            grid[1:] = grid[:-1]
            grid[0] = v2
            im.set_data(grid)
            # Real EDSAMPLE readings rarely approach the 8-bit ceiling (a quiet
            # room is often single digits), so a fixed 0-255 scale washes
            # everything to near-black -- rescale to what's actually been seen
            # (unless the user pinned --vmax) so weak signals stay visible.
            vmin, vmax = clim_for(grid)
            im.set_clim(vmin, vmax)
            return [im]

        # frames=None gives FuncAnimation an unbounded itertools.count() --
        # fine for an interactive show() (pulled one at a time by the GUI
        # timer) but .save() has to enumerate frames up front, so it would
        # hang forever without a bound. Only the save path needs one.
        frames = max_sweeps if args.out else None
        ani = animation.FuncAnimation(fig, update, frames=frames, interval=200,
                                      cache_frame_data=False, repeat=False)
        if args.out:
            ani.save(args.out, writer="pillow", fps=4)
            print(color_string((CG, f"-> {args.out}")))
        else:
            plt.show()


def _print_peaks(peaks):
    if not peaks:
        print(" - No clear peaks above baseline.")
        return
    print(" - Detected peaks (heuristic, not a decode):")
    for p in peaks:
        print(f"   {p['start']:>4}-{p['end']:<4} MHz  peak={p['peak']:<3}  {p['label']}")


def summarize(freqs, vals) -> str:
    """Shared by chameleon_cli_unit.py's generic get-result dispatch for this mode."""
    busiest = max(range(len(vals)), key=lambda i: vals[i])
    base = (f"{len(vals)} point(s), {freqs[0]}-{freqs[-1]} MHz -- "
            f"min={min(vals)} max={vals[busiest]} (at {freqs[busiest]} MHz) "
            f"mean={sum(vals) / len(vals):.1f} "
            "(raw EDSAMPLE, uncalibrated; `standalone spectrum plot` for the shape)")
    peaks = classify_peaks(freqs, vals)
    if not peaks:
        return base
    tags = "; ".join(f"{p['label']} @{p['center']:.0f}MHz" for p in peaks)
    return f"{base}\n  peaks: {tags}"
