"""cli_lf_xtal - LF crystal ppm measurement and tag-emulation timing trim
(lf xtal ...).

Measures this device's own HFXO offset by comparing its tick count against
the host computer's clock over a run of several minutes, and stores a
correction value the firmware applies to every LF tag-emulation PWM step's
duration (see lf_wave_form_apply_trim() in lf_tag_em.c). The stored value is
just a ppm correction -- what number to put there is up to the person
running it: it might be their own measured crystal error, same sign, (to get
this device's LF emulation as close to nominal timing as possible), or
(this device's own ppm - a specific reader's own ppm) to deliberately match
that reader's clock instead of nominal.

Accuracy is bounded by the host computer's own clock, which this tool makes
no attempt to check against anything external (no NTP). For a tighter
reference, see the ChameleonUltra-side tooling this command was prompted by:
https://mfcarroll.github.io/rfid-test-tools/chameleon/crystal/
"""

import argparse
import time

from cli_core import ArgumentParserNoExit, DeviceRequiredUnit, lf, CG, CY, CR, C0, _box

lf_xtal = lf.subgroup("xtal", "LF crystal ppm measurement / tag-emulation timing trim")

NOMINAL_HZ = 16_000_000
WRAP = 1 << 32
# TIMER1 is free-running 32-bit @ 16 MHz -- wraps every 2**32/16e6 =~ 268 s.
# Poll well under that so a wrap is never missed between two reads.
MAX_POLL_INTERVAL_S = 120


def _poll_ticks(cmd, prev_raw, total_offset):
    """One lf_xtal_read(), folded into a monotonically increasing 64-bit
    tick count via prev_raw/total_offset (caller keeps these across calls)."""
    not_running, raw, lapsed, running = cmd.lf_xtal_read()
    if not_running:
        return None
    if raw < prev_raw:
        total_offset += WRAP
    accumulated = total_offset + raw
    return accumulated, raw, total_offset, lapsed, running


def _linreg_slope(xs, ys):
    """Least-squares slope of ys against xs (ticks per host-second)."""
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den = sum((x - mean_x) ** 2 for x in xs)
    if den == 0:
        return None
    return num / den


@lf_xtal.command("measure")
class HWLfXtalMeasure(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = (
            "Measure this device's crystal offset in ppm against this computer's "
            "clock. Longer runs are more accurate: ~5 min is rough (+/-2 ppm or so), "
            "30 min (the default) is tight enough to be useful. Accuracy is capped "
            "by how good this computer's own clock is -- this command does not "
            "check it against anything external."
        )
        p.add_argument("--minutes", type=int, default=30, choices=[5, 15, 30, 60],
                       help="measurement duration (default 30)")
        p.add_argument("--interval", type=float, default=5.0,
                       help=f"seconds between samples, max {MAX_POLL_INTERVAL_S} (default 5)")
        return p

    def on_exec(self, args: argparse.Namespace):
        interval = max(0.5, min(args.interval, MAX_POLL_INTERVAL_S))
        duration_s = args.minutes * 60

        busy = self.cmd.lf_xtal_start()
        if busy:
            print(f' {CR}TIMER1 is busy (an hf 14a sniff --tap capture is probably running) -- try again after it finishes.{C0}')
            return

        print(f' {CY}Measuring for {args.minutes} min (every {interval:.1f}s). Keep the device away from LF/HF readers.{C0}')

        not_running, raw0, lapsed0, _running = self.cmd.lf_xtal_read()
        if not_running:
            print(f' {CR}Device reports the counter is not running right after start -- aborting.{C0}')
            return

        t0 = time.monotonic()
        prev_raw = raw0
        total_offset = 0
        xs = [0.0]
        ys = [raw0]  # same absolute tick scale as _poll_ticks's accumulated value below
        lapsed = lapsed0

        try:
            while time.monotonic() - t0 < duration_s:
                time.sleep(interval)
                sample = _poll_ticks(self.cmd, prev_raw, total_offset)
                if sample is None:
                    print(f' {CR}Device reports the counter stopped mid-run -- aborting.{C0}')
                    self.cmd.lf_xtal_stop()
                    return
                accumulated, prev_raw, total_offset, this_lapsed, _running = sample
                lapsed = lapsed or this_lapsed
                elapsed = time.monotonic() - t0
                xs.append(elapsed)
                ys.append(accumulated)
                slope = _linreg_slope(xs, ys) if len(xs) >= 3 else None
                if slope:
                    running_ppm = (slope / NOMINAL_HZ - 1.0) * 1e6
                    print(f'\r {CY}{elapsed:6.0f}s / {duration_s}s  running estimate: {running_ppm:+.2f} ppm{C0}', end='', flush=True)
        finally:
            not_running, raw_final, lapsed_final, _running = self.cmd.lf_xtal_stop()
            lapsed = lapsed or (not not_running and lapsed_final)

        print('')

        if lapsed:
            print(f' {CR}HFXO was reported not-running at some point during this run -- the sample is unreliable. Discarding; try again.{C0}')
            return

        if len(xs) < 3:
            print(f' {CR}Not enough samples to get a slope -- try a longer --minutes or shorter --interval.{C0}')
            return

        slope = _linreg_slope(xs, ys)
        if not slope:
            print(f' {CR}Could not compute a slope (no elapsed-time spread in the samples).{C0}')
            return

        ppm = (slope / NOMINAL_HZ - 1.0) * 1e6
        sign = '+' if ppm >= 0 else ''
        lines = [
            f"{'Samples':<14} {len(xs)}",
            f"{'Duration':<14} {xs[-1]:.0f} s",
            f"{'Measured':<14} {slope:,.1f} Hz (nominal {NOMINAL_HZ:,} Hz)",
            f"{'Offset':<14} {CY}{sign}{ppm:.2f} ppm{C0}  ({'runs fast' if ppm >= 0 else 'runs slow'})",
        ]
        for line in _box('Crystal Measurement', lines, color=CG, min_width=38):
            print(line)
        print('')
        print(" To cancel out this device's own crystal error (make its LF emulation")
        print(" timing match nominal), set a trim of about "
              f"{ppm * 10:+.0f} (tenths of a ppm):")
        print(f"   lf xtal trim --set {ppm * 10:.0f}")
        print(" To instead match a specific reader with its own known offset, use")
        print(" (this device's own ppm - that reader's own ppm) instead, same sign")
        print(" convention as above (positive = runs fast).")


@lf_xtal.command("trim")
class HWLfXtalTrim(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        p = ArgumentParserNoExit()
        p.description = (
            "Show, set, or clear the stored LF tag-emulation timing trim. Applied "
            "to every LF emulation protocol's PWM step duration: output duration is "
            "scaled by (1 + trim/1e7). Positive lengthens (slows), negative shortens "
            "(speeds). 0 = no correction."
        )
        g = p.add_mutually_exclusive_group()
        g.add_argument("--set", type=int, metavar="TENTHS_PPM",
                       help="set the trim, in tenths of a ppm (e.g. 15 = +1.5 ppm)")
        g.add_argument("--clear", action="store_true", help="reset the trim to 0")
        return p

    def on_exec(self, args: argparse.Namespace):
        if args.clear:
            self.cmd.set_lf_xtal_trim(0)
            print(f' {CG}Trim cleared.{C0}')
            return
        if args.set is not None:
            self.cmd.set_lf_xtal_trim(args.set)
            print(f' {CG}Trim set to {args.set} tenths of a ppm ({args.set / 10:+.1f} ppm).{C0}')
            return
        current = self.cmd.get_lf_xtal_trim()
        print(f' Current LF emulation timing trim: {current} tenths of a ppm ({current / 10:+.1f} ppm)')
