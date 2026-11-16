"""cli_lf_interactive - interactive LF emulation debug commands (lf interactive ...).

Reads back the exchange trace of the interactive LF engine (lf_ia_engine.c),
used by Hitag2 tag emulation: each reader command, its decoded bits, what
the slot answered and when. The trace is kept in retained RAM and survives
sleep, so it covers a session the host wasn't connected for.
"""

import argparse
import struct

from cli_core import ArgumentParserNoExit, DeviceRequiredUnit, lf, CR, color_string

lf_interactive = lf.subgroup("interactive", "Interactive LF emulation commands")

LF_IA_TRACE_REC = struct.Struct("<BBBBIIIIIIHHHHIHH16s16s96HHHI")
LF_IA_VERDICTS = {0: "ignored", 1: "answered", 2: "ended the exchange"}
LF_IA_DECODES = {
    0: "ok",
    1: "one interval class",
    2: "too few gaps",
    3: "too many gaps",
}


def _lf_ia_bits(raw: bytes, n: int) -> str:
    n = min(n, 8 * len(raw))
    return "".join("1" if raw[i // 8] >> (7 - i % 8) & 1 else "0" for i in range(n))


@lf_interactive.command("trace")
class LFInteractiveTrace(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Show the exchange trace of an interactive LF emulation (such as Hitag 2): each reader command with "
            "its decoded bits, what the slot answered and when, grouped by boot and field session, with the "
            "counters since the last clear. The trace survives sleep. A session with no command only counts in "
            "the counters."
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        recs, total, keep, boot = [], 0, 0, 0
        while True:
            total, size, chunk, keep, boot = self.cmd.lf_ia_trace_read(len(recs))
            if size != LF_IA_TRACE_REC.size:
                print(
                    f"{color_string((CR, 'ERROR'))}: trace record size {size}, this client reads {LF_IA_TRACE_REC.size}"
                )
                return
            if not chunk:
                break
            recs += chunk
        c = self.cmd.lf_ia_counters()
        print(
            f" - {c['sessions']} field sessions, {c['commands']} commands, {c['responses']} answered, "
            f"{c['late']} late, since the clear. This is boot {boot} since the clear."
        )
        lost = total - len(recs)
        if lost > 0:
            print(
                f" - {total} records: the first {keep} and the latest {len(recs) - keep} are kept"
            )
        else:
            print(f" - {total} records")
        last_session = None
        for i, raw in enumerate(recs):
            if lost > 0 and i == keep:
                print(f"   ... {lost} records overwritten ...")
                last_session = None
            v = LF_IA_TRACE_REC.unpack(raw)
            (
                kind,
                verdict,
                decode,
                flags,
                t_us,
                t_detect,
                t_ready,
                t_due,
                t_tx,
                t_tx_end,
            ) = v[:10]
            n_gaps, n_bits, n_tx_bits = v[10:13]
            bits, tx_bits = v[17], v[18]
            rec_boot, session, t_session = v[-3:]
            if (rec_boot, session) != last_session:
                last_session = (rec_boot, session)
                print(
                    f"   boot {rec_boot}, field session {session}, field on at {t_session / 1e6:.6f} s"
                )
            if kind == 2:
                print(
                    f"   {t_us / 1e6:12.6f} s  field off"
                    + ("  (came back)" if flags & 8 else "")
                )
            elif kind == 3:
                line = f"   {t_us / 1e6:12.6f} s  command, {n_gaps} gaps"
                if decode == 0:
                    line += f", {n_bits} bits {_lf_ia_bits(bits, n_bits)}"
                else:
                    line += f", decode: {LF_IA_DECODES.get(decode, decode)}"
                print(line + f", {LF_IA_VERDICTS.get(verdict, verdict)}")
                if verdict == 1:
                    late = color_string((CR, " LATE")) if flags & 1 else ""
                    print(
                        f"{'':18}answer {n_tx_bits} bits {_lf_ia_bits(tx_bits, n_tx_bits)}, ready {t_ready - t_us} us "
                        f"after the command, sent at {t_tx - t_us} us (due {t_due - t_us}){late}"
                    )


@lf_interactive.command("clear")
class LFInteractiveClear(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Clear the interactive LF emulation's exchange trace and its counters"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        self.cmd.lf_ia_trace_clear()
        print(" - Trace and counters cleared")


lf_interactive_env = lf_interactive.subgroup(
    "env", "Raw field envelope capture, for bench debugging"
)


@lf_interactive_env.command("arm")
class LFInteractiveEnvArm(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Arm the raw field envelope ring (the smoothed ADC samples the gap detector itself sees, 10 us apart). "
            "It keeps recording from here, oldest samples dropping off the back, until a command ends a listening "
            "session -- then it freezes on that command. With no command, there is no freeze: run 'env read' "
            "promptly after the test, while it still holds it."
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        self.cmd.lf_ia_env_arm()
        print(" - Envelope ring armed -- run the reader test now, then 'lf interactive env read'")


@lf_interactive_env.command("read")
class LFInteractiveEnvRead(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Read back the raw field envelope ring armed by 'env arm'. Prints the newest sample's time, whether "
            "the ring froze on a command, the sample range, and the samples themselves (ADC counts, 10 us apart)."
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        samples, last_us, frozen = [], 0, 0
        while True:
            frozen, last_us, chunk = self.cmd.lf_ia_env_read(len(samples))
            if not chunk:
                break
            samples += chunk
        if not samples:
            print(" - No samples (arm it first with 'lf interactive env arm')")
            return
        span_us = len(samples) * 10
        print(
            f" - {len(samples)} samples, {span_us / 1e3:.2f} ms, newest at {last_us / 1e6:.6f} s, "
            f"{'frozen on a command' if frozen else 'still live (not frozen)'}"
        )
        print(f" - range {min(samples)} .. {max(samples)} ADC counts")
        for i in range(0, len(samples), 16):
            t0_us = last_us - (len(samples) - i) * 10
            row = " ".join(f"{s:5d}" for s in samples[i:i + 16])
            print(f"   {t0_us / 1e3:9.2f} ms  {row}")
