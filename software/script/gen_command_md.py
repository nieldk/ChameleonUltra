#!/usr/bin/env python3
"""Generate docs/command.md from the live CLI parser tree.

Walks the CLITree in chameleon_cli_unit.py, renders every group and command with
its real argparse options (flags, help, choices, required, defaults). Run from
software/script/:  python3 gen_command_md.py > ../docs/command.md
"""
import argparse, re, io, sys
import chameleon_cli_unit as U
from chameleon_utils import CLITree

ANSI = re.compile(r'\x1b\[[0-9;]*m')
def clean(s):
    return ANSI.sub('', s).strip() if s else s

def anchor(fullname):
    return fullname.replace(' ', '-').replace('_', '_')

def render_opts(parser, out):
    seen = set()
    for a in parser._actions:
        if isinstance(a, argparse._HelpAction):
            continue
        flags = ", ".join(f"`{o}`" for o in a.option_strings) or f"`{a.dest}`"
        if flags in seen:      # de-dup accidental double-adds
            continue
        seen.add(flags)
        bits = []
        h = clean(a.help)
        if h:
            bits.append(h)
        meta = []
        if a.choices:
            meta.append("choices: " + ", ".join(str(c) for c in a.choices))
        if a.required:
            meta.append("required")
        if a.default not in (None, False) and not isinstance(a, argparse._StoreTrueAction):
            meta.append(f"default: {a.default}")
        line = flags
        if h:
            line += f" — {h}"
        if meta:
            line += f" ({'; '.join(meta)})"
        out.write(f"- {line}\n")

def walk(node: CLITree, depth, out, toc):
    # groups: name + help; leaves: name + parser.description + options
    if node.root:
        for c in sorted(node.children, key=lambda x: x.name):
            walk(c, depth, out, toc)
        return
    hashes = "#" * min(depth + 1, 6)
    title = node.fullname
    out.write(f"\n{hashes} `{title}`\n\n")
    toc.append((depth, title))
    if node.cls is None:
        # group node
        if node.help_text:
            out.write(f"{clean(node.help_text)}\n")
        for c in sorted(node.children, key=lambda x: x.name):
            walk(c, depth + 1, out, toc)
    else:
        parser = node.cls().args_parser()
        desc = clean(parser.description) or clean(node.help_text)
        if desc:
            out.write(f"{desc}\n\n")
        # count real options
        real = [a for a in parser._actions if not isinstance(a, argparse._HelpAction)]
        if real:
            render_opts(parser, out)
        if parser.epilog:
            ep = clean(parser.epilog)
            out.write(f"\n```\n{ep}\n```\n")

def main():
    out = io.StringIO()
    toc = []
    # count groups/commands
    def count(n):
        g = c = 0
        for ch in n.children:
            if ch.cls is None and not ch.root:
                g += 1; gg, cc = count(ch); g += gg; c += cc
            elif ch.cls is not None:
                c += 1
            else:
                gg, cc = count(ch); g += gg; c += cc
        return g, c
    ngroups, ncmds = count(U.root)

    body = io.StringIO()
    walk(U.root, 1, body, toc)

    print("# Phreakbyte CLI Command Reference\n")
    print("Complete reference for the Phreakbyte edition ChameleonUltra client "
          "(`chameleon_cli_main.py`), auto-generated from the live CLI parser: "
          f"{ngroups} command groups, {ncmds} commands.\n")
    print("Notation: `<...>` are values you supply. Each option lists its flags, "
          "help, allowed `choices`, whether it is `required`, and its `default`. "
          "Run any command with `-h` in the client for the same information live.\n")
    # File formats section — the genuinely useful addition
    print("## File formats\n")
    print("Several commands read and write **Proxmark3-compatible** files, sniffed "
          "by content so the extension is a convenience, not a requirement:\n")
    print("| Card | Command | Reads | Writes |")
    print("|------|---------|-------|--------|")
    print("| MIFARE Classic | `hf mf eload` / `hf mf esave` | `.bin`, `.eml`, PM3 `mfc v2` `.json` | `.bin`, `.eml`, PM3 `mfc v2` `.json` |")
    print("| DESFire | `hf des eload` / `hf des edump` / `hf des parse` | `.dfc`, `.dfcb`, PM3 `mfdes v1` `.json` | `.dfcb`, PM3 `mfdes v1` `.json` |")
    print("| EMV | `emv scan` / `emv load` | PM3 `emv scan` `.json` | PM3 `emv scan` `.json` |")
    print("| Keys | `hf mf fchk` | `.dic`, `.key` | `.dic`, `.key` |")
    print("| Traces | `hf 14a sniff -o` / `standalone get-result --pm3` | — | PM3 `.trace` |\n")
    print("Round-trips are validated against Proxmark3's own tooling: a `hf des edump -f x.json` "
          "file loads in `hf mfdes view`, and a `hf mfdes dump` file loads via `hf des eload`. "
          "Absent DESFire keys/files are preserved honestly (version-only keys carry no key bytes; "
          "unread files carry no data), per PM3's `mfdes v1` spec.\n")
    print(body.getvalue())

if __name__ == "__main__":
    main()
