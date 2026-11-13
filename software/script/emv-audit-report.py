#!/usr/bin/env python3
"""emv_audit_report.py -- findings report for a captured EMV scan.

Takes the JSON file produced by `emv scan -f <path>` (PM3-compatible
format -- see EMVScan.on_exec / _emv_decode_pairs in
chameleon_cli_unit.py) and evaluates the card's own declared fields
against well-documented EMV characteristics: offline data
authentication strength (SDA/DDA/CDA), cardholder verification method
policy, and a handful of related AIP flags. Output is a
severity-ranked findings report.

This script only reads back what an earlier `emv scan` already
captured from a direct card read -- it does not talk to a card or a
terminal itself, and it does not propose or perform any kind of test
against a terminal. It is an offline analysis pass over one JSON file.

Usage:
    python3 emv_audit_report.py card.json
    python3 emv_audit_report.py card.json --md report.md
    python3 emv_audit_report.py card.json --json findings.json
    python3 emv_audit_report.py card.json --quiet --md report.md
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cli_core import CR, CG, CY, CC, C0, _box, _term_width  # noqa: E402

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
SEVERITY_COLOR = {'CRITICAL': CR, 'HIGH': CR, 'MEDIUM': CY, 'LOW': CY, 'INFO': CG}


class Finding:
    def __init__(self, severity, title, detail, reference=''):
        self.severity = severity
        self.title = title
        self.detail = detail
        self.reference = reference

    def to_dict(self):
        return {'severity': self.severity, 'title': self.title,
                'detail': self.detail, 'reference': self.reference}


def _aip_bits(aip_hex):
    """First AIP byte, decoded per EMV Book 3 10.3. Returns None if the
    card's AIP was not captured in this scan."""
    if not aip_hex or len(aip_hex) < 2:
        return None
    b1 = int(aip_hex[0:2], 16)
    return {
        'sda': bool(b1 & 0x40),
        'dda': bool(b1 & 0x20),
        'cvm': bool(b1 & 0x10),
        'trm': bool(b1 & 0x08),
        'issuer_auth': bool(b1 & 0x04),
        'cda': bool(b1 & 0x01),
    }


def check_offline_auth(decoded, findings):
    bits = _aip_bits(decoded.get('AIP'))
    if bits is None:
        findings.append(Finding(
            'MEDIUM', 'No AIP captured',
            'Application Interchange Profile (tag 82) was not present in '
            'this scan, so offline data authentication strength could not '
            'be determined.', 'EMV Book 3, 10.3'))
        return
    if bits['cda']:
        findings.append(Finding(
            'INFO', 'Combined Dynamic Authentication (CDA) supported',
            'Strongest offline data authentication the card advertises -- '
            'ties data authentication to the transaction cryptogram, so it '
            'cannot be satisfied from previously captured static data alone.',
            'EMV Book 2, 6.3'))
    elif bits['dda']:
        findings.append(Finding(
            'INFO', 'Dynamic Data Authentication (DDA) supported',
            'The card can prove possession of its private key against a '
            'fresh, terminal-supplied challenge -- static card data by '
            'itself is not sufficient to authenticate it.', 'EMV Book 2, 6.2'))
    elif bits['sda']:
        findings.append(Finding(
            'CRITICAL', 'Static Data Authentication (SDA) only',
            'The card advertises SDA with neither DDA nor CDA. The signed '
            'data used for SDA (tags 90/92/93) is fixed and identical on '
            'every read of this card -- a terminal that accepts SDA as '
            'sufficient offline authentication is relying entirely on data '
            'that never changes, a long-documented weakness of SDA-only '
            'deployments.', 'EMV Book 2, 5'))
    else:
        findings.append(Finding(
            'HIGH', 'No offline data authentication advertised',
            'Neither SDA, DDA nor CDA is set in the AIP -- this card is not '
            'offering any offline cryptographic authentication method; a '
            'terminal can only fall back to online authorization for it.',
            'EMV Book 3, 10.3'))

    if not bits['trm']:
        findings.append(Finding(
            'INFO', 'Terminal risk management not flagged as required',
            'The AIP does not set the "terminal risk management required" '
            'bit, so the card is not itself requesting extra terminal-side '
            'risk checks.', 'EMV Book 3, 10.3'))
    if not bits['issuer_auth']:
        findings.append(Finding(
            'INFO', 'Issuer authentication not advertised',
            'The AIP does not set the issuer-authentication bit, so this '
            'card does not request an Issuer Authentication step '
            '(EXTERNAL AUTHENTICATE) after online processing.',
            'EMV Book 3, 10.3'))


_CVM_PIN_HINTS = ('Plaintext PIN', 'Enciphered PIN')


def check_cvm(decoded, findings):
    rules = decoded.get('CVMRules')
    if not rules:
        findings.append(Finding(
            'INFO', 'No CVM List captured',
            'No Cardholder Verification Method list (tag 8E) was found in '
            'this scan -- either the card did not return one, or the flow '
            'it took did not require cardholder verification.',
            'EMV Book 3, 10.5'))
        return

    has_no_cvm = any('No CVM required' in r for r in rules)
    has_pin = any(any(h in r for h in _CVM_PIN_HINTS) for r in rules)
    has_sig = any('Signature' in r for r in rules)

    if has_no_cvm:
        findings.append(Finding(
            'HIGH', "'No CVM required' rule present",
            'At least one CVM rule lets the transaction proceed with no '
            'cardholder verification at all, under its stated condition. '
            'Rules: ' + '; '.join(rules), 'EMV Book 3, 10.5'))
    if has_sig and not has_pin:
        findings.append(Finding(
            'MEDIUM', 'Signature is the strongest CVM offered',
            'No PIN-based rule is present; the strongest verification this '
            'card offers is a signature, which a terminal has no '
            'cryptographic way to check on its own. Rules: '
            + '; '.join(rules), 'EMV Book 3, 10.5'))
    if has_pin:
        findings.append(Finding(
            'INFO', 'PIN-based CVM available',
            'At least one rule requires a PIN. Rules: ' + '; '.join(rules),
            'EMV Book 3, 10.5'))


def check_pin_try_counter(decoded, findings):
    ptc = decoded.get('PINTryCounter')
    if ptc is None:
        return
    if ptc <= 1:
        findings.append(Finding(
            'LOW', 'PIN try counter is low',
            f'Only {ptc} offline PIN attempt(s) remain before the card '
            'blocks offline PIN verification.', 'EMV Book 3, 6.5.12'))


def check_static_data_capture(decoded, findings):
    have = [k for k in ('PAN', 'Expiry', 'ServiceCode', 'CardholderName',
                         'Track1_PAN', 'Track1_Name')
            if decoded.get(k)]
    if have:
        findings.append(Finding(
            'INFO', 'Static card data captured in this scan',
            'This direct card read captured: ' + ', '.join(have) + '. '
            'These are fixed fields that do not change between reads, '
            'which is what a static-response emulation slot reproduces.',
            ''))


def check_missing_core_fields(decoded, findings):
    missing = [k for k in ('AFL',) if not decoded.get(k)]
    if missing:
        findings.append(Finding(
            'MEDIUM', 'Application File Locator not captured',
            'No AFL (tag 94) was found, so this scan may not have reached '
            'READ RECORD -- the findings above may be based on an '
            'incomplete capture.', 'EMV Book 3, 10.2'))


CHECKS = (
    check_offline_auth,
    check_cvm,
    check_pin_try_counter,
    check_static_data_capture,
    check_missing_core_fields,
)


def run_checks(decoded):
    findings = []
    for check in CHECKS:
        check(decoded, findings)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings


def _mask_pan(pan):
    if not pan or len(pan) < 10:
        return pan or '(none captured)'
    return pan[:6] + '*' * (len(pan) - 10) + pan[-4:]


def _card_header(data):
    decoded = data.get('Decoded', {})
    contactless = data.get('Card', {}).get('Contactless', {})
    aid = data.get('Application', {}).get('AID', '')
    lines = [
        f"{'UID':<16} {contactless.get('UID', '?')}",
        f"{'AID':<16} {aid or '?'}",
        f"{'PAN (masked)':<16} {_mask_pan(decoded.get('PAN'))}",
        f"{'Expiry':<16} {decoded.get('Expiry', '?')}",
        f"{'Cardholder':<16} {decoded.get('CardholderName', '?')}",
    ]
    return lines


def render_terminal(data, findings):
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ', '.join(f'{counts[s]} {s}' for s in SEVERITY_ORDER if s in counts)

    out = []
    out.extend(_box('Card Audited', _card_header(data), color=CC, min_width=38))
    out.append('')
    out.append(f' {CC}Findings: {summary or "none"}{C0}')
    out.append('')
    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, C0)
        lines = [f"{'Detail':<10} {f.detail}"]
        if f.reference:
            lines.append(f"{'Reference':<10} {f.reference}")
        out.extend(_box(f'[{f.severity}] {f.title}', lines, color=color, min_width=38))
        out.append('')
    return out


def render_markdown(data, findings):
    decoded = data.get('Decoded', {})
    contactless = data.get('Card', {}).get('Contactless', {})
    aid = data.get('Application', {}).get('AID', '')
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    lines = [
        '# EMV Scan Audit Report',
        '',
        f'Generated: {ts}',
        '',
        '## Card',
        '',
        f"- UID: `{contactless.get('UID', '?')}`",
        f"- AID: `{aid or '?'}`",
        f"- PAN (masked): `{_mask_pan(decoded.get('PAN'))}`",
        f"- Expiry: {decoded.get('Expiry', '?')}",
        f"- Cardholder: {decoded.get('CardholderName', '?')}",
        '',
        '## Findings',
        '',
    ]
    for f in findings:
        lines.append(f'### [{f.severity}] {f.title}')
        lines.append('')
        lines.append(f.detail)
        if f.reference:
            lines.append('')
            lines.append(f'*Reference: {f.reference}*')
        lines.append('')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Generate a severity-ranked findings report from an '
                    '`emv scan -f` JSON capture.')
    parser.add_argument('scan_json', metavar='<scan.json>',
                        help='JSON file produced by `emv scan -f <path>`')
    parser.add_argument('--md', metavar='<path>', default='',
                        help='Also write a Markdown report to this path')
    parser.add_argument('--json', metavar='<path>', default='',
                        help='Also write the structured findings list as JSON')
    parser.add_argument('--quiet', action='store_true',
                        help='Suppress the terminal report (useful with --md/--json)')
    args = parser.parse_args()

    try:
        with open(args.scan_json) as fp:
            data = json.load(fp)
    except (OSError, json.JSONDecodeError) as e:
        print(f'{CR}Could not read {args.scan_json}: {e}{C0}', file=sys.stderr)
        return 1

    decoded = data.get('Decoded', {})
    if not decoded:
        print(f'{CR}No "Decoded" section in {args.scan_json} -- is this an '
              f'`emv scan -f` output file?{C0}', file=sys.stderr)
        return 1

    findings = run_checks(decoded)

    if not args.quiet:
        for line in render_terminal(data, findings):
            print(line)

    if args.md:
        with open(args.md, 'w') as fp:
            fp.write(render_markdown(data, findings))
        print(f'{CG}Markdown report written to {args.md}{C0}')

    if args.json:
        with open(args.json, 'w') as fp:
            json.dump([f.to_dict() for f in findings], fp, indent=2)
        print(f'{CG}Findings JSON written to {args.json}{C0}')

    has_critical = any(f.severity == 'CRITICAL' for f in findings)
    return 2 if has_critical else 0


if __name__ == '__main__':
    sys.exit(main())
