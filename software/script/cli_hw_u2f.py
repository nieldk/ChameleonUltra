"""cli_hw_u2f - provision the U2F standalone mode's attestation material (hw u2f ...)."""

import argparse

from cli_core import ArgumentParserNoExit, DeviceRequiredUnit, hw

hw_u2f = hw.subgroup("u2f", "Provision the U2F standalone mode")


def _load_priv_scalar(path: str) -> bytes:
    """Return the 32-byte big-endian P-256 private scalar from a PEM or DER key."""
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_der_private_key)
    raw = open(path, "rb").read()
    try:
        k = load_pem_private_key(raw, password=None)
    except ValueError:
        k = load_der_private_key(raw, password=None)
    return k.private_numbers().private_value.to_bytes(32, "big")


def _load_cert_der(path: str) -> bytes:
    """Return the certificate as DER bytes, accepting PEM or DER input."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    raw = open(path, "rb").read()
    cert = x509.load_pem_x509_certificate(raw) if b"-----BEGIN" in raw \
        else x509.load_der_x509_certificate(raw)
    return cert.public_bytes(Encoding.DER)


@hw_u2f.command("set-attestation")
class HWU2fSetAttestation(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = ("Provision the U2F attestation key + cert into FDS "
                              "(no recompile). Accepts PEM or DER.")
        parser.add_argument("-k", "--key", required=True, metavar="<file>",
                            help="P-256 attestation private key (PEM or DER)")
        parser.add_argument("-c", "--cert", required=True, metavar="<file>",
                            help="attestation certificate (PEM or DER)")
        parser.epilog = ("example:\n"
                         "  firmware/tools/gen_u2f_attestation.sh   # or your own openssl key+cert\n"
                         "  hw u2f set-attestation -k att.key -c att.crt")
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            priv = _load_priv_scalar(args.key)
            cert = _load_cert_der(args.cert)
        except ImportError:
            print(" - Needs the 'cryptography' package: pip install cryptography")
            return
        except Exception as e:
            print(f" - Could not parse key/cert: {e}")
            return
        if len(cert) > 512:
            print(f" - Cert is {len(cert)} bytes; firmware cap is 512. Use a smaller cert.")
            return
        self.cmd.u2f_set_attestation(priv, cert)
        print(f" - Provisioned: 32-byte key + {len(cert)}-byte cert. Re-arm u2f to apply.")
