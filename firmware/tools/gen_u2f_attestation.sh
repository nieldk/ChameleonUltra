#!/bin/sh
# Generate a self-signed P-256 U2F attestation key + cert and print the two C
# arrays to paste over U2F_ATT_PRIV / U2F_ATT_CERT in mode_u2f.c.
# Usage: ./gen_u2f_attestation.sh ["Common Name"]   (needs openssl only)
set -e
CN="${1:-Phreakbyte U2F}"
D="$(mktemp -d)"; trap 'rm -rf "$D"' EXIT
openssl ecparam -name prime256v1 -genkey -noout -out "$D/att.key"
openssl req -new -x509 -key "$D/att.key" -days 3650 -subj "/CN=$CN" -out "$D/att.crt"
openssl x509 -in "$D/att.crt" -outform der -out "$D/att.der"
PRIV=$(openssl asn1parse -in "$D/att.key" | awk '/l=  32 prim: OCTET STRING/{print; exit}' \
       | sed 's/.*\[HEX DUMP\]://')
CERT=$(od -v -An -tx1 "$D/att.der" | tr -d ' \n')
emit() {
  printf 'static const uint8_t %s = {\n' "$1"
  echo "$2" | fold -w2 | awk 'BEGIN{c=0}{printf (c%12==0?"    0x%s,":" 0x%s,"),$0; if(++c%12==0)printf"\n"}END{if(c%12)printf"\n"}'
  printf '};\n'
}
echo "/* attestation private key (32-byte P-256 scalar) */"
emit "U2F_ATT_PRIV[32]" "$PRIV"
echo "/* self-signed attestation cert, DER ($(wc -c < "$D/att.der") bytes) */"
emit "U2F_ATT_CERT[]" "$CERT"
