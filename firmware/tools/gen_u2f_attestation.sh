#!/bin/sh
# Generate a self-signed P-256 U2F attestation key + cert and SAVE them, for
#   hw u2f set-attestation -k att.key -c att.crt
# Options: -o <dir> output dir (default .)   -n <CN> subject CN   --print-c also
# print the C arrays (only needed for the old paste-into-mode_u2f.c path).
# openssl only.
set -e
OUT="."; CN="Phreakbyte U2F"; PRINT_C=0
while [ $# -gt 0 ]; do
  case "$1" in
    -o) OUT="$2"; shift 2;;
    -n) CN="$2"; shift 2;;
    --print-c) PRINT_C=1; shift;;
    *) echo "usage: $0 [-o dir] [-n CN] [--print-c]" >&2; exit 1;;
  esac
done
mkdir -p "$OUT"
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/att.key"
openssl req -new -x509 -key "$OUT/att.key" -days 3650 -subj "/CN=$CN" -out "$OUT/att.crt"
openssl x509 -in "$OUT/att.crt" -outform der -out "$OUT/att.der"
echo "wrote $OUT/att.key  $OUT/att.crt  $OUT/att.der ($(wc -c < "$OUT/att.der") byte cert)"
echo "provision:  hw u2f set-attestation -k $OUT/att.key -c $OUT/att.crt"
if [ "$PRINT_C" = 1 ]; then
  PRIV=$(openssl asn1parse -in "$OUT/att.key" | awk '/l=  32 prim: OCTET STRING/{print; exit}' | sed 's/.*\[HEX DUMP\]://')
  CERT=$(od -v -An -tx1 "$OUT/att.der" | tr -d ' \n')
  emit() { printf 'static const uint8_t %s = {\n' "$1"
    echo "$2" | fold -w2 | awk 'BEGIN{c=0}{printf (c%12==0?"    0x%s,":" 0x%s,"),$0; if(++c%12==0)printf"\n"}END{if(c%12)printf"\n"}'
    printf '};\n'; }
  echo; emit "U2F_ATT_PRIV[32]" "$PRIV"; emit "U2F_ATT_CERT[]" "$CERT"
fi
