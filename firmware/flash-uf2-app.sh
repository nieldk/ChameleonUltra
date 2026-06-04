#!/bin/bash
if [[ $BASH_SOURCE = */* ]]; then cd -- "${BASH_SOURCE%/*}/" || exit; fi

device_type=ultra
lsusb | grep 1915:521f | grep -q ChameleonLite && device_type=lite

uf2_file=objects/${device_type}-application.uf2
if [ ! -f "$uf2_file" ]; then
    echo "UF2 not found: $uf2_file — run build.sh first"
    exit 1
fi

echo "Waiting for CHAMELEON UF2 drive..."
echo "Enter UF2 mode: hold B and plug USB"

MOUNT=""
for i in $(seq 1 60); do
    MOUNT=$(findmnt -rn -o TARGET -S LABEL=CHAMELEON 2>/dev/null | head -1)
    [ -n "$MOUNT" ] && break
    sleep 1
done

if [ -z "$MOUNT" ]; then
    echo "CHAMELEON drive not found after 60s"
    exit 1
fi

echo "Found at $MOUNT — flashing $uf2_file ..."
cp "$uf2_file" "$MOUNT/"
sync
echo "Done. Device will reset into application."
