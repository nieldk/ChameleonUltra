#!/bin/bash
if [[ $BASH_SOURCE = */* ]]; then cd -- "${BASH_SOURCE%/*}/" || exit; fi

if ! ../resource/tools/enter_dfu.py; then
    echo "Press B and plug USB (LEDs 4 & 5 should blink)"
fi
while :; do lsusb | grep -q 1915:521f && break; sleep 1; done

device_type=ultra
lsusb | grep 1915:521f | grep -q ChameleonLite && device_type=lite

echo "Flashing SoftDevice + UF2 Bootloader to $device_type..."
nrfutil device program \
  --firmware objects/${device_type}-dfu-sdbl.zip \
  --traits nordicDfu

echo "Done. Device will reboot into UF2 bootloader."
echo "Run flash-uf2-app.sh to flash the application."
