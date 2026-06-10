#!/bin/bash
# Revert ChameleonUltra from this UF2 fork back to stock firmware,
# without SWD. Two-stage, mirroring the install process in reverse.
#
# Requires the stock RRG release zip (ultra-dfu-full.zip) passed as $1
# or placed at ~/Downloads/ultra-dfu-full.zip.
#
# Stage 1: build a recovery UF2 from the stock zip (embeds stock SD+BL
#          in a recovery app that runs bl_updater to rewrite the BL
#          region back to stock at 0xF3000).
# Stage 2: drop the recovery UF2 onto the CHAMELEON drive. The recovery
#          app overwrites the bootloader region with stock, then the
#          device reboots into the stock bootloader in DFU mode.
# Stage 3: flash the stock application via the stock serial DFU.
set -euo pipefail

if [[ $BASH_SOURCE = */* ]]; then cd -- "${BASH_SOURCE%/*}/" || exit; fi

STOCK_ZIP="${1:-$HOME/Downloads/ultra-dfu-full.zip}"

if [ ! -f "$STOCK_ZIP" ]; then
    echo "error: stock zip not found at $STOCK_ZIP"
    echo "Download ultra-dfu-full.zip from the RRG releases page,"
    echo "or pass its path as the first argument."
    exit 1
fi

device_type=ultra

wait_for_chameleon_drive() {
    echo "Waiting for CHAMELEON drive..." >&2
    local t=0
    while :; do
        drive=$(lsblk -o LABEL,PATH 2>/dev/null | awk '/CHAMELEON/{print $2}')
        if [ -n "$drive" ]; then
            mp=$(findmnt -n -o TARGET "$drive" 2>/dev/null || true)
            [ -z "$mp" ] && mp=$(udisksctl mount -b "$drive" 2>/dev/null | sed 's/.* at //' || true)
            [ -n "$mp" ] && echo "$mp" && return 0
        fi
        for d in /run/media/$USER/CHAMELEON /media/$USER/CHAMELEON /media/CHAMELEON; do
            [ -d "$d" ] && echo "$d" && return 0
        done
        sleep 1; t=$((t+1))
        [ $t -gt 60 ] && echo "timeout" >&2 && return 1
    done
}

wait_for_dfu() {
    echo "Waiting for stock serial DFU..."
    local t=0
    while :; do
        lsusb | grep -q 1915:521f && return 0
        sleep 1; t=$((t+1))
        [ $t -gt 30 ] && echo "timeout" && return 1
    done
}

echo "=== Stage 1: building recovery UF2 from $STOCK_ZIP ==="
RECOVERY_ZIP="$STOCK_ZIP" ./build.sh

recovery_uf2="objects/${device_type}-revert-to-stock.uf2"
[ -f "$recovery_uf2" ] || { echo "recovery UF2 not built"; exit 1; }

echo "=== Stage 2: dropping recovery UF2 ==="
echo "Enter UF2 DFU mode: cold-boot + hold B + plug USB"
mp=$(wait_for_chameleon_drive)
cp "$recovery_uf2" "$mp/"
sync
echo "Recovery UF2 written. Device will rewrite the bootloader and reboot."
echo "This takes a few seconds — do not unplug."
sleep 5

echo "=== Stage 3: flashing stock application ==="
wait_for_dfu
nrfutil device program --firmware "$STOCK_ZIP" --traits nordicDfu

echo
echo "Done. Device reverted to stock firmware."
