#!/bin/bash
# Two-stage UF2 bootloader installer.
#
# Stage 1: flash a minimal UF2-only BL at 0xF3000 via serial DFU (fits 44KB).
# Stage 2: flash the full BL at 0xEB000 via UF2 drag-and-drop.

if [[ $BASH_SOURCE = */* ]]; then cd -- "${BASH_SOURCE%/*}/" || exit; fi

wait_for_dfu() {
    echo "Waiting for DFU device..."
    while :; do lsusb | grep -q 1915:521f && break; sleep 1; done
}

wait_for_chameleon_drive() {
    echo "Waiting for CHAMELEON drive..."
    while :; do
        for dev in /run/media/$USER/CHAMELEON /media/$USER/CHAMELEON /media/CHAMELEON; do
            [ -d "$dev" ] && echo "$dev" && return
        done
        # Also check by block device label
        drive=$(lsblk -o LABEL,PATH | grep CHAMELEON | awk '{print $2}')
        if [ -n "$drive" ]; then
            mount_point=$(findmnt -n -o TARGET "$drive" 2>/dev/null)
            [ -n "$mount_point" ] && echo "$mount_point" && return
        fi
        sleep 1
    done
}

device_type=ultra
lsusb | grep 1915:521f | grep -q ChameleonLite && device_type=lite

stage1_zip="objects/${device_type}-dfu-sdbl-stage1.zip"
stage2_uf2="objects/${device_type}-fullimage.uf2"

if [ ! -f "$stage1_zip" ] || [ ! -f "$stage2_uf2" ]; then
    echo "error: build artifacts not found. Run ./build.sh first."
    exit 1
fi

# ---- Stage 1: serial DFU ----
echo "=== Stage 1: flashing minimal UF2 bootloader via serial DFU ==="
if ! ../resource/tools/enter_dfu.py; then
    echo "Press B and plug USB (LEDs 4 & 5 should blink)"
fi
wait_for_dfu

nrfutil device program \
  --firmware "$stage1_zip" \
  --traits nordicDfu

echo "Stage 1 complete. Waiting for UF2 bootloader to start..."
sleep 2

# ---- Stage 2: UF2 drag-and-drop ----
echo "=== Stage 2: flashing full UF2 bootloader via drag-and-drop ==="
echo "Enter UF2 DFU mode: cold-boot + hold B + plug USB"
mount_point=$(wait_for_chameleon_drive)
echo "CHAMELEON drive at $mount_point"

cp "$stage2_uf2" "$mount_point/"
echo "Stage 2 flashed. Device rebooting..."

echo
echo "Done. Full UF2 bootloader installed."
echo "Run flash-dfu-app.sh to flash the application."
