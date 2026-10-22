#!/bin/env bash

if [[ $BASH_SOURCE = */* ]]; then
  cd -- "${BASH_SOURCE%/*}/" || exit
fi

softdevice=s140
softdevice_version=7.2.0
softdevice_id=0x0100

application_version=1
bootloader_version=2

bootloader_start=0xF3000

device_type=${CURRENT_DEVICE_TYPE:-ultra}
case $device_type in
  "ultra") hw_version=0 ;;
  "lite")  hw_version=1 ;;
  *)       echo "Unknown CURRENT_DEVICE_TYPE $CURRENT_DEVICE_TYPE, aborting."; exit 1 ;;
esac

# ---------------------------------------------------------------------------
# Recovery-mode build
# ---------------------------------------------------------------------------

echo "Building firmware for $device_type (hw_version=$hw_version)"

set -xe

rm -rf "objects"

  # ---- Single composite bootloader at 0xF3000 (44KB) ---------------------
  # UF2 (MSC) + CDC serial DFU, no debug CDC, no logging. Fits the stock
  # 44KB region so it's directly flashable from stock — no SWD, no
  # two-stage. The MBR boots 0xF3000, which is where this BL lives.
  # -----------------------------------------------------------------------
  (
    cd bootloader
    make -j BL_VERSION=$bootloader_version
    # Ensure hex is generated (parallel build can miss it)
    make ../objects/bootloader.hex 2>/dev/null || \
    arm-none-eabi-objcopy -O ihex ../objects/bootloader.out ../objects/bootloader.hex
  )



(
  cd application
    make -j BL_VERSION=$bootloader_version APP_VERSION=$application_version
)

(
  cd objects

    cp ../nrf52_sdk/components/softdevice/${softdevice}/hex/${softdevice}_nrf52_${softdevice_version}_softdevice.hex softdevice.hex

    # The app image feeds pkg generate and uf2conv. nrfutil pads hex gaps,
    # so any page at/above the bootloader (0xF3000) — e.g. a merged settings
    # or MBR-param page — makes serial DFU overwrite the running BL mid-flash
    # and brick the device near 98%. Refuse to package such a hex.
    app_max=$(python3 - application.hex <<'PY'
import sys
base = top = 0
for line in open(sys.argv[1]):
    line = line.strip()
    if len(line) < 11 or line[0] != ':':
        continue
    n = int(line[1:3], 16); a = int(line[3:7], 16); t = int(line[7:9], 16)
    if t == 4:   base = int(line[9:13], 16) << 16
    elif t == 2: base = int(line[9:13], 16) << 4
    elif t == 0: top = max(top, base + a + n)
print(top)
PY
)
    if (( app_max > bootloader_start )); then
        printf 'ERROR: application.hex reaches 0x%X, past bootloader 0x%X.\n' \
               "$app_max" "$bootloader_start"
        echo "The DFU app image would overwrite the bootloader. Package the raw"
        echo "app hex (linker output), not a settings/full-merged one."
        exit 1
    fi

    # SD+BL DFU zip — composite BL at 0xF3000, flashable from stock
    nrfutil nrf5sdk-tools pkg generate \
      --hw-version $hw_version \
      --bootloader bootloader.hex --bootloader-version $bootloader_version \
      --sd-req ${softdevice_id} \
      --key-file ../../resource/dfu_key/chameleon.pem \
      ${device_type}-dfu-bl.zip

    nrfutil nrf5sdk-tools pkg generate \
      --hw-version $hw_version \
      --bootloader  bootloader.hex   --bootloader-version $bootloader_version  --key-file ../../resource/dfu_key/chameleon.pem \
      --application application.hex  --application-version $application_version \
      --softdevice  softdevice.hex \
      --sd-req ${softdevice_id} --sd-id ${softdevice_id} \
      ${device_type}-dfu-full.zip

    nrfutil nrf5sdk-tools pkg generate \
      --hw-version $hw_version --key-file ../../resource/dfu_key/chameleon.pem \
      --application application.hex  --application-version $application_version \
      --sd-req ${softdevice_id} \
      ${device_type}-dfu-app.zip

    nrfutil nrf5sdk-tools settings generate \
      --family NRF52840 \
      --application application.hex --application-version $application_version \
      --softdevice softdevice.hex \
      --bootloader-version $bootloader_version --bl-settings-version 2 \
      settings.hex

    mergehex \
      --merge \
      settings.hex \
      application.hex \
      --output application_merged.hex

    mergehex \
      --merge \
        bootloader.hex \
        application_merged.hex \
        softdevice.hex \
      --output fullimage.hex

    ../tools/uf2conv.py application.hex --family 0x1B57745F -o ${device_type}-application.uf2
    ../tools/uf2conv.py fullimage.hex --family 0x1B57745F -o ${device_type}-fullimage.uf2

    tmp_dir=$(mktemp -d -t cu_binaries_XXXXXXXXXX)
    cp *.hex "$tmp_dir"
    mv $tmp_dir/application_merged.hex $tmp_dir/application.hex
    rm $tmp_dir/settings.hex
    zip -j ${device_type}-binaries.zip $tmp_dir/*.hex
    rm -rf $tmp_dir

    set +x
    echo
    echo "=========================================================="
    echo "Build complete."
    echo "  SD+BL      : objects/${device_type}-dfu-bl.zip"
    echo "  App        : objects/${device_type}-dfu-app.zip"
    echo "  Full image : objects/${device_type}-fullimage.uf2"
    echo "Use flash-dfu-sdbl.sh to install both stages."
    echo "=========================================================="
)
