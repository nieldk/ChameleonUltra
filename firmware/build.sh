#!/bin/env bash

if [[ $BASH_SOURCE = */* ]]; then
  cd -- "${BASH_SOURCE%/*}/" || exit
fi

softdevice=s140
softdevice_version=7.2.0
softdevice_id=0x0100


# TODO: find a way to manage this automatically, I don't want to rely on action build #.
application_version=1
bootloader_version=4

device_type=${CURRENT_DEVICE_TYPE:-ultra}
case $device_type in
  "ultra") hw_version=0 ;;
  "lite")  hw_version=1 ;;
  *)       echo "Unknown CURRENT_DEVICE_TYPE $CURRENT_DEVICE_TYPE, aborting."; exit 1 ;;
esac

# ---------------------------------------------------------------------------
# Recovery-mode build
# ---------------------------------------------------------------------------
# Set RECOVERY_ZIP to the path of an upstream ultra-dfu-full.zip (or
# lite-dfu-full.zip) to build a revert-to-stock UF2 instead of a normal
# build. The resulting ${device_type}-revert-to-stock.uf2 can be dragged
# onto the CHAMELEON drive of a UF2-bootloader-equipped device to roll
# it back to stock firmware.
#
# Example:
#   RECOVERY_ZIP=~/Downloads/ultra-dfu-full.zip ./build.sh
# ---------------------------------------------------------------------------
if [[ -n "$RECOVERY_ZIP" ]]; then
  if [[ ! -f "$RECOVERY_ZIP" ]]; then
    echo "error: RECOVERY_ZIP=$RECOVERY_ZIP does not exist" >&2
    exit 1
  fi
  RECOVERY_MODE=1
  echo "Recovery-mode build — embedding stock BL from $RECOVERY_ZIP"
fi

echo "Building firmware for $device_type (hw_version=$hw_version)"

set -xe

rm -rf "objects"

if [[ -z "$RECOVERY_MODE" ]]; then
  # ---- Normal build path ------------------------------------------------
  # 1. Build the bootloader (with our UF2 transport)
  # 2. Generate embedded_bootloader.h from the just-built bootloader.hex
  #    so the application's bl_updater carries a copy of THIS build's BL
  # 3. Build the application (which #includes embedded_bootloader.h)
  # -----------------------------------------------------------------------
  (
    cd bootloader
    make -j
  )

  ./tools/gen_embedded_bl.py \
    objects/bootloader.hex \
    application/src/embedded_bootloader.h
else
  # ---- Recovery build path ----------------------------------------------
  # 1. Skip the bootloader build entirely (we're embedding the STOCK BL,
  #    not our UF2 one)
  # 2. Extract the stock BL from the upstream zip and emit
  #    embedded_bootloader.h pointing at it
  # 3. Build the application with RECOVERY_MODE=1 — its main() will skip
  #    all normal init and run bl_updater_run_and_invalidate_app() on boot
  # -----------------------------------------------------------------------
  ./tools/make_recovery_header.py \
    "$RECOVERY_ZIP" \
    application/src/embedded_bootloader.h
fi

(
  cd application
  if [[ -n "$RECOVERY_MODE" ]]; then
    make -j RECOVERY_MODE=1
  else
    make -j
  fi
)

(
  cd objects

  if [[ -n "$RECOVERY_MODE" ]]; then
    # Recovery output is just the UF2 file. Signed DFU zips would contain
    # our UF2 bootloader, which is the opposite of what end users want
    # here. Merged hex outputs aren't useful either — users running this
    # don't have SWD (that's the whole point).
    ../tools/uf2conv.py application.hex -o ${device_type}-revert-to-stock.uf2

    set +x
    echo
    echo "=========================================================="
    echo "Built recovery UF2: objects/${device_type}-revert-to-stock.uf2"
    echo "=========================================================="
    echo "End-user flow:"
    echo "  1. Cold-boot the device, hold B, plug to enter UF2 DFU mode"
    echo "  2. Drag ${device_type}-revert-to-stock.uf2 onto CHAMELEON"
    echo "  3. Wait ~2 seconds (device resets twice, drive disappears)"
    echo "  4. Stock bootloader now in place, device in stock DFU mode"
    echo "  5. Push stock app via the upstream flash-dfu-app.sh"
    echo
  else
    # Normal build — produce all the standard artifacts.
    cp ../nrf52_sdk/components/softdevice/${softdevice}/hex/${softdevice}_nrf52_${softdevice_version}_softdevice.hex softdevice.hex

    nrfutil nrf5sdk-tools pkg generate \
      --hw-version $hw_version \
      --bootloader  bootloader.hex   --bootloader-version  $bootloader_version  --key-file ../../resource/dfu_key/chameleon.pem \
      --application application.hex  --application-version $application_version\
      --softdevice  softdevice.hex \
      --sd-req ${softdevice_id} --sd-id ${softdevice_id} \
      ${device_type}-dfu-full.zip

    nrfutil nrf5sdk-tools pkg generate \
      --hw-version $hw_version --key-file ../../resource/dfu_key/chameleon.pem \
      --application application.hex  --application-version $application_version \
      --sd-req ${softdevice_id} \
      ${device_type}-dfu-app.zip

    # Add after the existing full zip generation in build.sh
    nrfutil nrf5sdk-tools pkg generate \
      --hw-version $hw_version \
      --bootloader  bootloader.hex  --bootloader-version $bootloader_version \
      --softdevice  softdevice.hex \
      --sd-req ${softdevice_id} --sd-id ${softdevice_id} \
      --key-file ../../resource/dfu_key/chameleon.pem \
      ${device_type}-dfu-sdbl.zip

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

    # UF2-format application for the drag-and-drop update flow with our
    # UF2 bootloader installed. Requires the type-02 patch in
    # tools/uf2conv.py (handles Nordic SDK's Extended Segment Address
    # records — without it, all target addresses come out as 0).
    ../tools/uf2conv.py application.hex -o ${device_type}-application.uf2

    # Full image UF2: MBR + SoftDevice + bootloader + app + settings.
    # Restores everything including the bootloader on devices with ACL removed.
    ../tools/uf2conv.py fullimage.hex -o ${device_type}-fullimage.uf2

    tmp_dir=$(mktemp -d -t cu_binaries_XXXXXXXXXX)
    cp *.hex "$tmp_dir"
    mv $tmp_dir/application_merged.hex $tmp_dir/application.hex
    rm $tmp_dir/settings.hex
    zip -j ${device_type}-binaries.zip $tmp_dir/*.hex
    rm -rf $tmp_dir
  fi
)
