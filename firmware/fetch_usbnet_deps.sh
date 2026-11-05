#!/usr/bin/env bash
# Fetch the pinned TinyUSB and lwIP sources used by STANDALONE_USB_NET=1.
# They land in firmware/deps/ (git-ignored). Build with:
#   STANDALONE_USB_NET=1 ./build.sh
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p deps

fetch() {   # name url revision
    local dir="deps/$1"
    if [ -d "$dir/.git" ] && [ "$(git -C "$dir" rev-parse HEAD)" = "$3" ]; then
        echo "$1: already at $3"
        return
    fi
    rm -rf "$dir"
    mkdir -p "$dir"
    git -C "$dir" init -q
    git -C "$dir" remote add origin "$2"
    git -C "$dir" fetch -q --depth 1 origin "$3"
    git -C "$dir" checkout -q FETCH_HEAD
    echo "$1: $3"
}

fetch tinyusb https://github.com/hathach/tinyusb.git     5217cee5de4cd555018da90f9f1bcc87fb1c1d3a   # 0.17.0
fetch lwip    https://github.com/lwip-tcpip/lwip.git     0a0452b2c39bdd91e252aef045c115f88f6ca773   # 2.2.0
