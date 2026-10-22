# Versioning

This fork does **not** derive versions from git tags. All version numbers are
set by hand, so builds are reproducible from a source tarball, a CI checkout,
or a shallow clone with no tags present.

There are three separate version values. They are unrelated and reported by
different commands.

## 1. Application firmware version — `hw version`

Set in `firmware/Makefile.defs`:

```makefile
APP_FW_VER_MAJOR := 1
APP_FW_VER_MINOR := 0
APP_FW_VER_PATCH := 0
APP_FW_SEMVER    := $(APP_FW_VER_MAJOR).$(APP_FW_VER_MINOR).$(APP_FW_VER_PATCH)
```

`APP_FW_VER_MAJOR` / `APP_FW_VER_MINOR` are compiled in (`-D…`) and reported to
the host in the `GET_APP_VERSION` response. `app_config.h` computes
`FW_VER_NUM` from them and fails the build if either is undefined, so both must
stay defined and numeric. Bump these by hand per release.

## 2. Build string — `GET_GIT_VERSION`

Also in `Makefile.defs`. A human-readable string: the semver plus a short
commit hash when git is available, degrading cleanly to bare semver in a
tarball/CI build:

```makefile
GIT_REV     := $(shell git rev-parse --short=7 HEAD 2>/dev/null)
GIT_DIRTY   := $(shell git diff --quiet 2>/dev/null || echo -dirty)
GIT_VERSION := v$(APP_FW_SEMVER)$(if $(GIT_REV),-g$(GIT_REV)$(GIT_DIRTY))
```

This uses the commit hash, never a tag. Example outputs: `v2.2.0-g1a2b3c4`,
`v2.2.0-g1a2b3c4-dirty`, or `v2.2.0` with no git history.

## 3. Bootloader version — `hw blver`

The bootloader carries its own identity: a 64-byte info block at a fixed
address, `0xFDFC0` (the last 64 bytes of the 44 KB region). It is built from
`firmware/bootloader/src/bl_info.[ch]` and placed by `bootloader-stage1.ld`
(`FLASH` ends at `0xFDFC0`, so code overflowing into it fails the link).

| Offset | Field |
|---|---|
| 0 | magic `"BLIN"` (`0x4E494C42`) |
| 4 | layout (u16, 1), size (u16, 64) |
| 8 | version (u32) - `bootloader_version` from `build.sh` |
| 12 | features (u32): bit0 UF2, bit1 CDC DFU, bit2 raw app write |
| 16 | GCC major, minor, patch |
| 20 | git revision, NUL padded (`g1a2b3c`, `-dirty` if modified; empty without git) |

`build.sh` passes `BL_VERSION=$bootloader_version` to the bootloader make.
No build date is stored, so builds stay reproducible.

`hw blver` reads the block through `hw bl info`'s reply (the app appends the
block and a CRC32 of `0xF3000-0xFE000` to the existing response) and prints:

```
 - Bootloader Version: 2 (g1a2b3c)
 - Built with        : GCC 15.2.1
 - Features          : UF2, CDC DFU, raw app write
 - Image             : 0xF3000-0xFE000 (45,056 bytes), CRC32 0x........
 - Settings counter  : 2
```

The image CRC32 covers the full 45,056-byte region and matches the CRC32
that `hw bl push` prints for the same hex. A bootloader built before the info
block, or an older app, falls back to the settings counter alone.

The settings counter is the `bootloader_version` field of the DFU settings
page (`0xFF000 + 12`). It is not part of the bootloader image and is not
changed by `hw bl push`; `hw version -b` sets it. This fork does **not**
enforce a monotonic bootloader version (see the downgrade note in
[flashing-and-bootloader.md](flashing-and-bootloader.md)).
