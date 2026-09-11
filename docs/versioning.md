# Versioning

This fork does **not** derive versions from git tags. All version numbers are
set by hand, so builds are reproducible from a source tarball, a CI checkout,
or a shallow clone with no tags present.

There are three separate version values. They are unrelated and reported by
different commands.

## 1. Application firmware version — `hw version`

Set in `firmware/Makefile.defs`:

```makefile
APP_FW_VER_MAJOR := 2
APP_FW_VER_MINOR := 2
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

Reported flat (a single integer), sourced from `build.sh` and compiled into
the **application**, so it ships in the normal application UF2 and updates on
every app flash — no settings-page write, no SWD (see
[flashing-and-bootloader.md](flashing-and-bootloader.md) for why that matters).

`firmware/build.sh`:

```bash
bootloader_version=40
```

The value is passed into the application build:

```bash
(
  cd application
  make -j BL_VERSION=$bootloader_version    # RECOVERY_MODE=1 also, in recovery build
)
```

`firmware/application/Makefile` turns it into a macro (default keeps a bare
`make` working):

```makefile
BL_VERSION ?= 0
CFLAGS += -DBL_VERSION=$(BL_VERSION)
```

and `cmd_processor_get_bootloader_version()` in `app_cmd.c` returns it directly
as a big-endian `uint32` (the client prints it flat):

```c
uint32_t payload = U32HTONL((uint32_t)BL_VERSION);
return data_frame_make(cmd, STATUS_SUCCESS, sizeof(payload), (uint8_t *)&payload);
```

`bootloader_version` is still also handed to `nrfutil pkg/settings generate` as
the nRF DFU version field, but this fork does **not** enforce a monotonic
bootloader version (see the downgrade note in
[flashing-and-bootloader.md](flashing-and-bootloader.md)), so you can set it to
whatever you want `hw blver` to show.

> Note: earlier revisions read `hw blver` from the DFU settings page
> (`0xFF000 + 12`) and split the value into `major.minor`. That could not be
> updated over UF2 and is no longer used — the value is now compile-time in the
> application.
