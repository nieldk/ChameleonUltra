# DFC core

DFC core is a portable DESFire-compatible engine. It provides these parts:

- A credential data model
- `.dfc` text encoding and decoding
- `.dfcb` binary encoding and decoding
- Secure messaging
- A virtual card emulator

It is suitable for hosted systems and freestanding C targets.

## Requirements

Use a C11 compiler and select either mbedTLS 3.x or
[tiny-crypto-c](https://github.com/mistial-dev/tiny-crypto-c). See
[Integration](docs/integration.md) for compiler options.

## Run the tests

With mbedTLS 3.x installed:

```sh
make -C tests test
```

With tiny-crypto-c checked out:

```sh
make -C tests test CRYPTO_BACKEND=tiny TINY_CRYPTO_DIR=/path/to/tiny-crypto-c
```

Run the suite under a sanitizer. AddressSanitizer and UndefinedBehaviorSanitizer
work with gcc or clang on any host; MemorySanitizer needs clang on Linux:

```sh
make -C tests test SANITIZE=address,undefined
make -C tests test CC=clang SANITIZE=memory
```

The test command builds and runs every unit suite and checks that each
reduced build profile compiles.

## Integrate the library

Add `src/` and `port/` to the compiler include path. Compile all files in
`src/`. Also compile one platform implementation and the crypto libraries.

For a complete procedure, see [Integration](docs/integration.md).

Use `port/dfc_port.h` to implement the platform services. Use
`port/dfc_bytebuf.h` to implement the response buffer. The `port/host/`
directory contains workstation implementations that you can use as examples.

Use `src/dfc_build_config.h` to select a feature profile. A reduced profile
rejects a known feature when the profile does not support that feature. It does
not silently discard data.

## License

DFC core is licensed under the GNU General Public License, version 2 or (at
your option) any later version (`GPL-2.0-or-later`). See [LICENSE](LICENSE).
