# Testing `jwt-compact` Crate in `no_std` Env

This simple crate tests that `jwt-compact` builds and can be used
in a `no_std` environment (namely, an [ARM Cortex-M3] microcontroller).
It requires a nightly toolchain. The `release` profile must be used
to not overflow the available microcontroller flash memory.

## Usage

Beside using a real microcontroller, the crate can be tested with [qemu].
In fact, Cargo is configured to run qemu when using `cargo run`.

1. Install a recent nightly Rust toolchain and the `thumbv7m-none-eabi` target
  for it.
2. Install qemu. In Linux, qemu is often included as a system package, so
  this step can be as simple as `sudo apt-get install qemu-system-arm`.
3. Compile and run the app on qemu using `cd $crate_dir && cargo run --release`,
  where `$crate_dir` is the directory containing this README.
  Switching to the crate directory is necessary to use the [Cargo config](.cargo/config.toml),
  which sets up necessary `rustc` flags and the qemu wrapper for `cargo run`.

By default, the binary only tests the `HS*` algorithms. You may run the binary
with `--features ed25519` or `--features rsa` in order to test additional algorithms.

[ARM Cortex-M3]: https://en.wikipedia.org/wiki/ARM_Cortex-M#Cortex-M3
[qemu]: https://www.qemu.org/
