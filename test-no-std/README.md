# Testing Usability of `jwt-compact` Crate in `no_std` Env

This simple crate tests that `jwt-compact` builds and can be used
in a `no_std` environment (namely, an [ARM Cortex-M3] microcontroller).
It requires a nightly toolchain. The `release` profile must be used
to not overflow the available microcontroller flash memory.

Beside using a real microcontroller, the crate can be tested with [qemu].
In fact, Cargo is configured to run qemu when using `cargo run`.

[Cortex-M3]: https://en.wikipedia.org/wiki/ARM_Cortex-M#Cortex-M3
[qemu]: https://www.qemu.org/
