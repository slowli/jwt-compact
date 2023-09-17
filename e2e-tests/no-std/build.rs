//! Copies `memory.x` declaration to where the linker is guaranteed to see it.
//! Taken from https://github.com/rust-embedded/cortex-m-quickstart with minor changes.

use std::{env, fs, path::PathBuf};

fn main() {
    // Put `memory.x` in our output directory and ensure it's on the linker search path.
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(out.join("memory.x"), include_bytes!("memory.x"))
        .expect("Failed copying `memory.x` declaration");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");

    // `--nmagic` is required if memory section addresses are not aligned to 0x10000,
    // for example the FLASH and RAM sections in your `memory.x`.
    // See https://github.com/rust-embedded/cortex-m-quickstart/pull/95
    println!("cargo:rustc-link-arg=--nmagic");
    // Set the linker script to the one provided by cortex-m-rt.
    println!("cargo:rustc-link-arg=-Tlink.x");
}
