# Testing `jwt-compact` Crate in WASM

This simple crate tests that `jwt-compact` builds and can be used in WASM.

Note that `chrono` and `getrandom` crates need to be configured in [`Cargo.toml`](Cargo.toml)
in order to work with the WASM target:

```toml
[dependencies]
chrono = { version = "0.4.19", features = ["wasmbind"] }
getrandom = { version = "0.2", features = ["js"] }
```

## Usage

1. Install WASM target for Rust via `rustup`: `rustup target add wasm32-unknown-unknown`.
2. Install [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/).
3. Install [Node](https://nodejs.org/).
4. Switch to the directory with this README and run `wasm-pack build --target nodejs`.
5. Run the testing script: `node test.js`. 
