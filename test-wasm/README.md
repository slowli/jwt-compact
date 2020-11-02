# Testing Usability of `jwt-compact` Crate in WASM

This simple crate tests that `jwt-compact` builds and can be used in WASM.

Not all crypto backends supported by `jwt-compact` work in WASM:

- **`no_std`-compatible:** non-feature-gated `HS*` algorithms, `ed25519-dalek`
  and `ed25519-compact`. The last one has a small caveat:
  the imported `getrandom` crate may require a workaround (a custom RNG definition).

- **Require `std`, still WASM-compatible:** `rsa`.
  
- **Too thick:** `exonum-crypto` and `secp256k1`. Both link to C libraries
  (libsodium and libsecp256k1, respectively), and thus do not work with WASM.

## Compiling

1. Install WASM target for Rust via `rustup`: `rustup target add wasm32-unknown-unknown`.
2. Install [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/).
3. Install [Node](https://nodejs.org/).
4. Switch to the directory with this README and run `wasm-pack build --target nodejs`.
5. Run the testing script: `node test.js`. 
