# Testing `jwt-compact` in Different Environments

This directory contains the auxiliary crates checking that `jwt-compacts`
actually works in resource-constrained environments.

- [`no-std`](no-std) uses `jwt-compact` within a bare-metal environment
  (ARM Cortex-M3 microcontroller).
- [`wasm`](wasm) uses `jwt-compact` within a WASM module targeting JS execution
  environment.
