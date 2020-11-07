# Changelog

All notable changes to this project will be documented in this file.
The project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add signature getters for untrusted and trusted tokens.

- Add the [`ed25519-compact`] backend for Ed25519-based tokens.

- Add `SigningKey` and `VerifyingKey` traits for generic access to cryptographic keys.

- Support RSA algorithms using pure-Rust [`rsa`] crate.

- Add `no_std` mode and check `no_std` / WASM compatibility via dedicated aux crates.
  Introduce two relevant crate features, `clock` and `std`.

### Changed

- Update dependencies.

- Update minimum supported Rust version due to dependencies.

- `es256k` feature should now be used for access to libsecp256k1 backend instead of
  `secp256k1`.

- Rework time-related token creation / validation logic. It is now possible to
  use a custom clock, which could be useful for testing or if there is no access
  to the system clock.

- Make `Header`, `Claims`, `TimeOptions`, and error types non-exhaustive.

## 0.2.0 - 2020-05-11

### Changed

- Update dependencies; replace `failure` error handling with `anyhow`.

## 0.1.0 - 2019-07-01

The initial release of `jwt-compact`.

[`ed25519-compact`]: https://crates.io/crates/ed25519-compact
[`rsa`]: https://crates.io/crates/rsa
