# Changelog

All notable changes to this project will be documented in this file.
The project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `new()` constructor for `HS*` keys that accepts any type implementing
  `AsRef<[u8]>`. This simplifies key loading.

- Add `new()` constructor for `UntrustedToken` that accepts any type implementing
  `AsRef<str>`. This simplifies token processing. 

### Changed

- Update dependencies.

- Rename `Header.signature_type` field to `token_type` to be more precise.

## 0.3.0 - 2020-11-30

No substantial changes compared to the 0.3.0-beta.2 release.

## 0.3.0-beta.2 - 2020-11-09

*(All changes are relative compared to [the 0.3.0-beta.1 release](#030-beta1---2020-11-08))*

### Changed

- Make `CreationError` non-exhaustive.

- Rename `StrongKey::inner()` method to `into_inner`.

### Fixed

- Fix `docs.rs` configuration.

## 0.3.0-beta.1 - 2020-11-08

### Added

- Add signature getters for untrusted and trusted tokens.

- Add the [`ed25519-compact`] backend for Ed25519-based tokens.

- Add `SigningKey` and `VerifyingKey` traits for generic access to cryptographic keys.

- Support RSA algorithms using pure-Rust [`rsa`] crate.

- Add `no_std` mode and check `no_std` / WASM compatibility via dedicated aux crates.
  Introduce two relevant crate features, `clock` and `std`.

- Add wrapper types for strong keys / JWT algorithms.

- Add details to some `ValidationError` variants.

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
