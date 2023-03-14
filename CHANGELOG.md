# Changelog

All notable changes to this project will be documented in this file.
The project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 0.7.0 - 2023-03-14

### Changed

- Update dependencies and bump minimum supported Rust version to 1.65.

## 0.6.0 - 2022-11-01

### Added

- Add ES256 implementation using pure-Rust [`p256`] crate.

### Changed

- Update dependencies, bump minimum supported Rust version to 1.60 and switch to 2021 Rust edition.

## 0.5.0 - 2021-12-29

*(All changes are relative compared to [the 0.5.0-beta.1 release](#050-beta1---2021-10-21))*

### Added

- Add `UntrustedToken::into_owned()` method to extend the token lifetime to static.
  This is useful if an `UntrustedToken` needs to be stashed / passed across threads.

- Add `UntrustedToken::deserialize_claims_unchecked()` to extract claims from a token
  without verification. As the name length implies, the method should only be used
  in exceptional cases.

- Implement `FromStr` and some standard traits (`Clone`, `Copy`, `PartialEq`) for `Rsa`.

- Introduce `AlgorithmSignature::LENGTH` constant for specifying the expected 
  signature length. The new `ValidationError::InvalidSignatureLen` variant provides
  more specific errors if the signature length is not as specified.

- Allow opting out from CBOR claims encoding by making `serde_cbor` dependency optional
  and using it as a crate feature. The relevant functionality (`AlgorithmExt::compact_token`,
  some error variants, etc.) is now gated behind this feature.
  This change is motivated by the fact that supporting verification of CBOR-encoded tokens 
  has non-zero cost for library users (e.g., in terms of code size or security analysis).

## 0.5.0-beta.1 - 2021-10-21

### Changed

- Update dependencies.

### Fixed

- Fix datetime overflow when validating the expiration claim.

- Fix `no_std` support for RSA-based JWS algorithms. As a part of the fix,
  to enable RSA, you should now use the `with_rsa` feature instead of `rsa`.

### Security

- Use constant-time base64 encoding / decoding from the [`base64ct`] crate.

## 0.4.0 - 2021-05-24

### Added

- Add `new()` constructor for `HS*` keys that accepts any type implementing
  `AsRef<[u8]>`. This simplifies key loading.

- Add `new()` constructor for `UntrustedToken` that accepts any type implementing
  `AsRef<str>`. This simplifies token processing.

- Add basic JSON Web Key (JWK) support. This allows (de)serializing keys from / into
  a uniform format and computing key thumbprints.

- Add ES256K implementation using pure-Rust [`k256`] crate.

### Changed

- Update dependencies.

- Rename `Header.signature_type` field to `token_type` to be more in line with JWT spec.

- Rename `Claims.expiration_date` to `expiration` to be more precise.

- Encapsulate `hmac` and `sha2` dependencies by introducing signature types 
  for `HS*` algorithms. The `digest` dependency is still public.

- `exonum-crypto` feature is no longer enabled by default.

- Change return type of `SigningKey::as_bytes()` to securely zeroize owned values on drop.

### Fixed

- Fix ES256K signature verification by accepting high-S signatures, which are still produced
  by some third-party implementations (e.g., OpenSSL).

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
[`k256`]: https://crates.io/crates/k256
[`p256`]: https://crates.io/crates/p256
[`base64ct`]: https://crates.io/crates/base64ct
