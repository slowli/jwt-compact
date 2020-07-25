# Changelog

All notable changes to this project will be documented in this file.
The project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add signature getters for untrusted and trusted tokens.

- Add the [`ed25519-compact`] backend for Ed25519-based tokens.

### Changed

- Update dependencies.

- Update minimum supported Rust version due to dependencies.

## 0.2.0 - 2020-05-11

### Changed

- Update dependencies; replace `failure` error handling with `anyhow`.

## 0.1.0 - 2019-07-01

The initial release of `jwt-compact`.

[`ed25519-compact`]: https://crates.io/crates/ed25519-compact
