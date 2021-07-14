# Compact JWT implementation in Rust

[![Build Status](https://github.com/slowli/jwt-compact/workflows/Rust/badge.svg?branch=master)](https://github.com/slowli/jwt-compact/actions)
[![License: Apache-2.0](https://img.shields.io/github/license/slowli/jwt-compact.svg)](https://github.com/slowli/jwt-compact/blob/master/LICENSE)
![rust 1.47.0+ required](https://img.shields.io/badge/rust-1.47.0+-blue.svg?label=Required%20Rust)
[![dependency status](https://deps.rs/repo/github/slowli/jwt-compact/status.svg)](https://deps.rs/repo/github/slowli/jwt-compact)

**Documentation:** [![Docs.rs](https://docs.rs/jwt-compact/badge.svg)](https://docs.rs/jwt-compact/)
[![crate docs (master)](https://img.shields.io/badge/master-yellow.svg?label=docs)](https://slowli.github.io/jwt-compact/jwt_compact/)

Minimalistic [JSON web token (JWT)][JWT] implementation with focus on type safety
and secure cryptographic primitives.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
jwt-compact = "0.4.0"
```

See the crate docs for the examples of usage.

## Features

- Algorithm-specific signing and verifying keys (i.e., type safety).
- Key strength requirements from [RFC 7518] are expressed with wrapper types.
- Easy to extend to support new signing algorithms.
- The crate supports more compact [CBOR] encoding of the claims.
- Basic [JWK] functionality for key conversion from human-readable formats (JSON / YAML / TOML)
  and computing [key thumbprints].
- `HS256`, `HS384` and `HS512` algorithms are implemented via pure Rust [`sha2`] crate.
- The crate supports `EdDSA` algorithm with the Ed25519 elliptic curve, and `ES256K` algorithm
  with the secp256k1 elliptic curve. Both curves are widely used in crypto community
  and believed to be securely generated (there are some doubts about parameter generation
  for elliptic curves used in standard `ES*` algorithms).
- RSA algorithms (`RS*` and `PS*`) are supported via pure Rust [`rsa`] crate.
- Supports the `no_std` mode. [No-std support](e2e-tests/no-std) and [WASM compatibility](e2e-tests/wasm)
  are explicitly tested.

### Missing features

- Built-in checks of some claims (e.g., `iss` – the token issuer).
  This is intentional: depending on the use case, such claims can have different semantics
  and thus be represented by different datatypes (e.g., `iss` may be a human-readable short ID,
  a hex-encoded key digest, etc.)

## Alternatives

[`jsonwebtoken`], [`frank_jwt`] or [`biscuit`] may be viable alternatives depending on the use case
(e.g., none of them seems to implement `EdDSA` or `ES256K` algorithms).

## License

Licensed under the [Apache-2.0 license](LICENSE).

[JWT]: https://jwt.io/
[JWK]: https://tools.ietf.org/html/rfc7517.html
[key thumbprints]: https://tools.ietf.org/html/rfc7638
[CBOR]: https://tools.ietf.org/html/rfc7049
[RFC 7518]: https://www.rfc-editor.org/rfc/rfc7518.html
[`sha2`]: https://crates.io/crates/sha2
[`jsonwebtoken`]: https://crates.io/crates/jsonwebtoken
[`frank_jwt`]: https://crates.io/crates/frank_jwt
[`biscuit`]: https://crates.io/crates/biscuit
[`rsa`]: https://crates.io/crates/rsa
