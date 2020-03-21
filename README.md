# Compact JWT implementation in Rust

[![Travis Build Status](https://img.shields.io/travis/com/slowli/jwt-compact/master.svg?label=Linux%20Build)](https://travis-ci.com/slowli/jwt-compact) 
[![License: Apache-2.0](https://img.shields.io/github/license/slowli/jwt-compact.svg)](https://github.com/slowli/jwt-compact/blob/master/LICENSE)
![rust 1.41.0+ required](https://img.shields.io/badge/rust-1.41.0+-blue.svg?label=Required%20Rust)

**Documentation:** [![crate docs (master)](https://img.shields.io/badge/master-yellow.svg?label=docs)](https://slowli.github.io/jwt-compact/jwt_compact/) 

Minimalistic [JSON web token (JWT)][JWT] implementation with focus on type safety
and secure cryptographic primitives.

## Usage

See the crate docs for the examples of usage.

## Features

- Algorithm-specific signing and verifying keys (i.e., type safety).
- Easy to extend to support new signing algorithms.
- The crate supports more compact [CBOR] encoding of the claims.
- `HS256`, `HS384` and `HS512` algorithms are implemented via pure Rust [`sha2`] crate.
- The crate supports `EdDSA` algorithm with the Ed25519 elliptic curve, and `ES256K` algorithm
  with the secp256k1 elliptic curve. Both curves are widely used in crypto community
  and believed to be securely generated (there are some doubts about parameter generation
  for elliptic curves used in standard `ES*` algorithms).

### Missing features

- Support of RSA (`RS*` and `PS*`) and standard elliptic curve (`ES*`) algorithms.
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
[CBOR]: https://tools.ietf.org/html/rfc7049
[`sha2`]: https://crates.io/crates/sha2
[`jsonwebtoken`]: https://crates.io/crates/jsonwebtoken
[`frank_jwt`]: https://crates.io/crates/frank_jwt
[`biscuit`]: https://crates.io/crates/biscuit
