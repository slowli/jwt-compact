# Compact JWT implementation in Rust

[![Build Status](https://github.com/slowli/jwt-compact/workflows/CI/badge.svg?branch=master)](https://github.com/slowli/jwt-compact/actions)
[![License: Apache-2.0](https://img.shields.io/github/license/slowli/jwt-compact.svg)](https://github.com/slowli/jwt-compact/blob/master/LICENSE)
![rust 1.65+ required](https://img.shields.io/badge/rust-1.65+-blue.svg?label=Required%20Rust)
![no_std supported](https://img.shields.io/badge/no__std-tested-green.svg)

**Documentation:** [![Docs.rs](https://docs.rs/jwt-compact/badge.svg)](https://docs.rs/jwt-compact/)
[![crate docs (master)](https://img.shields.io/badge/master-yellow.svg?label=docs)](https://slowli.github.io/jwt-compact/jwt_compact/)

Minimalistic [JSON web token (JWT)][JWT] implementation with focus on type safety
and secure cryptographic primitives.

## Usage

Add this to your `Crate.toml`:

```toml
[dependencies]
jwt-compact = "0.8.0-beta.1"
```

## Basic token lifecycle

```rust
use chrono::{Duration, Utc};
use jwt_compact::{prelude::*, alg::{Hs256, Hs256Key}};
use serde::{Serialize, Deserialize};

/// Custom claims encoded in the token.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct CustomClaims {
    #[serde(rename = "sub")]
    subject: String,
    // other fields...
}

// Choose time-related options for token creation / validation.
let time_options = TimeOptions::default();
// Create a symmetric HMAC key, which will be used both to create and verify tokens.
let key = Hs256Key::new(b"super_secret_key_donut_steel");
// Create a token.
let header = Header::empty().with_key_id("my-key");
let claims = Claims::new(CustomClaims { subject: "alice".to_owned() })
    .set_duration_and_issuance(&time_options, Duration::hours(1))
    .set_not_before(Utc::now());
let token_string = Hs256.token(&header, &claims, &key)?;
println!("token: {token_string}");

// Parse the token.
let token = UntrustedToken::new(&token_string)?;
// Before verifying the token, we might find the key which has signed the token
// using the `Header.key_id` field.
assert_eq!(token.header().key_id.as_deref(), Some("my-key"));
// Validate the token integrity.
let token: Token<CustomClaims> = Hs256.validator(&key).validate(&token)?;
// Validate additional conditions.
token.claims()
    .validate_expiration(&time_options)?
    .validate_maturity(&time_options)?;
Ok::<_, anyhow::Error>(())
```

See the crate docs for more examples of usage.

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
- The `ES256` algorithm is supported via pure Rust [`p256`] crate.
- RSA algorithms (`RS*` and `PS*`) are supported via pure Rust [`rsa`] crate.
- The crate supports the `no_std` mode. [No-std support](e2e-tests/no-std) 
  and [WASM compatibility](e2e-tests/wasm) are explicitly tested.

### Missing features

- Built-in checks of some claims (e.g., `iss` – the token issuer).
  This is intentional: depending on the use case, such claims can have different semantics
  and thus be represented by different datatypes (e.g., `iss` may be a human-readable short ID,
  a hex-encoded key digest, etc.)
- `ES384` and `ES512` algorithms.

## Alternatives

[`jsonwebtoken`], [`frank_jwt`] or [`biscuit`] may be viable alternatives depending on the use case
(e.g., none of them seems to implement `EdDSA` or `ES256K` algorithms).

## See also

- [justwebtoken.io](https://justwebtoken.io/) – educational mini-website that uses this library
  packaged in a WASM module.

## License

Licensed under the [Apache-2.0 license](LICENSE).

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `jwt-compact` by you, as defined in the Apache-2.0 license,
shall be licensed as above, without any additional terms or conditions.

[JWT]: https://jwt.io/
[JWK]: https://tools.ietf.org/html/rfc7517.html
[key thumbprints]: https://tools.ietf.org/html/rfc7638
[CBOR]: https://tools.ietf.org/html/rfc7049
[RFC 7518]: https://www.rfc-editor.org/rfc/rfc7518.html
[`sha2`]: https://crates.io/crates/sha2
[`jsonwebtoken`]: https://crates.io/crates/jsonwebtoken
[`frank_jwt`]: https://crates.io/crates/frank_jwt
[`biscuit`]: https://crates.io/crates/biscuit
[`p256`]: https://crates.io/crates/p256
[`rsa`]: https://crates.io/crates/rsa
