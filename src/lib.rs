//! Minimalistic [JSON web token (JWT)][JWT] implementation with focus on type safety
//! and secure cryptographic primitives.
//!
//! # Design choices
//!
//! - JWT signature algorithms (i.e., cryptographic algorithms providing JWT integrity)
//!   are expressed via the [`Algorithm`] trait, which uses fully typed keys and signatures.
//! - [JWT header] is represented by the [`Header`] struct. Notably, `Header` does not
//!   expose the [`alg` field].
//!   Instead, `alg` is filled automatically during token creation, and is compared to the
//!   expected value during verification. (If you do not know the JWT signature algorithm during
//!   verification, you're doing something wrong.) This eliminates the possibility
//!   of [algorithm switching attacks][switching].
//!
//! # Additional features
//!
//! - The crate supports more compact [CBOR] encoding of the claims. This feature is enabled
//!   via the [`serde_cbor` feature](#cbor-support).
//! - The crate supports `EdDSA` algorithm with the Ed25519 elliptic curve, and `ES256K` algorithm
//!   with the secp256k1 elliptic curve.
//! - Supports basic [JSON Web Key](https://tools.ietf.org/html/rfc7517.html) functionality,
//!   e.g., for converting keys to / from JSON or computing
//!   [a key thumbprint](https://tools.ietf.org/html/rfc7638).
//!
//! ## Supported algorithms
//!
//! | Algorithm(s) | Feature | Description |
//! |--------------|---------|-------------|
//! | `HS256`, `HS384`, `HS512` | - | Uses pure Rust [`sha2`] crate |
//! | `EdDSA` (Ed25519) | [`exonum-crypto`] | [`libsodium`] binding |
//! | `EdDSA` (Ed25519) | [`ed25519-dalek`] | Pure Rust implementation |
//! | `EdDSA` (Ed25519) | [`ed25519-compact`] | Compact pure Rust implementation, WASM-compatible |
//! | `ES256K` | `es256k` | [Rust binding][`secp256k1`] for [`libsecp256k1`] |
//! | `ES256K` | [`k256`] | Pure Rust implementation |
//! | `ES256`  | [`p256`] | Pure Rust implementation |
//! | `RS*`, `PS*` (RSA) | `rsa` | Uses pure Rust [`rsa`] crate with blinding |
//!
//! `EdDSA` and `ES256K` algorithms are somewhat less frequently supported by JWT implementations
//! than others since they are recent additions to the JSON Web Algorithms (JWA) suit.
//! They both work with elliptic curves
//! (Curve25519 and secp256k1; both are widely used in crypto community and believed to be
//! securely generated). These algs have 128-bit security, making them an alternative
//! to `ES256`.
//!
//! RSA support requires a system-wide RNG retrieved via the [`getrandom`] crate.
//! In case of a compilation failure in the `getrandom` crate, you may want
//! to include it as a direct dependency and specify one of its features
//! to assist `getrandom` with choosing an appropriate RNG implementation; consult `getrandom` docs
//! for more details. See also WASM and bare-metal E2E tests included
//! in the [source code repository] of this crate.
//!
//! ## CBOR support
//!
//! If the `serde_cbor` crate feature is enabled (and it is enabled by default), token claims can
//! be encoded using [CBOR] with the [`AlgorithmExt::compact_token()`] method.
//! The compactly encoded JWTs have the [`cty` field] (content type) in their header
//! set to `"CBOR"`. Tokens with such encoding can be verified in the same way as ordinary tokens;
//! see [examples below](#examples).
//!
//! If the `serde_cbor` feature is disabled, `AlgorithmExt::compact_token()` is not available.
//! Verifying CBOR-encoded tokens in this case is not supported either;
//! a [`ParseError::UnsupportedContentType`] will be returned when creating an [`UntrustedToken`]
//! from the token string.
//!
//! # `no_std` support
//!
//! The crate supports a `no_std` compilation mode. This is controlled by two features:
//! `clock` and `std`; both are on by default.
//!
//! - The `clock` feature enables getting the current time using `Utc::now()` from [`chrono`].
//!   Without it, some [`TimeOptions`] constructors, such as the `Default` impl,
//!   are not available. It is still possible to create `TimeOptions` with an explicitly specified
//!   clock function, or to set / verify time-related [`Claims`] fields manually.
//! - The `std` feature is propagated to the core dependencies and enables `std`-specific
//!   functionality (such as error types implementing the standard `Error` trait).
//!
//! Some `alloc` types are still used in the `no_std` mode, such as `String`, `Vec` and `Cow`.
//!
//! Note that not all crypto backends are `no_std`-compatible.
//!
//! [JWT]: https://jwt.io/
//! [switching]: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
//! [JWT header]: https://tools.ietf.org/html/rfc7519#section-5
//! [`alg` field]: https://tools.ietf.org/html/rfc7515#section-4.1.1
//! [`cty` field]: https://tools.ietf.org/html/rfc7515#section-4.1.10
//! [CBOR]: https://tools.ietf.org/html/rfc7049
//! [`sha2`]: https://docs.rs/sha2/
//! [`libsodium`]: https://download.libsodium.org/doc/
//! [`exonum-crypto`]: https://docs.rs/exonum-crypto/
//! [`ed25519-dalek`]: https://doc.dalek.rs/ed25519_dalek/
//! [`ed25519-compact`]: https://crates.io/crates/ed25519-compact
//! [`secp256k1`]: https://docs.rs/secp256k1/
//! [`libsecp256k1`]: https://github.com/bitcoin-core/secp256k1
//! [`k256`]: https://docs.rs/k256/
//! [`p256`]: https://docs.rs/p256/
//! [`rsa`]: https://docs.rs/rsa/
//! [`chrono`]: https://docs.rs/chrono/
//! [`getrandom`]: https://docs.rs/getrandom/
//! [source code repository]: https://github.com/slowli/jwt-compact
//!
//! # Examples
//!
//! Basic JWT lifecycle:
//!
//! ```
//! use chrono::{Duration, Utc};
//! use jwt_compact::{prelude::*, alg::{Hs256, Hs256Key}};
//! use serde::{Serialize, Deserialize};
//!
//! /// Custom claims encoded in the token.
//! #[derive(Debug, PartialEq, Serialize, Deserialize)]
//! struct CustomClaims {
//!     /// `sub` is a standard claim which denotes claim subject:
//!     /// https://tools.ietf.org/html/rfc7519#section-4.1.2
//!     #[serde(rename = "sub")]
//!     subject: String,
//! }
//!
//! # fn main() -> anyhow::Result<()> {
//! // Choose time-related options for token creation / validation.
//! let time_options = TimeOptions::default();
//! // Create a symmetric HMAC key, which will be used both to create and verify tokens.
//! let key = Hs256Key::new(b"super_secret_key_donut_steel");
//! // Create a token.
//! let header = Header::empty().with_key_id("my-key");
//! let claims = Claims::new(CustomClaims { subject: "alice".to_owned() })
//!     .set_duration_and_issuance(&time_options, Duration::days(7))
//!     .set_not_before(Utc::now() - Duration::hours(1));
//! let token_string = Hs256.token(&header, &claims, &key)?;
//! println!("token: {token_string}");
//!
//! // Parse the token.
//! let token = UntrustedToken::new(&token_string)?;
//! // Before verifying the token, we might find the key which has signed the token
//! // using the `Header.key_id` field.
//! assert_eq!(token.header().key_id, Some("my-key".to_owned()));
//! // Validate the token integrity.
//! let token: Token<CustomClaims> = Hs256.validator(&key).validate(&token)?;
//! // Validate additional conditions.
//! token.claims()
//!     .validate_expiration(&time_options)?
//!     .validate_maturity(&time_options)?;
//! // Now, we can extract information from the token (e.g., its subject).
//! let subject = &token.claims().custom.subject;
//! assert_eq!(subject, "alice");
//! # Ok(())
//! # } // end main()
//! ```
//!
//! ## Compact JWT
//!
//! ```
//! # use chrono::Duration;
//! # use hex_buffer_serde::{Hex as _, HexForm};
//! # use jwt_compact::{prelude::*, alg::{Hs256, Hs256Key}};
//! # use serde::{Serialize, Deserialize};
//! /// Custom claims encoded in the token.
//! #[derive(Debug, PartialEq, Serialize, Deserialize)]
//! struct CustomClaims {
//!     /// `sub` is a standard claim which denotes claim subject:
//!     ///     https://tools.ietf.org/html/rfc7519#section-4.1.2
//!     /// The custom serializer we use allows to efficiently
//!     /// encode the subject in CBOR.
//!     #[serde(rename = "sub", with = "HexForm")]
//!     subject: [u8; 32],
//! }
//!
//! # fn main() -> anyhow::Result<()> {
//! let time_options = TimeOptions::default();
//! let key = Hs256Key::new(b"super_secret_key_donut_steel");
//! let claims = Claims::new(CustomClaims { subject: [111; 32] })
//!     .set_duration_and_issuance(&time_options, Duration::days(7));
//! let token = Hs256.token(&Header::empty(), &claims, &key)?;
//! println!("token: {token}");
//! let compact_token = Hs256.compact_token(&Header::empty(), &claims, &key)?;
//! println!("compact token: {compact_token}");
//! // The compact token should be ~40 chars shorter.
//!
//! // Parse the compact token.
//! let token = UntrustedToken::new(&compact_token)?;
//! let token: Token<CustomClaims> = Hs256.validator(&key).validate(&token)?;
//! token.claims().validate_expiration(&time_options)?;
//! // Now, we can extract information from the token (e.g., its subject).
//! assert_eq!(token.claims().custom.subject, [111; 32]);
//! # Ok(())
//! # } // end main()
//! ```
//!
//! ## JWT with custom header fields
//!
//! ```
//! # use chrono::Duration;
//! # use jwt_compact::{prelude::*, alg::{Hs256, Hs256Key}};
//! # use serde::{Deserialize, Serialize};
//! #[derive(Debug, PartialEq, Serialize, Deserialize)]
//! struct CustomClaims { subject: [u8; 32] }
//!
//! /// Additional fields in the token header.
//! #[derive(Debug, Clone, Serialize, Deserialize)]
//! struct HeaderExtensions { custom: bool }
//!
//! # fn main() -> anyhow::Result<()> {
//! let time_options = TimeOptions::default();
//! let key = Hs256Key::new(b"super_secret_key_donut_steel");
//! let claims = Claims::new(CustomClaims { subject: [111; 32] })
//!     .set_duration_and_issuance(&time_options, Duration::days(7));
//! let header = Header::new(HeaderExtensions { custom: true })
//!     .with_key_id("my-key");
//! let token = Hs256.token(&header, &claims, &key)?;
//! print!("token: {token}");
//!
//! // Parse the token.
//! let token: UntrustedToken<HeaderExtensions> =
//!     token.as_str().try_into()?;
//! // Token header (incl. custom fields) can be accessed right away.
//! assert_eq!(token.header().key_id.as_deref(), Some("my-key"));
//! assert!(token.header().other_fields.custom);
//! // Token can then be validated as usual.
//! let token = Hs256.validator::<CustomClaims>(&key).validate(&token)?;
//! assert_eq!(token.claims().custom.subject, [111; 32]);
//! # Ok(())
//! # } // end main()
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
// Documentation settings.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/jwt-compact/0.7.0")]
// Linter settings.
#![warn(missing_debug_implementations, missing_docs, bare_trait_objects)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::module_name_repetitions
)]

pub mod alg;
mod claims;
mod error;
pub mod jwk;
mod token;
mod traits;

// Polyfill for `alloc` types.
mod alloc {
    #[cfg(not(feature = "std"))]
    extern crate alloc as std;

    pub use std::{
        borrow::{Cow, ToOwned},
        boxed::Box,
        string::{String, ToString},
        vec::Vec,
    };
}

/// Prelude to neatly import all necessary stuff from the crate.
pub mod prelude {
    #[doc(no_inline)]
    pub use crate::{AlgorithmExt as _, Claims, Header, TimeOptions, Token, UntrustedToken};
}

pub use crate::{
    claims::{Claims, Empty, TimeOptions},
    error::{Claim, CreationError, ParseError, ValidationError},
    token::{Header, SignedToken, Thumbprint, Token, UntrustedToken},
    traits::{Algorithm, AlgorithmExt, AlgorithmSignature, Renamed, Validator},
};

#[cfg(doctest)]
doc_comment::doctest!("../README.md");
