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
//! - The crate supports more compact [CBOR] encoding of the claims. The compactly encoded JWTs
//!   have [`cty` field] (content type) in their header set to `"CBOR"`.
//! - The crate supports `EdDSA` algorithm with the Ed25519 elliptic curve, and `ES256K` algorithm
//!   with the secp256k1 elliptic curve.
//!
//! ## Supported algorithms
//!
//! | Algorithm(s) | Feature | Description |
//! |--------------|---------|-------------|
//! | `HS256`, `HS384`, `HS512` | - | Uses pure Rust [`sha2`] crate |
//! | `EdDSA` (Ed25519) | [`exonum-crypto`] | [`libsodium`] binding. Enabled by default |
//! | `EdDSA` (Ed25519) | [`ed25519-dalek`] | Pure Rust implementation |
//! | `EdDSA` (Ed25519) | [`ed25519-compact`] | Compact pure Rust implementation, WASM-compatible |
//! | `ES256K` | `es256k` | [Rust binding][`secp256k1`] for [`libsecp256k1`] |
//! | `RS*`, `PS*` (RSA) | [`rsa`] | Uses pure Rust [`rsa`] crate with blinding |
//!
//! `EdDSA` and `ES256K` algorithms are non-standard. They both work with elliptic curves
//! (Curve25519 and secp256k1; both are widely used in crypto community and believed to be
//! securely generated). These algs have 128-bit security, making them an alternative
//! to `ES256`.
//!
//! # `no_std` support
//!
//! The crate supports a `no_std` compilation mode. This is controlled by two features:
//! `clock` and `std`; both are on by default.
//!
//! - The `clock` feature enables getting the current time using `Utc::now()` from [`chrono`].
//!   Without it, some [`TimeOptions`] constructors, such as the `Default` impl,
//!   are not available. It is still possible to create `TimeOptions` with an excplicitly specified
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
//! [`rsa`]: https://docs.rs/rsa/
//! [`chrono`]: https://docs.rs/chrono/
//!
//! # Examples
//!
//! Basic JWT lifecycle:
//!
//! ```
//! use chrono::{Duration, Utc};
//! use jwt_compact::{prelude::*, alg::{Hs256, Hs256Key}};
//! use serde::{Serialize, Deserialize};
//! use core::convert::TryFrom;
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
//! let key = Hs256Key::from(b"super_secret_key_donut_steel" as &[_]);
//! // Create a token.
//! let header = Header::default().with_key_id("my-key");
//! let claims = Claims::new(CustomClaims { subject: "alice".to_owned() })
//!     .set_duration_and_issuance(&time_options, Duration::days(7))
//!     .set_not_before(Utc::now() - Duration::hours(1));
//! let token_string = Hs256.token(header, &claims, &key)?;
//! println!("token: {}", token_string);
//!
//! // Parse the token.
//! let token = UntrustedToken::try_from(token_string.as_str())?;
//! // Before verifying the token, we might find the key which has signed the token
//! // using the `Header.key_id` field.
//! assert_eq!(token.header().key_id, Some("my-key".to_owned()));
//! // Validate the token integrity.
//! let token: Token<CustomClaims> = Hs256.validate_integrity(&token, &key)?;
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
//! # use core::convert::TryFrom;
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
//! let key = Hs256Key::from(b"super_secret_key_donut_steel" as &[_]);
//! let claims = Claims::new(CustomClaims { subject: [111; 32] })
//!     .set_duration_and_issuance(&time_options, Duration::days(7));
//! let token = Hs256.token(Header::default(), &claims, &key)?;
//! println!("token: {}", token);
//! let compact_token = Hs256.compact_token(Header::default(), &claims, &key)?;
//! println!("compact token: {}", compact_token);
//! // The compact token should be ~40 chars shorter.
//!
//! // Parse the compact token.
//! let token = UntrustedToken::try_from(compact_token.as_str())?;
//! let token: Token<CustomClaims> = Hs256.validate_integrity(&token, &key)?;
//! token.claims().validate_expiration(&time_options)?;
//! // Now, we can extract information from the token (e.g., its subject).
//! assert_eq!(token.claims().custom.subject, [111; 32]);
//! # Ok(())
//! # } // end main()
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/jwt-compact/0.3.0-beta.1")]
#![warn(missing_debug_implementations, missing_docs, bare_trait_objects)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::module_name_repetitions
)]

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};

use core::{convert::TryFrom, fmt};

pub mod alg;
mod claims;
mod error;

// Polyfill for `alloc` types.
mod alloc {
    #[cfg(not(feature = "std"))]
    extern crate alloc;

    #[cfg(not(feature = "std"))]
    pub use alloc::{
        borrow::{Cow, ToOwned},
        boxed::Box,
        string::String,
        vec::Vec,
    };
    #[cfg(feature = "std")]
    pub use std::{
        borrow::{Cow, ToOwned},
        boxed::Box,
        string::String,
        vec::Vec,
    };
}

/// Prelude to neatly import all necessary stuff from the crate.
pub mod prelude {
    pub use crate::{AlgorithmExt as _, Claims, Header, TimeOptions, Token, UntrustedToken};
}

pub use crate::{
    claims::{Claims, Empty, TimeOptions},
    error::{Claim, CreationError, ParseError, ValidationError},
};

use crate::alloc::{Cow, String, ToOwned, Vec};

/// Maximum "reasonable" signature size in bytes.
const SIGNATURE_SIZE: usize = 128;

/// Signature for a certain JWT signing `Algorithm`.
///
/// We require that signature can be restored from a byte slice,
/// and can be represented as a byte slice.
pub trait AlgorithmSignature: Sized {
    /// Attempts to restore a signature from a byte slice. This method may fail
    /// if the slice is malformed (e.g., has a wrong length).
    fn try_from_slice(slice: &[u8]) -> anyhow::Result<Self>;

    /// Represents this signature as bytes.
    fn as_bytes(&self) -> Cow<'_, [u8]>;
}

/// JWT signing algorithm.
pub trait Algorithm {
    /// Key used when issuing new tokens.
    type SigningKey;
    /// Key used when verifying tokens. May coincide with `SigningKey` for symmetric
    /// algorithms (e.g., `HS*`).
    type VerifyingKey;
    /// Signature produced by the algorithm.
    type Signature: AlgorithmSignature;

    /// Returns the name of this algorithm, as mentioned in the `alg` field of the JWT header.
    fn name(&self) -> Cow<'static, str>;

    /// Signs a `message` with the `signing_key`.
    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature;

    /// Verifies the `message` against the `signature` and `verifying_key`.
    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool;
}

/// Algorithm that uses a custom name when creating and validating tokens.
///
/// # Examples
///
/// ```
/// use jwt_compact::{alg::{Hs256, Hs256Key}, prelude::*, Empty, Renamed};
/// # use core::convert::TryFrom;
///
/// # fn main() -> anyhow::Result<()> {
/// let alg = Renamed::new(Hs256, "HS2");
/// let key = Hs256Key::from(b"super_secret_key_donut_steel" as &[_]);
/// let token_string = alg.token(Header::default(), &Claims::empty(), &key)?;
///
/// let token = UntrustedToken::try_from(token_string.as_str())?;
/// assert_eq!(token.algorithm(), "HS2");
/// // Note that the created token cannot be verified against the original algorithm
/// // since the algorithm name recorded in the token header doesn't match.
/// assert!(Hs256.validate_integrity::<Empty>(&token, &key).is_err());
///
/// // ...but the modified alg is working as expected.
/// assert!(alg.validate_integrity::<Empty>(&token, &key).is_ok());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Renamed<A> {
    inner: A,
    name: &'static str,
}

impl<A: Algorithm> Renamed<A> {
    /// Creates a renamed algorithm.
    pub fn new(algorithm: A, new_name: &'static str) -> Self {
        Self {
            inner: algorithm,
            name: new_name,
        }
    }
}

impl<A: Algorithm> Algorithm for Renamed<A> {
    type SigningKey = A::SigningKey;
    type VerifyingKey = A::VerifyingKey;
    type Signature = A::Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed(self.name)
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        self.inner.sign(signing_key, message)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        self.inner
            .verify_signature(signature, verifying_key, message)
    }
}

/// Automatically implemented extensions of the `Algorithm` trait.
pub trait AlgorithmExt: Algorithm {
    /// Creates a new token and serializes it to string.
    fn token<T>(
        &self,
        header: Header,
        claims: &Claims<T>,
        signing_key: &Self::SigningKey,
    ) -> Result<String, CreationError>
    where
        T: Serialize;

    /// Creates a new token with CBOR-encoded claims and serializes it to string.
    fn compact_token<T>(
        &self,
        header: Header,
        claims: &Claims<T>,
        signing_key: &Self::SigningKey,
    ) -> Result<String, CreationError>
    where
        T: Serialize;

    /// Validates the token integrity against the provided `verifying_key`.
    fn validate_integrity<T>(
        &self,
        token: &UntrustedToken<'_>,
        verifying_key: &Self::VerifyingKey,
    ) -> Result<Token<T>, ValidationError>
    where
        T: DeserializeOwned;

    /// Validates the token integrity against the provided `verifying_key`.
    ///
    /// Unlike [`validate_integrity`](#tymethod.validate_integrity), this method retains more
    /// information about the original token, in particular, its signature.
    fn validate_for_signed_token<T>(
        &self,
        token: &UntrustedToken<'_>,
        verifying_key: &Self::VerifyingKey,
    ) -> Result<SignedToken<Self, T>, ValidationError>
    where
        T: DeserializeOwned;
}

impl<A: Algorithm> AlgorithmExt for A {
    fn token<T>(
        &self,
        header: Header,
        claims: &Claims<T>,
        signing_key: &Self::SigningKey,
    ) -> Result<String, CreationError>
    where
        T: Serialize,
    {
        let complete_header = CompleteHeader {
            algorithm: self.name(),
            content_type: None,
            inner: header,
        };
        let header = serde_json::to_string(&complete_header).map_err(CreationError::Header)?;
        let mut buffer = base64::encode_config(&header, base64::URL_SAFE_NO_PAD);

        buffer.push('.');
        let claims = serde_json::to_string(claims).map_err(CreationError::Claims)?;
        base64::encode_config_buf(&claims, base64::URL_SAFE_NO_PAD, &mut buffer);

        let signature = self.sign(signing_key, buffer.as_bytes());
        buffer.push('.');
        base64::encode_config_buf(
            signature.as_bytes().as_ref(),
            base64::URL_SAFE_NO_PAD,
            &mut buffer,
        );

        Ok(buffer)
    }

    fn compact_token<T>(
        &self,
        header: Header,
        claims: &Claims<T>,
        signing_key: &Self::SigningKey,
    ) -> Result<String, CreationError>
    where
        T: Serialize,
    {
        let complete_header = CompleteHeader {
            algorithm: self.name(),
            content_type: Some("CBOR".to_owned()),
            inner: header,
        };
        let header = serde_json::to_string(&complete_header).map_err(CreationError::Header)?;
        let mut buffer = base64::encode_config(&header, base64::URL_SAFE_NO_PAD);

        buffer.push('.');
        let claims = serde_cbor::to_vec(claims).map_err(CreationError::CborClaims)?;
        base64::encode_config_buf(&claims, base64::URL_SAFE_NO_PAD, &mut buffer);

        let signature = self.sign(signing_key, buffer.as_bytes());
        buffer.push('.');
        base64::encode_config_buf(
            signature.as_bytes().as_ref(),
            base64::URL_SAFE_NO_PAD,
            &mut buffer,
        );

        Ok(buffer)
    }

    fn validate_integrity<T>(
        &self,
        token: &UntrustedToken<'_>,
        verifying_key: &Self::VerifyingKey,
    ) -> Result<Token<T>, ValidationError>
    where
        T: DeserializeOwned,
    {
        self.validate_for_signed_token(token, verifying_key)
            .map(|wrapper| wrapper.token)
    }

    fn validate_for_signed_token<T>(
        &self,
        token: &UntrustedToken<'_>,
        verifying_key: &Self::VerifyingKey,
    ) -> Result<SignedToken<Self, T>, ValidationError>
    where
        T: DeserializeOwned,
    {
        let expected_alg = self.name();
        if expected_alg != token.algorithm {
            return Err(ValidationError::AlgorithmMismatch {
                expected: expected_alg.into_owned(),
                actual: token.algorithm.to_owned(),
            });
        }

        let signature = Self::Signature::try_from_slice(&token.signature[..])
            .map_err(ValidationError::MalformedSignature)?;
        // We assume that parsing claims is less computationally demanding than
        // validating a signature.
        let claims: Claims<T> = match token.content_type {
            ContentType::Json => serde_json::from_slice(&token.serialized_claims)
                .map_err(ValidationError::MalformedClaims)?,
            ContentType::Cbor => serde_cbor::from_slice(&token.serialized_claims)
                .map_err(ValidationError::MalformedCborClaims)?,
        };
        if !self.verify_signature(&signature, verifying_key, token.signed_data) {
            return Err(ValidationError::InvalidSignature);
        }

        Ok(SignedToken {
            signature,
            token: Token {
                header: token.header.clone(),
                claims,
            },
        })
    }
}

/// JWT header.
///
/// See [RFC 7515](https://tools.ietf.org/html/rfc7515#section-4.1) for the description
/// of the fields. The purpose of all fields except `signature_type` is to determine
/// the verifying key. Since these values will be provided by the adversary in the case of
/// an attack, they require additional verification (e.g., a provided certificate might
/// be checked against the list of "acceptable" certificate authorities).
///
/// A `Header` can be created using `Default` implementation, which does not set any fields.
/// For added fluency, you may use `with_*` methods:
///
/// ```
/// # use jwt_compact::Header;
/// let header = Header::default()
///     .with_key_id("my-key-id")
///     .with_certificate_thumbprint("thumbprint");
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Header {
    /// URL of the JSON Web Key Set containing the key that has signed the token.
    /// This field is renamed to `jku` for serialization.
    #[serde(rename = "jku", default, skip_serializing_if = "Option::is_none")]
    pub key_set_url: Option<String>,

    /// Identifier of the key that has signed the token. This field is renamed to `kid`
    /// for serialization.
    #[serde(rename = "kid", default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// URL of the X.509 certificate for the signing key. This field is renamed to `x5u`
    /// for serialization.
    #[serde(rename = "x5u", default, skip_serializing_if = "Option::is_none")]
    pub certificate_url: Option<String>,

    /// Thumbprint of the X.509 certificate for the signing key. This field is renamed to `x5t`
    /// for serialization.
    #[serde(rename = "x5t", default, skip_serializing_if = "Option::is_none")]
    pub certificate_thumbprint: Option<String>,

    /// Application-specific signature type. This field is renamed to `typ` for serialization.
    #[serde(rename = "typ", default, skip_serializing_if = "Option::is_none")]
    pub signature_type: Option<String>,
}

impl Header {
    /// Sets the `key_set_url` field for this instance.
    pub fn with_key_set_url(mut self, key_set_url: impl Into<String>) -> Self {
        self.key_set_url = Some(key_set_url.into());
        self
    }

    /// Sets the `key_id` field for this instance.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Sets the `certificate_url` field for this instance.
    pub fn with_certificate_url(mut self, certificate_url: impl Into<String>) -> Self {
        self.certificate_url = Some(certificate_url.into());
        self
    }

    /// Sets the `certificate_thumbprint` field for this instance.
    pub fn with_certificate_thumbprint(
        mut self,
        certificate_thumbprint: impl Into<String>,
    ) -> Self {
        self.certificate_thumbprint = Some(certificate_thumbprint.into());
        self
    }

    /// Sets the `signature_type` field for this instance.
    pub fn with_signature_type(mut self, signature_type: impl Into<String>) -> Self {
        self.signature_type = Some(signature_type.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompleteHeader<'a> {
    #[serde(rename = "alg")]
    algorithm: Cow<'a, str>,

    #[serde(rename = "cty", default, skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,

    #[serde(flatten)]
    inner: Header,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentType {
    Json,
    Cbor,
}

/// Parsed, but unvalidated token.
#[derive(Debug, Clone)]
pub struct UntrustedToken<'a> {
    signed_data: &'a [u8],
    header: Header,
    algorithm: String,
    content_type: ContentType,
    serialized_claims: Vec<u8>,
    signature: SmallVec<[u8; SIGNATURE_SIZE]>,
}

/// Token with validated integrity.
///
/// Claims encoded in the token can be verified by invoking [`Claims`] methods
/// via [`Self::claims()`].
#[derive(Debug, Clone)]
pub struct Token<T> {
    header: Header,
    claims: Claims<T>,
}

impl<T> Token<T> {
    /// Gets token header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Gets token claims.
    pub fn claims(&self) -> &Claims<T> {
        &self.claims
    }
}

/// `Token` together with the validated token signature.
///
/// # Examples
///
/// ```
/// # use jwt_compact::{alg::{Hs256, Hs256Key}, prelude::*};
/// # use chrono::Duration;
/// # use hmac::crypto_mac::generic_array::{typenum, GenericArray};
/// # use serde::{Deserialize, Serialize};
/// # use core::convert::TryFrom;
/// #
/// #[derive(Serialize, Deserialize)]
/// struct MyClaims {
///     // Custom claims in the token...
/// }
///
/// # fn main() -> anyhow::Result<()> {
/// # let key = Hs256Key::from(b"super_secret_key" as &[_]);
/// # let claims = Claims::new(MyClaims {})
/// #     .set_duration_and_issuance(&TimeOptions::default(), Duration::days(7));
/// let token_string: String = // token from an external source
/// #   Hs256.token(Header::default(), &claims, &key)?;
/// let token = UntrustedToken::try_from(token_string.as_str())?;
/// let signed = Hs256.validate_for_signed_token::<MyClaims>(&token, &key)?;
///
/// // `signature` is strongly typed.
/// let array: GenericArray<u8, typenum::U32> = signed.signature.into_bytes();
/// // Token itself is available via `token` field.
/// let claims = signed.token.claims();
/// claims.validate_expiration(&TimeOptions::default())?;
/// // Process the claims...
/// # Ok(())
/// # } // end main()
/// ```
#[non_exhaustive]
pub struct SignedToken<A: Algorithm + ?Sized, T> {
    /// Token signature.
    pub signature: A::Signature,
    /// Verified token.
    pub token: Token<T>,
}

impl<A, T> fmt::Debug for SignedToken<A, T>
where
    A: Algorithm,
    A::Signature: fmt::Debug,
    T: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedToken")
            .field("token", &self.token)
            .field("signature", &self.signature)
            .finish()
    }
}

impl<A, T> Clone for SignedToken<A, T>
where
    A: Algorithm,
    A::Signature: Clone,
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            signature: self.signature.clone(),
            token: self.token.clone(),
        }
    }
}

impl<'a> TryFrom<&'a str> for UntrustedToken<'a> {
    type Error = ParseError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let token_parts: Vec<_> = s.splitn(4, '.').collect();
        match &token_parts[..] {
            [header, claims, signature] => {
                let header = base64::decode_config(header, base64::URL_SAFE_NO_PAD)?;
                let serialized_claims = base64::decode_config(claims, base64::URL_SAFE_NO_PAD)?;
                let mut decoded_signature = smallvec![0; 3 * (signature.len() + 3) / 4];
                let signature_len = base64::decode_config_slice(
                    signature,
                    base64::URL_SAFE_NO_PAD,
                    &mut decoded_signature[..],
                )?;
                decoded_signature.truncate(signature_len);

                let header: CompleteHeader<'_> =
                    serde_json::from_slice(&header).map_err(ParseError::MalformedHeader)?;
                let content_type = match header.content_type {
                    None => ContentType::Json,
                    Some(ref s) if s.eq_ignore_ascii_case("json") => ContentType::Json,
                    Some(ref s) if s.eq_ignore_ascii_case("cbor") => ContentType::Cbor,
                    Some(s) => return Err(ParseError::UnsupportedContentType(s)),
                };

                Ok(Self {
                    signed_data: s.rsplitn(2, '.').nth(1).unwrap().as_bytes(),
                    header: header.inner,
                    algorithm: header.algorithm.into_owned(),
                    content_type,
                    serialized_claims,
                    signature: decoded_signature,
                })
            }
            _ => Err(ParseError::InvalidTokenStructure),
        }
    }
}

impl<'a> UntrustedToken<'a> {
    /// Gets the token header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Gets the integrity algorithm used to secure the token.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Returns signature bytes from the token. These bytes are **not** guaranteed to form a valid
    /// signature.
    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alg::{Hs256, Hs256Key};

    use assert_matches::assert_matches;

    type Obj = serde_json::Map<String, serde_json::Value>;

    const HS256_TOKEN: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
                               eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
                               cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
                               dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const HS256_KEY: &str = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75\
                             aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

    #[test]
    fn invalid_token_structure() {
        let mangled_str = HS256_TOKEN.replace('.', "");
        assert_matches!(
            UntrustedToken::try_from(mangled_str.as_str()).unwrap_err(),
            ParseError::InvalidTokenStructure
        );

        let mut mangled_str = HS256_TOKEN.to_owned();
        let signature_start = mangled_str.rfind('.').unwrap();
        mangled_str.truncate(signature_start);
        assert_matches!(
            UntrustedToken::try_from(mangled_str.as_str()).unwrap_err(),
            ParseError::InvalidTokenStructure
        );

        let mut mangled_str = HS256_TOKEN.to_owned();
        mangled_str.push('.');
        assert_matches!(
            UntrustedToken::try_from(mangled_str.as_str()).unwrap_err(),
            ParseError::InvalidTokenStructure
        );
    }

    #[test]
    fn base64_error_during_parsing() {
        let mangled_str = HS256_TOKEN.replace('0', "+");
        assert_matches!(
            UntrustedToken::try_from(mangled_str.as_str()).unwrap_err(),
            ParseError::Base64(_)
        );

        let mut mangled_str = HS256_TOKEN.to_owned();
        mangled_str.truncate(mangled_str.len() - 1);
        assert_matches!(
            UntrustedToken::try_from(mangled_str.as_str()).unwrap_err(),
            ParseError::Base64(_)
        );
    }

    #[test]
    fn malformed_header() {
        let mangled_headers = [
            // Missing closing brace
            r#"{"alg":"HS256""#,
            // Missing necessary `alg` field
            "{}",
            // `alg` field is not a string
            r#"{"alg":5}"#,
            r#"{"alg":[1,"foo"]}"#,
            r#"{"alg":false}"#,
            // Duplicate `alg` field
            r#"{"alg":"HS256","alg":"none"}"#,
        ];

        for mangled_header in &mangled_headers {
            let mangled_header = base64::encode_config(mangled_header, base64::URL_SAFE_NO_PAD);
            let mut mangled_str = HS256_TOKEN.to_owned();
            mangled_str.replace_range(..mangled_str.find('.').unwrap(), &mangled_header);
            assert_matches!(
                UntrustedToken::try_from(mangled_str.as_str()).unwrap_err(),
                ParseError::MalformedHeader(_)
            );
        }
    }

    #[test]
    fn unsupported_content_type() {
        let mangled_header = r#"{"alg":"HS256","cty":"txt"}"#;
        let mangled_header = base64::encode_config(mangled_header, base64::URL_SAFE_NO_PAD);
        let mut mangled_str = HS256_TOKEN.to_owned();
        mangled_str.replace_range(..mangled_str.find('.').unwrap(), &mangled_header);
        assert_matches!(
            UntrustedToken::try_from(mangled_str.as_str()).unwrap_err(),
            ParseError::UnsupportedContentType(ref s) if s == "txt"
        );
    }

    #[test]
    fn malformed_json_claims() {
        let malformed_claims = [
            // Missing closing brace
            r#"{"exp":1500000000"#,
            // `exp` claim is not a number
            r#"{"exp":"1500000000"}"#,
            r#"{"exp":false}"#,
            // Duplicate `exp` claim
            r#"{"exp":1500000000,"nbf":1400000000,"exp":1510000000}"#,
            // Too large `exp` value
            r#"{"exp":1500000000000000000000000000000000}"#,
        ];

        let claims_start = HS256_TOKEN.find('.').unwrap() + 1;
        let claims_end = HS256_TOKEN.rfind('.').unwrap();
        let key = base64::decode_config(HS256_KEY, base64::URL_SAFE_NO_PAD).unwrap();
        let key = Hs256Key::from(&*key);

        for claims in &malformed_claims {
            let encoded_claims = base64::encode_config(claims.as_bytes(), base64::URL_SAFE_NO_PAD);
            let mut mangled_str = HS256_TOKEN.to_owned();
            mangled_str.replace_range(claims_start..claims_end, &encoded_claims);
            let token = UntrustedToken::try_from(mangled_str.as_str()).unwrap();
            assert_matches!(
                Hs256.validate_integrity::<Obj>(&token, &key).unwrap_err(),
                ValidationError::MalformedClaims(_),
                "Failing claims: {}",
                claims
            );
        }
    }
}
