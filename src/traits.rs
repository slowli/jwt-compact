//! Key traits defined by the crate.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{de::DeserializeOwned, Serialize};

use core::{marker::PhantomData, num::NonZeroUsize};

use crate::{
    alloc::{Cow, String, ToOwned, Vec},
    token::CompleteHeader,
    Claims, CreationError, Header, SignedToken, Token, UntrustedToken, ValidationError,
};

/// Signature for a certain JWT signing [`Algorithm`].
///
/// We require that signature can be restored from a byte slice,
/// and can be represented as a byte slice.
pub trait AlgorithmSignature: Sized {
    /// Constant byte length of signatures supported by the [`Algorithm`], or `None` if
    /// the signature length is variable.
    ///
    /// - If this value is `Some(_)`, the signature will be first checked for its length
    ///   during token verification. An [`InvalidSignatureLen`] error will be raised if the length
    ///   is invalid. [`Self::try_from_slice()`] will thus always receive a slice with
    ///   the expected length.
    /// - If this value is `None`, no length check is performed before calling
    ///   [`Self::try_from_slice()`].
    ///
    /// [`InvalidSignatureLen`]: crate::ValidationError::InvalidSignatureLen
    const LENGTH: Option<NonZeroUsize> = None;

    /// Attempts to restore a signature from a byte slice. This method may fail
    /// if the slice is malformed.
    fn try_from_slice(slice: &[u8]) -> anyhow::Result<Self>;

    /// Represents this signature as bytes.
    fn as_bytes(&self) -> Cow<'_, [u8]>;
}

/// JWT signing algorithm.
pub trait Algorithm {
    /// Key used when issuing new tokens.
    type SigningKey;
    /// Key used when verifying tokens. May coincide with [`Self::SigningKey`] for symmetric
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
///
/// # fn main() -> anyhow::Result<()> {
/// let alg = Renamed::new(Hs256, "HS2");
/// let key = Hs256Key::new(b"super_secret_key_donut_steel");
/// let token_string = alg.token(Header::default(), &Claims::empty(), &key)?;
///
/// let token = UntrustedToken::new(&token_string)?;
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
        header: Header<impl Serialize>,
        claims: &Claims<T>,
        signing_key: &Self::SigningKey,
    ) -> Result<String, CreationError>
    where
        T: Serialize;

    /// Creates a new token with CBOR-encoded claims and serializes it to string.
    #[cfg(feature = "serde_cbor")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde_cbor")))]
    fn compact_token<T>(
        &self,
        header: Header<impl Serialize>,
        claims: &Claims<T>,
        signing_key: &Self::SigningKey,
    ) -> Result<String, CreationError>
    where
        T: Serialize;

    /// Creates a JWT validator for the specified verifying key and the claims type.
    /// The validator can then be used to validate one or more tokens.
    fn validator<'a, T>(&'a self, verifying_key: &'a Self::VerifyingKey) -> Validator<'a, Self, T>;

    /// Validates the token integrity against the provided `verifying_key`.
    #[deprecated = "Use `.validator().validate()` for added flexibility"]
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
    #[deprecated = "Use `.validator().validate_for_signed_token()` for added flexibility"]
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
        header: Header<impl Serialize>,
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
        let mut buffer = Vec::new();
        encode_base64_buf(&header, &mut buffer);

        let claims = serde_json::to_string(claims).map_err(CreationError::Claims)?;
        buffer.push(b'.');
        encode_base64_buf(&claims, &mut buffer);

        let signature = self.sign(signing_key, &buffer);
        buffer.push(b'.');
        encode_base64_buf(signature.as_bytes(), &mut buffer);

        // SAFETY: safe by construction: base64 alphabet and `.` char are valid UTF-8.
        Ok(unsafe { String::from_utf8_unchecked(buffer) })
    }

    #[cfg(feature = "serde_cbor")]
    fn compact_token<T>(
        &self,
        header: Header<impl Serialize>,
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
        let mut buffer = Vec::new();
        encode_base64_buf(&header, &mut buffer);

        let claims = serde_cbor::to_vec(claims).map_err(CreationError::CborClaims)?;
        buffer.push(b'.');
        encode_base64_buf(&claims, &mut buffer);

        let signature = self.sign(signing_key, &buffer);
        buffer.push(b'.');
        encode_base64_buf(signature.as_bytes(), &mut buffer);

        // SAFETY: safe by construction: base64 alphabet and `.` char are valid UTF-8.
        Ok(unsafe { String::from_utf8_unchecked(buffer) })
    }

    fn validator<'a, T>(&'a self, verifying_key: &'a Self::VerifyingKey) -> Validator<'a, Self, T> {
        Validator {
            algorithm: self,
            verifying_key,
            _claims: PhantomData,
        }
    }

    fn validate_integrity<T>(
        &self,
        token: &UntrustedToken<'_>,
        verifying_key: &Self::VerifyingKey,
    ) -> Result<Token<T>, ValidationError>
    where
        T: DeserializeOwned,
    {
        self.validator::<T>(verifying_key).validate(token)
    }

    fn validate_for_signed_token<T>(
        &self,
        token: &UntrustedToken<'_>,
        verifying_key: &Self::VerifyingKey,
    ) -> Result<SignedToken<Self, T>, ValidationError>
    where
        T: DeserializeOwned,
    {
        self.validator::<T>(verifying_key)
            .validate_for_signed_token(token)
    }
}

/// Validator for a certain signing [`Algorithm`] associated with a specific verifying key
/// and a claims type. Produced by the [`AlgorithmExt::validator()`] method.
#[derive(Debug)]
pub struct Validator<'a, A: Algorithm + ?Sized, T> {
    algorithm: &'a A,
    verifying_key: &'a A::VerifyingKey,
    _claims: PhantomData<fn() -> T>,
}

impl<A: Algorithm + ?Sized, T> Clone for Validator<'_, A, T> {
    fn clone(&self) -> Self {
        Self {
            algorithm: self.algorithm,
            verifying_key: self.verifying_key,
            _claims: PhantomData,
        }
    }
}

impl<A: Algorithm + ?Sized, T> Copy for Validator<'_, A, T> {}

impl<A: Algorithm + ?Sized, T: DeserializeOwned> Validator<'_, A, T> {
    /// Validates the token integrity against a verifying key enclosed in this validator.
    pub fn validate<H: Clone>(
        self,
        token: &UntrustedToken<'_, H>,
    ) -> Result<Token<T, H>, ValidationError> {
        self.validate_for_signed_token(token)
            .map(|signed| signed.token)
    }

    /// Validates the token integrity against a verifying key enclosed in this validator,
    /// and returns the validated [`Token`] together with its signature.
    pub fn validate_for_signed_token<H: Clone>(
        self,
        token: &UntrustedToken<'_, H>,
    ) -> Result<SignedToken<A, T, H>, ValidationError> {
        let expected_alg = self.algorithm.name();
        if expected_alg != token.algorithm() {
            return Err(ValidationError::AlgorithmMismatch {
                expected: expected_alg.into_owned(),
                actual: token.algorithm().to_owned(),
            });
        }

        let signature = token.signature_bytes();
        if let Some(expected_len) = A::Signature::LENGTH {
            if signature.len() != expected_len.get() {
                return Err(ValidationError::InvalidSignatureLen {
                    expected: expected_len.get(),
                    actual: signature.len(),
                });
            }
        }

        let signature =
            A::Signature::try_from_slice(signature).map_err(ValidationError::MalformedSignature)?;
        // We assume that parsing claims is less computationally demanding than
        // validating a signature.
        let claims = token.deserialize_claims_unchecked::<T>()?;
        if !self
            .algorithm
            .verify_signature(&signature, self.verifying_key, &token.signed_data)
        {
            return Err(ValidationError::InvalidSignature);
        }

        Ok(SignedToken {
            signature,
            token: Token::new(token.header().clone(), claims),
        })
    }
}

fn encode_base64_buf(source: impl AsRef<[u8]>, buffer: &mut Vec<u8>) {
    let source = source.as_ref();
    let previous_len = buffer.len();
    let claims_len = Base64UrlUnpadded::encoded_len(source);
    buffer.resize(previous_len + claims_len, 0);
    Base64UrlUnpadded::encode(source, &mut buffer[previous_len..])
        .expect("miscalculated base64-encoded length; this should never happen");
}
