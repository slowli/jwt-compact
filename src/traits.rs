//! Key traits defined by the crate.

use serde::{de::DeserializeOwned, Serialize};

use crate::{
    alloc::{Cow, String, ToOwned},
    token::CompleteHeader,
    Claims, CreationError, Header, SignedToken, Token, UntrustedToken, ValidationError,
};

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
        if expected_alg != token.algorithm() {
            return Err(ValidationError::AlgorithmMismatch {
                expected: expected_alg.into_owned(),
                actual: token.algorithm().to_owned(),
            });
        }

        let signature = Self::Signature::try_from_slice(token.signature_bytes())
            .map_err(ValidationError::MalformedSignature)?;
        // We assume that parsing claims is less computationally demanding than
        // validating a signature.
        let claims = token.deserialize_claims::<T>()?;
        if !self.verify_signature(&signature, verifying_key, token.signed_data) {
            return Err(ValidationError::InvalidSignature);
        }

        Ok(SignedToken {
            signature,
            token: Token::new(token.header().clone(), claims),
        })
    }
}
