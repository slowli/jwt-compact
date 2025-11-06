//! `EdDSA` algorithm implementation using the `ed25519-dalek` crate.

use core::num::NonZeroUsize;

use ed25519_dalek::{
    KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH, SecretKey, Signature,
    Signer, Verifier,
};

use crate::{
    Algorithm, AlgorithmSignature, Renamed,
    alg::{SecretBytes, SigningKey, VerifyingKey},
    alloc::Cow,
    jwk::{JsonWebKey, JwkError, KeyType},
};

impl AlgorithmSignature for Signature {
    const LENGTH: Option<NonZeroUsize> = NonZeroUsize::new(SIGNATURE_LENGTH);

    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::try_from(bytes).map_err(|err| anyhow::anyhow!(err))
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_bytes().to_vec())
    }
}

/// Integrity algorithm using digital signatures on the Ed25519 elliptic curve.
///
/// The name of the algorithm is specified as `EdDSA` as per the [IANA registry].
/// Use `with_specific_name()` to switch to non-standard `Ed25519`.
///
/// [IANA registry]: https://www.iana.org/assignments/jose/jose.xhtml
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Ed25519;

impl Ed25519 {
    /// Creates an algorithm instance with the algorithm name specified as `Ed25519`.
    /// This is a non-standard name, but it is used in some apps.
    pub fn with_specific_name() -> Renamed<Self> {
        Renamed::new(Self, "Ed25519")
    }
}

impl Algorithm for Ed25519 {
    type SigningKey = ed25519_dalek::SigningKey;
    type VerifyingKey = ed25519_dalek::VerifyingKey;
    type Signature = Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("EdDSA")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        signing_key.sign(message)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        verifying_key.verify(message, signature).is_ok()
    }
}

impl VerifyingKey<Ed25519> for ed25519_dalek::VerifyingKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        let raw = <&[u8; PUBLIC_KEY_LENGTH]>::try_from(raw).map_err(|err| {
            anyhow::anyhow!(err).context("Ed25519 public key has unexpected length")
        })?;
        Self::from_bytes(raw).map_err(|err| anyhow::anyhow!(err))
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_ref())
    }
}

impl SigningKey<Ed25519> for ed25519_dalek::SigningKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        if let Ok(secret) = <&SecretKey>::try_from(raw) {
            Ok(Self::from_bytes(secret))
        } else if let Ok(keypair_bytes) = <&[u8; KEYPAIR_LENGTH]>::try_from(raw) {
            Self::from_keypair_bytes(keypair_bytes).map_err(|err| anyhow::anyhow!(err))
        } else {
            Err(anyhow::anyhow!("Ed25519 secret key has unexpected length"))
        }
    }

    fn to_verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.into()
    }

    fn as_bytes(&self) -> SecretBytes<'_> {
        // We return the expanded key for compatibility with other implementations
        SecretBytes::owned(self.to_keypair_bytes().to_vec())
    }
}

impl<'a> From<&'a ed25519_dalek::VerifyingKey> for JsonWebKey<'a> {
    fn from(key: &'a ed25519_dalek::VerifyingKey) -> JsonWebKey<'a> {
        JsonWebKey::KeyPair {
            curve: Cow::Borrowed("Ed25519"),
            x: Cow::Borrowed(key.as_ref()),
            secret: None,
        }
    }
}

impl TryFrom<&JsonWebKey<'_>> for ed25519_dalek::VerifyingKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        let JsonWebKey::KeyPair { curve, x, .. } = jwk else {
            return Err(JwkError::key_type(jwk, KeyType::KeyPair));
        };

        JsonWebKey::ensure_curve(curve, "Ed25519")?;
        JsonWebKey::ensure_len("x", x, PUBLIC_KEY_LENGTH)?;
        ed25519_dalek::VerifyingKey::from_slice(x).map_err(JwkError::custom)
    }
}

impl<'a> From<&'a ed25519_dalek::SigningKey> for JsonWebKey<'a> {
    fn from(signing_key: &'a ed25519_dalek::SigningKey) -> JsonWebKey<'a> {
        JsonWebKey::KeyPair {
            curve: Cow::Borrowed("Ed25519"),
            x: Cow::Borrowed(signing_key.as_ref().as_bytes()),
            secret: Some(SecretBytes::owned(signing_key.to_bytes().to_vec())),
        }
    }
}

impl TryFrom<&JsonWebKey<'_>> for ed25519_dalek::SigningKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        let JsonWebKey::KeyPair { secret, .. } = jwk else {
            return Err(JwkError::key_type(jwk, KeyType::KeyPair));
        };
        let sk_bytes = secret.as_deref();
        let sk_bytes = sk_bytes.ok_or_else(|| JwkError::NoField("d".into()))?;
        JsonWebKey::ensure_len("d", sk_bytes, SECRET_KEY_LENGTH)?;

        let secret: &SecretKey = sk_bytes.try_into().unwrap();
        let signing_key = ed25519_dalek::SigningKey::from(secret);
        jwk.ensure_key_match(signing_key)
    }
}
