//! `ES256` algorithm implementation using the `p256` crate.

use p256::ecdsa::{
    signature::{DigestSigner, DigestVerifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

use core::num::NonZeroUsize;

use crate::{
    alg::{self, SecretBytes},
    alloc::Cow,
    jwk::{JsonWebKey, JwkError, KeyType},
    Algorithm, AlgorithmSignature,
};

impl AlgorithmSignature for Signature {
    const LENGTH: Option<NonZeroUsize> = NonZeroUsize::new(64);

    fn try_from_slice(slice: &[u8]) -> anyhow::Result<Self> {
        Signature::try_from(slice).map_err(|err| anyhow::anyhow!(err))
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_bytes().to_vec())
    }
}

/// `ES256` signing algorithm. Implements elliptic curve digital signatures (ECDSA)
/// on the secp256r1 curve (aka P-256).
#[derive(Debug, Default)]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
pub struct Es256;

impl Algorithm for Es256 {
    type SigningKey = SigningKey;
    type VerifyingKey = VerifyingKey;
    type Signature = Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("ES256")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        let mut digest = Sha256::default();
        digest.update(message);
        signing_key.sign_digest(digest)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        let mut digest = Sha256::default();
        digest.update(message);

        verifying_key.verify_digest(digest, signature).is_ok()
    }
}

impl alg::SigningKey<Es256> for SigningKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        Self::from_slice(raw).map_err(|err| anyhow::anyhow!(err))
    }

    fn to_verifying_key(&self) -> VerifyingKey {
        *self.verifying_key()
    }

    fn as_bytes(&self) -> SecretBytes<'_> {
        SecretBytes::owned(self.to_bytes().to_vec())
    }
}

impl alg::VerifyingKey<Es256> for VerifyingKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        Self::from_sec1_bytes(raw).map_err(|err| anyhow::anyhow!(err))
    }

    /// Serializes the key as a 33-byte compressed form.
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        let bytes = self.to_encoded_point(true).as_bytes().to_vec();
        Cow::Owned(bytes)
    }
}

fn create_jwk<'a>(pk: &VerifyingKey, sk: Option<&'a SigningKey>) -> JsonWebKey<'a> {
    let uncompressed = pk.to_encoded_point(false);
    JsonWebKey::EllipticCurve {
        curve: "P-256".into(),
        x: Cow::Owned(uncompressed.x().expect("x coord").to_vec()),
        y: Cow::Owned(uncompressed.y().expect("y coord").to_vec()),
        secret: sk.map(|sk| SecretBytes::owned(sk.to_bytes().to_vec())),
    }
}

impl<'a> From<&'a VerifyingKey> for JsonWebKey<'a> {
    fn from(key: &'a VerifyingKey) -> JsonWebKey<'a> {
        create_jwk(key, None)
    }
}

impl TryFrom<&JsonWebKey<'_>> for VerifyingKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        const COORDINATE_SIZE: usize = 32;

        let JsonWebKey::EllipticCurve { curve, x, y, .. } = jwk else {
            return Err(JwkError::key_type(jwk, KeyType::EllipticCurve));
        };
        JsonWebKey::ensure_curve(curve, "P-256")?;
        JsonWebKey::ensure_len("x", x, COORDINATE_SIZE)?;
        JsonWebKey::ensure_len("y", y, COORDINATE_SIZE)?;

        let mut key_bytes = [0_u8; 2 * COORDINATE_SIZE + 1];
        key_bytes[0] = 4; // uncompressed key marker
        key_bytes[1..=COORDINATE_SIZE].copy_from_slice(x);
        key_bytes[(1 + COORDINATE_SIZE)..].copy_from_slice(y);
        VerifyingKey::from_sec1_bytes(&key_bytes[..])
            .map_err(|err| JwkError::custom(anyhow::anyhow!(err)))
    }
}

impl<'a> From<&'a SigningKey> for JsonWebKey<'a> {
    fn from(key: &'a SigningKey) -> JsonWebKey<'a> {
        create_jwk(key.verifying_key(), Some(key))
    }
}

impl TryFrom<&JsonWebKey<'_>> for SigningKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        let JsonWebKey::EllipticCurve { secret, .. } = jwk else {
            return Err(JwkError::key_type(jwk, KeyType::EllipticCurve));
        };
        let sk_bytes = secret.as_deref();
        let sk_bytes = sk_bytes.ok_or_else(|| JwkError::NoField("d".into()))?;
        JsonWebKey::ensure_len("d", sk_bytes, 32)?;

        let sk =
            Self::from_slice(sk_bytes).map_err(|err| JwkError::custom(anyhow::anyhow!(err)))?;
        jwk.ensure_key_match(sk)
    }
}
