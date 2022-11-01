//! `EdDSA` algorithm implementation using the `ed25519-compact` crate.

use ed25519_compact::{KeyPair, Noise, PublicKey, SecretKey, Seed, Signature};
use rand_core::{CryptoRng, RngCore};

use core::num::NonZeroUsize;

use crate::{
    alg::{SecretBytes, SigningKey, VerifyingKey},
    alloc::Cow,
    jwk::{JsonWebKey, JwkError, KeyType},
    Algorithm, AlgorithmSignature, Renamed,
};

impl AlgorithmSignature for Signature {
    const LENGTH: Option<NonZeroUsize> = NonZeroUsize::new(Signature::BYTES);

    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut signature = [0_u8; Signature::BYTES];
        signature.copy_from_slice(bytes);
        Ok(Self::new(signature))
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_ref())
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

    /// Generate a new key pair.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> (SecretKey, PublicKey) {
        let mut seed = [0_u8; Seed::BYTES];
        rng.fill_bytes(&mut seed);
        let keypair = KeyPair::from_seed(Seed::new(seed));
        (keypair.sk, keypair.pk)
    }
}

impl Algorithm for Ed25519 {
    type SigningKey = SecretKey;
    type VerifyingKey = PublicKey;
    type Signature = Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("EdDSA")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        signing_key.sign(message, Some(Noise::default()))
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

impl VerifyingKey<Ed25519> for PublicKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        Self::from_slice(raw).map_err(|e| anyhow::anyhow!(e))
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_ref())
    }
}

impl SigningKey<Ed25519> for SecretKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        Self::from_slice(raw).map_err(|e| anyhow::anyhow!(e))
    }

    fn to_verifying_key(&self) -> PublicKey {
        self.public_key()
    }

    fn as_bytes(&self) -> SecretBytes<'_> {
        SecretBytes::borrowed(self.as_ref())
    }
}

impl<'a> From<&'a PublicKey> for JsonWebKey<'a> {
    fn from(key: &'a PublicKey) -> JsonWebKey<'a> {
        JsonWebKey::KeyPair {
            curve: Cow::Borrowed("Ed25519"),
            x: Cow::Borrowed(&key[..]),
            secret: None,
        }
    }
}

impl TryFrom<&JsonWebKey<'_>> for PublicKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        let (curve, x) = if let JsonWebKey::KeyPair { curve, x, .. } = jwk {
            (curve, x)
        } else {
            return Err(JwkError::key_type(jwk, KeyType::KeyPair));
        };
        JsonWebKey::ensure_curve(curve, "Ed25519")?;
        JsonWebKey::ensure_len("x", x, PublicKey::BYTES)?;

        <PublicKey as VerifyingKey<_>>::from_slice(x).map_err(JwkError::custom)
    }
}

impl<'a> From<&'a SecretKey> for JsonWebKey<'a> {
    fn from(key: &'a SecretKey) -> JsonWebKey<'a> {
        JsonWebKey::KeyPair {
            curve: Cow::Borrowed("Ed25519"),
            x: Cow::Borrowed(&key[Seed::BYTES..]),
            secret: Some(SecretBytes::borrowed(&key[..Seed::BYTES])),
        }
    }
}

impl TryFrom<&JsonWebKey<'_>> for SecretKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        let seed_bytes = if let JsonWebKey::KeyPair { secret, .. } = jwk {
            secret.as_deref()
        } else {
            return Err(JwkError::key_type(jwk, KeyType::KeyPair));
        };
        let seed_bytes = seed_bytes.ok_or_else(|| JwkError::NoField("d".into()))?;
        JsonWebKey::ensure_len("d", seed_bytes, Seed::BYTES)?;
        let seed_bytes = *<&[u8; Seed::BYTES]>::try_from(seed_bytes).unwrap();

        let secret_key = KeyPair::from_seed(Seed::new(seed_bytes)).sk;
        jwk.ensure_key_match(secret_key)
    }
}
