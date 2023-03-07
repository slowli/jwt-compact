//! `EdDSA` algorithm implementation using the `exonum-crypto` crate.

use anyhow::format_err;
use exonum_crypto::{
    gen_keypair_from_seed, sign, verify, PublicKey, SecretKey, Seed, Signature, PUBLIC_KEY_LENGTH,
    SEED_LENGTH, SIGNATURE_LENGTH,
};

use core::num::NonZeroUsize;

use crate::{
    alg::{SecretBytes, SigningKey, VerifyingKey},
    alloc::Cow,
    jwk::{JsonWebKey, JwkError, KeyType},
    Algorithm, AlgorithmSignature, Renamed,
};

impl AlgorithmSignature for Signature {
    const LENGTH: Option<NonZeroUsize> = NonZeroUsize::new(SIGNATURE_LENGTH);

    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        // There are no checks other than by signature length in `from_slice`,
        // so the `unwrap()` below is safe.
        Ok(Self::from_slice(bytes).unwrap())
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_ref())
    }
}

/// Integrity algorithm using digital signatures on the Ed25519 elliptic curve.
///
/// The name of the algorithm is specified as `EdDSA` as per [IANA registry].
/// Use `with_specific_name()` to switch to non-standard `Ed25519`.
///
/// [IANA registry]: https://www.iana.org/assignments/jose/jose.xhtml
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "exonum-crypto",
        feature = "ed25519-dalek",
        feature = "ed25519-compact"
    )))
)]
pub struct Ed25519;

impl Ed25519 {
    /// Creates an algorithm instance with the algorithm name specified as `Ed25519`.
    /// This is a non-standard name, but it is used in some apps.
    pub fn with_specific_name() -> Renamed<Self> {
        Renamed::new(Self, "Ed25519")
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
        sign(message, signing_key)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        verify(signature, message, verifying_key)
    }
}

impl VerifyingKey<Ed25519> for PublicKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        Self::from_slice(raw).ok_or_else(|| format_err!("Invalid public key length"))
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_ref())
    }
}

impl SigningKey<Ed25519> for SecretKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        Self::from_slice(raw).ok_or_else(|| format_err!("Invalid secret key bytes"))
    }

    fn to_verifying_key(&self) -> PublicKey {
        // Slightly hacky. The backend does not expose functions for converting secret keys
        // to public ones, and we don't want to use `KeyPair` instead of `SecretKey`
        // for this single purpose.
        PublicKey::from_slice(&self[SEED_LENGTH..]).unwrap()
    }

    fn as_bytes(&self) -> SecretBytes<'_> {
        SecretBytes::borrowed(&self[..])
    }
}

impl<'a> From<&'a PublicKey> for JsonWebKey<'a> {
    fn from(key: &'a PublicKey) -> JsonWebKey<'a> {
        JsonWebKey::KeyPair {
            curve: Cow::Borrowed("Ed25519"),
            x: Cow::Borrowed(key.as_ref()),
            secret: None,
        }
    }
}

impl TryFrom<&JsonWebKey<'_>> for PublicKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        let JsonWebKey::KeyPair { curve, x, .. } = jwk else {
            return Err(JwkError::key_type(jwk, KeyType::KeyPair));
        };

        JsonWebKey::ensure_curve(curve, "Ed25519")?;
        JsonWebKey::ensure_len("x", x, PUBLIC_KEY_LENGTH)?;
        Ok(PublicKey::from_slice(x).unwrap())
        // ^ unlike some other impls, libsodium does not check public key validity on creation
    }
}

impl<'a> From<&'a SecretKey> for JsonWebKey<'a> {
    fn from(key: &'a SecretKey) -> JsonWebKey<'a> {
        JsonWebKey::KeyPair {
            curve: Cow::Borrowed("Ed25519"),
            x: Cow::Borrowed(&key[SEED_LENGTH..]),
            secret: Some(SecretBytes::borrowed(&key[..SEED_LENGTH])),
        }
    }
}

impl TryFrom<&JsonWebKey<'_>> for SecretKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        let JsonWebKey::KeyPair { secret, .. } = jwk else {
            return Err(JwkError::key_type(jwk, KeyType::KeyPair));
        };
        let seed_bytes = secret.as_deref();
        let seed_bytes = seed_bytes.ok_or_else(|| JwkError::NoField("d".to_owned()))?;

        JsonWebKey::ensure_len("d", seed_bytes, SEED_LENGTH)?;
        let seed = Seed::from_slice(seed_bytes).unwrap();
        let (_, sk) = gen_keypair_from_seed(&seed);
        jwk.ensure_key_match(sk)
    }
}
