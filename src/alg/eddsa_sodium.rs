use anyhow::format_err;
use exonum_crypto::{sign, verify, PublicKey, SecretKey, Signature, SEED_LENGTH};

use std::borrow::Cow;

use crate::{
    alg::{SigningKey, VerifyingKey},
    Algorithm, AlgorithmSignature, Renamed,
};

impl AlgorithmSignature for Signature {
    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::from_slice(bytes).ok_or_else(|| format_err!("Invalid signature length"))
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
/// *This type is available if the crate is built with the `exonum-crypto` feature.*
///
/// [IANA registry]: https://www.iana.org/assignments/jose/jose.xhtml
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

    fn as_bytes(&self) -> Cow<[u8]> {
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

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(&self[..])
    }
}
