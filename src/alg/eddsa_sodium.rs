use exonum_crypto::{sign, verify, PublicKey, SecretKey, Signature};
use failure::format_err;

use std::borrow::Cow;

use crate::{Algorithm, AlgorithmSignature};

impl AlgorithmSignature for Signature {
    fn try_from_slice(bytes: &[u8]) -> Result<Self, failure::Error> {
        Self::from_slice(bytes).ok_or_else(|| format_err!("Invalid signature length"))
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.as_ref())
    }
}

/// `EdDSA` algorithm using the Ed25519 elliptic curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519;

impl Algorithm for Ed25519 {
    type SigningKey = SecretKey;
    type VerifyingKey = PublicKey;
    type Signature = Signature;

    const NAME: &'static str = "EdDSA";

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
