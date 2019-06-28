use ed25519_dalek::{Keypair, PublicKey, Signature};

use std::borrow::Cow;

use crate::{Algorithm, AlgorithmSignature};

impl AlgorithmSignature for Signature {
    fn try_from_slice(bytes: &[u8]) -> Result<Self, failure::Error> {
        Self::from_bytes(bytes).map_err(Into::into)
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.to_bytes().to_vec())
    }
}

/// `EdDSA` algorithm using the Ed25519 elliptic curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519;

impl Algorithm for Ed25519 {
    type SigningKey = Keypair;
    type VerifyingKey = PublicKey;
    type Signature = Signature;

    const NAME: &'static str = "EdDSA";

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
