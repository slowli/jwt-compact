use secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey, Signature};
use sha2::{
    digest::{generic_array::typenum::U32, Digest},
    Sha256,
};

use std::{borrow::Cow, marker::PhantomData};

use crate::{Algorithm, AlgorithmSignature};

impl AlgorithmSignature for Signature {
    fn try_from_slice(slice: &[u8]) -> Result<Self, failure::Error> {
        Signature::from_compact(slice).map_err(Into::into)
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.serialize_compact()[..].to_vec())
    }
}

/// `ES256K` algorithm implementing ECDSA on the secp256k1 curve.
///
/// The algorithm does not fix the choice of the message digest algorithm; instead,
/// it is provided as a type parameter. SHA-256 is the default parameter value,
/// but it can be set to any cryptographically secure hash function with 32-byte output
/// (e.g., SHA3-256).
#[derive(Debug)]
pub struct Es256k<D = Sha256> {
    context: Secp256k1<All>,
    _digest: PhantomData<D>,
}

impl<D> Default for Es256k<D>
where
    D: Digest<OutputSize = U32> + Default,
{
    fn default() -> Self {
        Es256k {
            context: Secp256k1::new(),
            _digest: PhantomData,
        }
    }
}

impl<D> Es256k<D>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Creates a new algorithm instance.
    /// This is a (moderately) expensive operation, so if necessary, the algorithm should
    /// be `clone()`d rather than created anew.
    pub fn new(context: Secp256k1<All>) -> Self {
        Es256k {
            context,
            _digest: PhantomData,
        }
    }
}

impl<D> Algorithm for Es256k<D>
where
    D: Digest<OutputSize = U32> + Default,
{
    type SigningKey = SecretKey;
    type VerifyingKey = PublicKey;
    type Signature = Signature;

    const NAME: &'static str = "ES256K";

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        let mut digest = D::default();
        digest.input(message);
        let message = Message::from_slice(&digest.result())
            .expect("failed to convert message to the correct form");

        self.context.sign(&message, signing_key)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        let mut digest = D::default();
        digest.input(message);
        let message = Message::from_slice(&digest.result())
            .expect("failed to convert message to the correct form");

        self.context
            .verify(&message, signature, verifying_key)
            .is_ok()
    }
}
