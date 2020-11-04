use lazy_static::lazy_static;
use secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey, Signature};
use sha2::{
    digest::{generic_array::typenum::U32, Digest},
    Sha256,
};

use std::{borrow::Cow, marker::PhantomData};

use crate::{
    alg::{SigningKey, VerifyingKey},
    Algorithm, AlgorithmSignature,
};

impl AlgorithmSignature for Signature {
    fn try_from_slice(slice: &[u8]) -> anyhow::Result<Self> {
        Signature::from_compact(slice).map_err(Into::into)
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.serialize_compact()[..].to_vec())
    }
}

/// Algorithm implementing elliptic curve digital signatures (ECDSA) on the secp256k1 curve.
///
/// The algorithm does not fix the choice of the message digest algorithm; instead,
/// it is provided as a type parameter. SHA-256 is the default parameter value,
/// but it can be set to any cryptographically secure hash function with 32-byte output
/// (e.g., SHA3-256).
#[derive(Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "es256k")))]
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

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("ES256K")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        let mut digest = D::default();
        digest.update(message);
        let message = Message::from_slice(&digest.finalize())
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
        digest.update(message);
        let message = Message::from_slice(&digest.finalize())
            .expect("failed to convert message to the correct form");

        self.context
            .verify(&message, signature, verifying_key)
            .is_ok()
    }
}

/// This implementation initializes a `libsecp256k1` context once on the first call to
/// `to_verifying_key` if it was not initialized previously.
impl SigningKey<Es256k> for SecretKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        Self::from_slice(raw).map_err(From::from)
    }

    fn to_verifying_key(&self) -> PublicKey {
        lazy_static! {
            static ref CONTEXT: Secp256k1<All> = Secp256k1::new();
        }
        PublicKey::from_secret_key(&CONTEXT, self)
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self[..])
    }
}

impl VerifyingKey<Es256k> for PublicKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        Self::from_slice(raw).map_err(From::from)
    }

    /// Serializes the key as a 33-byte compressed form, as per [`Self::serialize()`].
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.serialize().to_vec())
    }
}
