use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey, Signature};
use sha2::{
    digest::{generic_array::typenum::U32, Digest},
    Sha256,
};
use std::{borrow::Cow, marker::PhantomData};

use crate::{Algorithm, AlgorithmSignature};

impl AlgorithmSignature for Signature {
    fn try_from_slice(slice: &[u8]) -> anyhow::Result<Self> {
        Signature::from_compact(slice).map_err(Into::into)
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.serialize_compact()[..].to_vec())
    }
}

/// A verification key.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Es256kVerifyingKey(PublicKey);

impl AsRef<PublicKey> for Es256kVerifyingKey {
    fn as_ref(&self) -> &PublicKey {
        &self.0
    }
}

impl Es256kVerifyingKey {
    /// Create a verification key from a slice.
    pub fn from_slice(raw: &[u8]) -> anyhow::Result<Es256kVerifyingKey> {
        Ok(Es256kVerifyingKey(PublicKey::from_slice(raw)?))
    }
}

/// A signing key.
#[derive(Debug)]
pub struct Es256kSigningKey(SecretKey);

impl AsRef<SecretKey> for Es256kSigningKey {
    fn as_ref(&self) -> &SecretKey {
        &self.0
    }
}

impl Es256kSigningKey {
    /// Create a signing key from a slice.
    pub fn from_slice(raw: &[u8]) -> anyhow::Result<Es256kSigningKey> {
        Ok(Es256kSigningKey(SecretKey::from_slice(raw)?))
    }

    /// Convert a signing key to a verification key.
    pub fn to_verifying_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &self.0)
    }
}

/// Algorithm implementing elliptic curve digital signatures (ECDSA) on the secp256k1 curve.
///
/// The algorithm does not fix the choice of the message digest algorithm; instead,
/// it is provided as a type parameter. SHA-256 is the default parameter value,
/// but it can be set to any cryptographically secure hash function with 32-byte output
/// (e.g., SHA3-256).
///
/// *This type is available if the crate is built with the `secp256k1` feature.*
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
    type SigningKey = Es256kSigningKey;
    type VerifyingKey = Es256kVerifyingKey;
    type Signature = Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("ES256K")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        let mut digest = D::default();
        digest.update(message);
        let message = Message::from_slice(&digest.finalize())
            .expect("failed to convert message to the correct form");

        self.context.sign(&message, signing_key.as_ref())
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
            .verify(&message, signature, verifying_key.as_ref())
            .is_ok()
    }
}

impl Es256k {
    /// Generate a new key pair.
    pub fn generate<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
    ) -> (Es256kSigningKey, Es256kVerifyingKey) {
        let signing_key = loop {
            let bytes: [u8; secp256k1::constants::SECRET_KEY_SIZE] = rng.gen();
            if let Ok(key) = SecretKey::from_slice(&bytes) {
                break Es256kSigningKey(key);
            }
        };
        let verifying_key = Es256kVerifyingKey(signing_key.to_verifying_key());
        (signing_key, verifying_key)
    }
}
