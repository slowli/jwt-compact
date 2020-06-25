use ed25519_compact::{KeyPair, PublicKey, SecretKey, Seed, Signature};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use std::borrow::Cow;
use std::fmt;

use crate::{Algorithm, AlgorithmSignature, Renamed};

impl AlgorithmSignature for Signature {
    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut signature = [0u8; Signature::BYTES];
        if bytes.len() != signature.len() {
            return Err(ed25519_compact::Error::SignatureMismatch.into());
        }
        signature.copy_from_slice(bytes);
        Ok(Self::new(signature))
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.as_ref().to_vec())
    }
}

/// A verification key.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Ed25519VerifyingKey(PublicKey);

impl AsRef<PublicKey> for Ed25519VerifyingKey {
    fn as_ref(&self) -> &PublicKey {
        &self.0
    }
}

impl Ed25519VerifyingKey {
    /// Create a verification key from a slice.
    pub fn from_slice(raw: &[u8]) -> anyhow::Result<Ed25519VerifyingKey> {
        Ok(Ed25519VerifyingKey(PublicKey::from_slice(raw)?))
    }

    /// Return the key as raw bytes.
    pub fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.as_ref().as_ref().to_vec())
    }
}

/// A signing key.
pub struct Ed25519SigningKey(SecretKey);

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ed25519 secret key: {:?}", self.as_ref().as_ref())
    }
}

impl AsRef<SecretKey> for Ed25519SigningKey {
    fn as_ref(&self) -> &SecretKey {
        &self.0
    }
}

impl Ed25519SigningKey {
    /// Create a signing key from a slice.
    pub fn from_slice(raw: &[u8]) -> anyhow::Result<Ed25519SigningKey> {
        Ok(Ed25519SigningKey(SecretKey::from_slice(raw)?))
    }

    /// Convert a signing key to a verification key.
    pub fn to_verifying_key(&self) -> PublicKey {
        self.as_ref().public_key()
    }

    /// Return the key as raw bytes.
    pub fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.as_ref().as_ref().to_vec())
    }
}

/// Integrity algorithm using digital signatures on the Ed25519 elliptic curve.
///
/// The name of the algorithm is specified as `EdDSA` as per the [IANA registry].
/// Use `with_specific_name()` to switch to non-standard `Ed25519`.
///
/// *This type is available if the crate is built with the `ed25519-dalek` feature.*
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

    /// Generate a new key pair.
    pub fn generate<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
    ) -> (Ed25519SigningKey, Ed25519VerifyingKey) {
        let keypair = KeyPair::from_seed(Seed::new(rng.gen()));
        (
            Ed25519SigningKey(keypair.sk),
            Ed25519VerifyingKey(keypair.pk),
        )
    }
}

impl Algorithm for Ed25519 {
    type SigningKey = Ed25519SigningKey;
    type VerifyingKey = Ed25519VerifyingKey;
    type Signature = Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("EdDSA")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        signing_key.as_ref().sign(message, Some(Default::default()))
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        verifying_key.as_ref().verify(message, signature).is_ok()
    }
}
