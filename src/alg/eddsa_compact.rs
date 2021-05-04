use ed25519_compact::{KeyPair, Noise, PublicKey, SecretKey, Seed, Signature};
use rand_core::{CryptoRng, RngCore};

use crate::{
    alg::{KeyFields, SigningKey, ThumbprintKey, VerifyingKey},
    alloc::Cow,
    Algorithm, AlgorithmSignature, Renamed,
};

impl AlgorithmSignature for Signature {
    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut signature = [0_u8; Signature::BYTES];
        if bytes.len() != signature.len() {
            return Err(anyhow::anyhow!(ed25519_compact::Error::SignatureMismatch));
        }
        signature.copy_from_slice(bytes);
        Ok(Self::new(signature))
    }

    fn as_bytes(&self) -> Cow<[u8]> {
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

    fn as_bytes(&self) -> Cow<[u8]> {
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

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.as_ref())
    }
}

impl ThumbprintKey for PublicKey {
    fn key_fields(&self) -> KeyFields<'_> {
        KeyFields::new("OKP")
            .with_str_field("crv", "Ed25519")
            .with_bytes_field("x", self.as_ref())
    }
}
