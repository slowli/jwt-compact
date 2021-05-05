use ed25519_dalek::{
    Keypair, PublicKey, SecretKey, Signature, Signer, Verifier, PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH,
};

use core::convert::TryFrom;

use crate::{
    alg::{SigningKey, VerifyingKey},
    alloc::Cow,
    jwk::{JsonWebKey, JwkError},
    Algorithm, AlgorithmSignature, Renamed,
};

impl AlgorithmSignature for Signature {
    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::try_from(bytes).map_err(|e| anyhow::anyhow!(e))
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.to_bytes().to_vec())
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
}

impl Algorithm for Ed25519 {
    type SigningKey = Keypair;
    type VerifyingKey = PublicKey;
    type Signature = Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("EdDSA")
    }

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

impl VerifyingKey<Ed25519> for PublicKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        Self::from_bytes(raw).map_err(|e| anyhow::anyhow!(e))
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.as_ref())
    }
}

impl SigningKey<Ed25519> for Keypair {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        Self::from_bytes(raw).map_err(|e| anyhow::anyhow!(e))
    }

    fn to_verifying_key(&self) -> PublicKey {
        self.public
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.to_bytes().to_vec())
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
        let (curve, x) = if let JsonWebKey::KeyPair { curve, x, .. } = jwk {
            (curve, x)
        } else {
            return Err(JwkError::UnexpectedKeyType);
        };

        JsonWebKey::ensure_curve(curve, "Ed25519")?;
        JsonWebKey::ensure_len("x", x, PUBLIC_KEY_LENGTH)?;
        PublicKey::from_slice(x).map_err(JwkError::custom)
    }
}

impl<'a> From<&'a Keypair> for JsonWebKey<'a> {
    fn from(keypair: &'a Keypair) -> JsonWebKey<'a> {
        JsonWebKey::KeyPair {
            curve: Cow::Borrowed("Ed25519"),
            x: Cow::Borrowed(keypair.public.as_ref()),
            secret: Some(Cow::Borrowed(keypair.secret.as_ref())),
        }
    }
}

impl TryFrom<&JsonWebKey<'_>> for Keypair {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        let sk_bytes = if let JsonWebKey::KeyPair { secret, .. } = jwk {
            secret.as_deref()
        } else {
            return Err(JwkError::UnexpectedKeyType);
        };
        let sk_bytes = sk_bytes.ok_or_else(|| JwkError::NoField("d".into()))?;
        JsonWebKey::ensure_len("d", sk_bytes, SECRET_KEY_LENGTH)?;

        let secret = SecretKey::from_bytes(sk_bytes).unwrap();
        let keypair = Keypair {
            public: PublicKey::from(&secret),
            secret,
        };
        jwk.ensure_key_match(keypair)
    }
}
