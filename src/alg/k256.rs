//! `ES256K` algorithm implementation using the `k256` crate.

use k256::{
    ecdsa::{
        signature::{DigestSigner, DigestVerifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::sec1::ToEncodedPoint,
};
use sha2::{
    digest::{generic_array::typenum::U32, BlockInput, FixedOutput, Reset, Update},
    Sha256,
};

use core::{convert::TryFrom, marker::PhantomData};

use crate::{
    alg::{self, SecretBytes},
    alloc::Cow,
    jwk::{JsonWebKey, JwkError, KeyType},
    Algorithm, AlgorithmSignature,
};

impl AlgorithmSignature for Signature {
    fn try_from_slice(slice: &[u8]) -> anyhow::Result<Self> {
        Signature::try_from(slice).map_err(|err| anyhow::anyhow!(err))
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_ref())
    }
}

/// Algorithm implementing elliptic curve digital signatures (ECDSA) on the secp256k1 curve.
///
/// The algorithm does not fix the choice of the message digest algorithm; instead,
/// it is provided as a type parameter. SHA-256 is the default parameter value,
/// but it can be set to any cryptographically secure hash function with 32-byte output
/// (e.g., SHA3-256).
#[derive(Debug)]
#[cfg_attr(docsrs, doc(cfg(any(feature = "es256k", feature = "k256"))))]
pub struct Es256k<D = Sha256> {
    _digest: PhantomData<D>,
}

impl<D> Default for Es256k<D>
where
    D: BlockInput + FixedOutput<OutputSize = U32> + Clone + Default + Reset + Update,
{
    fn default() -> Self {
        Es256k {
            _digest: PhantomData,
        }
    }
}

impl<D> Algorithm for Es256k<D>
where
    D: BlockInput + FixedOutput<OutputSize = U32> + Clone + Default + Reset + Update,
{
    type SigningKey = SigningKey;
    type VerifyingKey = VerifyingKey;
    type Signature = Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("ES256K")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        let mut digest = D::default();
        digest.update(message);
        signing_key.sign_digest(digest)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        let mut digest = D::default();
        digest.update(message);

        // Some implementations (e.g., OpenSSL) produce high-S signatures, which
        // are considered invalid by this implementation. Hence, we perform normalization here.
        //
        // See also: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
        let mut normalized_signature = *signature;
        if normalized_signature.normalize_s().is_err() {
            return false;
        }

        verifying_key
            .verify_digest(digest, &normalized_signature)
            .is_ok()
    }
}

impl alg::SigningKey<Es256k> for SigningKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        Self::from_bytes(raw).map_err(|err| anyhow::anyhow!(err))
    }

    fn to_verifying_key(&self) -> VerifyingKey {
        self.verify_key()
    }

    fn as_bytes(&self) -> SecretBytes<'_> {
        SecretBytes::owned(self.to_bytes().to_vec())
    }
}

impl alg::VerifyingKey<Es256k> for VerifyingKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        Self::from_sec1_bytes(raw).map_err(|err| anyhow::anyhow!(err))
    }

    /// Serializes the key as a 33-byte compressed form.
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_bytes().to_vec())
    }
}

fn create_jwk<'a>(pk: &VerifyingKey, sk: Option<&'a SigningKey>) -> JsonWebKey<'a> {
    let uncompressed = pk.to_encoded_point(false);
    JsonWebKey::EllipticCurve {
        curve: "secp256k1".into(),
        x: Cow::Owned(uncompressed.x().expect("x coord").to_vec()),
        y: Cow::Owned(uncompressed.y().expect("y coord").to_vec()),
        secret: sk.map(|sk| SecretBytes::owned(sk.to_bytes().to_vec())),
    }
}

impl<'a> From<&'a VerifyingKey> for JsonWebKey<'a> {
    fn from(key: &'a VerifyingKey) -> JsonWebKey<'a> {
        create_jwk(key, None)
    }
}

impl TryFrom<&JsonWebKey<'_>> for VerifyingKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        const COORDINATE_SIZE: usize = 32;

        let (x, y) = if let JsonWebKey::EllipticCurve { curve, x, y, .. } = jwk {
            JsonWebKey::ensure_curve(curve, "secp256k1")?;
            (x.as_ref(), y.as_ref())
        } else {
            return Err(JwkError::key_type(jwk, KeyType::EllipticCurve));
        };
        JsonWebKey::ensure_len("x", x, COORDINATE_SIZE)?;
        JsonWebKey::ensure_len("y", y, COORDINATE_SIZE)?;

        let mut key_bytes = [0_u8; 2 * COORDINATE_SIZE + 1];
        key_bytes[0] = 4; // uncompressed key marker
        key_bytes[1..=COORDINATE_SIZE].copy_from_slice(x);
        key_bytes[(1 + COORDINATE_SIZE)..].copy_from_slice(y);
        VerifyingKey::from_sec1_bytes(&key_bytes[..])
            .map_err(|err| JwkError::custom(anyhow::anyhow!(err)))
    }
}

impl<'a> From<&'a SigningKey> for JsonWebKey<'a> {
    fn from(key: &'a SigningKey) -> JsonWebKey<'a> {
        create_jwk(&key.verify_key(), Some(key))
    }
}

impl TryFrom<&JsonWebKey<'_>> for SigningKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        let sk_bytes = if let JsonWebKey::EllipticCurve { secret, .. } = jwk {
            secret.as_deref()
        } else {
            return Err(JwkError::key_type(jwk, KeyType::EllipticCurve));
        };
        let sk_bytes = sk_bytes.ok_or_else(|| JwkError::NoField("d".into()))?;
        JsonWebKey::ensure_len("d", sk_bytes, 32)?;

        let sk =
            Self::from_bytes(sk_bytes).map_err(|err| JwkError::custom(anyhow::anyhow!(err)))?;
        jwk.ensure_key_match(sk)
    }
}
