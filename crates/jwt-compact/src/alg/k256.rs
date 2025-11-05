//! `ES256K` algorithm implementation using the `k256` crate.

use core::{marker::PhantomData, num::NonZeroUsize, ops::Add};

use k256::{
    Secp256k1,
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{DigestSigner, DigestVerifier},
    },
    elliptic_curve::FieldBytesSize,
};
use sha2::{
    Digest, Sha256,
    digest::{Update, typenum::Unsigned},
};

use crate::{
    Algorithm, AlgorithmSignature,
    alg::{self, SecretBytes},
    alloc::Cow,
    jwk::{JsonWebKey, JwkError, KeyType},
};

impl AlgorithmSignature for Signature {
    const LENGTH: Option<NonZeroUsize> =
        NonZeroUsize::new(<FieldBytesSize<Secp256k1> as Add>::Output::USIZE);

    fn try_from_slice(slice: &[u8]) -> anyhow::Result<Self> {
        Signature::try_from(slice).map_err(|err| anyhow::anyhow!(err))
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_bytes().to_vec())
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
    D: Default + Digest + Update,
    SigningKey: DigestSigner<D, Signature>,
    VerifyingKey: DigestVerifier<D, Signature>,
{
    fn default() -> Self {
        Es256k {
            _digest: PhantomData,
        }
    }
}

impl<D> Algorithm for Es256k<D>
where
    D: Default + Digest + Update,
    SigningKey: DigestSigner<D, Signature>,
    VerifyingKey: DigestVerifier<D, Signature>,
{
    type SigningKey = SigningKey;
    type VerifyingKey = VerifyingKey;
    type Signature = Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("ES256K")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        signing_key.sign_digest(|digest| Digest::update(digest, message))
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        // Some implementations (e.g., OpenSSL) produce high-S signatures, which
        // are considered invalid by this implementation. Hence, we perform normalization here.
        //
        // See also: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
        let normalized_signature = signature.normalize_s();

        verifying_key
            .verify_digest(
                |digest| {
                    Digest::update(digest, message);
                    Ok(())
                },
                &normalized_signature,
            )
            .is_ok()
    }
}

impl alg::SigningKey<Es256k> for SigningKey {
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
        Self::from_slice(raw).map_err(|err| anyhow::anyhow!(err))
    }

    fn to_verifying_key(&self) -> VerifyingKey {
        *self.verifying_key()
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
        let bytes = self.to_encoded_point(true).as_bytes().to_vec();
        Cow::Owned(bytes)
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

        let JsonWebKey::EllipticCurve { curve, x, y, .. } = jwk else {
            return Err(JwkError::key_type(jwk, KeyType::EllipticCurve));
        };
        JsonWebKey::ensure_curve(curve, "secp256k1")?;
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
        create_jwk(key.verifying_key(), Some(key))
    }
}

impl TryFrom<&JsonWebKey<'_>> for SigningKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        let JsonWebKey::EllipticCurve { secret, .. } = jwk else {
            return Err(JwkError::key_type(jwk, KeyType::EllipticCurve));
        };
        let sk_bytes = secret.as_deref();
        let sk_bytes = sk_bytes.ok_or_else(|| JwkError::NoField("d".into()))?;
        JsonWebKey::ensure_len("d", sk_bytes, 32)?;

        let sk =
            Self::from_slice(sk_bytes).map_err(|err| JwkError::custom(anyhow::anyhow!(err)))?;
        jwk.ensure_key_match(sk)
    }
}
