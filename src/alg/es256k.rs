//! `ES256K` algorithm implementation using the `secp256k1` crate.

use lazy_static::lazy_static;
use secp256k1::{
    constants::{
        COMPACT_SIGNATURE_SIZE, FIELD_SIZE, SECRET_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE,
    },
    ecdsa::Signature,
    All, Message, PublicKey, Secp256k1, SecretKey,
};
use sha2::{
    digest::{
        crypto_common::BlockSizeUser, generic_array::typenum::U32, FixedOutputReset, HashMarker,
    },
    Digest, Sha256,
};

use core::{marker::PhantomData, num::NonZeroUsize};

use crate::{
    alg::{SecretBytes, SigningKey, VerifyingKey},
    alloc::Cow,
    jwk::{JsonWebKey, JwkError, KeyType},
    Algorithm, AlgorithmSignature,
};

/// Byte size of a serialized EC coordinate.
const COORDINATE_SIZE: usize = FIELD_SIZE.len();

impl AlgorithmSignature for Signature {
    const LENGTH: Option<NonZeroUsize> = NonZeroUsize::new(COMPACT_SIGNATURE_SIZE);

    fn try_from_slice(slice: &[u8]) -> anyhow::Result<Self> {
        Signature::from_compact(slice).map_err(Into::into)
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
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
#[cfg_attr(docsrs, doc(cfg(any(feature = "es256k", feature = "k256"))))]
pub struct Es256k<D = Sha256> {
    context: Secp256k1<All>,
    _digest: PhantomData<D>,
}

impl<D> Default for Es256k<D>
where
    D: FixedOutputReset<OutputSize = U32> + BlockSizeUser + Clone + Default + HashMarker,
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
    D: FixedOutputReset<OutputSize = U32> + BlockSizeUser + Clone + Default + HashMarker,
{
    /// Creates a new algorithm instance.
    /// This is a (moderately) expensive operation, so if necessary, the algorithm should
    /// be `clone()`d rather than created anew.
    #[cfg_attr(docsrs, doc(cfg(feature = "es256k")))]
    pub fn new(context: Secp256k1<All>) -> Self {
        Es256k {
            context,
            _digest: PhantomData,
        }
    }
}

impl<D> Algorithm for Es256k<D>
where
    D: FixedOutputReset<OutputSize = U32> + BlockSizeUser + Clone + Default + HashMarker,
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
        let message = Message::from_digest(digest.finalize().into());

        self.context.sign_ecdsa(&message, signing_key)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        let mut digest = D::default();
        digest.update(message);
        let message = Message::from_digest(digest.finalize().into());

        // Some implementations (e.g., OpenSSL) produce high-S signatures, which
        // are considered invalid by this implementation. Hence, we perform normalization here.
        //
        // See also: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
        let mut normalized_signature = *signature;
        normalized_signature.normalize_s();

        self.context
            .verify_ecdsa(&message, &normalized_signature, verifying_key)
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

    fn as_bytes(&self) -> SecretBytes<'_> {
        SecretBytes::borrowed(&self[..])
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

fn create_jwk<'a>(pk: &PublicKey, sk: Option<&'a SecretKey>) -> JsonWebKey<'a> {
    let uncompressed = pk.serialize_uncompressed();
    JsonWebKey::EllipticCurve {
        curve: "secp256k1".into(),
        x: Cow::Owned(uncompressed[1..=COORDINATE_SIZE].to_vec()),
        y: Cow::Owned(uncompressed[(1 + COORDINATE_SIZE)..].to_vec()),
        secret: sk.map(|sk| SecretBytes::borrowed(&sk.as_ref()[..])),
    }
}

impl<'a> From<&'a PublicKey> for JsonWebKey<'a> {
    fn from(key: &'a PublicKey) -> JsonWebKey<'a> {
        create_jwk(key, None)
    }
}

impl TryFrom<&JsonWebKey<'_>> for PublicKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        let JsonWebKey::EllipticCurve { curve, x, y, .. } = jwk else {
            return Err(JwkError::key_type(jwk, KeyType::EllipticCurve));
        };
        JsonWebKey::ensure_curve(curve, "secp256k1")?;
        JsonWebKey::ensure_len("x", x, COORDINATE_SIZE)?;
        JsonWebKey::ensure_len("y", y, COORDINATE_SIZE)?;

        let mut key_bytes = [0_u8; UNCOMPRESSED_PUBLIC_KEY_SIZE];
        key_bytes[0] = 4; // uncompressed key marker
        key_bytes[1..=COORDINATE_SIZE].copy_from_slice(x);
        key_bytes[(1 + COORDINATE_SIZE)..].copy_from_slice(y);
        PublicKey::from_slice(&key_bytes[..]).map_err(JwkError::custom)
    }
}

impl<'a> From<&'a SecretKey> for JsonWebKey<'a> {
    fn from(key: &'a SecretKey) -> JsonWebKey<'a> {
        create_jwk(&key.to_verifying_key(), Some(key))
    }
}

impl TryFrom<&JsonWebKey<'_>> for SecretKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        let JsonWebKey::EllipticCurve { secret, .. } = jwk else {
            return Err(JwkError::key_type(jwk, KeyType::EllipticCurve));
        };
        let sk_bytes = secret.as_deref();
        let sk_bytes = sk_bytes.ok_or_else(|| JwkError::NoField("d".into()))?;
        JsonWebKey::ensure_len("d", sk_bytes, SECRET_KEY_SIZE)?;

        let sk = SecretKey::from_slice(sk_bytes).map_err(JwkError::custom)?;
        jwk.ensure_key_match(sk)
    }
}
