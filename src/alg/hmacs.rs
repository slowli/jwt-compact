//! JWT algorithms based on HMACs.

use anyhow::ensure;
use hmac::crypto_mac::generic_array::{typenum::Unsigned, GenericArray};
use hmac::{crypto_mac, Hmac, Mac as _, NewMac};
use rand_core::{CryptoRng, RngCore};
use sha2::{
    digest::{BlockInput, Digest},
    Sha256, Sha384, Sha512,
};
use smallvec::{smallvec, SmallVec};
use zeroize::Zeroize;

use core::{convert::TryFrom, fmt};

use crate::{
    alg::{SigningKey, StrongKey, VerifyingKey, WeakKeyError},
    alloc::Cow,
    jwk::{JsonWebKey, JwkError, KeyType},
    Algorithm, AlgorithmSignature,
};

macro_rules! define_hmac_signature {
    (
        $(#[$($attr:meta)+])*
        struct $name:ident<$digest:ident>;
    ) => {
        $(#[$($attr)+])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(crypto_mac::Output<Hmac<$digest>>);

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_tuple(stringify!($name)).field(&"_").finish()
            }
        }

        impl AlgorithmSignature for $name {
            fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
                let expected_len = <$digest as Digest>::OutputSize::to_usize();
                ensure!(bytes.len() == expected_len, "Invalid signature length");
                let bytes = GenericArray::clone_from_slice(bytes);
                Ok(Self(crypto_mac::Output::new(bytes)))
            }

            fn as_bytes(&self) -> Cow<'_, [u8]> {
                Cow::Owned(self.0.clone().into_bytes().to_vec())
            }
        }
    };
}

define_hmac_signature!(
    /// Signature produced by the [`Hs256`] algorithm.
    struct Hs256Signature<Sha256>;
);
define_hmac_signature!(
    /// Signature produced by the [`Hs384`] algorithm.
    struct Hs384Signature<Sha384>;
);
define_hmac_signature!(
    /// Signature produced by the [`Hs512`] algorithm.
    struct Hs512Signature<Sha512>;
);

macro_rules! define_hmac_key {
    (
        $(#[$($attr:meta)+])*
        struct $name:ident<$digest:ident>([u8; $buffer_size:expr]);
    ) => {
        $(#[$($attr)+])*
        #[derive(Clone, Zeroize)]
        #[zeroize(drop)]
        pub struct $name(pub(crate) SmallVec<[u8; $buffer_size]>);

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_tuple(stringify!($name)).field(&"_").finish()
            }
        }

        impl $name {
            /// Generates a random key using a cryptographically secure RNG.
            pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> StrongKey<Self> {
                let mut key = $name(smallvec![0; <$digest as BlockInput>::BlockSize::to_usize()]);
                rng.fill_bytes(&mut key.0);
                StrongKey(key)
            }

            /// Creates a key from the specified `bytes`.
            pub fn new(bytes: impl AsRef<[u8]>) -> Self {
                Self(bytes.as_ref().into())
            }

            /// Computes HMAC with this key and the specified `message`.
            fn hmac(&self, message: impl AsRef<[u8]>) -> crypto_mac::Output<Hmac<$digest>> {
                let mut hmac = Hmac::<$digest>::new_from_slice(&self.0)
                    .expect("HMACs work with any key size");
                hmac.update(message.as_ref());
                hmac.finalize()
            }
        }

        impl From<&[u8]> for $name {
            fn from(bytes: &[u8]) -> Self {
                $name(bytes.into())
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl AsMut<[u8]> for $name {
            fn as_mut(&mut self) -> &mut [u8] {
                &mut self.0
            }
        }

        impl TryFrom<$name> for StrongKey<$name> {
            type Error = WeakKeyError<$name>;

            fn try_from(value: $name) -> Result<Self, Self::Error> {
                if value.0.len() >= <$digest as BlockInput>::BlockSize::to_usize() {
                    Ok(StrongKey(value))
                } else {
                    Err(WeakKeyError(value))
                }
            }
        }
    };
}

define_hmac_key! {
    /// Signing / verifying key for `HS256` algorithm. Zeroed on drop.
    struct Hs256Key<Sha256>([u8; 64]);
}
define_hmac_key! {
    /// Signing / verifying key for `HS384` algorithm. Zeroed on drop.
    struct Hs384Key<Sha384>([u8; 128]);
}
define_hmac_key! {
    /// Signing / verifying key for `HS512` algorithm. Zeroed on drop.
    struct Hs512Key<Sha512>([u8; 128]);
}

/// `HS256` signing algorithm.
///
/// See [RFC 7518] for the algorithm specification.
///
/// [RFC 7518]: https://tools.ietf.org/html/rfc7518#section-3.2
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Hs256;

impl Algorithm for Hs256 {
    type SigningKey = Hs256Key;
    type VerifyingKey = Hs256Key;
    type Signature = Hs256Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("HS256")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        Hs256Signature(signing_key.hmac(message))
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        verifying_key.hmac(message) == signature.0
    }
}

/// `HS384` signing algorithm.
///
/// See [RFC 7518] for the algorithm specification.
///
/// [RFC 7518]: https://tools.ietf.org/html/rfc7518#section-3.2
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Hs384;

impl Algorithm for Hs384 {
    type SigningKey = Hs384Key;
    type VerifyingKey = Hs384Key;
    type Signature = Hs384Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("HS384")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        Hs384Signature(signing_key.hmac(message))
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        verifying_key.hmac(message) == signature.0
    }
}

/// `HS512` signing algorithm.
///
/// See [RFC 7518] for the algorithm specification.
///
/// [RFC 7518]: https://tools.ietf.org/html/rfc7518#section-3.2
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Hs512;

impl Algorithm for Hs512 {
    type SigningKey = Hs512Key;
    type VerifyingKey = Hs512Key;
    type Signature = Hs512Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("HS512")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        Hs512Signature(signing_key.hmac(message))
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        verifying_key.hmac(message) == signature.0
    }
}

macro_rules! impl_key_traits {
    ($key:ident<$alg:ident>) => {
        impl SigningKey<$alg> for $key {
            fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
                Ok(Self::from(raw))
            }

            fn to_verifying_key(&self) -> Self {
                self.clone()
            }

            fn as_bytes(&self) -> Cow<'_, [u8]> {
                Cow::Borrowed(self.as_ref())
            }
        }

        impl VerifyingKey<$alg> for $key {
            fn from_slice(raw: &[u8]) -> anyhow::Result<Self> {
                Ok(Self::from(raw))
            }

            fn as_bytes(&self) -> Cow<'_, [u8]> {
                Cow::Borrowed(self.as_ref())
            }
        }

        impl<'a> From<&'a $key> for JsonWebKey<'a> {
            fn from(key: &'a $key) -> JsonWebKey<'a> {
                JsonWebKey::Symmetric {
                    secret: Cow::Borrowed(key.as_ref()),
                }
            }
        }

        impl TryFrom<&JsonWebKey<'_>> for $key {
            type Error = JwkError;

            fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
                match jwk {
                    JsonWebKey::Symmetric { secret } => Ok(Self::new(secret)),
                    _ => Err(JwkError::key_type(jwk, KeyType::Symmetric)),
                }
            }
        }
    };
}

impl_key_traits!(Hs256Key<Hs256>);
impl_key_traits!(Hs384Key<Hs384>);
impl_key_traits!(Hs512Key<Hs512>);
