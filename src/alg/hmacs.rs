use anyhow::bail;
use hmac::crypto_mac::generic_array::{typenum::Unsigned, GenericArray};
use hmac::{crypto_mac, Hmac, Mac as _, NewMac};
use rand_core::{CryptoRng, RngCore};
use sha2::{digest::BlockInput, Sha256, Sha384, Sha512};
use smallvec::{smallvec, SmallVec};
use zeroize::Zeroize;

use std::{borrow::Cow, fmt};

use crate::{Algorithm, AlgorithmSignature};

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
            pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
                let mut key = $name(smallvec![0; <$digest as BlockInput>::BlockSize::to_usize()]);
                rng.fill_bytes(&mut key.0);
                key
            }

            /// Computes HMAC with this key and the specified `message`.
            pub fn hmac(&self, message: impl AsRef<[u8]>) -> crypto_mac::Output<Hmac<$digest>> {
                let mut hmac = Hmac::<$digest>::new_varkey(&self.0)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hs256;

impl AlgorithmSignature for crypto_mac::Output<Hmac<Sha256>> {
    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 32 {
            bail!("Invalid signature length");
        }
        Ok(crypto_mac::Output::new(GenericArray::clone_from_slice(
            bytes,
        )))
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.clone().into_bytes().to_vec())
    }
}

impl Algorithm for Hs256 {
    type SigningKey = Hs256Key;
    type VerifyingKey = Hs256Key;
    type Signature = crypto_mac::Output<Hmac<Sha256>>;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("HS256")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        signing_key.hmac(message)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        verifying_key.hmac(message) == *signature
    }
}

/// `HS384` signing algorithm.
///
/// See [RFC 7518] for the algorithm specification.
///
/// [RFC 7518]: https://tools.ietf.org/html/rfc7518#section-3.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hs384;

impl AlgorithmSignature for crypto_mac::Output<Hmac<Sha384>> {
    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 48 {
            bail!("Invalid signature length");
        }
        Ok(crypto_mac::Output::new(GenericArray::clone_from_slice(
            bytes,
        )))
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.clone().into_bytes().to_vec())
    }
}

impl Algorithm for Hs384 {
    type SigningKey = Hs384Key;
    type VerifyingKey = Hs384Key;
    type Signature = crypto_mac::Output<Hmac<Sha384>>;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("HS384")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        signing_key.hmac(message)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        verifying_key.hmac(message) == *signature
    }
}

/// `HS512` signing algorithm.
///
/// See [RFC 7518] for the algorithm specification.
///
/// [RFC 7518]: https://tools.ietf.org/html/rfc7518#section-3.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hs512;

impl AlgorithmSignature for crypto_mac::Output<Hmac<Sha512>> {
    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 64 {
            bail!("Invalid signature length");
        }
        Ok(crypto_mac::Output::new(GenericArray::clone_from_slice(
            bytes,
        )))
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.clone().into_bytes().to_vec())
    }
}

impl Algorithm for Hs512 {
    type SigningKey = Hs512Key;
    type VerifyingKey = Hs512Key;
    type Signature = crypto_mac::Output<Hmac<Sha512>>;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("HS512")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        signing_key.hmac(message)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        verifying_key.hmac(message) == *signature
    }
}
