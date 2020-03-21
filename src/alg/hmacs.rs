use anyhow::bail;
use hmac::crypto_mac::generic_array::{
    typenum::{Unsigned, U32, U48, U64},
    GenericArray,
};
use hmac::{crypto_mac::MacResult, Hmac, Mac as _};
use rand_core::{CryptoRng, RngCore};
use sha2::{digest::BlockInput, Sha256, Sha384, Sha512};
use smallvec::{smallvec, SmallVec};
use zeroize::Zeroize;

use std::{borrow::Cow, fmt};

use crate::{Algorithm, AlgorithmSignature};

macro_rules! define_hmac_key {
    (
        $(#[$($attr:meta)+])*
        struct $name:ident<$digest:ident, $out_size:ident>([u8; $buffer_size:expr]);
    ) => {
        $(#[$($attr)+])*
        #[derive(Clone, Zeroize)]
        #[zeroize(drop)]
        pub struct $name(pub(crate) SmallVec<[u8; $buffer_size]>);

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
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
            pub fn hmac(&self, message: impl AsRef<[u8]>) -> MacResult<$out_size> {
                let mut hmac = Hmac::<$digest>::new_varkey(&self.0)
                    .expect("HMACs work with any key size");
                hmac.input(message.as_ref());
                hmac.result()
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
    struct Hs256Key<Sha256, U32>([u8; 64]);
}
define_hmac_key! {
    /// Signing / verifying key for `HS384` algorithm. Zeroed on drop.
    struct Hs384Key<Sha384, U48>([u8; 128]);
}
define_hmac_key! {
    /// Signing / verifying key for `HS512` algorithm. Zeroed on drop.
    struct Hs512Key<Sha512, U64>([u8; 128]);
}

/// `HS256` signing algorithm.
///
/// See [RFC 7518] for the algorithm specification.
///
/// [RFC 7518]: https://tools.ietf.org/html/rfc7518#section-3.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hs256;

impl AlgorithmSignature for MacResult<U32> {
    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 32 {
            bail!("Invalid signature length");
        }
        Ok(MacResult::new(GenericArray::clone_from_slice(bytes)))
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.clone().code().to_vec())
    }
}

impl Algorithm for Hs256 {
    type SigningKey = Hs256Key;
    type VerifyingKey = Hs256Key;
    type Signature = MacResult<U32>;

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

impl AlgorithmSignature for MacResult<U48> {
    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 48 {
            bail!("Invalid signature length");
        }
        Ok(MacResult::new(GenericArray::clone_from_slice(bytes)))
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.clone().code().to_vec())
    }
}

impl Algorithm for Hs384 {
    type SigningKey = Hs384Key;
    type VerifyingKey = Hs384Key;
    type Signature = MacResult<U48>;

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

impl AlgorithmSignature for MacResult<U64> {
    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 64 {
            bail!("Invalid signature length");
        }
        Ok(MacResult::new(GenericArray::clone_from_slice(bytes)))
    }

    fn as_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.clone().code().to_vec())
    }
}

impl Algorithm for Hs512 {
    type SigningKey = Hs512Key;
    type VerifyingKey = Hs512Key;
    type Signature = MacResult<U64>;

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
