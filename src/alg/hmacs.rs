use clear_on_drop::clear::Clear;
use failure::bail;
use hmac::crypto_mac::generic_array::{
    typenum::{U32, U48, U64},
    GenericArray,
};
use hmac::{crypto_mac::MacResult, Hmac, Mac as _};
use rand_core::{CryptoRng, RngCore};
use sha2::{Sha256, Sha384, Sha512};
use smallvec::{smallvec, SmallVec};

use std::{borrow::Cow, fmt};

use crate::{Algorithm, AlgorithmSignature};

macro_rules! define_hmac_key {
    ($alg_description:expr => $name:ident, $buffer_size:expr, $default_size:expr) => {
        #[doc = $alg_description]
        #[derive(Clone)]
        pub struct $name(pub(crate) SmallVec<[u8; $buffer_size]>);

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.debug_tuple(stringify!($name)).field(&"_").finish()
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                Clear::clear(&mut self.0);
            }
        }

        impl $name {
            /// Generates a random key using a cryptographically secure RNG.
            pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
                let mut key = $name(smallvec![0; $default_size]);
                rng.fill_bytes(&mut key.0);
                key
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
    };
}

define_hmac_key!("Signing / verifying key for `HS256` algorithm." => Hs256Key, 64, 64);
define_hmac_key!("Signing / verifying key for `HS384` algorithm." => Hs384Key, 128, 96);
define_hmac_key!("Signing / verifying key for `HS512` algorithm" => Hs512Key, 128, 128);

/// `HS256` signing algorithm.
///
/// See [RFC 7518] for the algorithm specification.
///
/// [RFC 7518]: https://tools.ietf.org/html/rfc7518#section-3.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hs256;

impl AlgorithmSignature for MacResult<U32> {
    fn try_from_slice(bytes: &[u8]) -> Result<Self, failure::Error> {
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
        let mut hmac =
            Hmac::<Sha256>::new_varkey(&signing_key.0).expect("HMACs work with any key size");
        hmac.input(message);
        hmac.result()
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        let mut hmac =
            Hmac::<Sha256>::new_varkey(&verifying_key.0).expect("HMACs work with any key size");
        hmac.input(message);
        hmac.result() == *signature
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
    fn try_from_slice(bytes: &[u8]) -> Result<Self, failure::Error> {
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
        let mut hmac =
            Hmac::<Sha384>::new_varkey(&signing_key.0).expect("HMACs work with any key size");
        hmac.input(message);
        hmac.result()
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        let mut hmac =
            Hmac::<Sha384>::new_varkey(&verifying_key.0).expect("HMACs work with any key size");
        hmac.input(message);
        hmac.result() == *signature
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
    fn try_from_slice(bytes: &[u8]) -> Result<Self, failure::Error> {
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
        let mut hmac =
            Hmac::<Sha512>::new_varkey(&signing_key.0).expect("HMACs work with any key size");
        hmac.input(message);
        hmac.result()
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        let mut hmac =
            Hmac::<Sha512>::new_varkey(&verifying_key.0).expect("HMACs work with any key size");
        hmac.input(message);
        hmac.result() == *signature
    }
}
