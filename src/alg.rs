//! Implementations of JWT signing / verification algorithms. Also contains generic traits
//! for signing and verifying keys.

use core::fmt;

use crate::{alloc::Cow, Algorithm};

mod generic;
mod hmacs;
// Alternative ES256K implementations.
#[cfg(feature = "secp256k1")]
mod es256k;
#[cfg(feature = "k256")]
mod k256;
// Alternative EdDSA implementations.
#[cfg(feature = "ed25519-compact")]
mod eddsa_compact;
#[cfg(feature = "ed25519-dalek")]
mod eddsa_dalek;
#[cfg(feature = "exonum-crypto")]
mod eddsa_sodium;
// ES256 implemenation.
#[cfg(feature = "p256")]
mod p256;
// RSA implementation.
#[cfg(feature = "rsa")]
mod rsa;

#[cfg(feature = "ed25519-compact")]
pub use self::eddsa_compact::*;
#[cfg(feature = "ed25519-dalek")]
pub use self::eddsa_dalek::Ed25519;
#[cfg(feature = "exonum-crypto")]
pub use self::eddsa_sodium::Ed25519;
#[cfg(feature = "es256k")]
pub use self::es256k::Es256k;
pub use self::generic::{SecretBytes, SigningKey, VerifyingKey};
pub use self::hmacs::*;
#[cfg(feature = "k256")]
pub use self::k256::Es256k;
#[cfg(feature = "p256")]
pub use self::p256::Es256;
#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
pub use self::rsa::{
    ModulusBits, ModulusBitsError, Rsa, RsaError, RsaParseError, RsaPrivateKey, RsaPublicKey,
    RsaSignature,
};

/// Wrapper around keys allowing to enforce key strength requirements.
///
/// The wrapper signifies that the key has supported strength as per the corresponding
/// algorithm spec. For example, RSA keys must have length at least 2,048 bits per [RFC 7518].
/// Likewise, `HS*` keys must have at least the length of the hash output
/// (e.g., 32 bytes for `HS256`). Since these requirements sometimes clash with backward
/// compatibility (and sometimes a lesser level of security is enough),
/// notion of key strength is implemented in such an opt-in, composable way.
///
/// It's easy to convert a `StrongKey<T>` to `T` via [`into_inner()`](Self::into_inner()) or to
/// access `&T` via `AsRef` impl. In contrast, the reverse transformation is fallible, and
/// is defined with the help of [`TryFrom`]. The error type for `TryFrom` is [`WeakKeyError`],
/// a simple wrapper around a weak key.
///
/// # Examples
///
/// See [`StrongAlg`] docs for an example of usage.
///
/// [RFC 7518]: https://www.rfc-editor.org/rfc/rfc7518.html
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrongKey<T>(T);

impl<T> StrongKey<T> {
    /// Returns the wrapped value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> AsRef<T> for StrongKey<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

/// Error type used for fallible conversion into a [`StrongKey`].
///
/// The error wraps around a weak key, which can be extracted for further use.
#[derive(Debug)]
pub struct WeakKeyError<T>(pub T);

impl<T> fmt::Display for WeakKeyError<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Weak cryptographic key")
    }
}

#[cfg(feature = "std")]
impl<T: fmt::Debug + 'static> std::error::Error for WeakKeyError<T> {}

/// Wrapper around a JWT algorithm signalling that it supports only [`StrongKey`]s.
///
/// The wrapper will implement `Algorithm` if the wrapped value is an `Algorithm` with both
/// signing and verifying keys convertible to `StrongKey`s.
///
/// # Examples
///
/// ```
/// # use rand::thread_rng;
/// # use jwt_compact::{prelude::*, alg::{Hs256, Hs256Key, StrongAlg, StrongKey}};
/// # fn main() -> anyhow::Result<()> {
/// let weak_key = Hs256Key::new(b"too short!");
/// assert!(StrongKey::try_from(weak_key).is_err());
/// // There is no way to create a `StrongKey` from `weak_key`!
///
/// let strong_key: StrongKey<_> = Hs256Key::generate(&mut thread_rng());
/// let claims = // ...
/// #   Claims::empty();
/// let token = StrongAlg(Hs256)
///     .token(&Header::empty(), &claims, &strong_key)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct StrongAlg<T>(pub T);

#[allow(clippy::trait_duplication_in_bounds)] // false positive
impl<T: Algorithm> Algorithm for StrongAlg<T>
where
    StrongKey<T::SigningKey>: TryFrom<T::SigningKey>,
    StrongKey<T::VerifyingKey>: TryFrom<T::VerifyingKey>,
{
    type SigningKey = StrongKey<T::SigningKey>;
    type VerifyingKey = StrongKey<T::VerifyingKey>;
    type Signature = T::Signature;

    fn name(&self) -> Cow<'static, str> {
        self.0.name()
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        self.0.sign(&signing_key.0, message)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        self.0
            .verify_signature(signature, &verifying_key.0, message)
    }
}
