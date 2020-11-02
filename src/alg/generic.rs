//! Generic traits providing uniform interfaces for a certain cryptosystem
//! across different backends.

use crate::{alloc::Cow, Algorithm};

/// Verifying key for a specific signature cryptosystem. In the case of public-key cryptosystems,
/// this is a public key.
///
/// This trait provides a uniform interface for different backends / implementations
/// of the same cryptosystem.
pub trait VerifyingKey<T>: Sized
where
    T: Algorithm<VerifyingKey = Self>,
{
    /// Creates a key from `raw` bytes. Returns an error if the bytes do not represent
    /// a valid key.
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self>;

    /// Returns the key as raw bytes.
    ///
    /// Implementations should return `Cow::Borrowed` whenever possible (that is, if the bytes
    /// are actually stored within the implementing data structure).
    fn as_bytes(&self) -> Cow<[u8]>;
}

/// Signing key for a specific signature cryptosystem. In the case of public-key cryptosystems,
/// this is a private key.
///
/// This trait provides a uniform interface for different backends / implementations
/// of the same cryptosystem.
pub trait SigningKey<T>: Sized
where
    T: Algorithm<SigningKey = Self>,
{
    /// Creates a key from `raw` bytes. Returns an error if the bytes do not represent
    /// a valid key.
    fn from_slice(raw: &[u8]) -> anyhow::Result<Self>;

    /// Converts a signing key to a verification key.
    fn to_verifying_key(&self) -> T::VerifyingKey;

    /// Returns the key as raw bytes.
    ///
    /// Implementations should return `Cow::Borrowed` whenever possible (that is, if the bytes
    /// are actually stored within the implementing data structure).
    fn as_bytes(&self) -> Cow<[u8]>;
}
