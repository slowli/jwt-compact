//! Generic traits providing uniform interfaces for a certain cryptosystem
//! across different backends.

use zeroize::Zeroize;

use core::{fmt, ops};

use crate::{
    alloc::{Cow, Vec},
    Algorithm,
};

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
    fn as_bytes(&self) -> Cow<'_, [u8]>;
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
    fn as_bytes(&self) -> SecretBytes<'_>;
}

/// Generic container for secret bytes, which can be either owned or borrowed.
/// If owned, bytes are zeroized on drop.
///
/// Comparisons on `SecretBytes` are constant-time, but other operations (e.g., deserialization)
/// may be var-time.
///
/// # Serialization
///
/// Represented in human-readable formats (JSON, TOML, YAML, etc.) as a base64-url encoded string
/// with no padding. For other formats (e.g., CBOR), `SecretBytes` will be serialized directly
/// as a byte sequence.
#[derive(Clone)]
pub struct SecretBytes<'a>(Cow<'a, [u8]>);

impl<'a> SecretBytes<'a> {
    pub(crate) fn new(inner: Cow<'a, [u8]>) -> Self {
        Self(inner)
    }

    /// Creates secret bytes from a borrowed slice.
    pub fn borrowed(bytes: &'a [u8]) -> Self {
        Self(Cow::Borrowed(bytes))
    }

    /// Creates secret bytes from an owned `Vec`.
    pub fn owned(bytes: Vec<u8>) -> Self {
        Self(Cow::Owned(bytes))
    }
}

impl fmt::Debug for SecretBytes<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("len", &self.0.len())
            .finish()
    }
}

impl Drop for SecretBytes<'_> {
    fn drop(&mut self) {
        // if bytes are borrowed, we don't need to perform any special cleaning.
        if let Cow::Owned(bytes) = &mut self.0 {
            Zeroize::zeroize(bytes);
        }
    }
}

impl ops::Deref for SecretBytes<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl AsRef<[u8]> for SecretBytes<'_> {
    fn as_ref(&self) -> &[u8] {
        &*self
    }
}

impl PartialEq for SecretBytes<'_> {
    fn eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self.as_ref(), other.as_ref()).into()
    }
}
