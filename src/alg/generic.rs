//! Generic traits providing uniform interfaces for a certain cryptosystem
//! across different backends.

use sha2::digest::{Digest, Output};

use core::fmt;

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
    fn as_bytes(&self) -> Cow<'_, [u8]>;
}

#[allow(missing_docs)] // FIXME
pub trait ThumbprintKey {
    fn key_fields(&self) -> KeyFields<'_>;

    fn thumbprint<D: Digest>(&self) -> Output<D> {
        self.key_fields().thumbprint::<D>()
    }
}

#[allow(missing_docs)] // FIXME
pub struct KeyFields<'a> {
    fields: Vec<(&'static str, KeyField<'a>)>,
}

impl fmt::Debug for KeyFields<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_map()
            .entries(self.fields.iter().map(|(name, field)| (*name, field)))
            .finish()
    }
}

#[allow(missing_docs)] // FIXME
impl<'a> KeyFields<'a> {
    pub fn new(key_type: &'static str) -> Self {
        let mut fields = Vec::with_capacity(4);
        fields.push(("kty", KeyField::Str(key_type)));
        Self { fields }
    }

    pub fn with_str_field(mut self, field_name: &'static str, value: &'static str) -> Self {
        let existing_field = self.fields.iter().find(|(name, _)| *name == field_name);
        if let Some((_, old_value)) = existing_field {
            panic!("Field `{}` is already defined: {:?}", field_name, old_value);
        }
        self.fields.push((field_name, KeyField::Str(value)));
        self
    }

    pub fn with_bytes_field(
        mut self,
        field_name: &'static str,
        value: impl Into<Cow<'a, [u8]>>,
    ) -> Self {
        let existing_field = self.fields.iter().find(|(name, _)| *name == field_name);
        if let Some((_, old_value)) = existing_field {
            panic!("Field `{}` is already defined: {:?}", field_name, old_value);
        }
        self.fields
            .push((field_name, KeyField::Bytes(value.into())));
        self
    }

    pub fn thumbprint<D: Digest>(mut self) -> Output<D> {
        self.fields.sort_unstable_by_key(|(name, _)| *name);
        let field_len = self.fields.len();

        let mut digest = D::new();
        digest.update(b"{");
        for (i, (name, value)) in self.fields.into_iter().enumerate() {
            digest.update(b"\"");
            digest.update(name.as_bytes());
            digest.update(b"\":\"");
            value.digest_as_str(&mut digest);
            digest.update(b"\"");

            if i + 1 < field_len {
                digest.update(b",");
            }
        }
        digest.update(b"}");
        digest.finalize()
    }
}

#[derive(Debug)]
enum KeyField<'a> {
    Str(&'static str),
    Bytes(Cow<'a, [u8]>),
}

impl KeyField<'_> {
    fn digest_as_str(&self, digest: &mut impl Digest) {
        match self {
            Self::Str(s) => digest.update(s),
            Self::Bytes(bytes) => {
                let encoded = base64::encode_config(bytes, base64::URL_SAFE_NO_PAD);
                digest.update(&encoded);
            }
        }
    }
}
