//! Basic support of JSON Web Keys (JWK).

use serde::{
    de::{Error as DeError, MapAccess, Unexpected, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::digest::{Digest, Output};

use core::fmt;

use crate::alloc::{Cow, String, ToString, Vec};

/// Conversion to [`JsonWebKey`]. This trait is implemented for all verifying keys in the crate.
pub trait ToJsonWebKey {
    /// Converts this key to a JWK presentation.
    fn to_jwk(&self) -> JsonWebKey<'_>;
}

/// Errors that can occur when transforming a [`JsonWebKey`] into the presentation specific for
/// a crypto backend, via [`TryFrom`](core::convert::TryFrom) trait.
#[derive(Debug)]
pub enum JwkError {
    /// Required field is absent from JWK.
    NoField(String),
    /// JWK field type is incorrect (e.g., a string instead of bytes).
    IncorrectFieldType(String),
    /// JWK field has an unexpected value.
    UnexpectedValue {
        /// Field name.
        field: String,
        /// Expected value of the field.
        expected: String,
        /// Actual value of the field.
        actual: String,
    },
    /// JWK field has an unexpected byte length.
    UnexpectedLen {
        /// Field name.
        field: String,
        /// Expected byte length of the field.
        expected: usize,
        /// Actual byte length of the field.
        actual: usize,
    },
    /// Custom error specific to a crypto backend.
    Custom(anyhow::Error),
}

impl fmt::Display for JwkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoField(field) => {
                write!(formatter, "field `{}` is absent from JWK", field)
            }
            Self::IncorrectFieldType(field) => {
                write!(formatter, "field `{}` has incorrect type", field)
            }
            Self::UnexpectedValue {
                field,
                expected,
                actual,
            } => {
                write!(
                    formatter,
                    "field `{}` has unexpected value (expected: {}, got: {})",
                    field, expected, actual
                )
            }
            Self::UnexpectedLen {
                field,
                expected,
                actual,
            } => {
                write!(
                    formatter,
                    "field `{}` has unexpected length (expected: {}, got: {})",
                    field, expected, actual
                )
            }
            Self::Custom(err) => fmt::Display::fmt(err, formatter),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for JwkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Custom(err) => Some(err.as_ref()),
            _ => None,
        }
    }
}

impl JwkError {
    /// Creates a `Custom` error variant.
    pub fn custom(err: impl Into<anyhow::Error>) -> Self {
        Self::Custom(err.into())
    }
}

/// Basic [JWK] functionality: serialization and creating thumbprints.
///
/// The internal format of the key is not exposed, but its fields can be indirectly accessed via
/// [`Self::thumbprint()`] method and [`Display`](fmt::Display) implementation. The latter returns
/// the presentation of the key used for hashing.
///
/// [JWK]: https://tools.ietf.org/html/rfc7517.html
#[derive(PartialEq)]
pub struct JsonWebKey<'a> {
    fields: Vec<(String, JwkField<'a>)>,
}

impl fmt::Debug for JsonWebKey<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_map()
            .entries(self.fields.iter().map(|(name, field)| (name, field)))
            .finish()
    }
}

impl fmt::Display for JsonWebKey<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("{")?;
        let field_len = self.fields.len();
        for (i, (name, value)) in self.fields.iter().enumerate() {
            write!(
                formatter,
                "\"{name}\":\"{value}\"",
                name = name,
                value = value
            )?;
            if i + 1 < field_len {
                formatter.write_str(",")?;
            }
        }
        formatter.write_str("}")
    }
}

impl<'a> JsonWebKey<'a> {
    const CAPACITY: usize = 4;

    /// Instantiates a key builder.
    pub fn builder(key_type: &'static str) -> JsonWebKeyBuilder<'a> {
        let mut fields = Vec::with_capacity(Self::CAPACITY);
        fields.push(("kty".to_owned(), JwkField::str(key_type)));
        JsonWebKeyBuilder {
            inner: Self { fields },
        }
    }

    fn field(&self, field_name: &str) -> Result<&JwkField<'a>, JwkError> {
        self.fields
            .iter()
            .find(|(name, _)| *name == field_name)
            .map(|(_, value)| value)
            .ok_or_else(|| JwkError::NoField(field_name.to_owned()))
    }

    /// Ensures that a string field has an expected value.
    ///
    /// # Errors
    ///
    /// Returns an error if the field is not present, does not have a string type or has
    /// an unexpected value.
    pub fn ensure_str_field(&self, field_name: &str, expected_value: &str) -> Result<(), JwkError> {
        if let JwkField::Str(val) = self.field(field_name)? {
            if *val == expected_value {
                Ok(())
            } else {
                Err(JwkError::UnexpectedValue {
                    field: field_name.to_owned(),
                    expected: expected_value.to_owned(),
                    actual: val.clone().into_owned(),
                })
            }
        } else {
            Err(JwkError::IncorrectFieldType(field_name.to_owned()))
        }
    }

    /// Obtains a bytes field with the specified name from this JWK.
    ///
    /// # Errors
    ///
    /// Returns an error if the field is not present or does not have the bytes type.
    pub fn bytes_field(
        &self,
        field_name: &str,
        expected_len: impl Into<Option<usize>>,
    ) -> Result<&[u8], JwkError> {
        let expected_len = expected_len.into();
        if let JwkField::Bytes(val) = self.field(field_name)? {
            if let Some(expected) = expected_len {
                if expected != val.len() {
                    return Err(JwkError::UnexpectedLen {
                        field: field_name.to_owned(),
                        expected,
                        actual: val.len(),
                    });
                }
            }
            Ok(&*val)
        } else {
            Err(JwkError::IncorrectFieldType(field_name.to_owned()))
        }
    }

    /// Computes a thumbprint of this JWK as per [RFC 7638].
    ///
    /// [RFC 7638]: https://tools.ietf.org/html/rfc7638
    pub fn thumbprint<D: Digest>(&self) -> Output<D> {
        D::digest(self.to_string().as_bytes())
    }
}

impl Serialize for JsonWebKey<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.fields.len()))?;
        for (name, value) in &self.fields {
            map.serialize_entry(name.as_str(), &value.to_string())?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for JsonWebKey<'static> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor;

        const BYTE_FIELDS: &[&str] = &["x", "y", "k", "e", "n"];

        impl<'v> Visitor<'v> for MapVisitor {
            type Value = JsonWebKey<'static>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON web key")
            }

            fn visit_map<A: MapAccess<'v>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut fields: Vec<(String, JwkField<'static>)> =
                    Vec::with_capacity(map.size_hint().unwrap_or(JsonWebKey::CAPACITY));

                while let Some((field_name, value)) = map.next_entry::<String, String>()? {
                    if fields.iter().any(|(name, _)| *name == field_name) {
                        return Err(A::Error::custom("duplicate field"));
                    }

                    let value = if BYTE_FIELDS.contains(&field_name.as_str()) {
                        let bytes = base64::decode_config(&*value, base64::URL_SAFE_NO_PAD)
                            .map_err(|_| {
                                A::Error::invalid_value(
                                    Unexpected::Str(&*value),
                                    &"base64url-encoded data",
                                )
                            })?;
                        JwkField::Bytes(bytes.into())
                    } else {
                        JwkField::Str(value.into())
                    };
                    fields.push((field_name, value));
                }

                fields.sort_unstable_by(|(x, _), (y, _)| x.cmp(y));
                Ok(JsonWebKey { fields })
            }
        }

        deserializer.deserialize_map(MapVisitor)
    }
}

/// Builder for [`JsonWebKey`].
#[derive(Debug)]
pub struct JsonWebKeyBuilder<'a> {
    inner: JsonWebKey<'a>,
}

impl<'a> JsonWebKeyBuilder<'a> {
    fn assert_no_field(&self, field_name: &str) {
        let existing_field = self
            .inner
            .fields
            .iter()
            .find(|(name, _)| *name == field_name);
        if let Some((_, old_value)) = existing_field {
            panic!("Field `{}` is already defined: {:?}", field_name, old_value);
        }
    }

    /// Adds a string field with the specified name.
    ///
    /// # Panics
    ///
    /// Panics if the field with this name is already present.
    pub fn with_str_field(mut self, field_name: &'static str, value: &'static str) -> Self {
        self.assert_no_field(field_name);
        self.inner
            .fields
            .push((field_name.to_owned(), JwkField::str(value)));
        self
    }

    /// Adds a byte field with the specified name. Bytes can be borrowed from the key, or
    /// can be instantiated for this method.
    ///
    /// # Panics
    ///
    /// Panics if the field with this name is already present.
    pub fn with_bytes_field(
        mut self,
        field_name: &'static str,
        value: impl Into<Cow<'a, [u8]>>,
    ) -> Self {
        self.assert_no_field(field_name);
        self.inner
            .fields
            .push((field_name.to_owned(), JwkField::Bytes(value.into())));
        self
    }

    /// Consumes this builder creating [`JsonWebKey`].
    pub fn build(self) -> JsonWebKey<'a> {
        let mut inner = self.inner;
        inner.fields.sort_unstable_by(|(x, _), (y, _)| x.cmp(y));
        inner
    }
}

#[derive(Debug, PartialEq)]
enum JwkField<'a> {
    Str(Cow<'static, str>),
    Bytes(Cow<'a, [u8]>),
}

impl fmt::Display for JwkField<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Str(s) => formatter.write_str(s),
            Self::Bytes(bytes) => {
                let encoded = base64::encode_config(bytes, base64::URL_SAFE_NO_PAD);
                formatter.write_str(&encoded)
            }
        }
    }
}

impl JwkField<'_> {
    fn str(s: &'static str) -> Self {
        Self::Str(Cow::Borrowed(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;

    fn create_jwk() -> JsonWebKey<'static> {
        JsonWebKey {
            fields: vec![
                ("crv".to_owned(), JwkField::str("Ed25519")),
                ("kty".to_owned(), JwkField::str("OKP")),
                ("x".to_owned(), JwkField::Bytes(Cow::Borrowed(b"test"))),
            ],
        }
    }

    #[test]
    fn serializing_jwk() {
        let jwk = create_jwk();

        let json = serde_json::to_value(&jwk).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "crv": "Ed25519", "kty": "OKP", "x": "dGVzdA" })
        );

        let restored: JsonWebKey<'_> = serde_json::from_value(json).unwrap();
        assert_eq!(restored, jwk);
    }

    #[test]
    fn jwk_deserialization_errors() {
        let duplicate_field_json = r#"{"crv":"Ed25519","crv":"secp256k1"}"#;
        let duplicate_field_err = serde_json::from_str::<JsonWebKey<'_>>(duplicate_field_json)
            .unwrap_err()
            .to_string();
        assert!(
            duplicate_field_err.contains("duplicate field"),
            "{}",
            duplicate_field_err
        );

        let base64_json = r#"{"crv":"Ed25519","kty":"OKP","x":"??"}"#;
        let base64_err = serde_json::from_str::<JsonWebKey<'_>>(base64_json)
            .unwrap_err()
            .to_string();
        assert!(
            base64_err.contains("invalid value: string \"??\""),
            "{}",
            base64_err
        );
        assert!(
            base64_err.contains("base64url-encoded data"),
            "{}",
            base64_err
        );
    }

    #[test]
    fn converting_jwk_errors() {
        let jwk = create_jwk();

        let absent_err = jwk.ensure_str_field("y", "?").unwrap_err();
        assert_matches!(absent_err, JwkError::NoField(field) if field == "y");

        let type_err = jwk.ensure_str_field("x", "OKP").unwrap_err();
        assert_matches!(type_err, JwkError::IncorrectFieldType(field) if field == "x");

        let val_err = jwk.ensure_str_field("kty", "EC").unwrap_err();
        assert_matches!(
            val_err,
            JwkError::UnexpectedValue { field, actual, .. } if field == "kty" && actual == "OKP"
        );

        let len_err = jwk.bytes_field("x", 16).unwrap_err();
        assert_matches!(
            len_err,
            JwkError::UnexpectedLen { field, actual, .. } if field == "x" && actual == 4
        );
    }
}
