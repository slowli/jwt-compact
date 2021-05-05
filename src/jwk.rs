//! Basic support of JSON Web Keys (JWK).

use serde::{
    de::{Error as DeError, MapAccess, Unexpected, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::digest::{Digest, Output};

use core::{cmp, fmt};

use crate::alloc::{Cow, String, ToOwned, ToString, Vec};

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
    NoField(JwkFieldName),
    /// JWK field type is incorrect (e.g., a string instead of bytes).
    IncorrectFieldType(JwkFieldName),
    /// JWK field has an unexpected value.
    UnexpectedValue {
        /// Field name.
        field: JwkFieldName,
        /// Expected value of the field.
        expected: String,
        /// Actual value of the field.
        actual: String,
    },
    /// JWK field has an unexpected byte length.
    UnexpectedLen {
        /// Field name.
        field: JwkFieldName,
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

/// JWK field.
#[derive(Debug, Clone, Eq)]
#[non_exhaustive]
pub enum JwkFieldName {
    /// Key type (`kty`).
    KeyType,
    /// Secret bytes (`k`).
    SecretBytes,
    /// RSA modulus (`n`).
    RsaModulus,
    /// RSA public exponent (`e`).
    RsaPubExponent,
    /// Elliptic curve name (`crv`).
    EllipticCurveName,
    /// `x` coordinate on an elliptic curve (`x`).
    EllipticCurveX,
    /// `y` coordinate on an elliptic curve (`y`).
    EllipticCurveY,
    /// Other field.
    Other(String),
}

impl JwkFieldName {
    fn is_bytes(&self) -> bool {
        matches!(
            self,
            Self::SecretBytes
                | Self::RsaModulus
                | Self::RsaPubExponent
                | Self::EllipticCurveX
                | Self::EllipticCurveY
        )
    }
}

impl AsRef<str> for JwkFieldName {
    fn as_ref(&self) -> &str {
        match self {
            Self::KeyType => "kty",
            Self::SecretBytes => "k",
            Self::RsaModulus => "n",
            Self::RsaPubExponent => "e",
            Self::EllipticCurveName => "crv",
            Self::EllipticCurveX => "x",
            Self::EllipticCurveY => "y",
            Self::Other(other) => other,
        }
    }
}

impl From<String> for JwkFieldName {
    fn from(s: String) -> Self {
        match s.as_str() {
            "kty" => Self::KeyType,
            "k" => Self::SecretBytes,
            "n" => Self::RsaModulus,
            "e" => Self::RsaPubExponent,
            "crv" => Self::EllipticCurveName,
            "x" => Self::EllipticCurveX,
            "y" => Self::EllipticCurveY,
            _ => Self::Other(s),
        }
    }
}

impl From<&str> for JwkFieldName {
    fn from(s: &str) -> Self {
        match s {
            "kty" => Self::KeyType,
            "k" => Self::SecretBytes,
            "n" => Self::RsaModulus,
            "e" => Self::RsaPubExponent,
            "crv" => Self::EllipticCurveName,
            "x" => Self::EllipticCurveX,
            "y" => Self::EllipticCurveY,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl PartialEq for JwkFieldName {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl PartialOrd for JwkFieldName {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for JwkFieldName {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl fmt::Display for JwkFieldName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_ref(), formatter)
    }
}

/// Basic [JWK] functionality: serialization and creating thumbprints.
///
/// The internal format of the key is not exposed, but its fields can be indirectly accessed via
/// [`Self::thumbprint()`] method and [`Display`](fmt::Display) implementation. The latter returns
/// the presentation of the key used for hashing.
///
/// [JWK]: https://tools.ietf.org/html/rfc7517.html
#[derive(PartialEq, Clone)]
pub struct JsonWebKey<'a> {
    fields: Vec<(JwkFieldName, JwkField<'a>)>,
}

impl fmt::Debug for JsonWebKey<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_map()
            .entries(
                self.fields
                    .iter()
                    .map(|(name, field)| (name.as_ref(), field)),
            )
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
                name = name.as_ref(),
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
        fields.push((JwkFieldName::KeyType, JwkField::str(key_type)));
        JsonWebKeyBuilder {
            inner: Self { fields },
        }
    }

    fn field(&self, field_name: &JwkFieldName) -> Result<&JwkField<'a>, JwkError> {
        self.fields
            .iter()
            .find(|(name, _)| name == field_name)
            .map(|(_, value)| value)
            .ok_or_else(|| JwkError::NoField(field_name.to_owned()))
    }

    /// Ensures that a string field has an expected value.
    ///
    /// # Errors
    ///
    /// Returns an error if the field is not present, does not have a string type or has
    /// an unexpected value.
    pub fn ensure_str_field(
        &self,
        field_name: &JwkFieldName,
        expected_value: &str,
    ) -> Result<(), JwkError> {
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
        field_name: &JwkFieldName,
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
            map.serialize_entry(name.as_ref(), &value.to_string())?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for JsonWebKey<'static> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor;

        impl<'v> Visitor<'v> for MapVisitor {
            type Value = JsonWebKey<'static>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON web key")
            }

            fn visit_map<A: MapAccess<'v>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut fields: Vec<(JwkFieldName, JwkField<'static>)> =
                    Vec::with_capacity(map.size_hint().unwrap_or(JsonWebKey::CAPACITY));

                while let Some((field_name, value)) = map.next_entry::<String, String>()? {
                    let field_name = JwkFieldName::from(field_name);
                    if fields.iter().any(|(name, _)| *name == field_name) {
                        let mut msg = String::from("duplicate field: ");
                        msg.push_str(field_name.as_ref());
                        return Err(A::Error::custom(msg));
                    }

                    let value = if field_name.is_bytes() {
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
    fn assert_no_field(&self, field_name: &JwkFieldName) {
        let existing_field = self
            .inner
            .fields
            .iter()
            .find(|(name, _)| name == field_name);
        if let Some((_, old_value)) = existing_field {
            panic!("Field `{}` is already defined: {:?}", field_name, old_value);
        }
    }

    /// Adds a string field with the specified name.
    ///
    /// # Panics
    ///
    /// Panics if the field with this name is already present.
    pub fn with_str_field(
        mut self,
        field_name: impl Into<JwkFieldName>,
        value: &'static str,
    ) -> Self {
        let field_name = field_name.into();
        self.assert_no_field(&field_name);
        self.inner.fields.push((field_name, JwkField::str(value)));
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
        field_name: impl Into<JwkFieldName>,
        value: impl Into<Cow<'a, [u8]>>,
    ) -> Self {
        let field_name = field_name.into();
        self.assert_no_field(&field_name);
        self.inner
            .fields
            .push((field_name, JwkField::Bytes(value.into())));
        self
    }

    /// Consumes this builder creating [`JsonWebKey`].
    pub fn build(self) -> JsonWebKey<'a> {
        let mut inner = self.inner;
        inner.fields.sort_unstable_by(|(x, _), (y, _)| x.cmp(y));
        inner
    }
}

#[derive(Debug, Clone, PartialEq)]
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
    use crate::alg::Hs256Key;

    use assert_matches::assert_matches;
    use core::convert::TryFrom;

    fn create_jwk() -> JsonWebKey<'static> {
        JsonWebKey {
            fields: vec![
                ("crv".into(), JwkField::str("Ed25519")),
                ("kty".into(), JwkField::str("OKP")),
                ("x".into(), JwkField::Bytes(Cow::Borrowed(b"test"))),
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

        let absent_err = jwk
            .ensure_str_field(&JwkFieldName::EllipticCurveY, "?")
            .unwrap_err();
        assert_matches!(absent_err, JwkError::NoField(field) if field.as_ref() == "y");

        let type_err = jwk
            .ensure_str_field(&JwkFieldName::EllipticCurveX, "OKP")
            .unwrap_err();
        assert_matches!(type_err, JwkError::IncorrectFieldType(field) if field.as_ref() == "x");

        let val_err = jwk
            .ensure_str_field(&JwkFieldName::KeyType, "EC")
            .unwrap_err();
        assert_matches!(
            val_err,
            JwkError::UnexpectedValue { field, actual, .. }
                if field.as_ref() == "kty" && actual == "OKP"
        );

        let len_err = jwk
            .bytes_field(&JwkFieldName::EllipticCurveX, 16)
            .unwrap_err();
        assert_matches!(
            len_err,
            JwkError::UnexpectedLen { field, actual, .. } if field.as_ref() == "x" && actual == 4
        );
    }

    #[test]
    fn extra_jwk_fields() {
        let json_str = r#"
            { "kty": "oct", "k": "dGVzdA", "kid": "my-unique-key" }
        "#;
        let jwk: JsonWebKey<'_> = serde_json::from_str(json_str).unwrap();

        assert_eq!(jwk.fields.len(), 3);
        jwk.ensure_str_field(&"kid".into(), "my-unique-key")
            .unwrap();

        let key = Hs256Key::try_from(jwk).unwrap();
        let jwk_from_key = key.to_jwk();

        assert_eq!(jwk_from_key.fields.len(), 2);
        assert!(jwk_from_key
            .fields
            .iter()
            .all(|(name, _)| name.as_ref() != "kid"));
    }
}
