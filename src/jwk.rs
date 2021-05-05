//! Basic support of [JSON Web Keys](https://tools.ietf.org/html/rfc7517.html) (JWK).
//!
//! The functionality defined in this module allows converting between
//! the [generic JWK format](JsonWebKey) and key presentation specific for the crypto backend.
//! [`JsonWebKey`]s can be (de)serialized using [`serde`] infrastructure, and can be used
//! to compute key thumbprint as per [RFC 7638].
//!
//! [`serde`]: https://crates.io/crates/serde
//! [RFC 7638]: https://tools.ietf.org/html/rfc7638
//!
//! # Examples
//!
//! ```
//! use jwt_compact::{alg::Hs256Key, jwk::JsonWebKey};
//! use sha2::Sha256;
//! # use std::convert::TryFrom;
//!
//! # fn main() -> anyhow::Result<()> {
//! // Load a key from the JWK presentation.
//! let json_str = r#"
//!     { "kty": "oct", "k": "t-bdv41MJXExXnpquHBuDn7n1YGyX7gLQchVHAoNu50" }
//! "#;
//! let jwk: JsonWebKey<'_> = serde_json::from_str(json_str)?;
//! let key = Hs256Key::try_from(&jwk)?;
//!
//! // Convert `key` back to JWK.
//! let jwk_from_key = JsonWebKey::from(&key);
//! assert_eq!(jwk_from_key, jwk);
//! println!("{}", serde_json::to_string(&jwk)?);
//!
//! // Compute the key thumbprint.
//! let thumbprint = jwk_from_key.thumbprint::<Sha256>();
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use sha2::digest::{Digest, Output};

use core::{convert::TryFrom, fmt};

use crate::{
    alg::SigningKey,
    alloc::{Cow, String, ToOwned, ToString, Vec},
    Algorithm,
};

/// Errors that can occur when transforming a [`JsonWebKey`] into the presentation specific for
/// a crypto backend, via [`TryFrom`](core::convert::TryFrom) trait.
#[derive(Debug)]
pub enum JwkError {
    /// Required field is absent from JWK.
    NoField(String),
    /// FIXME
    UnexpectedKeyType,
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
    /// Signing and verifying keys do not match.
    MismatchedKeys,
    /// Custom error specific to a crypto backend.
    Custom(anyhow::Error),
}

impl fmt::Display for JwkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedKeyType => formatter.write_str("Unexpected key type"),
            Self::NoField(field) => write!(formatter, "field `{}` is absent from JWK", field),
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
            Self::MismatchedKeys => {
                formatter.write_str("Private and public keys encoded in JWK do not match")
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

/// Basic [JWK] functionality: (de)serialization and creating thumbprints.
///
/// [`Self::thumbprint()`] and the [`Display`](fmt::Display) implementation
/// allow to get the overall presentation of the key.
///
/// [JWK]: https://tools.ietf.org/html/rfc7517.html
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kty")]
#[allow(missing_docs)]
pub enum JsonWebKey<'a> {
    #[serde(rename = "RSA")]
    Rsa {
        #[serde(rename = "n", with = "base64url")]
        modulus: Cow<'a, [u8]>,
        #[serde(rename = "e", with = "base64url")]
        public_exponent: Cow<'a, [u8]>,
    },
    #[serde(rename = "EC")]
    EllipticCurve {
        #[serde(rename = "crv")]
        curve: Cow<'a, str>,
        #[serde(with = "base64url")]
        x: Cow<'a, [u8]>,
        #[serde(with = "base64url")]
        y: Cow<'a, [u8]>,
        #[serde(
            rename = "d",
            default,
            skip_serializing_if = "Option::is_none",
            with = "base64url_opt"
        )]
        secret: Option<Cow<'a, [u8]>>,
    },
    #[serde(rename = "oct")]
    Symmetric {
        #[serde(rename = "k", with = "base64url")]
        secret: Cow<'a, [u8]>,
    },
    #[serde(rename = "OKP")]
    KeyPair {
        #[serde(rename = "crv")]
        curve: Cow<'a, str>,
        #[serde(with = "base64url")]
        x: Cow<'a, [u8]>,
        #[serde(
            rename = "d",
            default,
            skip_serializing_if = "Option::is_none",
            with = "base64url_opt"
        )]
        secret: Option<Cow<'a, [u8]>>,
    },
}

impl<'a> JsonWebKey<'a> {
    pub(crate) fn ensure_curve(curve: &str, expected: &str) -> Result<(), JwkError> {
        if curve == expected {
            Ok(())
        } else {
            Err(JwkError::UnexpectedValue {
                field: "crv".to_owned(),
                expected: expected.to_owned(),
                actual: curve.to_owned(),
            })
        }
    }

    pub(crate) fn ensure_len(
        field: &str,
        bytes: &[u8],
        expected_len: usize,
    ) -> Result<(), JwkError> {
        if bytes.len() == expected_len {
            Ok(())
        } else {
            Err(JwkError::UnexpectedLen {
                field: field.to_owned(),
                expected: expected_len,
                actual: bytes.len(),
            })
        }
    }

    /// Ensures that the provided signing key matches the verifying key restored from the same JWK.
    /// This is useful when implementing [`TryFrom`] conversion from `JsonWebKey` for private keys.
    pub(crate) fn ensure_key_match<Alg, K>(&self, signing_key: K) -> Result<K, JwkError>
    where
        Alg: Algorithm<SigningKey = K>,
        K: SigningKey<Alg>,
        Alg::VerifyingKey: for<'jwk> TryFrom<&'jwk Self, Error = JwkError> + PartialEq,
    {
        let verifying_key = <Alg::VerifyingKey>::try_from(self)?;
        if verifying_key == signing_key.to_verifying_key() {
            Ok(signing_key)
        } else {
            Err(JwkError::MismatchedKeys)
        }
    }

    /// Returns a copy of this key with parts not necessary for signature verification removed.
    pub fn to_verifying_key(&self) -> Self {
        match self {
            Self::Rsa {
                modulus,
                public_exponent,
            } => Self::Rsa {
                modulus: modulus.clone(),
                public_exponent: public_exponent.clone(),
            },

            Self::EllipticCurve { curve, x, y, .. } => Self::EllipticCurve {
                curve: curve.clone(),
                x: x.clone(),
                y: y.clone(),
                secret: None,
            },

            Self::Symmetric { secret } => Self::Symmetric {
                secret: secret.clone(),
            },

            Self::KeyPair { curve, x, .. } => Self::KeyPair {
                curve: curve.clone(),
                x: x.clone(),
                secret: None,
            },
        }
    }

    /// Computes a thumbprint of this JWK. If the key contains only mandatory fields
    /// (which is the case for keys created using [`From`] trait),
    /// the result complies to key thumbprint defined in [RFC 7638].
    ///
    /// [RFC 7638]: https://tools.ietf.org/html/rfc7638
    pub fn thumbprint<D: Digest>(&self) -> Output<D> {
        D::digest(self.to_verifying_key().to_string().as_bytes())
    }
}

impl fmt::Display for JsonWebKey<'_> {
    // TODO: Not the most efficient approach
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json_value = serde_json::to_value(self).expect("Cannot convert JsonWebKey to JSON");
        let json_value = json_value.as_object().unwrap();
        // ^ unwrap() is safe: `JsonWebKey` serialization is always an object.

        let mut json_entries: Vec<_> = json_value.iter().collect();
        json_entries.sort_unstable_by(|(x, _), (y, _)| x.cmp(y));

        formatter.write_str("{")?;
        let field_count = json_entries.len();
        for (i, (name, value)) in json_entries.into_iter().enumerate() {
            write!(formatter, "\"{name}\":{value}", name = name, value = value)?;
            if i + 1 < field_count {
                formatter.write_str(",")?;
            }
        }
        formatter.write_str("}")
    }
}

/// [`JsonWebKey`] together with user-defined info, such as key ID (`kid`).
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ExtendedJsonWebKey<'a, T = ()> {
    /// Standard fields.
    #[serde(flatten)]
    pub base: JsonWebKey<'a>,
    /// User-defined fields.
    #[serde(flatten)]
    pub extra: T,
}

impl<'a> From<JsonWebKey<'a>> for ExtendedJsonWebKey<'a> {
    fn from(base: JsonWebKey<'a>) -> Self {
        Self { base, extra: () }
    }
}

mod base64url {
    use serde::{
        de::{Error as DeError, Unexpected, Visitor},
        Deserializer, Serializer,
    };

    use core::fmt;

    use crate::alloc::{Cow, Vec};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode_config(value, base64::URL_SAFE_NO_PAD))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Cow<'static, [u8]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Base64Visitor;

        impl Visitor<'_> for Base64Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "base64url-encoded data")
            }

            fn visit_str<E: DeError>(self, value: &str) -> Result<Self::Value, E> {
                base64::decode_config(value, base64::URL_SAFE_NO_PAD)
                    .map_err(|_| E::invalid_value(Unexpected::Str(value), &self))
            }
        }

        deserializer.deserialize_str(Base64Visitor).map(Cow::Owned)
    }
}

mod base64url_opt {
    use serde::{Deserializer, Serializer};

    use super::base64url;
    use crate::alloc::Cow;

    #[allow(clippy::option_if_let_else)] // false positive; `serializer` is moved into both clauses
    pub fn serialize<S>(value: &Option<Cow<'_, [u8]>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(value) = value {
            base64url::serialize(value, serializer)
        } else {
            serializer.serialize_none()
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Cow<'static, [u8]>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        base64url::deserialize(deserializer).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alg::Hs256Key;

    use assert_matches::assert_matches;
    use core::convert::TryFrom;

    fn create_jwk() -> JsonWebKey<'static> {
        JsonWebKey::KeyPair {
            curve: Cow::Borrowed("Ed25519"),
            x: Cow::Borrowed(b"test"),
            secret: None,
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
        let missing_field_json = r#"{"crv":"Ed25519"}"#;
        let missing_field_err = serde_json::from_str::<JsonWebKey<'_>>(missing_field_json)
            .unwrap_err()
            .to_string();
        assert!(
            missing_field_err.contains("missing field `kty`"),
            "{}",
            missing_field_err
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
    fn extra_jwk_fields() {
        #[derive(Debug, Deserialize)]
        struct Extra {
            #[serde(rename = "kid")]
            key_id: String,
            #[serde(rename = "use")]
            key_use: KeyUse,
        }

        #[derive(Debug, Deserialize, PartialEq)]
        enum KeyUse {
            #[serde(rename = "sig")]
            Signature,
            #[serde(rename = "enc")]
            Encryption,
        }

        let json_str = r#"
            { "kty": "oct", "kid": "my-unique-key", "k": "dGVzdA", "use": "sig" }
        "#;
        let jwk: ExtendedJsonWebKey<'_, Extra> = serde_json::from_str(json_str).unwrap();

        assert_matches!(&jwk.base, JsonWebKey::Symmetric { secret } if secret.as_ref() == b"test");
        assert_eq!(jwk.extra.key_id, "my-unique-key");
        assert_eq!(jwk.extra.key_use, KeyUse::Signature);

        let key = Hs256Key::try_from(&jwk.base).unwrap();
        let jwk_from_key = JsonWebKey::from(&key);

        assert_matches!(
            jwk_from_key,
            JsonWebKey::Symmetric { secret } if secret.as_ref() == b"test"
        );
    }
}
