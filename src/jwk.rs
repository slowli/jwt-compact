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

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::digest::{Digest, Output};

use core::fmt;

use crate::{
    alg::SecretBytes,
    alloc::{Cow, String, ToString, Vec},
};

/// Type of a [`JsonWebKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyType {
    /// Public or private RSA key. Corresponds to the `RSA` value of the `kty` field for JWKs.
    Rsa,
    /// Public or private key in an ECDSA crypto system. Corresponds to the `EC` value
    /// of the `kty` field for JWKs.
    EllipticCurve,
    /// Symmetric key. Corresponds to the `oct` value of the `kty` field for JWKs.
    Symmetric,
    /// Generic asymmetric keypair. Corresponds to the `OKP` value of the `kty` field for JWKs.
    KeyPair,
}

impl fmt::Display for KeyType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rsa => "RSA",
            Self::EllipticCurve => "EC",
            Self::Symmetric => "oct",
            Self::KeyPair => "OKP",
        })
    }
}

/// Errors that can occur when transforming a [`JsonWebKey`] into the presentation specific for
/// a crypto backend, using the [`TryFrom`] trait.
#[derive(Debug)]
#[non_exhaustive]
pub enum JwkError {
    /// Required field is absent from JWK.
    NoField(String),
    /// Key type (the `kty` field) is not as expected.
    UnexpectedKeyType {
        /// Expected key type.
        expected: KeyType,
        /// Actual key type.
        actual: KeyType,
    },
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
            Self::UnexpectedKeyType { expected, actual } => {
                write!(
                    formatter,
                    "unexpected key type: {actual} (expected {expected})"
                )
            }
            Self::NoField(field) => write!(formatter, "field `{field}` is absent from JWK"),
            Self::UnexpectedValue {
                field,
                expected,
                actual,
            } => {
                write!(
                    formatter,
                    "field `{field}` has unexpected value (expected: {expected}, got: {actual})"
                )
            }
            Self::UnexpectedLen {
                field,
                expected,
                actual,
            } => {
                write!(
                    formatter,
                    "field `{field}` has unexpected length (expected: {expected}, got: {actual})"
                )
            }
            Self::MismatchedKeys => {
                formatter.write_str("private and public keys encoded in JWK do not match")
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

    pub(crate) fn key_type(jwk: &JsonWebKey<'_>, expected: KeyType) -> Self {
        let actual = jwk.key_type();
        debug_assert_ne!(actual, expected);
        Self::UnexpectedKeyType { actual, expected }
    }
}

impl Serialize for SecretBytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        base64url::serialize(self.as_ref(), serializer)
    }
}

impl<'de> Deserialize<'de> for SecretBytes<'_> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        base64url::deserialize(deserializer).map(SecretBytes::new)
    }
}

/// Basic [JWK] functionality: (de)serialization and creating thumbprints.
///
/// See [RFC 7518] for the details about the fields for various key types.
///
/// [`Self::thumbprint()`] and the [`Display`](fmt::Display) implementation
/// allow to get the overall presentation of the key. The latter returns JSON serialization
/// of the key with fields ordered alphabetically. That is, this output for verifying keys
/// can be used to compute key thumbprints.
///
/// # Serialization
///
/// For human-readable formats (e.g., JSON, TOML, YAML), byte fields in `JsonWebKey`
/// and embedded types ([`SecretBytes`], [`RsaPrivateParts`], [`RsaPrimeFactor`]) will be
/// serialized in base64-url encoding with no padding, as per the JWK spec.
/// For other formats (e.g., CBOR), byte fields will be serialized as byte sequences.
///
/// Because of [the limitations](https://github.com/pyfisch/cbor/issues/3)
/// of the CBOR support in `serde`, a `JsonWebKey` serialized in CBOR is **not** compliant
/// with the [CBOR Object Signing and Encryption spec][COSE] (COSE). It can still be a good
/// way to decrease the serialized key size.
///
/// # Conversions
///
/// A JWK can be obtained from signing and verifying keys defined in the [`alg`](crate::alg)
/// module via [`From`] / [`Into`] traits. Conversion from a JWK to a specific key is fallible
/// and can be performed via [`TryFrom`] with [`JwkError`] as an error
/// type.
///
/// As a part of conversion for asymmetric signing keys, it is checked whether
/// the signing and verifying parts of the JWK match; [`JwkError::MismatchedKeys`] is returned
/// otherwise. This check is **not** performed for verifying keys even if the necessary data
/// is present in the provided JWK.
///
/// ⚠ **Warning.** Conversions for private RSA keys are not fully compliant with [RFC 7518].
/// See the docs for the relevant `impl`s for more details.
///
/// [RFC 7518]: https://tools.ietf.org/html/rfc7518#section-6
/// [JWK]: https://tools.ietf.org/html/rfc7517.html
/// [COSE]: https://tools.ietf.org/html/rfc8152
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kty")]
#[non_exhaustive]
pub enum JsonWebKey<'a> {
    /// Public or private RSA key. Has `kty` field set to `RSA`.
    #[serde(rename = "RSA")]
    Rsa {
        /// Key modulus (`n`).
        #[serde(rename = "n", with = "base64url")]
        modulus: Cow<'a, [u8]>,
        /// Public exponent (`e`).
        #[serde(rename = "e", with = "base64url")]
        public_exponent: Cow<'a, [u8]>,
        /// Private RSA parameters. Only present for private keys.
        #[serde(flatten)]
        private_parts: Option<RsaPrivateParts<'a>>,
    },
    /// Public or private key in an ECDSA crypto system. Has `kty` field set to `EC`.
    #[serde(rename = "EC")]
    EllipticCurve {
        /// Curve name (`crv`), such as `secp256k1`.
        #[serde(rename = "crv")]
        curve: Cow<'a, str>,
        /// `x` coordinate of the curve point.
        #[serde(with = "base64url")]
        x: Cow<'a, [u8]>,
        /// `y` coordinate of the curve point.
        #[serde(with = "base64url")]
        y: Cow<'a, [u8]>,
        /// Secret scalar (`d`); not present for public keys.
        #[serde(rename = "d", default, skip_serializing_if = "Option::is_none")]
        secret: Option<SecretBytes<'a>>,
    },
    /// Generic symmetric key, e.g. for `HS256` algorithm. Has `kty` field set to `oct`.
    #[serde(rename = "oct")]
    Symmetric {
        /// Bytes representing this key.
        #[serde(rename = "k")]
        secret: SecretBytes<'a>,
    },
    /// Generic asymmetric keypair. This key type is used e.g. for Ed25519 keys.
    #[serde(rename = "OKP")]
    KeyPair {
        /// Curve name (`crv`), such as `Ed25519`.
        #[serde(rename = "crv")]
        curve: Cow<'a, str>,
        /// Public key. For Ed25519, this is the standard 32-byte public key presentation
        /// (`x` coordinate of a point on the curve + sign).
        #[serde(with = "base64url")]
        x: Cow<'a, [u8]>,
        /// Secret key (`d`). For Ed25519, this is the seed.
        #[serde(rename = "d", default, skip_serializing_if = "Option::is_none")]
        secret: Option<SecretBytes<'a>>,
    },
}

impl JsonWebKey<'_> {
    /// Gets the type of this key.
    pub fn key_type(&self) -> KeyType {
        match self {
            Self::Rsa { .. } => KeyType::Rsa,
            Self::EllipticCurve { .. } => KeyType::EllipticCurve,
            Self::Symmetric { .. } => KeyType::Symmetric,
            Self::KeyPair { .. } => KeyType::KeyPair,
        }
    }

    /// Returns `true` if this key can be used for signing (has [`SecretBytes`] fields).
    pub fn is_signing_key(&self) -> bool {
        match self {
            Self::Rsa { private_parts, .. } => private_parts.is_some(),
            Self::EllipticCurve { secret, .. } | Self::KeyPair { secret, .. } => secret.is_some(),
            Self::Symmetric { .. } => true,
        }
    }

    /// Returns a copy of this key with parts not necessary for signature verification removed.
    #[must_use]
    pub fn to_verifying_key(&self) -> Self {
        match self {
            Self::Rsa {
                modulus,
                public_exponent,
                ..
            } => Self::Rsa {
                modulus: modulus.clone(),
                public_exponent: public_exponent.clone(),
                private_parts: None,
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

    /// Computes a thumbprint of this JWK. The result complies with the key thumbprint defined
    /// in [RFC 7638].
    ///
    /// [RFC 7638]: https://tools.ietf.org/html/rfc7638
    pub fn thumbprint<D: Digest>(&self) -> Output<D> {
        let hashed_key = if self.is_signing_key() {
            Cow::Owned(self.to_verifying_key())
        } else {
            Cow::Borrowed(self)
        };
        D::digest(hashed_key.to_string().as_bytes())
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
            write!(formatter, "\"{name}\":{value}")?;
            if i + 1 < field_count {
                formatter.write_str(",")?;
            }
        }
        formatter.write_str("}")
    }
}

/// Parts of [`JsonWebKey::Rsa`] that are specific to private keys.
///
/// # Serialization
///
/// Fields of this struct are serialized using the big endian presentation
/// with the minimum necessary number of bytes. See [`JsonWebKey` notes](JsonWebKey#serialization)
/// on encoding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RsaPrivateParts<'a> {
    /// Private exponent (`d`).
    #[serde(rename = "d")]
    pub private_exponent: SecretBytes<'a>,
    /// First prime factor (`p`).
    #[serde(rename = "p")]
    pub prime_factor_p: SecretBytes<'a>,
    /// Second prime factor (`q`).
    #[serde(rename = "q")]
    pub prime_factor_q: SecretBytes<'a>,
    /// First factor CRT exponent (`dp`).
    #[serde(rename = "dp", default, skip_serializing_if = "Option::is_none")]
    pub p_crt_exponent: Option<SecretBytes<'a>>,
    /// Second factor CRT exponent (`dq`).
    #[serde(rename = "dq", default, skip_serializing_if = "Option::is_none")]
    pub q_crt_exponent: Option<SecretBytes<'a>>,
    /// CRT coefficient of the second factor (`qi`).
    #[serde(rename = "qi", default, skip_serializing_if = "Option::is_none")]
    pub q_crt_coefficient: Option<SecretBytes<'a>>,
    /// Other prime factors.
    #[serde(rename = "oth", default, skip_serializing_if = "Vec::is_empty")]
    pub other_prime_factors: Vec<RsaPrimeFactor<'a>>,
}

/// Block for an additional prime factor in [`RsaPrivateParts`].
///
/// # Serialization
///
/// Fields of this struct are serialized using the big endian presentation
/// with the minimum necessary number of bytes. See [`JsonWebKey` notes](JsonWebKey#serialization)
/// on encoding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RsaPrimeFactor<'a> {
    /// Prime factor (`r`).
    #[serde(rename = "r")]
    pub factor: SecretBytes<'a>,
    /// Factor CRT exponent (`d`).
    #[serde(rename = "d", default, skip_serializing_if = "Option::is_none")]
    pub crt_exponent: Option<SecretBytes<'a>>,
    /// Factor CRT coefficient (`t`).
    #[serde(rename = "t", default, skip_serializing_if = "Option::is_none")]
    pub crt_coefficient: Option<SecretBytes<'a>>,
}

#[cfg(any(
    feature = "es256k",
    feature = "k256",
    feature = "exonum-crypto",
    feature = "ed25519-dalek",
    feature = "ed25519-compact"
))]
mod helpers {
    use super::{JsonWebKey, JwkError};
    use crate::{alg::SigningKey, alloc::ToOwned, Algorithm};

    impl JsonWebKey<'_> {
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
    }
}

mod base64url {
    use base64ct::{Base64UrlUnpadded, Encoding};
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
        if serializer.is_human_readable() {
            serializer.serialize_str(&Base64UrlUnpadded::encode_string(value))
        } else {
            serializer.serialize_bytes(value)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Cow<'static, [u8]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Base64Visitor;

        impl Visitor<'_> for Base64Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("base64url-encoded data")
            }

            fn visit_str<E: DeError>(self, value: &str) -> Result<Self::Value, E> {
                Base64UrlUnpadded::decode_vec(value)
                    .map_err(|_| E::invalid_value(Unexpected::Str(value), &self))
            }

            fn visit_bytes<E: DeError>(self, value: &[u8]) -> Result<Self::Value, E> {
                Ok(value.to_vec())
            }

            fn visit_byte_buf<E: DeError>(self, value: Vec<u8>) -> Result<Self::Value, E> {
                Ok(value)
            }
        }

        struct BytesVisitor;

        impl<'de> Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("byte buffer")
            }

            fn visit_bytes<E: DeError>(self, value: &[u8]) -> Result<Self::Value, E> {
                Ok(value.to_vec())
            }

            fn visit_byte_buf<E: DeError>(self, value: Vec<u8>) -> Result<Self::Value, E> {
                Ok(value)
            }
        }

        let maybe_bytes = if deserializer.is_human_readable() {
            deserializer.deserialize_str(Base64Visitor)
        } else {
            deserializer.deserialize_bytes(BytesVisitor)
        };
        maybe_bytes.map(Cow::Owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alg::Hs256Key;

    use assert_matches::assert_matches;

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
            "{missing_field_err}"
        );

        let base64_json = r#"{"crv":"Ed25519","kty":"OKP","x":"??"}"#;
        let base64_err = serde_json::from_str::<JsonWebKey<'_>>(base64_json)
            .unwrap_err()
            .to_string();
        assert!(
            base64_err.contains("invalid value: string \"??\""),
            "{base64_err}"
        );
        assert!(
            base64_err.contains("base64url-encoded data"),
            "{base64_err}"
        );
    }

    #[test]
    fn extra_jwk_fields() {
        #[derive(Debug, Serialize, Deserialize)]
        struct ExtendedJsonWebKey<'a, T> {
            #[serde(flatten)]
            base: JsonWebKey<'a>,
            #[serde(flatten)]
            extra: T,
        }

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

    #[test]
    #[cfg(feature = "ciborium")]
    fn jwk_with_cbor() {
        let key = JsonWebKey::KeyPair {
            curve: Cow::Borrowed("Ed25519"),
            x: Cow::Borrowed(b"public"),
            secret: Some(SecretBytes::borrowed(b"private")),
        };
        let mut bytes = vec![];
        ciborium::into_writer(&key, &mut bytes).unwrap();
        assert!(bytes.windows(6).any(|window| window == b"public"));
        assert!(bytes.windows(7).any(|window| window == b"private"));

        let restored: JsonWebKey<'_> = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(restored, key);
    }
}
