//! `Token` and closely related types.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};

use core::{convert::TryFrom, fmt};

use crate::{
    alloc::{Cow, String, Vec},
    Algorithm, Claims, ParseError, ValidationError,
};

/// Maximum "reasonable" signature size in bytes.
const SIGNATURE_SIZE: usize = 128;

/// JWT header.
///
/// See [RFC 7515](https://tools.ietf.org/html/rfc7515#section-4.1) for the description
/// of the fields. The purpose of all fields except `token_type` is to determine
/// the verifying key. Since these values will be provided by the adversary in the case of
/// an attack, they require additional verification (e.g., a provided certificate might
/// be checked against the list of "acceptable" certificate authorities).
///
/// A `Header` can be created using `Default` implementation, which does not set any fields.
/// For added fluency, you may use `with_*` methods:
///
/// ```
/// # use jwt_compact::Header;
/// use sha2::{digest::Digest, Sha256};
///
/// let my_key_cert = // DER-encoded key certificate
/// #   b"Hello, world!";
/// let header = Header::default()
///     .with_key_id("my-key-id")
///     .with_certificate_thumbprint(Sha256::digest(my_key_cert).into());
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Header {
    /// URL of the JSON Web Key Set containing the key that has signed the token.
    /// This field is renamed to [`jku`] for serialization.
    ///
    /// [`jku`]: https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.2
    #[serde(rename = "jku", default, skip_serializing_if = "Option::is_none")]
    pub key_set_url: Option<String>,

    /// Identifier of the key that has signed the token. This field is renamed to [`kid`]
    /// for serialization.
    ///
    /// [`kid`]: https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4
    #[serde(rename = "kid", default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// URL of the X.509 certificate for the signing key. This field is renamed to [`x5u`]
    /// for serialization.
    ///
    /// [`x5u`]: https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.5
    #[serde(rename = "x5u", default, skip_serializing_if = "Option::is_none")]
    pub certificate_url: Option<String>,

    /// SHA-1 thumbprint of the X.509 certificate for the signing key.
    /// This field is renamed to [`x5t`] for serialization.
    ///
    /// [`x5t`]: https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.7
    #[serde(
        rename = "x5t",
        with = "base64url",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub certificate_sha1_thumbprint: Option<[u8; 20]>,

    /// SHA-256 thumbprint of the X.509 certificate for the signing key.
    /// This field is renamed to [`x5t#S256`] for serialization.
    ///
    /// [`x5t#S256`]: https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.8
    #[serde(
        rename = "x5t#S256",
        with = "base64url",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub certificate_thumbprint: Option<[u8; 32]>,

    /// Application-specific [token type]. This field is renamed to `typ` for serialization.
    ///
    /// [token type]: https://tools.ietf.org/html/rfc7519#section-5.1
    #[serde(rename = "typ", default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

impl Header {
    /// Sets the `key_set_url` field for this header.
    pub fn with_key_set_url(mut self, key_set_url: impl Into<String>) -> Self {
        self.key_set_url = Some(key_set_url.into());
        self
    }

    /// Sets the `key_id` field for this header.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Sets the `certificate_url` field for this header.
    pub fn with_certificate_url(mut self, certificate_url: impl Into<String>) -> Self {
        self.certificate_url = Some(certificate_url.into());
        self
    }

    /// Sets the `certificate_sha1_thumbprint` field for this header.
    pub fn with_certificate_sha1_thumbprint(mut self, certificate_thumbprint: [u8; 20]) -> Self {
        self.certificate_sha1_thumbprint = Some(certificate_thumbprint);
        self
    }

    /// Sets the `certificate_thumbprint` field for this header.
    pub fn with_certificate_thumbprint(mut self, certificate_thumbprint: [u8; 32]) -> Self {
        self.certificate_thumbprint = Some(certificate_thumbprint);
        self
    }

    /// Sets the `token_type` field for this header.
    pub fn with_token_type(mut self, token_type: impl Into<String>) -> Self {
        self.token_type = Some(token_type.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CompleteHeader<'a> {
    #[serde(rename = "alg")]
    pub algorithm: Cow<'a, str>,
    #[serde(rename = "cty", default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(flatten)]
    pub inner: Header,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentType {
    Json,
    Cbor,
}

/// Parsed, but unvalidated token.
#[derive(Debug, Clone)]
pub struct UntrustedToken<'a> {
    pub(crate) signed_data: &'a [u8],
    header: Header,
    algorithm: String,
    content_type: ContentType,
    serialized_claims: Vec<u8>,
    signature: SmallVec<[u8; SIGNATURE_SIZE]>,
}

/// Token with validated integrity.
///
/// Claims encoded in the token can be verified by invoking [`Claims`] methods
/// via [`Self::claims()`].
#[derive(Debug, Clone)]
pub struct Token<T> {
    header: Header,
    claims: Claims<T>,
}

impl<T> Token<T> {
    pub(crate) fn new(header: Header, claims: Claims<T>) -> Self {
        Self { header, claims }
    }

    /// Gets token header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Gets token claims.
    pub fn claims(&self) -> &Claims<T> {
        &self.claims
    }
}

/// `Token` together with the validated token signature.
///
/// # Examples
///
/// ```
/// # use jwt_compact::{alg::{Hs256, Hs256Key, Hs256Signature}, prelude::*};
/// # use chrono::Duration;
/// # use hmac::crypto_mac::generic_array::{typenum, GenericArray};
/// # use serde::{Deserialize, Serialize};
/// #
/// #[derive(Serialize, Deserialize)]
/// struct MyClaims {
///     // Custom claims in the token...
/// }
///
/// # fn main() -> anyhow::Result<()> {
/// # let key = Hs256Key::new(b"super_secret_key");
/// # let claims = Claims::new(MyClaims {})
/// #     .set_duration_and_issuance(&TimeOptions::default(), Duration::days(7));
/// let token_string: String = // token from an external source
/// #   Hs256.token(Header::default(), &claims, &key)?;
/// let token = UntrustedToken::new(&token_string)?;
/// let signed = Hs256.validate_for_signed_token::<MyClaims>(&token, &key)?;
///
/// // `signature` is strongly typed.
/// let signature: Hs256Signature = signed.signature;
/// // Token itself is available via `token` field.
/// let claims = signed.token.claims();
/// claims.validate_expiration(&TimeOptions::default())?;
/// // Process the claims...
/// # Ok(())
/// # } // end main()
/// ```
#[non_exhaustive]
pub struct SignedToken<A: Algorithm + ?Sized, T> {
    /// Token signature.
    pub signature: A::Signature,
    /// Verified token.
    pub token: Token<T>,
}

impl<A, T> fmt::Debug for SignedToken<A, T>
where
    A: Algorithm,
    A::Signature: fmt::Debug,
    T: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedToken")
            .field("token", &self.token)
            .field("signature", &self.signature)
            .finish()
    }
}

impl<A, T> Clone for SignedToken<A, T>
where
    A: Algorithm,
    A::Signature: Clone,
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            signature: self.signature.clone(),
            token: self.token.clone(),
        }
    }
}

impl<'a> TryFrom<&'a str> for UntrustedToken<'a> {
    type Error = ParseError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let token_parts: Vec<_> = s.splitn(4, '.').collect();
        match &token_parts[..] {
            [header, claims, signature] => {
                let header = base64::decode_config(header, base64::URL_SAFE_NO_PAD)?;
                let serialized_claims = base64::decode_config(claims, base64::URL_SAFE_NO_PAD)?;
                let mut decoded_signature = smallvec![0; 3 * (signature.len() + 3) / 4];
                let signature_len = base64::decode_config_slice(
                    signature,
                    base64::URL_SAFE_NO_PAD,
                    &mut decoded_signature[..],
                )?;
                decoded_signature.truncate(signature_len);

                let header: CompleteHeader<'_> =
                    serde_json::from_slice(&header).map_err(ParseError::MalformedHeader)?;
                let content_type = match header.content_type {
                    None => ContentType::Json,
                    Some(ref s) if s.eq_ignore_ascii_case("json") => ContentType::Json,
                    Some(ref s) if s.eq_ignore_ascii_case("cbor") => ContentType::Cbor,
                    Some(s) => return Err(ParseError::UnsupportedContentType(s)),
                };

                Ok(Self {
                    signed_data: s.rsplitn(2, '.').nth(1).unwrap().as_bytes(),
                    header: header.inner,
                    algorithm: header.algorithm.into_owned(),
                    content_type,
                    serialized_claims,
                    signature: decoded_signature,
                })
            }
            _ => Err(ParseError::InvalidTokenStructure),
        }
    }
}

impl<'a> UntrustedToken<'a> {
    /// Creates an untrusted token from a string. This is a shortcut for calling the [`TryFrom`]
    /// conversion.
    pub fn new<S: AsRef<str> + ?Sized>(s: &'a S) -> Result<Self, ParseError> {
        Self::try_from(s.as_ref())
    }

    /// Gets the token header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Gets the integrity algorithm used to secure the token.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Returns signature bytes from the token. These bytes are **not** guaranteed to form a valid
    /// signature.
    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature
    }

    pub(crate) fn deserialize_claims<T>(&self) -> Result<Claims<T>, ValidationError>
    where
        T: DeserializeOwned,
    {
        match self.content_type {
            ContentType::Json => serde_json::from_slice(&self.serialized_claims)
                .map_err(ValidationError::MalformedClaims),
            ContentType::Cbor => serde_cbor::from_slice(&self.serialized_claims)
                .map_err(ValidationError::MalformedCborClaims),
        }
    }
}

mod base64url {
    use base64::decode_config_slice;
    use serde::{
        de::{Error as DeError, Visitor},
        Deserializer, Serializer,
    };

    use core::{fmt, marker::PhantomData};

    #[allow(clippy::option_if_let_else)] // false positive; `serializer` is moved into both clauses
    pub fn serialize<T, S>(value: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        if let Some(value) = value {
            let bytes = value.as_ref();
            serializer.serialize_str(&base64::encode_config(bytes, base64::URL_SAFE_NO_PAD))
        } else {
            serializer.serialize_none()
        }
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        T: Default + AsMut<[u8]>,
        D: Deserializer<'de>,
    {
        struct Base64Visitor<V>(PhantomData<V>);

        impl<V> Visitor<'_> for Base64Visitor<V>
        where
            V: Default + AsMut<[u8]>,
        {
            type Value = V;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "base64url-encoded digest")
            }

            fn visit_str<E: DeError>(self, value: &str) -> Result<Self::Value, E> {
                let mut bytes = V::default();
                let expected_len = bytes.as_mut().len();

                let decoded_len = value.len() * 3 / 4;
                if decoded_len != expected_len {
                    return Err(E::invalid_length(decoded_len, &self));
                }

                let len = decode_config_slice(value, base64::URL_SAFE_NO_PAD, bytes.as_mut())
                    .map_err(E::custom)?;
                if len != expected_len {
                    return Err(E::invalid_length(len, &self));
                }

                Ok(bytes)
            }
        }

        deserializer
            .deserialize_str(Base64Visitor(PhantomData))
            .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        alg::{Hs256, Hs256Key},
        alloc::ToOwned,
        AlgorithmExt,
    };

    use assert_matches::assert_matches;

    type Obj = serde_json::Map<String, serde_json::Value>;

    const HS256_TOKEN: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
                               eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
                               cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
                               dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const HS256_KEY: &str = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75\
                             aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

    #[test]
    fn invalid_token_structure() {
        let mangled_str = HS256_TOKEN.replace('.', "");
        assert_matches!(
            UntrustedToken::new(&mangled_str).unwrap_err(),
            ParseError::InvalidTokenStructure
        );

        let mut mangled_str = HS256_TOKEN.to_owned();
        let signature_start = mangled_str.rfind('.').unwrap();
        mangled_str.truncate(signature_start);
        assert_matches!(
            UntrustedToken::new(&mangled_str).unwrap_err(),
            ParseError::InvalidTokenStructure
        );

        let mut mangled_str = HS256_TOKEN.to_owned();
        mangled_str.push('.');
        assert_matches!(
            UntrustedToken::new(&mangled_str).unwrap_err(),
            ParseError::InvalidTokenStructure
        );
    }

    #[test]
    fn base64_error_during_parsing() {
        let mangled_str = HS256_TOKEN.replace('0', "+");
        assert_matches!(
            UntrustedToken::new(&mangled_str).unwrap_err(),
            ParseError::Base64(_)
        );

        let mut mangled_str = HS256_TOKEN.to_owned();
        mangled_str.truncate(mangled_str.len() - 1);
        assert_matches!(
            UntrustedToken::new(&mangled_str).unwrap_err(),
            ParseError::Base64(_)
        );
    }

    #[test]
    fn header_fields_are_not_serialized_if_not_present() {
        let header = Header::default();
        let json = serde_json::to_string(&header).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn header_with_x5t_field() {
        let header = r#"{"alg":"HS256","x5t":"lDpwLQbzRZmu4fjajvn3KWAx1pk"}"#;
        let header: CompleteHeader = serde_json::from_str(header).unwrap();
        let thumbprint = header.inner.certificate_sha1_thumbprint.unwrap();

        assert_eq!(thumbprint[0], 0x94);
        assert_eq!(thumbprint[19], 0x99);

        let json = serde_json::to_value(header).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "alg": "HS256",
                "x5t": "lDpwLQbzRZmu4fjajvn3KWAx1pk",
            })
        );
    }

    #[test]
    fn header_with_x5t_sha256_field() {
        let header = r#"{"alg":"HS256","x5t#S256":"MV9b23bQeMQ7isAGTkoBZGErH853yGk0W_yUx1iU7dM"}"#;
        let header: CompleteHeader = serde_json::from_str(header).unwrap();
        let thumbprint = header.inner.certificate_thumbprint.unwrap();

        assert_eq!(thumbprint[0], 0x31);
        assert_eq!(thumbprint[31], 0xd3);

        let json = serde_json::to_value(header).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "alg": "HS256",
                "x5t#S256": "MV9b23bQeMQ7isAGTkoBZGErH853yGk0W_yUx1iU7dM",
            })
        );
    }

    #[test]
    fn malformed_header() {
        let mangled_headers = [
            // Missing closing brace
            r#"{"alg":"HS256""#,
            // Missing necessary `alg` field
            "{}",
            // `alg` field is not a string
            r#"{"alg":5}"#,
            r#"{"alg":[1,"foo"]}"#,
            r#"{"alg":false}"#,
            // Duplicate `alg` field
            r#"{"alg":"HS256","alg":"none"}"#,
            // Invalid thumbprint fields
            r#"{"alg":"HS256","x5t":"lDpwLQbzRZmu4fjajvn3KWAx1p"}"#,
            r#"{"alg":"HS256","x5t":["lDpwLQbzRZmu4fjajvn3KWAx1pk"]}"#,
            r#"{"alg":"HS256","x5t":"lDpwLQbzRZmu4fjajvn3KWAx1 k"}"#,
            r#"{"alg":"HS256","x5t":"lDpwLQbzRZmu4fjajvn3KWAx1pk==="}"#,
            r#"{"alg":"HS256","x5t":"lDpwLQbzRZmu4fjajvn3KWAx1pkk"}"#,
            r#"{"alg":"HS256","x5t":"MV9b23bQeMQ7isAGTkoBZGErH853yGk0W_yUx1iU7dM"}"#,
            r#"{"alg":"HS256","x5t#S256":"lDpwLQbzRZmu4fjajvn3KWAx1pk"}"#,
        ];

        for mangled_header in &mangled_headers {
            let mangled_header = base64::encode_config(mangled_header, base64::URL_SAFE_NO_PAD);
            let mut mangled_str = HS256_TOKEN.to_owned();
            mangled_str.replace_range(..mangled_str.find('.').unwrap(), &mangled_header);
            assert_matches!(
                UntrustedToken::new(&mangled_str).unwrap_err(),
                ParseError::MalformedHeader(_)
            );
        }
    }

    #[test]
    fn unsupported_content_type() {
        let mangled_header = r#"{"alg":"HS256","cty":"txt"}"#;
        let mangled_header = base64::encode_config(mangled_header, base64::URL_SAFE_NO_PAD);
        let mut mangled_str = HS256_TOKEN.to_owned();
        mangled_str.replace_range(..mangled_str.find('.').unwrap(), &mangled_header);
        assert_matches!(
            UntrustedToken::new(&mangled_str).unwrap_err(),
            ParseError::UnsupportedContentType(ref s) if s == "txt"
        );
    }

    #[test]
    fn malformed_json_claims() {
        let malformed_claims = [
            // Missing closing brace
            r#"{"exp":1500000000"#,
            // `exp` claim is not a number
            r#"{"exp":"1500000000"}"#,
            r#"{"exp":false}"#,
            // Duplicate `exp` claim
            r#"{"exp":1500000000,"nbf":1400000000,"exp":1510000000}"#,
            // Too large `exp` value
            r#"{"exp":1500000000000000000000000000000000}"#,
        ];

        let claims_start = HS256_TOKEN.find('.').unwrap() + 1;
        let claims_end = HS256_TOKEN.rfind('.').unwrap();
        let key = base64::decode_config(HS256_KEY, base64::URL_SAFE_NO_PAD).unwrap();
        let key = Hs256Key::new(&key);

        for claims in &malformed_claims {
            let encoded_claims = base64::encode_config(claims.as_bytes(), base64::URL_SAFE_NO_PAD);
            let mut mangled_str = HS256_TOKEN.to_owned();
            mangled_str.replace_range(claims_start..claims_end, &encoded_claims);
            let token = UntrustedToken::new(&mangled_str).unwrap();
            assert_matches!(
                Hs256.validate_integrity::<Obj>(&token, &key).unwrap_err(),
                ValidationError::MalformedClaims(_),
                "Failing claims: {}",
                claims
            );
        }
    }
}
