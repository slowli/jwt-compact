//! `Token` and closely related types.

use core::{cmp, fmt};

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{DeserializeOwned, Error as DeError, Visitor},
};
use smallvec::{SmallVec, smallvec};

#[cfg(feature = "ciborium")]
use crate::error::CborDeError;
use crate::{
    Algorithm, Claims, Empty, ParseError, ValidationError,
    alloc::{Cow, String, Vec, format},
};

/// Maximum "reasonable" signature size in bytes.
const SIGNATURE_SIZE: usize = 128;

/// Representation of a X.509 certificate thumbprint (`x5t` and `x5t#S256` fields in
/// the JWT [`Header`]).
///
/// As per the JWS spec in [RFC 7515], a certificate thumbprint (i.e., the SHA-1 / SHA-256
/// digest of the certificate) must be base64url-encoded. Some JWS implementations however
/// encode not the thumbprint itself, but rather its hex encoding, sometimes even
/// with additional chars spliced within. To account for these implementations,
/// a thumbprint is represented as an enum – either a properly encoded hash digest,
/// or an opaque base64-encoded string.
///
/// [RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515.html
///
/// # Examples
///
/// ```
/// # use assert_matches::assert_matches;
/// # use jwt_compact::{
/// #     alg::{Hs256, Hs256Key}, AlgorithmExt, Claims, Header, Thumbprint, UntrustedToken,
/// # };
/// # fn main() -> anyhow::Result<()> {
/// let key = Hs256Key::new(b"super_secret_key_donut_steel");
///
/// // Creates a token with a custom-encoded SHA-1 thumbprint.
/// let thumbprint = "65:AF:69:09:B1:B0:75:8E:06:C6:E0:48:C4:60:02:B5:C6:95:E3:6B";
/// let header = Header::empty()
///     .with_key_id("my_key")
///     .with_certificate_sha1_thumbprint(thumbprint);
/// let token = Hs256.token(&header, &Claims::empty(), &key)?;
/// println!("{token}");
///
/// // Deserialize the token and check that its header fields are readable.
/// let token = UntrustedToken::new(&token)?;
/// let deserialized_thumbprint =
///     token.header().certificate_sha1_thumbprint.as_ref();
/// assert_matches!(
///     deserialized_thumbprint,
///     Some(Thumbprint::String(s)) if s == thumbprint
/// );
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Thumbprint<const N: usize> {
    /// Byte representation of a SHA-1 or SHA-256 digest.
    Bytes([u8; N]),
    /// Opaque string representation of the thumbprint. It is the responsibility
    /// of an application to verify that this value is valid.
    String(String),
}

impl<const N: usize> From<[u8; N]> for Thumbprint<N> {
    fn from(value: [u8; N]) -> Self {
        Self::Bytes(value)
    }
}

impl<const N: usize> From<String> for Thumbprint<N> {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl<const N: usize> From<&str> for Thumbprint<N> {
    fn from(s: &str) -> Self {
        Self::String(s.into())
    }
}

impl<const N: usize> Serialize for Thumbprint<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let input = match self {
            Self::Bytes(bytes) => bytes.as_slice(),
            Self::String(s) => s.as_bytes(),
        };
        serializer.serialize_str(&Base64UrlUnpadded::encode_string(input))
    }
}

impl<'de, const N: usize> Deserialize<'de> for Thumbprint<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Base64Visitor<const L: usize>;

        impl<const L: usize> Visitor<'_> for Base64Visitor<L> {
            type Value = Thumbprint<L>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "base64url-encoded thumbprint")
            }

            fn visit_str<E: DeError>(self, mut value: &str) -> Result<Self::Value, E> {
                // Allow for padding. RFC 7515 defines base64url encoding as one without padding:
                //
                // > Base64url Encoding: Base64 encoding using the URL- and filename-safe
                // > character set defined in Section 5 of RFC 4648 [RFC4648], with all trailing '='
                // > characters omitted [...]
                //
                // ...but it's easy to trim the padding, so we support it anyway.
                //
                // See: https://www.rfc-editor.org/rfc/rfc7515.html#section-2
                for _ in 0..2 {
                    if value.as_bytes().last() == Some(&b'=') {
                        value = &value[..value.len() - 1];
                    }
                }

                let decoded_len = value.len() * 3 / 4;
                match decoded_len.cmp(&L) {
                    cmp::Ordering::Less => Err(E::custom(format!(
                        "thumbprint must contain at least {L} bytes"
                    ))),
                    cmp::Ordering::Equal => {
                        let mut bytes = [0_u8; L];
                        let len = Base64UrlUnpadded::decode(value, &mut bytes)
                            .map_err(E::custom)?
                            .len();
                        debug_assert_eq!(len, L);
                        Ok(bytes.into())
                    }
                    cmp::Ordering::Greater => {
                        let decoded = Base64UrlUnpadded::decode_vec(value).map_err(E::custom)?;
                        let decoded = String::from_utf8(decoded)
                            .map_err(|err| E::custom(err.utf8_error()))?;
                        Ok(decoded.into())
                    }
                }
            }
        }

        deserializer.deserialize_str(Base64Visitor)
    }
}

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
/// let thumbprint: [u8; 32] = Sha256::digest(my_key_cert).into();
/// let header = Header::empty()
///     .with_key_id("my-key-id")
///     .with_certificate_thumbprint(thumbprint);
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Header<T = Empty> {
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
    #[serde(rename = "x5t", default, skip_serializing_if = "Option::is_none")]
    pub certificate_sha1_thumbprint: Option<Thumbprint<20>>,

    /// SHA-256 thumbprint of the X.509 certificate for the signing key.
    /// This field is renamed to [`x5t#S256`] for serialization.
    ///
    /// [`x5t#S256`]: https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.8
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub certificate_thumbprint: Option<Thumbprint<32>>,

    /// Application-specific [token type]. This field is renamed to `typ` for serialization.
    ///
    /// [token type]: https://tools.ietf.org/html/rfc7519#section-5.1
    #[serde(rename = "typ", default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    /// Other fields encoded in the header. These fields may be used by agreement between
    /// the producer and consumer of the token to pass additional information.
    /// See Sections 4.2 and 4.3 of [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515#section-4.2)
    /// for details.
    ///
    /// For the token creation and validation to work properly, the fields type must [`Serialize`]
    /// to a JSON object.
    ///
    /// Note that these fields do not include the signing algorithm (`alg`) and the token
    /// content type (`cty`) since both these fields have predefined semantics and are used
    /// internally by the crate logic.
    #[serde(flatten)]
    pub other_fields: T,
}

impl Header {
    /// Creates an empty header.
    pub const fn empty() -> Self {
        Self {
            key_set_url: None,
            key_id: None,
            certificate_url: None,
            certificate_sha1_thumbprint: None,
            certificate_thumbprint: None,
            token_type: None,
            other_fields: Empty {},
        }
    }
}

impl<T> Header<T> {
    /// Creates a header with the specified custom fields.
    pub const fn new(fields: T) -> Header<T> {
        Header {
            key_set_url: None,
            key_id: None,
            certificate_url: None,
            certificate_sha1_thumbprint: None,
            certificate_thumbprint: None,
            token_type: None,
            other_fields: fields,
        }
    }

    /// Sets the `key_set_url` field for this header.
    #[must_use]
    pub fn with_key_set_url(mut self, key_set_url: impl Into<String>) -> Self {
        self.key_set_url = Some(key_set_url.into());
        self
    }

    /// Sets the `key_id` field for this header.
    #[must_use]
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Sets the `certificate_url` field for this header.
    #[must_use]
    pub fn with_certificate_url(mut self, certificate_url: impl Into<String>) -> Self {
        self.certificate_url = Some(certificate_url.into());
        self
    }

    /// Sets the `certificate_sha1_thumbprint` field for this header.
    #[must_use]
    pub fn with_certificate_sha1_thumbprint(
        mut self,
        certificate_thumbprint: impl Into<Thumbprint<20>>,
    ) -> Self {
        self.certificate_sha1_thumbprint = Some(certificate_thumbprint.into());
        self
    }

    /// Sets the `certificate_thumbprint` field for this header.
    #[must_use]
    pub fn with_certificate_thumbprint(
        mut self,
        certificate_thumbprint: impl Into<Thumbprint<32>>,
    ) -> Self {
        self.certificate_thumbprint = Some(certificate_thumbprint.into());
        self
    }

    /// Sets the `token_type` field for this header.
    #[must_use]
    pub fn with_token_type(mut self, token_type: impl Into<String>) -> Self {
        self.token_type = Some(token_type.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CompleteHeader<'a, T> {
    #[serde(rename = "alg")]
    pub algorithm: Cow<'a, str>,
    #[serde(rename = "cty", default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(flatten)]
    pub inner: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentType {
    Json,
    #[cfg(feature = "ciborium")]
    Cbor,
}

/// Parsed, but unvalidated token.
///
/// The type param ([`Empty`] by default) corresponds to the [additional information] enclosed
/// in the token [`Header`].
///
/// An `UntrustedToken` can be parsed from a string using the [`TryFrom`] implementation.
/// This checks that a token is well-formed (has a header, claims and a signature),
/// but does not validate the signature.
/// As a shortcut, a token without additional header info can be created using [`Self::new()`].
///
/// [additional information]: Header#other_fields
///
/// # Examples
///
/// ```
/// # use jwt_compact::UntrustedToken;
/// let token_str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJp\
///     c3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leG\
///     FtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJ\
///     U1p1r_wW1gFWFOEjXk";
/// let token: UntrustedToken = token_str.try_into()?;
/// // The same operation using a shortcut:
/// let same_token = UntrustedToken::new(token_str)?;
/// // Token header can be accessed to select the verifying key etc.
/// let key_id: Option<&str> = token.header().key_id.as_deref();
/// # Ok::<_, anyhow::Error>(())
/// ```
///
/// ## Handling tokens with custom header fields
///
/// ```
/// # use serde::Deserialize;
/// # use jwt_compact::UntrustedToken;
/// #[derive(Debug, Clone, Deserialize)]
/// struct HeaderExtensions {
///     custom: String,
/// }
///
/// let token_str = "eyJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Rfa2V5Iiwid\
///     HlwIjoiSldUIiwiY3VzdG9tIjoiY3VzdG9tIn0.eyJzdWIiOiIxMjM0NTY\
///     3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9._27Fb6nF\
///     Tg-HSt3vO4ylaLGcU_ZV2VhMJR4HL7KaQik";
/// let token: UntrustedToken<HeaderExtensions> = token_str.try_into()?;
/// let extensions = &token.header().other_fields;
/// println!("{}", extensions.custom);
/// # Ok::<_, anyhow::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct UntrustedToken<'a, H = Empty> {
    pub(crate) signed_data: Cow<'a, [u8]>,
    header: Header<H>,
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
pub struct Token<T, H = Empty> {
    header: Header<H>,
    claims: Claims<T>,
}

impl<T, H> Token<T, H> {
    pub(crate) fn new(header: Header<H>, claims: Claims<T>) -> Self {
        Self { header, claims }
    }

    /// Gets token header.
    pub fn header(&self) -> &Header<H> {
        &self.header
    }

    /// Gets token claims.
    pub fn claims(&self) -> &Claims<T> {
        &self.claims
    }

    /// Splits the `Token` into the respective `Header` and `Claims` while consuming it.
    pub fn into_parts(self) -> (Header<H>, Claims<T>) {
        (self.header, self.claims)
    }
}

/// `Token` together with the validated token signature.
///
/// # Examples
///
/// ```
/// # use jwt_compact::{alg::{Hs256, Hs256Key, Hs256Signature}, prelude::*};
/// # use chrono::Duration;
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
/// #   Hs256.token(&Header::empty(), &claims, &key)?;
/// let token = UntrustedToken::new(&token_string)?;
/// let signed = Hs256.validator::<MyClaims>(&key)
///     .validate_for_signed_token(&token)?;
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
pub struct SignedToken<A: Algorithm + ?Sized, T, H = Empty> {
    /// Token signature.
    pub signature: A::Signature,
    /// Verified token.
    pub token: Token<T, H>,
}

impl<A, T, H> fmt::Debug for SignedToken<A, T, H>
where
    A: Algorithm,
    A::Signature: fmt::Debug,
    T: fmt::Debug,
    H: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedToken")
            .field("token", &self.token)
            .field("signature", &self.signature)
            .finish()
    }
}

impl<A, T, H> Clone for SignedToken<A, T, H>
where
    A: Algorithm,
    A::Signature: Clone,
    T: Clone,
    H: Clone,
{
    fn clone(&self) -> Self {
        Self {
            signature: self.signature.clone(),
            token: self.token.clone(),
        }
    }
}

impl<'a, H: DeserializeOwned> TryFrom<&'a str> for UntrustedToken<'a, H> {
    type Error = ParseError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let token_parts: Vec<_> = s.splitn(4, '.').collect();
        match &token_parts[..] {
            [header, claims, signature] => {
                let header = Base64UrlUnpadded::decode_vec(header)
                    .map_err(|_| ParseError::InvalidBase64Encoding)?;
                let serialized_claims = Base64UrlUnpadded::decode_vec(claims)
                    .map_err(|_| ParseError::InvalidBase64Encoding)?;

                let mut decoded_signature = smallvec![0; 3 * (signature.len() + 3) / 4];
                let signature_len =
                    Base64UrlUnpadded::decode(signature, &mut decoded_signature[..])
                        .map_err(|_| ParseError::InvalidBase64Encoding)?
                        .len();
                decoded_signature.truncate(signature_len);

                let header: CompleteHeader<_> =
                    serde_json::from_slice(&header).map_err(ParseError::MalformedHeader)?;
                let content_type = match header.content_type {
                    None => ContentType::Json,
                    Some(s) if s.eq_ignore_ascii_case("json") => ContentType::Json,
                    #[cfg(feature = "ciborium")]
                    Some(s) if s.eq_ignore_ascii_case("cbor") => ContentType::Cbor,
                    Some(s) => return Err(ParseError::UnsupportedContentType(s)),
                };
                let signed_data = s.rsplit_once('.').unwrap().0.as_bytes();
                Ok(Self {
                    signed_data: Cow::Borrowed(signed_data),
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
}

impl<H> UntrustedToken<'_, H> {
    /// Converts this token to an owned form.
    pub fn into_owned(self) -> UntrustedToken<'static, H> {
        UntrustedToken {
            signed_data: Cow::Owned(self.signed_data.into_owned()),
            header: self.header,
            algorithm: self.algorithm,
            content_type: self.content_type,
            serialized_claims: self.serialized_claims,
            signature: self.signature,
        }
    }

    /// Gets the token header.
    pub fn header(&self) -> &Header<H> {
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

    /// Deserializes claims from this token without checking token integrity. The resulting
    /// claims are thus **not** guaranteed to be valid.
    pub fn deserialize_claims_unchecked<T>(&self) -> Result<Claims<T>, ValidationError>
    where
        T: DeserializeOwned,
    {
        match self.content_type {
            ContentType::Json => serde_json::from_slice(&self.serialized_claims)
                .map_err(ValidationError::MalformedClaims),

            #[cfg(feature = "ciborium")]
            ContentType::Cbor => {
                ciborium::from_reader(&self.serialized_claims[..]).map_err(|err| {
                    ValidationError::MalformedCborClaims(match err {
                        CborDeError::Io(err) => CborDeError::Io(anyhow::anyhow!(err)),
                        // ^ In order to be able to use `anyhow!` in both std and no-std envs,
                        // we inline the error transform directly here.
                        CborDeError::Syntax(offset) => CborDeError::Syntax(offset),
                        CborDeError::Semantic(offset, description) => {
                            CborDeError::Semantic(offset, description)
                        }
                        CborDeError::RecursionLimitExceeded => CborDeError::RecursionLimitExceeded,
                    })
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use base64ct::{Base64UrlUnpadded, Encoding};

    use super::*;
    use crate::{
        AlgorithmExt, Empty,
        alg::{Hs256, Hs256Key},
        alloc::{ToOwned, ToString},
    };

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
            ParseError::InvalidBase64Encoding
        );
    }

    #[test]
    fn base64_padding_error_during_parsing() {
        let mut mangled_str = HS256_TOKEN.to_owned();
        mangled_str.pop();
        mangled_str.push('_'); // leads to non-zero padding for the last encoded byte
        assert_matches!(
            UntrustedToken::new(&mangled_str).unwrap_err(),
            ParseError::InvalidBase64Encoding
        );
    }

    #[test]
    fn header_fields_are_not_serialized_if_not_present() {
        let header = Header::empty();
        let json = serde_json::to_string(&header).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn header_with_x5t_field() {
        let header = r#"{"alg":"HS256","x5t":"lDpwLQbzRZmu4fjajvn3KWAx1pk"}"#;
        let header: CompleteHeader<Header<Empty>> = serde_json::from_str(header).unwrap();
        let thumbprint = header.inner.certificate_sha1_thumbprint.as_ref().unwrap();
        let Thumbprint::Bytes(thumbprint) = thumbprint else {
            unreachable!();
        };

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
    fn header_with_padded_x5t_field() {
        let header = r#"{"alg":"HS256","x5t":"lDpwLQbzRZmu4fjajvn3KWAx1pk=="}"#;
        let header: CompleteHeader<Header<Empty>> = serde_json::from_str(header).unwrap();
        let thumbprint = header.inner.certificate_sha1_thumbprint.as_ref().unwrap();
        let Thumbprint::Bytes(thumbprint) = thumbprint else {
            unreachable!()
        };

        assert_eq!(thumbprint[0], 0x94);
        assert_eq!(thumbprint[19], 0x99);
    }

    #[test]
    fn header_with_hex_x5t_field() {
        let header =
            r#"{"alg":"HS256","x5t":"NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg"}"#;
        let header: CompleteHeader<Header<Empty>> = serde_json::from_str(header).unwrap();
        let thumbprint = header.inner.certificate_sha1_thumbprint.as_ref().unwrap();
        let Thumbprint::String(thumbprint) = thumbprint else {
            unreachable!()
        };

        assert_eq!(thumbprint, "65AF6909B1B0758E06C6E048C46002B5C695E36B");

        let json = serde_json::to_value(header).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "alg": "HS256",
                "x5t": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
            })
        );
    }

    #[test]
    fn header_with_padded_hex_x5t_field() {
        let header =
            r#"{"alg":"HS256","x5t":"NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg=="}"#;
        let header: CompleteHeader<Header<Empty>> = serde_json::from_str(header).unwrap();
        let thumbprint = header.inner.certificate_sha1_thumbprint.as_ref().unwrap();
        let Thumbprint::String(thumbprint) = thumbprint else {
            unreachable!()
        };

        assert_eq!(thumbprint, "65AF6909B1B0758E06C6E048C46002B5C695E36B");
    }

    #[test]
    fn header_with_overly_short_x5t_field() {
        let header = r#"{"alg":"HS256","x5t":"aGk="}"#;
        let err = serde_json::from_str::<CompleteHeader<Header<Empty>>>(header).unwrap_err();
        let err = err.to_string();
        assert!(
            err.contains("thumbprint must contain at least 20 bytes"),
            "{err}"
        );
    }

    #[test]
    fn header_with_non_base64_x5t_field() {
        let headers = [
            r#"{"alg":"HS256","x5t":"lDpwLQbzRZmu4fjajvn3KWAx1p?"}"#,
            r#"{"alg":"HS256","x5t":"NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk!RTM2Qg"}"#,
        ];
        for header in headers {
            let err = serde_json::from_str::<CompleteHeader<Header<Empty>>>(header).unwrap_err();
            let err = err.to_string();
            assert!(err.contains("Base64"), "{err}");
        }
    }

    #[test]
    fn header_with_x5t_sha256_field() {
        let header = r#"{"alg":"HS256","x5t#S256":"MV9b23bQeMQ7isAGTkoBZGErH853yGk0W_yUx1iU7dM"}"#;
        let header: CompleteHeader<Header<Empty>> = serde_json::from_str(header).unwrap();
        let thumbprint = header.inner.certificate_thumbprint.as_ref().unwrap();
        let Thumbprint::Bytes(thumbprint) = thumbprint else {
            unreachable!()
        };

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
            let mangled_header = Base64UrlUnpadded::encode_string(mangled_header.as_bytes());
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
        let mangled_header = br#"{"alg":"HS256","cty":"txt"}"#;
        let mangled_header = Base64UrlUnpadded::encode_string(mangled_header);
        let mut mangled_str = HS256_TOKEN.to_owned();
        mangled_str.replace_range(..mangled_str.find('.').unwrap(), &mangled_header);
        assert_matches!(
            UntrustedToken::new(&mangled_str).unwrap_err(),
            ParseError::UnsupportedContentType(s) if s == "txt"
        );
    }

    #[test]
    fn extracting_custom_header_fields() {
        let header = r#"{"alg":"HS256","custom":[1,"field"],"x5t":"lDpwLQbzRZmu4fjajvn3KWAx1pk"}"#;
        let header: CompleteHeader<Header<Obj>> = serde_json::from_str(header).unwrap();
        assert_eq!(header.algorithm, "HS256");
        assert!(header.inner.certificate_sha1_thumbprint.is_some());
        assert_eq!(header.inner.other_fields.len(), 1);
        assert!(header.inner.other_fields["custom"].is_array());
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
        let key = Base64UrlUnpadded::decode_vec(HS256_KEY).unwrap();
        let key = Hs256Key::new(key);

        for claims in &malformed_claims {
            let encoded_claims = Base64UrlUnpadded::encode_string(claims.as_bytes());
            let mut mangled_str = HS256_TOKEN.to_owned();
            mangled_str.replace_range(claims_start..claims_end, &encoded_claims);
            let token = UntrustedToken::new(&mangled_str).unwrap();
            assert_matches!(
                Hs256.validator::<Obj>(&key).validate(&token).unwrap_err(),
                ValidationError::MalformedClaims(_),
                "Failing claims: {claims}"
            );
        }
    }

    fn test_invalid_signature_len(mangled_str: &str, actual_len: usize) {
        let token = UntrustedToken::new(&mangled_str).unwrap();
        let key = Base64UrlUnpadded::decode_vec(HS256_KEY).unwrap();
        let key = Hs256Key::new(key);

        let err = Hs256.validator::<Empty>(&key).validate(&token).unwrap_err();
        assert_matches!(
            err,
            ValidationError::InvalidSignatureLen { actual, expected: 32 }
                if actual == actual_len
        );
    }

    #[test]
    fn short_signature_error() {
        test_invalid_signature_len(&HS256_TOKEN[..HS256_TOKEN.len() - 3], 30);
    }

    #[test]
    fn long_signature_error() {
        let mut mangled_string = HS256_TOKEN.to_owned();
        mangled_string.push('a');
        test_invalid_signature_len(&mangled_string, 33);
    }
}
