//! Error handling.

use core::fmt;

use crate::alloc::String;

/// Errors that may occur during token parsing.
#[derive(Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// Token has invalid structure.
    ///
    /// Valid tokens must consist of 3 base64url-encoded parts (header, claims, and signature)
    /// separated by periods.
    InvalidTokenStructure,
    /// Cannot decode base64.
    InvalidBase64Encoding,
    /// Token header cannot be parsed.
    MalformedHeader(serde_json::Error),
    /// [Content type][cty] mentioned in the token header is not supported.
    ///
    /// Supported content types are JSON (used by default) and CBOR (only if the `serde_cbor`
    /// crate feature is enabled, which it is by default).
    ///
    /// [cty]: https://tools.ietf.org/html/rfc7515#section-4.1.10
    UnsupportedContentType(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTokenStructure => formatter.write_str("invalid token structure"),
            Self::InvalidBase64Encoding => write!(formatter, "invalid base64 decoding"),
            Self::MalformedHeader(err) => write!(formatter, "malformed token header: {err}"),
            Self::UnsupportedContentType(ty) => {
                write!(formatter, "unsupported content type: {ty}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MalformedHeader(err) => Some(err),
            _ => None,
        }
    }
}

/// Errors that can occur during token validation.
#[derive(Debug)]
#[non_exhaustive]
pub enum ValidationError {
    /// Algorithm mentioned in the token header differs from invoked one.
    AlgorithmMismatch {
        /// Expected algorithm name.
        expected: String,
        /// Actual algorithm in the token.
        actual: String,
    },
    /// Token signature has invalid byte length.
    InvalidSignatureLen {
        /// Expected signature length.
        expected: usize,
        /// Actual signature length.
        actual: usize,
    },
    /// Token signature is malformed.
    MalformedSignature(anyhow::Error),
    /// Token signature has failed verification.
    InvalidSignature,
    /// Token claims cannot be deserialized from JSON.
    MalformedClaims(serde_json::Error),
    /// Token claims cannot be deserialized from CBOR.
    #[cfg(feature = "serde_cbor")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde_cbor")))]
    MalformedCborClaims(serde_cbor::error::Error),
    /// Claim requested during validation is not present in the token.
    NoClaim(Claim),
    /// Token has expired.
    Expired,
    /// Token is not yet valid as per `nbf` claim.
    NotMature,
}

/// Identifier of a claim in `Claims`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Claim {
    /// `exp` claim (expiration time).
    Expiration,
    /// `nbf` claim (valid not before).
    NotBefore,
}

impl fmt::Display for Claim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Expiration => "exp",
            Self::NotBefore => "nbf",
        })
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlgorithmMismatch { expected, actual } => write!(
                formatter,
                "token algorithm ({actual}) differs from expected ({expected})"
            ),
            Self::InvalidSignatureLen { expected, actual } => write!(
                formatter,
                "invalid signature length: expected {expected} bytes, got {actual} bytes"
            ),
            Self::MalformedSignature(err) => write!(formatter, "malformed token signature: {err}"),
            Self::InvalidSignature => formatter.write_str("signature has failed verification"),
            Self::MalformedClaims(err) => write!(formatter, "cannot deserialize claims: {err}"),
            #[cfg(feature = "serde_cbor")]
            Self::MalformedCborClaims(err) => write!(formatter, "cannot deserialize claims: {err}"),
            Self::NoClaim(claim) => write!(
                formatter,
                "claim `{claim}` requested during validation is not present in the token"
            ),
            Self::Expired => formatter.write_str("token has expired"),
            Self::NotMature => formatter.write_str("token is not yet ready"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MalformedSignature(err) => Some(err.as_ref()),
            Self::MalformedClaims(err) => Some(err),
            #[cfg(feature = "serde_cbor")]
            Self::MalformedCborClaims(err) => Some(err),
            _ => None,
        }
    }
}

/// Errors that can occur during token creation.
#[derive(Debug)]
#[non_exhaustive]
pub enum CreationError {
    /// Token header cannot be serialized.
    Header(serde_json::Error),
    /// Token claims cannot be serialized into JSON.
    Claims(serde_json::Error),
    /// Token claims cannot be serialized into CBOR.
    #[cfg(feature = "serde_cbor")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde_cbor")))]
    CborClaims(serde_cbor::error::Error),
}

impl fmt::Display for CreationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(err) => write!(formatter, "cannot serialize header: {err}"),
            Self::Claims(err) => write!(formatter, "cannot serialize claims: {err}"),
            #[cfg(feature = "serde_cbor")]
            Self::CborClaims(err) => write!(formatter, "cannot serialize claims into CBOR: {err}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CreationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Header(err) | Self::Claims(err) => Some(err),
            #[cfg(feature = "serde_cbor")]
            Self::CborClaims(err) => Some(err),
        }
    }
}
