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
    Base64(base64::DecodeError),
    /// Token header cannot be parsed.
    MalformedHeader(serde_json::Error),
    /// [Content type][cty] mentioned in the token header is not supported.
    ///
    /// Supported content types are JSON (used by default) and CBOR.
    ///
    /// [cty]: https://tools.ietf.org/html/rfc7515#section-4.1.10
    UnsupportedContentType(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTokenStructure => formatter.write_str("Invalid token structure"),
            Self::Base64(e) => write!(formatter, "base64 decoding error: {}", e),
            Self::MalformedHeader(e) => write!(formatter, "Malformed token header: {}", e),
            Self::UnsupportedContentType(ty) => {
                write!(formatter, "Unsupported content type: {}", ty)
            }
        }
    }
}

impl From<base64::DecodeError> for ParseError {
    fn from(error: base64::DecodeError) -> Self {
        Self::Base64(error)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Base64(e) => Some(e),
            Self::MalformedHeader(e) => Some(e),
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
    /// Token signature is malformed (e.g., has an incorrect length).
    MalformedSignature(anyhow::Error),
    /// Token signature has failed verification.
    InvalidSignature,
    /// Token claims cannot be deserialized from JSON.
    MalformedClaims(serde_json::Error),
    /// Token claims cannot be deserialized from CBOR.
    MalformedCborClaims(serde_cbor::error::Error),
    /// Claim requested during validation is not present in the token.
    NoClaim(Claim),
    /// Token has expired.
    Expired,
    /// Token is not yet valid as per `nbf` claim.
    NotMature,
}

/// Identifier of a claim in `Claims`.
#[derive(Debug, Clone, PartialEq)]
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
                "Token algorithm ({actual}) differs from expected ({expected})",
                expected = expected,
                actual = actual
            ),
            Self::MalformedSignature(e) => write!(formatter, "Malformed token signature: {}", e),
            Self::InvalidSignature => formatter.write_str("Signature has failed verification"),
            Self::MalformedClaims(e) => write!(formatter, "Cannot deserialize claims: {}", e),
            Self::MalformedCborClaims(e) => write!(formatter, "Cannot deserialize claims: {}", e),
            Self::NoClaim(claim) => write!(
                formatter,
                "Claim `{}` requested during validation is not present in the token",
                claim
            ),
            Self::Expired => formatter.write_str("Token has expired"),
            Self::NotMature => formatter.write_str("Token is not yet ready"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MalformedSignature(e) => Some(e.as_ref()),
            Self::MalformedClaims(e) => Some(e),
            Self::MalformedCborClaims(e) => Some(e),
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
    CborClaims(serde_cbor::error::Error),
}

impl fmt::Display for CreationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(e) => write!(formatter, "Cannot serialize header: {}", e),
            Self::Claims(e) => write!(formatter, "Cannot serialize claims: {}", e),
            Self::CborClaims(e) => write!(formatter, "Cannot serialize claims into CBOR: {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CreationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Header(e) | Self::Claims(e) => Some(e),
            Self::CborClaims(e) => Some(e),
        }
    }
}
