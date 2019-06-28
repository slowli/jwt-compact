use failure_derive::*;

/// Errors that may occur during token parsing.
#[derive(Debug, Fail)]
pub enum ParseError {
    /// Token has invalid structure.
    ///
    /// Valid tokens must consist of 3 base64url-encoded parts (header, claims, and signature)
    /// separated by periods.
    #[fail(display = "Invalid token structure")]
    InvalidTokenStructure,

    /// Cannot decode base64.
    #[fail(display = "base64 decoding error: {}", _0)]
    Base64(#[fail(cause)] base64::DecodeError),

    /// Token header cannot be parsed.
    #[fail(display = "Malformed token header: {}", _0)]
    MalformedHeader(#[fail(cause)] serde_json::Error),

    /// [Content type][cty] mentioned in the token header is not supported.
    ///
    /// Supported content types are JSON (used by default) and CBOR.
    ///
    /// [cty]: https://tools.ietf.org/html/rfc7515#section-4.1.10
    #[fail(display = "Unsupported content type: {}", _0)]
    UnsupportedContentType(String),
}

impl From<base64::DecodeError> for ParseError {
    fn from(error: base64::DecodeError) -> Self {
        ParseError::Base64(error)
    }
}

/// Errors that can occur during token validation.
#[derive(Debug, Fail)]
pub enum ValidationError {
    /// Algorithm mentioned in the token header differs from invoked one.
    #[fail(display = "Token algorithm differs from the expected one")]
    AlgorithmMismatch,

    /// Token signature is malformed (e.g., has an incorrect length).
    #[fail(display = "Malformed token signature: {}", _0)]
    MalformedSignature(#[fail(cause)] failure::Error),

    /// Token signature has failed verification.
    #[fail(display = "Signature has failed verification")]
    InvalidSignature,

    /// Token claims cannot be deserialized from JSON.
    #[fail(display = "Cannot deserialize claims: {}", _0)]
    MalformedClaims(#[fail(cause)] serde_json::Error),

    /// Token claims cannot be deserialized from CBOR.
    #[fail(display = "Cannot deserialize claims: {}", _0)]
    MalformedCborClaims(#[fail(cause)] serde_cbor::error::Error),

    /// Claim requested during validation is not present in the token.
    #[fail(display = "Claim requested during validation is not present in the token")]
    NoClaim,

    /// Token has expired.
    #[fail(display = "Token has expired")]
    Expired,

    /// Token is not yet valid as per `nbf` claim.
    #[fail(display = "Token is not yet ready")]
    NotMature,
}

/// Errors that can occur during token creation.
#[derive(Debug, Fail)]
pub enum CreationError {
    /// Token header cannot be serialized.
    #[fail(display = "Cannot serialize header: {}", _0)]
    Header(#[fail(cause)] serde_json::Error),

    /// Token claims cannot be serialized into JSON.
    #[fail(display = "Cannot serialize claims: {}", _0)]
    Claims(#[fail(cause)] serde_json::Error),

    /// Token claims cannot be serialized into CBOR.
    #[fail(display = "Cannot serialize claims into CBOR: {}", _0)]
    CborClaims(#[fail(cause)] serde_cbor::error::Error),
}
