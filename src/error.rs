use thiserror::Error;

/// Errors that may occur during token parsing.
#[derive(Debug, Error)]
pub enum ParseError {
    /// Token has invalid structure.
    ///
    /// Valid tokens must consist of 3 base64url-encoded parts (header, claims, and signature)
    /// separated by periods.
    #[error("Invalid token structure")]
    InvalidTokenStructure,

    /// Cannot decode base64.
    #[error("base64 decoding error: {}", _0)]
    Base64(#[from] base64::DecodeError),

    /// Token header cannot be parsed.
    #[error("Malformed token header: {}", _0)]
    MalformedHeader(#[source] serde_json::Error),

    /// [Content type][cty] mentioned in the token header is not supported.
    ///
    /// Supported content types are JSON (used by default) and CBOR.
    ///
    /// [cty]: https://tools.ietf.org/html/rfc7515#section-4.1.10
    #[error("Unsupported content type: {}", _0)]
    UnsupportedContentType(String),
}

/// Errors that can occur during token validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// Algorithm mentioned in the token header differs from invoked one.
    #[error("Token algorithm differs from the expected one")]
    AlgorithmMismatch,

    /// Token signature is malformed (e.g., has an incorrect length).
    #[error("Malformed token signature: {}", _0)]
    MalformedSignature(#[source] anyhow::Error),

    /// Token signature has failed verification.
    #[error("Signature has failed verification")]
    InvalidSignature,

    /// Token claims cannot be deserialized from JSON.
    #[error("Cannot deserialize claims: {}", _0)]
    MalformedClaims(#[source] serde_json::Error),

    /// Token claims cannot be deserialized from CBOR.
    #[error("Cannot deserialize claims: {}", _0)]
    MalformedCborClaims(#[source] serde_cbor::error::Error),

    /// Claim requested during validation is not present in the token.
    #[error("Claim requested during validation is not present in the token")]
    NoClaim,

    /// Token has expired.
    #[error("Token has expired")]
    Expired,

    /// Token is not yet valid as per `nbf` claim.
    #[error("Token is not yet ready")]
    NotMature,
}

/// Errors that can occur during token creation.
#[derive(Debug, Error)]
pub enum CreationError {
    /// Token header cannot be serialized.
    #[error("Cannot serialize header: {}", _0)]
    Header(#[source] serde_json::Error),

    /// Token claims cannot be serialized into JSON.
    #[error("Cannot serialize claims: {}", _0)]
    Claims(#[source] serde_json::Error),

    /// Token claims cannot be serialized into CBOR.
    #[error("Cannot serialize claims into CBOR: {}", _0)]
    CborClaims(#[source] serde_cbor::error::Error),
}
