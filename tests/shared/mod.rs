//! Functionality shared by `algorithms` and `rsa` tests.

use assert_matches::assert_matches;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{Duration, TimeZone, Utc};
use hex_buffer_serde::{Hex as _, HexForm};
use jwt_compact::{prelude::*, Algorithm, ValidationError};
use rand::{rng, seq::index::sample as sample_indexes};
use serde::{Deserialize, Serialize};

pub type Obj = serde_json::Map<String, serde_json::Value>;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SampleClaims {
    #[serde(rename = "sub")]
    pub subject: String,
    pub name: String,
    #[serde(default)]
    pub admin: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompactClaims {
    /// We use a public claim (https://tools.ietf.org/html/rfc7519#section-4.1.2)
    /// with a custom (de)serializer. This allows to store the `subject` efficiently
    /// in the CBOR encoding.
    #[serde(rename = "sub", with = "HexForm")]
    subject: [u8; 32],
}

pub fn create_claims() -> Claims<CompactClaims> {
    let now = Utc.with_ymd_and_hms(2020, 9, 1, 10, 0, 0).single().unwrap();
    let now = now - Duration::nanoseconds(i64::from(now.timestamp_subsec_nanos()));

    let mut claims = Claims::new(CompactClaims { subject: [1; 32] });
    claims.issued_at = Some(now);
    claims.expiration = Some(now + Duration::try_days(7).unwrap());
    claims
}

pub fn test_algorithm<A: Algorithm>(
    algorithm: &A,
    signing_key: &A::SigningKey,
    verifying_key: &A::VerifyingKey,
) {
    // Maximum number of signature bits mangled.
    const MAX_MANGLED_BITS: usize = 128;

    let claims = create_claims();

    // Successful case with a compact token.
    #[cfg(feature = "ciborium")]
    {
        let token_string = algorithm
            .compact_token(&Header::empty(), &claims, signing_key)
            .unwrap();
        let token = UntrustedToken::new(&token_string).unwrap();
        let token = algorithm.validator(verifying_key).validate(&token).unwrap();
        assert_eq!(*token.claims(), claims);
    }

    // Successful case.
    let token_string = algorithm
        .token(&Header::empty(), &claims, signing_key)
        .unwrap();
    let token = UntrustedToken::new(&token_string).unwrap();
    let token = algorithm.validator(verifying_key).validate(&token).unwrap();
    assert_eq!(*token.claims(), claims);

    // Mutate signature bits.
    let signature = token_string.rsplit('.').next().unwrap();
    let signature_start = token_string.rfind('.').unwrap() + 1;
    let signature = Base64UrlUnpadded::decode_vec(signature).unwrap();
    let signature_bits = signature.len() * 8;

    let mangled_bits: Box<dyn Iterator<Item = usize>> = if signature_bits <= MAX_MANGLED_BITS {
        Box::new(0..signature_bits)
    } else {
        let indexes = sample_indexes(&mut rng(), signature_bits, MAX_MANGLED_BITS);
        Box::new(indexes.into_iter())
    };

    for i in mangled_bits {
        let mut mangled_signature = signature.clone();
        mangled_signature[i / 8] ^= 1 << (i % 8) as u8;
        let mangled_signature = Base64UrlUnpadded::encode_string(&mangled_signature);

        let mut mangled_str = token_string.clone();
        mangled_str.replace_range(signature_start.., &mangled_signature);
        let token = UntrustedToken::new(&mangled_str).unwrap();
        let err = algorithm
            .validator::<Obj>(verifying_key)
            .validate(&token)
            .unwrap_err();
        match err {
            ValidationError::InvalidSignature | ValidationError::MalformedSignature(_) => {}
            err => panic!("Unexpected error: {err:?}"),
        }
    }

    // Mutate header.
    let mangled_header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, algorithm.name());
    let mangled_header = Base64UrlUnpadded::encode_string(mangled_header.as_bytes());
    let header_end = token_string.find('.').unwrap();
    assert_ne!(mangled_header, &token_string[..header_end]);
    let mut mangled_str = token_string.clone();
    mangled_str.replace_range(..header_end, &mangled_header);
    let token = UntrustedToken::new(&mangled_str).unwrap();
    let err = algorithm
        .validator::<Obj>(verifying_key)
        .validate(&token)
        .unwrap_err();
    assert_matches!(err, ValidationError::InvalidSignature);

    // Mutate claims.
    let claims_string = Base64UrlUnpadded::encode_string(
        &serde_json::to_vec(&{
            let mut mangled_claims = claims;
            let issued_at = mangled_claims.issued_at.as_mut().unwrap();
            *issued_at += Duration::try_seconds(1).unwrap();
            mangled_claims
        })
        .unwrap(),
    );
    assert_ne!(
        claims_string,
        token_string[(header_end + 1)..(signature_start - 1)]
    );
    let mut mangled_str = token_string.clone();
    mangled_str.replace_range((header_end + 1)..(signature_start - 1), &claims_string);
    let token = UntrustedToken::new(&mangled_str).unwrap();
    let err = algorithm
        .validator::<Obj>(verifying_key)
        .validate(&token)
        .unwrap_err();
    assert_matches!(err, ValidationError::InvalidSignature);
}
