use assert_matches::assert_matches;
use chrono::{Duration, Utc};
use hex_buffer_serde::{Hex as _, HexForm};
use jwt_compact::{alg::*, prelude::*, Algorithm, ValidationError};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_json::json;

use std::{collections::HashMap, convert::TryFrom};

type Obj = serde_json::Map<String, serde_json::Value>;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct SampleClaims {
    #[serde(rename = "sub")]
    subject: String,
    name: String,
    #[serde(default)]
    admin: bool,
}

#[test]
fn hs256_reference() {
    //! Example from https://tools.ietf.org/html/rfc7515#appendix-A.1

    const TOKEN: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
                         eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
                         cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
                         dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const KEY: &str = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75\
                       aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

    let token = UntrustedToken::try_from(TOKEN).unwrap();
    assert_eq!(token.algorithm(), "HS256");

    let key = base64::decode_config(KEY, base64::URL_SAFE_NO_PAD).unwrap();
    let key = Hs256Key::from(key.as_slice());
    let token = Hs256.validate_integrity::<Obj>(&token, &key).unwrap();
    assert_eq!(
        token.claims().expiration_date.unwrap().timestamp(),
        1_300_819_380
    );
    assert_eq!(token.claims().custom["iss"], json!("joe"));
    assert_eq!(
        token.claims().custom["http://example.com/is_root"],
        json!(true)
    );
}

#[test]
fn hs384_reference() {
    //! Example generated using https://jwt.io/

    const TOKEN: &str = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.\
                         eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUs\
                         ImlhdCI6MTUxNjIzOTAyMn0.\
                         bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh";
    const KEY: &[u8] = b"your-384-bit-secret";

    let token = UntrustedToken::try_from(TOKEN).unwrap();
    assert_eq!(token.algorithm(), "HS384");
    assert_eq!(token.header().signature_type, Some("JWT".to_owned()));

    let key = Hs384Key::from(KEY);
    let token = Hs384
        .validate_integrity::<SampleClaims>(&token, &key)
        .unwrap();
    assert_eq!(token.claims().issued_at.unwrap().timestamp(), 1_516_239_022);
    assert_eq!(
        token.claims().custom,
        SampleClaims {
            subject: "1234567890".to_owned(),
            name: "John Doe".to_owned(),
            admin: true,
        }
    );
}

#[test]
fn hs512_reference() {
    //! Example generated using https://jwt.io/

    const TOKEN: &str = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.\
                         eyJzdWIiOiI5ODc2NTQzMjEiLCJuYW1lIjoiSmFuZSBEb2UiLCJhZG1pbiI6Zm\
                         Fsc2UsImlhdCI6MTUxNjIzOTEyMn0.\
                         zGgI9yNlkGofH0aIuYq7v_VPi6THftCS-59DXMQ0XugapLalKKDo6qAJkBy0i8\
                         d9DFcYIySIUgQ69Dprvp4fpA";
    const KEY: &[u8] = b"your-512-bit-secret";

    let token = UntrustedToken::try_from(TOKEN).unwrap();
    assert_eq!(token.algorithm(), "HS512");
    assert_eq!(token.header().signature_type, Some("JWT".to_owned()));

    let key = Hs512Key::from(KEY);
    let token = Hs512
        .validate_integrity::<SampleClaims>(&token, &key)
        .unwrap();
    assert_eq!(token.claims().issued_at.unwrap().timestamp(), 1_516_239_122);
    assert_eq!(
        token.claims().custom,
        SampleClaims {
            subject: "987654321".to_owned(),
            name: "Jane Doe".to_owned(),
            admin: false,
        }
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn es256k_reference() {
    //! Generated using https://github.com/uport-project/did-jwt based on the unit tests
    //! in the repository.

    use secp256k1::PublicKey;

    const TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.\
                         eyJpYXQiOjE1NjE4MTQ3ODgsImJsYSI6ImJsYSIsImlzcyI6ImRpZDp1cG9\
                         ydDoyblF0aVFHNkNnbTFHWVRCYWFLQWdyNzZ1WTdpU2V4VWtxWCJ9.\
                         cJI3_GRjb6d6LJqOXAPKhLjYnFg1ZdqTK8huTiTCb9Q53xNZiSWK95\
                         vaG4nk1Vk0-FbyVpug6yf9HoFqtKnmLQ";
    /// Uncompressed secp256k1 public key.
    const KEY_HEX: &str = "04fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479\
                           46393f8145252eea68afe67e287b3ed9b31685ba6c3b00060a73b9b1242d68f7";

    let public_key = PublicKey::from_slice(&hex::decode(KEY_HEX).unwrap()).unwrap();
    let es256k: Es256k = Default::default();
    let token = UntrustedToken::try_from(TOKEN).unwrap();
    assert_eq!(token.algorithm(), "ES256K");

    let token = es256k
        .validate_integrity::<Obj>(&token, &public_key)
        .unwrap();
    assert_eq!(token.claims().issued_at.unwrap().timestamp(), 1_561_814_788);
    let expected_claims = json!({
        "bla": "bla",
        "iss": "did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX",
    });
    assert_eq!(token.claims().custom, *expected_claims.as_object().unwrap());
}

#[cfg(any(
    feature = "exonum-crypto",
    feature = "ed25519-dalek",
    feature = "ed25519-compact"
))]
#[test]
fn ed25519_reference() {
    //! Generated using https://github.com/uport-project/did-jwt based on the unit tests
    //! in the repository.

    const TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZDI1NTE5In0.\
                         eyJpYXQiOjE1NjE4MTU1MjYsImZvbyI6ImJhciIsImlzcyI6ImRpZDp1cG9yd\
                         DoyblF0aVFHNkNnbTFHWVRCYWFLQWdyNzZ1WTdpU2V4VWtxWCJ9.\
                         Du1gZvmrmykgWnqtBFvyFZAmEQ8wGSuknEn4Qnu9jW8MwHwyAgru\
                         J3YzOVZiukhvp9RFiJlwdp4BfNbReJx8Cg";
    const KEY: &str = "06fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f61115075";

    #[cfg(feature = "exonum-crypto")]
    let bytes_to_pk = exonum_crypto::PublicKey::from_slice;
    #[cfg(feature = "ed25519-dalek")]
    let bytes_to_pk = ed25519_dalek::PublicKey::from_bytes;
    #[cfg(feature = "ed25519-compact")]
    let bytes_to_pk = Ed25519VerifyingKey::from_slice;

    let public_key = bytes_to_pk(&hex::decode(KEY).unwrap()).unwrap();
    let token = UntrustedToken::try_from(TOKEN).unwrap();
    assert_eq!(token.algorithm(), "Ed25519");

    let token = Ed25519::with_specific_name()
        .validate_integrity::<Obj>(&token, &public_key)
        .unwrap();
    assert_eq!(token.claims().issued_at.unwrap().timestamp(), 1_561_815_526);
    let expected_claims = json!({
        "foo": "bar",
        "iss": "did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX",
    });
    assert_eq!(token.claims().custom, *expected_claims.as_object().unwrap());
}

fn test_algorithm<A: Algorithm>(
    algorithm: &A,
    signing_key: &A::SigningKey,
    verifying_key: &A::VerifyingKey,
) {
    let claims = create_claims();

    // Successful case with a compact token.
    let token_string = algorithm
        .compact_token(Header::default(), &claims, signing_key)
        .unwrap();
    let token = UntrustedToken::try_from(token_string.as_str()).unwrap();
    let token = algorithm.validate_integrity(&token, verifying_key).unwrap();
    assert_eq!(*token.claims(), claims);

    // Successful case.
    let token_string = algorithm
        .token(Header::default(), &claims, signing_key)
        .unwrap();
    let token = UntrustedToken::try_from(token_string.as_str()).unwrap();
    let token = algorithm.validate_integrity(&token, verifying_key).unwrap();
    assert_eq!(*token.claims(), claims);

    // Mutate each bit of the signature.
    let signature = token_string.rsplit('.').next().unwrap();
    let signature_start = token_string.rfind('.').unwrap() + 1;
    let signature = base64::decode_config(signature, base64::URL_SAFE_NO_PAD).unwrap();
    for i in 0..(signature.len() * 8) {
        let mut mangled_signature = signature.clone();
        mangled_signature[i / 8] ^= 1 << (i % 8) as u8;
        let mangled_signature = base64::encode_config(&mangled_signature, base64::URL_SAFE_NO_PAD);

        let mut mangled_str = token_string.clone();
        mangled_str.replace_range(signature_start.., &mangled_signature);
        let token = UntrustedToken::try_from(mangled_str.as_str()).unwrap();
        let err = algorithm
            .validate_integrity::<Obj>(&token, verifying_key)
            .unwrap_err();
        match err {
            ValidationError::InvalidSignature | ValidationError::MalformedSignature(_) => {}
            err => panic!("Unexpected error: {:?}", err),
        }
    }

    // Mutate header.
    let mangled_header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, algorithm.name());
    let mangled_header = base64::encode_config(&mangled_header, base64::URL_SAFE_NO_PAD);
    let header_end = token_string.find('.').unwrap();
    assert_ne!(mangled_header, &token_string[..header_end]);
    let mut mangled_str = token_string.clone();
    mangled_str.replace_range(..header_end, &mangled_header);
    let token = UntrustedToken::try_from(mangled_str.as_str()).unwrap();
    let err = algorithm
        .validate_integrity::<Obj>(&token, verifying_key)
        .unwrap_err();
    assert_matches!(err, ValidationError::InvalidSignature);

    // Mutate claims.
    let claims_string = base64::encode_config(
        &serde_json::to_vec(&{
            let mut mangled_claims = claims;
            let issued_at = mangled_claims.issued_at.as_mut().unwrap();
            *issued_at = *issued_at + Duration::seconds(1);
            mangled_claims
        })
        .unwrap(),
        base64::URL_SAFE_NO_PAD,
    );
    assert_ne!(
        claims_string,
        token_string[(header_end + 1)..(signature_start - 1)]
    );
    let mut mangled_str = token_string.clone();
    mangled_str.replace_range((header_end + 1)..(signature_start - 1), &claims_string);
    let token = UntrustedToken::try_from(mangled_str.as_str()).unwrap();
    let err = algorithm
        .validate_integrity::<Obj>(&token, verifying_key)
        .unwrap_err();
    assert_matches!(err, ValidationError::InvalidSignature);
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct CompactClaims {
    /// We use a public claim (https://tools.ietf.org/html/rfc7519#section-4.1.2)
    /// with a custom (de)serializer. This allows to store the `subject` efficiently
    /// in the CBOR encoding.
    #[serde(rename = "sub", with = "HexForm")]
    subject: [u8; 32],
}

fn create_claims() -> Claims<CompactClaims> {
    let now = Utc::now();
    let now = now - Duration::nanoseconds(i64::from(now.timestamp_subsec_nanos()));

    Claims {
        issued_at: Some(now),
        expiration_date: Some(now + Duration::days(7)),
        not_before: None,
        custom: CompactClaims { subject: [1; 32] },
    }
}

#[test]
fn hs256_algorithm() {
    let key = Hs256Key::generate(&mut thread_rng());
    test_algorithm(&Hs256, &key, &key);
}

#[test]
fn hs384_algorithm() {
    let key = Hs384Key::generate(&mut thread_rng());
    test_algorithm(&Hs384, &key, &key);
}

#[test]
fn hs512_algorithm() {
    let key = Hs512Key::generate(&mut thread_rng());
    test_algorithm(&Hs512, &key, &key);
}

#[test]
fn compact_token_hs256() {
    let claims = create_claims();
    let key = Hs256Key::generate(&mut thread_rng());
    let long_token_str = Hs256.token(Header::default(), &claims, &key).unwrap();
    let token_str = Hs256
        .compact_token(Header::default(), &claims, &key)
        .unwrap();
    assert!(
        token_str.len() < long_token_str.len() - 40,
        "Full token length = {}, compact token length = {}",
        long_token_str.len(),
        token_str.len(),
    );
    let untrusted_token = UntrustedToken::try_from(&*token_str).unwrap();
    let token = Hs256.validate_integrity(&untrusted_token, &key).unwrap();
    assert_eq!(*token.claims(), claims);

    // Check that we can collect unknown / hard to parse claims into `Claims.custom`.
    let generic_token: Token<HashMap<String, serde_cbor::Value>> =
        Hs256.validate_integrity(&untrusted_token, &key).unwrap();
    assert_matches!(
        generic_token.claims().custom["sub"],
        serde_cbor::Value::Bytes(_)
    );
}

#[cfg(feature = "exonum-crypto")]
#[test]
fn ed25519_algorithm() {
    use exonum_crypto::gen_keypair;
    let (verifying_key, signing_key) = gen_keypair();
    test_algorithm(&Ed25519, &signing_key, &verifying_key);
}

#[cfg(feature = "ed25519-dalek")]
#[test]
fn ed25519_algorithm() {
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);
    test_algorithm(&Ed25519, &keypair, &keypair.public);
}

#[cfg(feature = "ed25519-compact")]
#[test]
fn ed25519_algorithm() {
    let mut rng = thread_rng();
    let (signing_key, verifying_key) = Ed25519.generate(&mut rng);
    test_algorithm(&Ed25519, &signing_key, &verifying_key);
}

#[cfg(feature = "secp256k1")]
#[test]
fn es256k_algorithm() {
    use rand::Rng;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    let mut rng = thread_rng();
    let signing_key = loop {
        let bytes: [u8; 32] = rng.gen();
        if let Ok(key) = SecretKey::from_slice(&bytes) {
            break key;
        }
    };
    let context = Secp256k1::new();
    let verifying_key = PublicKey::from_secret_key(&context, &signing_key);
    let es256k: Es256k<sha2::Sha256> = Es256k::new(context);
    test_algorithm(&es256k, &signing_key, &verifying_key);
}
