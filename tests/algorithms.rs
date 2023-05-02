//! General tests for various JWK algorithms.

use assert_matches::assert_matches;
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_json::json;

mod shared;

use crate::shared::{create_claims, test_algorithm, Obj, SampleClaims};
use jwt_compact::{alg::*, prelude::*, Algorithm, AlgorithmExt, ParseError, ValidationError};

#[test]
fn hs256_reference() {
    //! Example from https://tools.ietf.org/html/rfc7515#appendix-A.1

    const TOKEN: &str =
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAs\
         DQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1\
         gFWFOEjXk";
    const KEY: &str =
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

    let token = UntrustedToken::new(TOKEN).unwrap();
    assert_eq!(token.algorithm(), "HS256");

    let key = Base64UrlUnpadded::decode_vec(KEY).unwrap();
    let key = Hs256Key::new(key);
    #[allow(deprecated)] // Check that the deprecated API still works
    Hs256.validate_integrity::<Obj>(&token, &key).unwrap();

    let validated_token = Hs256.validator::<Obj>(&key).validate(&token).unwrap();
    assert_eq!(
        validated_token.claims().expiration.unwrap().timestamp(),
        1_300_819_380
    );
    assert_eq!(validated_token.claims().custom["iss"], json!("joe"));
    assert_eq!(
        validated_token.claims().custom["http://example.com/is_root"],
        json!(true)
    );

    let checked_key = StrongKey::try_from(key).unwrap();
    #[allow(deprecated)] // Check that the deprecated API still works
    StrongAlg(Hs256)
        .validate_integrity::<Obj>(&token, &checked_key)
        .unwrap();
    StrongAlg(Hs256)
        .validator::<Obj>(&checked_key)
        .validate(&token)
        .unwrap();
}

#[test]
fn short_hs256_key_cannot_be_checked() {
    const KEY: &[u8] = b"your-256-bit-secret";

    let key = Hs384Key::from(KEY);
    assert!(StrongKey::try_from(key).is_err());
}

#[test]
fn hs384_reference() {
    //! Example generated using https://jwt.io/

    const TOKEN: &str =
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9l\
         IiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfC\
         lLufmCVZRUuyTwJF311JHuh";
    const KEY: &[u8] = b"your-384-bit-secret";

    let token = UntrustedToken::new(TOKEN).unwrap();
    assert_eq!(token.algorithm(), "HS384");
    assert_eq!(token.header().token_type, Some("JWT".to_owned()));

    let key = Hs384Key::from(KEY);
    #[allow(deprecated)] // Check that the deprecated API still works
    Hs384
        .validate_integrity::<SampleClaims>(&token, &key)
        .unwrap();
    let token = Hs384
        .validator::<SampleClaims>(&key)
        .validate(&token)
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

    const TOKEN: &str =
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5ODc2NTQzMjEiLCJuYW1lIjoiSmFuZSBEb2Ui\
         LCJhZG1pbiI6ZmFsc2UsImlhdCI6MTUxNjIzOTEyMn0.zGgI9yNlkGofH0aIuYq7v_VPi6THftCS-59DXMQ0X\
         ugapLalKKDo6qAJkBy0i8d9DFcYIySIUgQ69Dprvp4fpA";
    const KEY: &[u8] = b"your-512-bit-secret";

    let token = UntrustedToken::new(TOKEN).unwrap();
    assert_eq!(token.algorithm(), "HS512");
    assert_eq!(token.header().token_type, Some("JWT".to_owned()));

    let key = Hs512Key::from(KEY);
    let token = Hs512
        .validator::<SampleClaims>(&key)
        .validate(&token)
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

#[cfg(feature = "p256")]
#[test]
fn es256_reference() {
    //! Taken from https://www.rfc-editor.org/rfc/rfc7515.html

    use jwt_compact::jwk::JsonWebKey;

    type PublicKey = <Es256 as Algorithm>::VerifyingKey;

    const TOKEN: &str =
        "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
         cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5d\
         jxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
    });
    let jwk: JsonWebKey<'_> = serde_json::from_value(jwk).unwrap();
    let public_key = PublicKey::try_from(&jwk).unwrap();

    let token = UntrustedToken::new(TOKEN).unwrap();
    assert_eq!(token.algorithm(), "ES256");

    let token = Es256
        .validator::<Obj>(&public_key)
        .validate(&token)
        .unwrap();
    assert_eq!(
        token.claims().expiration.unwrap().timestamp(),
        1_300_819_380
    );
    let expected_claims = json!({
        "iss": "joe",
        "http://example.com/is_root": true,
    });
    assert_eq!(token.claims().custom, *expected_claims.as_object().unwrap());
}

#[cfg(any(feature = "es256k", feature = "k256"))]
#[test]
fn es256k_reference() {
    //! Generated using https://github.com/uport-project/did-jwt based on the unit tests
    //! in the repository.

    use const_decoder::Decoder::Hex;

    const TOKEN: &str =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE1NjE4MTQ3ODgsImJsYSI6ImJsYSIsImlzcy\
         I6ImRpZDp1cG9ydDoyblF0aVFHNkNnbTFHWVRCYWFLQWdyNzZ1WTdpU2V4VWtxWCJ9.cJI3_GRjb6d6LJqOXA\
         PKhLjYnFg1ZdqTK8huTiTCb9Q53xNZiSWK95vaG4nk1Vk0-FbyVpug6yf9HoFqtKnmLQ";

    /// Uncompressed secp256k1 public key.
    const KEY: [u8; 65] = Hex.decode(
        b"04fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea535847\
          946393f8145252eea68afe67e287b3ed9b31685ba6c3b00060a73b9b1242d68f7",
    );

    type PublicKey = <Es256k as Algorithm>::VerifyingKey;

    let public_key = PublicKey::from_slice(&KEY).unwrap();
    let es256k = <Es256k>::default();
    let token = UntrustedToken::new(TOKEN).unwrap();
    assert_eq!(token.algorithm(), "ES256K");

    let token = es256k
        .validator::<Obj>(&public_key)
        .validate(&token)
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

    use const_decoder::Decoder::Hex;

    type EdSigningKey = <Ed25519 as Algorithm>::SigningKey;
    type EdVerifyingKey = <Ed25519 as Algorithm>::VerifyingKey;

    const TOKEN: &str =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZDI1NTE5In0.eyJpYXQiOjE1NjE4MTU1MjYsImZvbyI6ImJhciIsImlzc\
         yI6ImRpZDp1cG9ydDoyblF0aVFHNkNnbTFHWVRCYWFLQWdyNzZ1WTdpU2V4VWtxWCJ9.Du1gZvmrmykgWnqtB\
         FvyFZAmEQ8wGSuknEn4Qnu9jW8MwHwyAgruJ3YzOVZiukhvp9RFiJlwdp4BfNbReJx8Cg";
    const KEY: [u8; 32] =
        Hex.decode(b"06fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f61115075");
    const SIGNING_KEY: [u8; 64] = Hex.decode(
        b"9e55d1e1aa1f455b8baad9fdf975503655f8b359d542fa7e4ce84106d625b352\
          06fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f61115075",
    );

    fn check_key_traits<Sk, Vk>()
    where
        Sk: SigningKey<Ed25519>,
        Vk: VerifyingKey<Ed25519>,
        Ed25519: Algorithm<SigningKey = Sk, VerifyingKey = Vk>,
    {
        let public_key = Vk::from_slice(&KEY).unwrap();
        assert_eq!(*public_key.as_bytes(), KEY);

        let secret_key = Sk::from_slice(&SIGNING_KEY).unwrap();
        assert_eq!(*secret_key.as_bytes(), SIGNING_KEY);
        assert_eq!(*secret_key.to_verifying_key().as_bytes(), KEY);
    }

    check_key_traits::<EdSigningKey, EdVerifyingKey>();

    let public_key = EdVerifyingKey::from_slice(&KEY).unwrap();
    let token = UntrustedToken::new(TOKEN).unwrap();
    assert_eq!(token.algorithm(), "Ed25519");

    let token = Ed25519::with_specific_name()
        .validator::<Obj>(&public_key)
        .validate(&token)
        .unwrap();
    assert_eq!(token.claims().issued_at.unwrap().timestamp(), 1_561_815_526);
    let expected_claims = json!({
        "foo": "bar",
        "iss": "did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX",
    });
    assert_eq!(token.claims().custom, *expected_claims.as_object().unwrap());
}

#[test]
fn hs256_algorithm() {
    let key = Hs256Key::generate(&mut thread_rng()).into_inner();
    test_algorithm(&Hs256, &key, &key);
}

#[test]
fn hs384_algorithm() {
    let key = Hs384Key::generate(&mut thread_rng()).into_inner();
    test_algorithm(&Hs384, &key, &key);
}

#[test]
fn hs512_algorithm() {
    let key = Hs512Key::generate(&mut thread_rng()).into_inner();
    test_algorithm(&Hs512, &key, &key);
}

#[cfg(feature = "serde_cbor")]
#[test]
fn compact_token_hs256() {
    let claims = shared::create_claims();
    let key = Hs256Key::generate(&mut thread_rng()).into_inner();
    let long_token_str = Hs256.token(&Header::empty(), &claims, &key).unwrap();
    let token_str = Hs256
        .compact_token(&Header::empty(), &claims, &key)
        .unwrap();
    assert!(
        token_str.len() < long_token_str.len() - 40,
        "Full token length = {}, compact token length = {}",
        long_token_str.len(),
        token_str.len(),
    );
    let untrusted_token = UntrustedToken::new(&token_str).unwrap();
    let token = Hs256.validator(&key).validate(&untrusted_token).unwrap();
    assert_eq!(*token.claims(), claims);

    // Check that we can collect unknown / hard to parse claims into `Claims.custom`.
    // `serde_cbor::Value` is not defined without `std`.
    #[cfg(feature = "std")]
    {
        use std::collections::HashMap;

        let generic_token: Token<HashMap<String, serde_cbor::Value>> =
            Hs256.validator(&key).validate(&untrusted_token).unwrap();
        assert_matches::assert_matches!(
            generic_token.claims().custom["sub"],
            serde_cbor::Value::Bytes(_)
        );
    }
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
    use ed25519_dalek::{Keypair, SecretKey, SECRET_KEY_LENGTH};
    use rand_core::RngCore;

    // Since `ed25519_dalek` works with `rand` v0.7 rather than v0.8, we use this roundabout way
    // to generate a keypair.
    let mut secret = [0_u8; SECRET_KEY_LENGTH];
    thread_rng().fill_bytes(&mut secret);
    let secret = SecretKey::from_bytes(&secret).unwrap();
    let keypair = Keypair {
        public: (&secret).into(),
        secret,
    };

    test_algorithm(&Ed25519, &keypair, &keypair.public);
}

#[cfg(feature = "ed25519-compact")]
#[test]
fn ed25519_algorithm() {
    let (signing_key, verifying_key) = Ed25519::generate(&mut thread_rng());
    test_algorithm(&Ed25519, &signing_key, &verifying_key);
}

#[cfg(any(feature = "es256k", feature = "k256"))]
#[test]
fn es256k_algorithm() {
    use rand::Rng;

    type SecretKey = <Es256k as Algorithm>::SigningKey;
    type PublicKey = <Es256k as Algorithm>::VerifyingKey;

    let mut rng = thread_rng();
    let signing_key = loop {
        let bytes: [u8; 32] = rng.gen();
        if let Ok(key) = SecretKey::from_slice(&bytes) {
            break key;
        }
    };
    let verifying_key = signing_key.to_verifying_key();
    let es256k: Es256k = Es256k::default();
    test_algorithm(&es256k, &signing_key, &verifying_key);

    // Test correctness of `SigningKey` / `VerifyingKey` trait implementations.
    let signing_key_bytes = SigningKey::as_bytes(&signing_key);
    let signing_key_copy: SecretKey = SigningKey::from_slice(&signing_key_bytes).unwrap();
    assert_eq!(signing_key.as_bytes(), signing_key_copy.as_bytes());
    assert_eq!(verifying_key, signing_key.to_verifying_key());

    let verifying_key_bytes = verifying_key.as_bytes();
    assert_eq!(verifying_key_bytes.len(), 33);
    let verifying_key_copy: PublicKey = VerifyingKey::from_slice(&verifying_key_bytes).unwrap();
    assert_eq!(verifying_key, verifying_key_copy);
}

#[cfg(any(feature = "es256k", feature = "k256"))]
#[test]
fn high_s_in_signature_is_successfully_validated() {
    use jwt_compact::jwk::JsonWebKey;

    type PublicKey = <Es256k as Algorithm>::VerifyingKey;

    const TOKEN: &str = "eyJhbGciOiJFUzI1NksifQ.\
         eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6ZmFsc2UsImV4cCI6MTYyMTc5ODg3OSwic3ViIjoiam9obi5\
         kb2VAZXhhbXBsZS5jb20ifQ.\
         h2LqgiD_K_jYPzwU1g28hmB-zfwJ94eU_M7BvrRfxTv7Mr92ueHIe52_8HJBzZmzZeELqFsQDgJb3ppTRUYdfQ";

    let jwk = json!({
        "kty": "EC",
        "crv": "secp256k1",
        "x": "95MHYo69A7OwsGFDf7rvPgv3HDXUgUwpyPi2nJnAXD0",
        "y": "YZZvIWme4a0PpEBme0vTQYJ0I9suh7-CZICQHEn_Y_4",
    });
    let jwk: JsonWebKey<'_> = serde_json::from_value(jwk).unwrap();
    let public_key = PublicKey::try_from(&jwk).unwrap();

    let token = UntrustedToken::new(TOKEN).unwrap();
    <Es256k>::default()
        .validator::<serde_json::Value>(&public_key)
        .validate(&token)
        .unwrap();
}

#[cfg(feature = "p256")]
#[test]
fn es256_algorithm() {
    use rand::Rng;

    type SecretKey = <Es256 as Algorithm>::SigningKey;
    type PublicKey = <Es256 as Algorithm>::VerifyingKey;

    let mut rng = thread_rng();
    let signing_key = loop {
        let bytes: [u8; 32] = rng.gen();
        if let Ok(key) = SecretKey::from_slice(&bytes) {
            break key;
        }
    };
    let verifying_key = signing_key.to_verifying_key();
    test_algorithm(&Es256, &signing_key, &verifying_key);

    // Test correctness of `SigningKey` / `VerifyingKey` trait implementations.
    let signing_key_bytes = SigningKey::as_bytes(&signing_key);
    let signing_key_copy: SecretKey = SigningKey::from_slice(&signing_key_bytes).unwrap();
    assert_eq!(signing_key.as_bytes(), signing_key_copy.as_bytes());
    assert_eq!(verifying_key, signing_key.to_verifying_key());

    let verifying_key_bytes = verifying_key.as_bytes();
    assert_eq!(verifying_key_bytes.len(), 33);
    let verifying_key_copy: PublicKey = VerifyingKey::from_slice(&verifying_key_bytes).unwrap();
    assert_eq!(verifying_key, verifying_key_copy);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeaderExtensions {
    custom: String,
}

fn create_header() -> Header<HeaderExtensions> {
    Header::new(HeaderExtensions {
        custom: "custom".to_owned(),
    })
    .with_token_type("JWT")
    .with_key_id("test_key")
}

fn test_algorithm_with_custom_header<A: Algorithm>(
    algorithm: &A,
    signing_key: &A::SigningKey,
    verifying_key: &A::VerifyingKey,
) {
    type Untrusted<'a> = UntrustedToken<'a, HeaderExtensions>;

    let header = create_header();
    let claims = create_claims();

    // Successful case with a compact token.
    #[cfg(feature = "serde_cbor")]
    {
        let token_string = algorithm
            .compact_token(&header, &claims, signing_key)
            .unwrap();
        let token = Untrusted::try_from(token_string.as_str()).unwrap();
        assert_eq!(token.header().other_fields.custom, "custom");
        let token = algorithm.validator(verifying_key).validate(&token).unwrap();
        assert_eq!(token.header().other_fields.custom, "custom");
        assert_eq!(*token.claims(), claims);
    }

    // Successful case.
    let token_string = algorithm.token(&header, &claims, signing_key).unwrap();
    let token = Untrusted::try_from(token_string.as_str()).unwrap();
    assert_eq!(token.header().other_fields.custom, "custom");
    let token = algorithm.validator(verifying_key).validate(&token).unwrap();
    assert_eq!(token.header().other_fields.custom, "custom");
    assert_eq!(*token.claims(), claims);

    // Mutate header.
    let mangled_header = format!(
        r#"{{"alg":"{}","typ":"JWT","custom":"?"}}"#,
        algorithm.name()
    );
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

    // Check that token validation fails if the mandatory field is missing from the header.
    let bogus_token_string = algorithm
        .token(&Header::empty(), &claims, signing_key)
        .unwrap();
    let err = Untrusted::try_from(bogus_token_string.as_str()).unwrap_err();
    let ParseError::MalformedHeader(err) = err else {
        panic!("unexpected parse error: {err}");
    };
    assert!(err.to_string().contains("custom"), "{err}");
}

#[test]
fn hs256_algorithm_with_custom_header() {
    let key = Hs256Key::generate(&mut thread_rng()).into_inner();
    test_algorithm_with_custom_header(&Hs256, &key, &key);
}

#[test]
fn hs384_algorithm_with_custom_header() {
    let key = Hs384Key::generate(&mut thread_rng()).into_inner();
    test_algorithm_with_custom_header(&Hs384, &key, &key);
}

#[test]
fn hs512_algorithm_with_custom_header() {
    let key = Hs512Key::generate(&mut thread_rng()).into_inner();
    test_algorithm_with_custom_header(&Hs512, &key, &key);
}
