use assert_matches::assert_matches;
use chrono::{Duration, TimeZone, Utc};
use hex_buffer_serde::{Hex as _, HexForm};
use rand::{seq::index::sample as sample_indexes, thread_rng};
use serde::{Deserialize, Serialize};
use serde_json::json;

use core::convert::TryFrom;

use jwt_compact::{alg::*, prelude::*, Algorithm, ValidationError};

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

fn test_ed25519_reference() {
    //! Generated using https://github.com/uport-project/did-jwt based on the unit tests
    //! in the repository.

    type EdSigningKey = <Ed25519 as Algorithm>::SigningKey;
    type EdVerifyingKey = <Ed25519 as Algorithm>::VerifyingKey;

    const TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZDI1NTE5In0.\
                         eyJpYXQiOjE1NjE4MTU1MjYsImZvbyI6ImJhciIsImlzcyI6ImRpZDp1cG9yd\
                         DoyblF0aVFHNkNnbTFHWVRCYWFLQWdyNzZ1WTdpU2V4VWtxWCJ9.\
                         Du1gZvmrmykgWnqtBFvyFZAmEQ8wGSuknEn4Qnu9jW8MwHwyAgru\
                         J3YzOVZiukhvp9RFiJlwdp4BfNbReJx8Cg";
    const KEY: &str = "06fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f61115075";
    const SIGNING_KEY: &str = "9e55d1e1aa1f455b8baad9fdf975503655f8b359d542fa7e4ce84106d625b352\
        06fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f61115075";

    fn check_key_traits<Sk, Vk>()
    where
        Sk: SigningKey<Ed25519>,
        Vk: VerifyingKey<Ed25519>,
        Ed25519: Algorithm<SigningKey = Sk, VerifyingKey = Vk>,
    {
        let public_key_bytes = hex::decode(KEY).unwrap();
        let public_key = Vk::from_slice(&public_key_bytes).unwrap();
        assert_eq!(public_key.as_bytes(), public_key_bytes);

        let secret_key_bytes = hex::decode(SIGNING_KEY).unwrap();
        let secret_key = Sk::from_slice(&secret_key_bytes).unwrap();
        assert_eq!(secret_key.as_bytes(), secret_key_bytes);
        assert_eq!(secret_key.to_verifying_key().as_bytes(), public_key_bytes);
    }

    check_key_traits::<EdSigningKey, EdVerifyingKey>();

    let public_key_bytes = hex::decode(KEY).unwrap();
    let public_key = EdVerifyingKey::from_slice(&public_key_bytes).unwrap();
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

#[cfg(any(
    feature = "exonum-crypto",
    feature = "ed25519-dalek",
    feature = "ed25519-compact"
))]
#[test]
fn ed25519_reference() {
    test_ed25519_reference();
}

fn test_algorithm<A: Algorithm>(
    algorithm: &A,
    signing_key: &A::SigningKey,
    verifying_key: &A::VerifyingKey,
) {
    // Maximum number of signature bits mangled.
    const MAX_MANGLED_BITS: usize = 128;

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

    // Mutate signature bits.
    let signature = token_string.rsplit('.').next().unwrap();
    let signature_start = token_string.rfind('.').unwrap() + 1;
    let signature = base64::decode_config(signature, base64::URL_SAFE_NO_PAD).unwrap();
    let signature_bits = signature.len() * 8;

    let mangled_bits: Box<dyn Iterator<Item = usize>> = if signature_bits <= MAX_MANGLED_BITS {
        Box::new(0..signature_bits)
    } else {
        let indexes = sample_indexes(&mut thread_rng(), signature_bits, MAX_MANGLED_BITS);
        Box::new(indexes.into_iter())
    };

    for i in mangled_bits {
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
    let now = Utc.ymd(2020, 9, 1).and_hms(10, 0, 0);
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
    // `serde_cbor::Value` is not defined without `std`.
    #[cfg(feature = "std")]
    {
        use std::collections::HashMap;

        let generic_token: Token<HashMap<String, serde_cbor::Value>> =
            Hs256.validate_integrity(&untrusted_token, &key).unwrap();
        assert_matches!(
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
    let (signing_key, verifying_key) = Ed25519::generate(&mut rng);
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

    // Test correctness of `SigningKey` / `VerifyingKey` trait implementations.
    let signing_key_bytes = SigningKey::as_bytes(&signing_key);
    let signing_key_copy: SecretKey = SigningKey::from_slice(&signing_key_bytes).unwrap();
    assert_eq!(signing_key, signing_key_copy);
    assert_eq!(verifying_key, signing_key.to_verifying_key());

    let verifying_key_bytes = verifying_key.as_bytes();
    assert_eq!(verifying_key_bytes.len(), 33);
    let verifying_key_copy: PublicKey = VerifyingKey::from_slice(&verifying_key_bytes).unwrap();
    assert_eq!(verifying_key, verifying_key_copy);
}

#[cfg(feature = "rsa")]
const RSA_PRIVATE_KEY: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----
"#;

#[cfg(feature = "rsa")]
#[test]
fn rs256_algorithm() {
    let rsa = Rsa::rs256();
    let signing_key = rsa::pem::parse(RSA_PRIVATE_KEY).unwrap();
    let signing_key = RSAPrivateKey::from_pkcs1(&signing_key.contents).unwrap();
    signing_key.validate().unwrap();
    let verifying_key = signing_key.to_public_key();
    test_algorithm(&rsa, &signing_key, &verifying_key);
}

#[cfg(feature = "rsa")]
#[test]
fn rs256_algorithm_with_generated_keys() {
    //! Since RSA key generation is very slow in the debug mode, we test generated keys
    //! for only one JWS algorithm.

    let rsa = Rsa::rs256();
    let (signing_key, verifying_key) =
        Rsa::generate(&mut thread_rng(), ModulusBits::TwoKilobytes).unwrap();
    test_algorithm(&rsa, &signing_key, &verifying_key);
}

#[cfg(feature = "rsa")]
#[test]
fn rs384_algorithm() {
    let rsa = Rsa::rs384();
    let signing_key = rsa::pem::parse(RSA_PRIVATE_KEY).unwrap();
    let signing_key = RSAPrivateKey::from_pkcs1(&signing_key.contents).unwrap();
    signing_key.validate().unwrap();
    let verifying_key = signing_key.to_public_key();
    test_algorithm(&rsa, &signing_key, &verifying_key);
}

#[cfg(feature = "rsa")]
#[test]
fn rs512_algorithm() {
    let rsa = Rsa::rs512();
    let signing_key = rsa::pem::parse(RSA_PRIVATE_KEY).unwrap();
    let signing_key = RSAPrivateKey::from_pkcs1(&signing_key.contents).unwrap();
    signing_key.validate().unwrap();
    let verifying_key = signing_key.to_public_key();
    test_algorithm(&rsa, &signing_key, &verifying_key);
}

#[cfg(feature = "rsa")]
#[test]
fn ps256_algorithm() {
    let rsa = Rsa::ps256();
    let signing_key = rsa::pem::parse(RSA_PRIVATE_KEY).unwrap();
    let signing_key = RSAPrivateKey::from_pkcs1(&signing_key.contents).unwrap();
    signing_key.validate().unwrap();
    let verifying_key = signing_key.to_public_key();
    test_algorithm(&rsa, &signing_key, &verifying_key);
}

#[cfg(feature = "rsa")]
#[test]
fn ps384_algorithm() {
    let rsa = Rsa::ps384();
    let signing_key = rsa::pem::parse(RSA_PRIVATE_KEY).unwrap();
    let signing_key = RSAPrivateKey::from_pkcs1(&signing_key.contents).unwrap();
    signing_key.validate().unwrap();
    let verifying_key = signing_key.to_public_key();
    test_algorithm(&rsa, &signing_key, &verifying_key);
}

#[cfg(feature = "rsa")]
#[test]
fn ps512_algorithm() {
    let rsa = Rsa::ps512();
    let signing_key = rsa::pem::parse(RSA_PRIVATE_KEY).unwrap();
    let signing_key = RSAPrivateKey::from_pkcs1(&signing_key.contents).unwrap();
    signing_key.validate().unwrap();
    let verifying_key = signing_key.to_public_key();
    test_algorithm(&rsa, &signing_key, &verifying_key);
}

#[cfg(feature = "rsa")]
const RSA_PUBLIC_KEY: &str = r#"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----
"#;

#[cfg(feature = "rsa")]
fn test_rsa_reference(rsa: Rsa, token: &str) {
    let public_key = rsa::pem::parse(RSA_PUBLIC_KEY).unwrap();
    let public_key = RSAPublicKey::from_pkcs8(&public_key.contents).unwrap();
    let token = UntrustedToken::try_from(token).unwrap();
    assert_eq!(token.algorithm(), rsa.name());

    let token = rsa
        .validate_integrity::<SampleClaims>(&token, &public_key)
        .unwrap();
    assert_eq!(token.claims().issued_at.unwrap().timestamp(), 1_516_239_022);
    assert_eq!(
        token.claims().custom,
        SampleClaims {
            subject: "1234567890".to_owned(),
            name: "John Doe".to_owned(),
            admin: true
        }
    );
}

#[cfg(feature = "rsa")]
#[test]
fn rs256_reference() {
    // Generated using https://jwt.io/
    const TOKEN: &str = "\
        eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lI\
        iwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DN\
        Sl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEb\
        DRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6Xx\
        UTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7t\
        uPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA";

    test_rsa_reference(Rsa::rs256(), TOKEN);
}

#[cfg(feature = "rsa")]
#[test]
fn rs384_reference() {
    // Generated using https://jwt.io/
    const TOKEN: &str = "\
        eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lI\
        iwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.D4kXa3UspFjRA9ys5tsD4YDyxxam3l_XnOb3hMEdPDT\
        fSLRHPv4HPwxvin-pIkEmfJshXPSK7O4zqSXWAXFO52X-upJjFc_gpGDswctNWpOJeXe1xBgJ--VuGDzUQCqkr\
        9UBpN-Q7TE5u9cgIVisekSFSH5Ax6aXQC9vCO5LooNFx_WnbTLNZz7FUia9vyJ544kLB7UcacL-_idgRNIWPdd\
        _d1vvnNGkknIMarRjCsjAEf6p5JGhYZ8_C18g-9DsfokfUfSpKgBR23R8v8ZAAmPPPiJ6MZXkefqE7p3jRbA--\
        58z5TlHmH9nTB1DYE2872RYvyzG3LoQ-2s93VaVuw";

    test_rsa_reference(Rsa::rs384(), TOKEN);
}

#[cfg(feature = "rsa")]
#[test]
fn rs512_reference() {
    // Generated using https://jwt.io/
    const TOKEN: &str = "\
        eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lI\
        iwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7c\
        IgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyf\
        oDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwz\
        aSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajz\
        Z7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A";

    test_rsa_reference(Rsa::rs512(), TOKEN);
}

#[cfg(feature = "rsa")]
#[test]
fn ps256_reference() {
    // Generated using https://jwt.io/
    const TOKEN: &str = "\
        eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lI\
        iwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.hZnl5amPk_I3tb4O-Otci_5XZdVWhPlFyVRvcqSwnDo\
        _srcysDvhhKOD01DigPK1lJvTSTolyUgKGtpLqMfRDXQlekRsF4XhAjYZTmcynf-C-6wO5EI4wYewLNKFGGJzH\
        AknMgotJFjDi_NCVSjHsW3a10nTao1lB82FRS305T226Q0VqNVJVWhE4G0JQvi2TssRtCxYTqzXVt22iDKkXeZ\
        JARZ1paXHGV5Kd1CljcZtkNZYIGcwnj65gvuCwohbkIxAnhZMJXCLaVvHqv9l-AAUV7esZvkQR1IpwBAiDQJh4\
        qxPjFGylyXrHMqh5NlT_pWL2ZoULWTg_TJjMO9TuQ";

    test_rsa_reference(Rsa::ps256(), TOKEN);
}

#[cfg(feature = "rsa")]
#[test]
fn ps384_reference() {
    // Generated using https://jwt.io/
    const TOKEN: &str = "\
        eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lI\
        iwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.MqF1AKsJkijKnfqEI3VA1OnzAL2S4eIpAuievMgD3tE\
        FyFMU67gCbg-fxsc5dLrxNwdZEXs9h0kkicJZ70mp6p5vdv-j2ycDKBWg05Un4OhEl7lYcdIsCsB8QUPmstF-l\
        QWnNqnq3wra1GynJrOXDL27qIaJnnQKlXuayFntBF0j-82jpuVdMaSXvk3OGaOM-7rCRsBcSPmocaAO-uWJEGP\
        w_OWVaC5RRdWDroPi4YL4lTkDEC-KEvVkqCnFm_40C-T_siXquh5FVbpJjb3W2_YvcqfDRj44TsRrpVhk6ohsH\
        MNeUad_cxnFnpolIKnaXq_COv35e9EgeQIPAbgIeg";

    test_rsa_reference(Rsa::ps384(), TOKEN);
}
