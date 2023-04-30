//! Tests for RSA algorithms.

use assert_matches::assert_matches;
use rand::thread_rng;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePublicKey};

mod shared;

use crate::shared::{create_claims, test_algorithm, CompactClaims, SampleClaims};
use jwt_compact::{alg::*, prelude::*, Algorithm, ValidationError};

const RSA_PRIVATE_KEY: &str = "\
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
-----END RSA PRIVATE KEY-----";

const RSA_PUBLIC_KEY: &str = "\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----";

#[test]
fn rs256_algorithm() {
    let signing_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
    signing_key.validate().unwrap();
    let verifying_key = signing_key.to_public_key();
    test_algorithm(&Rsa::rs256(), &signing_key, &verifying_key);
}

#[test]
fn rs256_algorithm_with_checked_len() {
    let signing_key = {
        let key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        key.validate().unwrap();
        StrongKey::try_from(key).unwrap()
    };
    let verifying_key = signing_key.to_public_key();
    test_algorithm(&StrongAlg(Rsa::rs256()), &signing_key, &verifying_key);
}

#[test]
fn rs256_algorithm_with_generated_keys() {
    //! Since RSA key generation is very slow in the debug mode, we test generated keys
    //! for only one JWS algorithm.

    let rsa = StrongAlg(Rsa::rs256());
    let (signing_key, verifying_key) =
        Rsa::generate(&mut thread_rng(), ModulusBits::TwoKibibytes).unwrap();
    test_algorithm(&rsa, &signing_key, &verifying_key);
}

#[test]
fn ps256_checked_len_fails_on_undersized_key() {
    let small_private_key = RsaPrivateKey::new(&mut thread_rng(), 1_024).unwrap();
    let claims = create_claims();
    let token = Rsa::ps256()
        .token(Header::empty(), &claims, &small_private_key)
        .unwrap();
    let token = UntrustedToken::new(&token).unwrap();

    // We should not be able to wrap the private key or a public key generated from it.
    let small_public_key = small_private_key.to_public_key();
    assert!(StrongKey::try_from(small_public_key).is_err());
    assert!(StrongKey::try_from(small_private_key).is_err());

    let public_key = RsaPublicKey::from_public_key_pem(RSA_PUBLIC_KEY).unwrap();
    let public_key = StrongKey::try_from(public_key).unwrap();

    let err = StrongAlg(Rsa::ps256())
        .validator::<CompactClaims>(&public_key)
        .validate(&token)
        .unwrap_err();
    assert_matches!(err, ValidationError::InvalidSignature);
}

#[test]
fn rs384_algorithm() {
    let signing_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
    signing_key.validate().unwrap();
    let verifying_key = signing_key.to_public_key();
    test_algorithm(&Rsa::rs384(), &signing_key, &verifying_key);
}

#[test]
fn rs512_algorithm() {
    let signing_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
    signing_key.validate().unwrap();
    let verifying_key = signing_key.to_public_key();
    test_algorithm(&Rsa::rs512(), &signing_key, &verifying_key);
}

#[test]
fn ps256_algorithm() {
    let signing_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
    signing_key.validate().unwrap();
    let verifying_key = signing_key.to_public_key();
    test_algorithm(&Rsa::ps256(), &signing_key, &verifying_key);
}

#[test]
fn ps384_algorithm() {
    let signing_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
    signing_key.validate().unwrap();
    let verifying_key = signing_key.to_public_key();
    test_algorithm(&Rsa::ps384(), &signing_key, &verifying_key);
}

#[test]
fn ps512_algorithm() {
    let signing_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
    signing_key.validate().unwrap();
    let verifying_key = signing_key.to_public_key();
    test_algorithm(&Rsa::ps512(), &signing_key, &verifying_key);
}

fn test_rsa_reference(rsa: Rsa, token: &str) {
    let public_key = RsaPublicKey::from_public_key_pem(RSA_PUBLIC_KEY).unwrap();
    let token = UntrustedToken::new(token).unwrap();
    assert_eq!(token.algorithm(), rsa.name());

    let validated_token = rsa
        .validator::<SampleClaims>(&public_key)
        .validate(&token)
        .unwrap();
    assert_eq!(
        validated_token.claims().issued_at.unwrap().timestamp(),
        1_516_239_022
    );
    assert_eq!(
        validated_token.claims().custom,
        SampleClaims {
            subject: "1234567890".to_owned(),
            name: "John Doe".to_owned(),
            admin: true
        }
    );

    // A version with checked key length should work as well.
    let public_key = StrongKey::try_from(public_key).unwrap();
    StrongAlg(rsa)
        .validator::<SampleClaims>(&public_key)
        .validate(&token)
        .unwrap();
}

#[test]
fn rs256_reference() {
    // Generated using https://jwt.io/
    const TOKEN: &str =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lI\
         iwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DN\
         Sl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEb\
         DRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6Xx\
         UTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7t\
         uPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA";

    test_rsa_reference(Rsa::rs256(), TOKEN);
}

#[test]
fn rs384_reference() {
    // Generated using https://jwt.io/
    const TOKEN: &str =
        "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lI\
         iwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.D4kXa3UspFjRA9ys5tsD4YDyxxam3l_XnOb3hMEdPDT\
         fSLRHPv4HPwxvin-pIkEmfJshXPSK7O4zqSXWAXFO52X-upJjFc_gpGDswctNWpOJeXe1xBgJ--VuGDzUQCqkr\
         9UBpN-Q7TE5u9cgIVisekSFSH5Ax6aXQC9vCO5LooNFx_WnbTLNZz7FUia9vyJ544kLB7UcacL-_idgRNIWPdd\
         _d1vvnNGkknIMarRjCsjAEf6p5JGhYZ8_C18g-9DsfokfUfSpKgBR23R8v8ZAAmPPPiJ6MZXkefqE7p3jRbA--\
         58z5TlHmH9nTB1DYE2872RYvyzG3LoQ-2s93VaVuw";

    test_rsa_reference(Rsa::rs384(), TOKEN);
}

#[test]
fn rs512_reference() {
    // Generated using https://jwt.io/
    const TOKEN: &str =
        "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lI\
         iwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7c\
         IgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyf\
         oDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwz\
         aSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajz\
         Z7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A";

    test_rsa_reference(Rsa::rs512(), TOKEN);
}

#[test]
fn ps256_reference() {
    // Generated using https://jwt.io/
    const TOKEN: &str =
        "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lI\
         iwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.hZnl5amPk_I3tb4O-Otci_5XZdVWhPlFyVRvcqSwnDo\
         _srcysDvhhKOD01DigPK1lJvTSTolyUgKGtpLqMfRDXQlekRsF4XhAjYZTmcynf-C-6wO5EI4wYewLNKFGGJzH\
         AknMgotJFjDi_NCVSjHsW3a10nTao1lB82FRS305T226Q0VqNVJVWhE4G0JQvi2TssRtCxYTqzXVt22iDKkXeZ\
         JARZ1paXHGV5Kd1CljcZtkNZYIGcwnj65gvuCwohbkIxAnhZMJXCLaVvHqv9l-AAUV7esZvkQR1IpwBAiDQJh4\
         qxPjFGylyXrHMqh5NlT_pWL2ZoULWTg_TJjMO9TuQ";

    test_rsa_reference(Rsa::ps256(), TOKEN);
}

#[test]
fn ps384_reference() {
    // Generated using https://jwt.io/
    const TOKEN: &str =
        "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lI\
         iwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.MqF1AKsJkijKnfqEI3VA1OnzAL2S4eIpAuievMgD3tE\
         FyFMU67gCbg-fxsc5dLrxNwdZEXs9h0kkicJZ70mp6p5vdv-j2ycDKBWg05Un4OhEl7lYcdIsCsB8QUPmstF-l\
         QWnNqnq3wra1GynJrOXDL27qIaJnnQKlXuayFntBF0j-82jpuVdMaSXvk3OGaOM-7rCRsBcSPmocaAO-uWJEGP\
         w_OWVaC5RRdWDroPi4YL4lTkDEC-KEvVkqCnFm_40C-T_siXquh5FVbpJjb3W2_YvcqfDRj44TsRrpVhk6ohsH\
         MNeUad_cxnFnpolIKnaXq_COv35e9EgeQIPAbgIeg";

    test_rsa_reference(Rsa::ps384(), TOKEN);
}

#[test]
fn parsing_rsa_alg_from_string() {
    let rsa: Rsa = "PS256".parse().unwrap();
    assert_eq!(rsa, Rsa::ps256());
}
