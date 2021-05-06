//! Checks key thumbprints. Reference thumbprint values are computed using [`jose`].
//!
//! [`jose`]: https://www.npmjs.com/package/jose

use assert_matches::assert_matches;
use sha2::{digest::Digest, Sha256, Sha384, Sha512};

use std::convert::TryFrom;

use jwt_compact::{
    alg::Hs256Key,
    jwk::{JsonWebKey, JwkError, KeyType},
};

fn key_thumbprint<'a, D, K>(key: &'a K) -> String
where
    D: Digest,
    JsonWebKey<'a>: From<&'a K>,
{
    base64::encode_config(
        JsonWebKey::from(key).thumbprint::<D>(),
        base64::URL_SAFE_NO_PAD,
    )
}

fn assert_jwk_roundtrip(jwk: &JsonWebKey) {
    let jwk_string = jwk.to_string();
    let restored: JsonWebKey<'_> = serde_json::from_str(&jwk_string).unwrap();
    assert_eq!(restored, *jwk);

    let json = serde_json::to_value(jwk).unwrap();
    let restored_from_json: JsonWebKey<'_> = serde_json::from_value(json).unwrap();
    assert_eq!(restored_from_json, *jwk);
}

#[test]
fn hs256_jwk() {
    const KEY: &str =
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

    let key = base64::decode_config(KEY, base64::URL_SAFE_NO_PAD).unwrap();
    let key = Hs256Key::new(&key);

    let jwk = JsonWebKey::from(&key);
    assert_eq!(
        jwk.to_string(),
        r#"{"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuT
           wjAzZr1Z9CAow","kty":"oct"}"#
            .replace(|c: char| c.is_ascii_whitespace(), "")
    );
    assert_jwk_roundtrip(&jwk);
    assert_eq!(Hs256Key::try_from(&jwk).unwrap().as_ref(), key.as_ref());

    assert_eq!(
        key_thumbprint::<Sha256, _>(&key),
        "y_x3gCJnL6oKGBBIXScabduwxTVy2Wd2bzRVEUbdUzc"
    );
    assert_eq!(
        key_thumbprint::<Sha384, _>(&key),
        "fSRdJnLOn2xxz1WCXvwy2mlKp8SyEytzrcRUph9-YKryizmKOu9vfzKmM4HRRQYe"
    );
    assert_eq!(
        key_thumbprint::<Sha512, _>(&key),
        "ExXc7w4tS8HODuTiuwzp7RQwGXK0O7u4oHli0ve5jW43KC5MnKVmmvC0DZG4h2dllCKFi5FL_E7ZqQhkrUxK-A"
    );
}

#[test]
fn hs256_incorrect_key_type() {
    let jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "NK0ABg2FlJUVj9UIOrh4wOlLtlV3WL70SQYXSl4Kh0c",
    });
    let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();
    let err = Hs256Key::try_from(&jwk).unwrap_err();

    assert_matches!(
        err,
        JwkError::UnexpectedKeyType {
            expected: KeyType::Symmetric,
            actual: KeyType::KeyPair,
        }
    );
}

#[cfg(feature = "rsa")]
mod rsa_jwk {
    use super::*;

    use rsa::{errors::Error as RsaError, BigUint, RSAPrivateKey, RSAPublicKey};

    // Taken from https://tools.ietf.org/html/rfc7638#section-3.1
    const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2\
        aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi\
        FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65Y\
        GjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n\
        91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_x\
        BniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    // Taken from https://tools.ietf.org/html/rfc7515#appendix-A.2.1
    fn create_signing_jwk() -> serde_json::Value {
        serde_json::json!({
            "kty": "RSA",
            "n": "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx\
                HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs\
                D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH\
                SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV\
                MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8\
                NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
            "e": "AQAB",
            "d": "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I\
                jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0\
                BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn\
                439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT\
                CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh\
                BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
            "p": "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi\
                YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG\
                BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
            "q": "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa\
                ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA\
                -njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
            "dp": "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q\
                CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb\
                34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
            "dq": "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa\
                7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky\
                NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
            "qi": "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o\
                y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU\
                W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U",
        })
    }

    #[test]
    fn verifying_jwk() {
        let n = base64::decode_config(RSA_N, base64::URL_SAFE_NO_PAD).unwrap();
        let n = BigUint::from_bytes_be(&n);
        let public_key = RSAPublicKey::new(n, BigUint::from(65_537_u32)).unwrap();

        assert_eq!(
            key_thumbprint::<Sha256, _>(&public_key),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );

        let jwk = JsonWebKey::from(&public_key);
        assert_jwk_roundtrip(&jwk);
        assert_eq!(RSAPublicKey::try_from(&jwk).unwrap(), public_key);
    }

    #[test]
    fn signing_jwk() {
        let jwk = create_signing_jwk();
        let jwk: JsonWebKey<'_> = serde_json::from_value(jwk).unwrap();

        let private_key = RSAPrivateKey::try_from(&jwk).unwrap();
        let public_key = RSAPublicKey::try_from(&jwk).unwrap();
        assert_eq!(public_key, private_key.to_public_key());

        let jwk_from_key = JsonWebKey::from(&private_key);
        // `jwk_from_key` won't be equal to `jwk`, but we can still check that a private key
        // can be restored from it.
        let private_key_copy = RSAPrivateKey::try_from(&jwk_from_key).unwrap();
        assert_eq!(private_key_copy, private_key);

        assert_eq!(
            jwk.thumbprint::<Sha256>(),
            JsonWebKey::from(&public_key).thumbprint::<Sha256>()
        );

        let public_jwk = JsonWebKey::from(&public_key);
        assert_eq!(public_jwk, jwk.to_verifying_key());

        let err = RSAPrivateKey::try_from(&public_jwk).unwrap_err();
        assert_matches!(err, JwkError::NoField(field) if field == "d");
    }

    #[test]
    fn incorrect_key_type() {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "NK0ABg2FlJUVj9UIOrh4wOlLtlV3WL70SQYXSl4Kh0c",
        });
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();
        let err = RSAPublicKey::try_from(&jwk).unwrap_err();

        assert_matches!(
            err,
            JwkError::UnexpectedKeyType {
                expected: KeyType::Rsa,
                actual: KeyType::KeyPair,
            }
        );
    }

    #[test]
    fn key_mismatch() {
        let mut jwk = create_signing_jwk();
        jwk.as_object_mut().unwrap()["n"] = String::from(RSA_N).into();
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();
        let err = RSAPrivateKey::try_from(&jwk).unwrap_err();

        assert_matches!(err, JwkError::Custom(err) if err.is::<RsaError>());
    }
}

#[cfg(feature = "es256k")]
mod es256k {
    use super::*;
    use jwt_compact::alg::SigningKey;

    use const_decoder::Decoder::Hex;
    use secp256k1::{PublicKey, SecretKey};

    #[test]
    fn verifying_jwk() {
        // Randomly generated
        const KEY_BYTES: [u8; 65] = Hex.decode(
            b"0420c644561d2b431f9091f7cd46f74eb4cd1e52695612cea7f515cb5307782934\
             4c059f585e48d46f02292d0937444eda180f3e5cdba11b23548b827e37d899e2",
        );
        let public_key = PublicKey::from_slice(&KEY_BYTES[..]).unwrap();

        let jwk = JsonWebKey::from(&public_key);
        assert_jwk_roundtrip(&jwk);
        assert_eq!(
            jwk.to_string(),
            r#"{"crv":"secp256k1","kty":"EC","x":"IMZEVh0rQx-QkffNRvdOtM0eUmlWEs6n9RXLUwd4KTQ",
               "y":"TAWfWF5I1G8CKS0JN0RO2hgPPlzboRsjVIuCfjfYmeI"}"#
                .replace(|c: char| c.is_ascii_whitespace(), "")
        );
        assert_eq!(PublicKey::try_from(&jwk).unwrap(), public_key);

        assert_eq!(
            key_thumbprint::<Sha256, _>(&public_key),
            "WXjRM2dXofF2PGP339yJXhia89VsAQRBMZA5_lWuYFY"
        );
        assert_eq!(
            key_thumbprint::<Sha384, _>(&public_key),
            "DkN4OrLRtgfYiVlkoF53iPZrTObzQaXHVxpxL0HITjrvd0HueC5IxIKZMipO5ZUb"
        );
        assert_eq!(
            key_thumbprint::<Sha512, _>(&public_key),
            "7lKlxJoslozeLTIG9Sdq060YFDTG_74DeFvqCacavxUZ4Rqs1VsJe4RfO4cqUL9nWf4Fi8K73OaTzcuwBGF6DA"
        );
    }

    #[test]
    fn signing_jwk() {
        // Randomly generated
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "secp256k1",
            "x": "_axQlhVy0Fy_slQfh5DvSC_foMd4390JbniILOmbiK8",
            "y": "UWYZV-H7itKPKenuQZ4utsKN3shM5NUjRqq5DsgGHqU",
            "d": "d3N3gPucle_VNEjYVNHfULzQqUYhAjkOG7HwVCT9Wos",
        });
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();

        let secret_key = SecretKey::try_from(&jwk).unwrap();
        let public_key = PublicKey::try_from(&jwk).unwrap();
        assert_eq!(public_key, secret_key.to_verifying_key());

        assert_eq!(JsonWebKey::from(&secret_key), jwk);
        assert_eq!(
            jwk.thumbprint::<Sha256>(),
            JsonWebKey::from(&public_key).thumbprint::<Sha256>()
        );

        let public_jwk = JsonWebKey::from(&public_key);
        assert_eq!(public_jwk, jwk.to_verifying_key());

        let err = SecretKey::try_from(&public_jwk).unwrap_err();
        assert_matches!(err, JwkError::NoField(field) if field == "d");
    }

    #[test]
    fn incorrect_key_type() {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "NK0ABg2FlJUVj9UIOrh4wOlLtlV3WL70SQYXSl4Kh0c",
        });
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();
        let err = PublicKey::try_from(&jwk).unwrap_err();

        assert_matches!(
            err,
            JwkError::UnexpectedKeyType {
                expected: KeyType::EllipticCurve,
                actual: KeyType::KeyPair,
            }
        );
    }

    #[test]
    fn incorrect_curve() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "_axQlhVy0Fy_slQfh5DvSC_foMd4390JbniILOmbiK8",
            "y": "UWYZV-H7itKPKenuQZ4utsKN3shM5NUjRqq5DsgGHqU",
        });
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();
        let err = PublicKey::try_from(&jwk).unwrap_err();

        assert_matches!(
            err,
            JwkError::UnexpectedValue { field, expected, actual }
                if field == "crv" && expected == "secp256k1" && actual == "P-256"
        );
    }

    #[test]
    fn incorrect_x_len() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "secp256k1",
            "x": "AQAB",
            "y": "UWYZV-H7itKPKenuQZ4utsKN3shM5NUjRqq5DsgGHqU",
        });
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();
        let err = PublicKey::try_from(&jwk).unwrap_err();

        assert_matches!(
            err,
            JwkError::UnexpectedLen {
                field,
                expected: 32,
                actual: 3,
            } if field == "x"
        );
    }

    #[test]
    fn point_not_on_curve() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "secp256k1",
            "x": "UWYZV-H7itKPKenuQZ4utsKN3shM5NUjRqq5DsgGHqU",
            "y": "UWYZV-H7itKPKenuQZ4utsKN3shM5NUjRqq5DsgGHqU",
        });
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();
        let err = PublicKey::try_from(&jwk).unwrap_err();

        assert_matches!(
            err,
            JwkError::Custom(e) if e.to_string().contains("malformed public key")
        );
    }

    #[test]
    fn incorrect_scalar_len() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "secp256k1",
            "x": "_axQlhVy0Fy_slQfh5DvSC_foMd4390JbniILOmbiK8",
            "y": "UWYZV-H7itKPKenuQZ4utsKN3shM5NUjRqq5DsgGHqU",
            "d": "AQAB",
        });
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();
        let err = SecretKey::try_from(&jwk).unwrap_err();

        assert_matches!(
            err,
            JwkError::UnexpectedLen {
                field,
                expected: 32,
                actual: 3,
            } if field == "d"
        );
    }

    #[test]
    fn key_mismatch() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "secp256k1",
            "x": "_axQlhVy0Fy_slQfh5DvSC_foMd4390JbniILOmbiK8",
            "y": "UWYZV-H7itKPKenuQZ4utsKN3shM5NUjRqq5DsgGHqU",
            "d": "c3N3gPucle_VNEjYVNHfULzQqUYhAjkOG7HwVCT9Wos",
        });
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();
        let err = SecretKey::try_from(&jwk).map(drop).unwrap_err();

        assert_matches!(err, JwkError::MismatchedKeys);
    }
}

#[cfg(any(
    feature = "exonum-crypto",
    feature = "ed25519-dalek",
    feature = "ed25519-compact"
))]
mod ed25519 {
    use super::*;
    use jwt_compact::{
        alg::{Ed25519, SigningKey, VerifyingKey},
        Algorithm,
    };

    use const_decoder::Decoder::Hex;

    type SecretKey = <Ed25519 as Algorithm>::SigningKey;
    type PublicKey = <Ed25519 as Algorithm>::VerifyingKey;

    #[test]
    fn verifying_jwk() {
        const KEY_BYTES: [u8; 32] =
            Hex.decode(b"b7e6ddbf8d4c2571315e7a6ab8706e0e7ee7d581b25fb80b41c8551c0a0dbb9d");
        let public_key = <PublicKey as VerifyingKey<Ed25519>>::from_slice(&KEY_BYTES).unwrap();

        let jwk = JsonWebKey::from(&public_key);
        assert_jwk_roundtrip(&jwk);
        assert_eq!(
            jwk.to_string(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"t-bdv41MJXExXnpquHBuDn7n1YGyX7gLQchVHAoNu50"}"#
        );
        assert_eq!(
            PublicKey::try_from(&jwk).unwrap().as_bytes(),
            public_key.as_bytes()
        );

        assert_eq!(
            key_thumbprint::<Sha256, _>(&public_key),
            "TZ72OrmiQl5Bz5Zm3NIM_0ksFtfP36SFdPZrwCj_2ZE"
        );
        assert_eq!(
            key_thumbprint::<Sha384, _>(&public_key),
            "XWHXvgq2_opOw9_uEiv-mxzOUuQ_Rf04O83o3mCL77Q-QkCf4bxMGh5BJHNH3UBb"
        );
        assert_eq!(
            key_thumbprint::<Sha512, _>(&public_key),
            "WqIaoagn_JL_tfn1G7a4CbWyXYObfOXyTRfl03ARFojwYyTxX0OavuDAAipIfHpZSq-i3WzexF1Qb1X3P8JzEA"
        );
    }

    #[test]
    fn signing_jwk() {
        // Randomly generated
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "NK0ABg2FlJUVj9UIOrh4wOlLtlV3WL70SQYXSl4Kh0c",
            "d": "8fyd_fcp8v4cR2pj74QMiTxo7hcYz1jZ1FeyTgWnsGI"
        });
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();

        let secret_key = SecretKey::try_from(&jwk).unwrap();
        let public_key = PublicKey::try_from(&jwk).unwrap();
        assert_eq!(public_key, secret_key.to_verifying_key());

        assert_eq!(JsonWebKey::from(&secret_key), jwk);
        assert_eq!(
            jwk.thumbprint::<Sha256>(),
            JsonWebKey::from(&public_key).thumbprint::<Sha256>()
        );

        let public_jwk = JsonWebKey::from(&public_key);
        assert_eq!(public_jwk, jwk.to_verifying_key());

        let err = SecretKey::try_from(&public_jwk).map(drop).unwrap_err();
        assert_matches!(err, JwkError::NoField(field) if field == "d");
    }

    #[test]
    fn incorrect_key_type() {
        let jwk = serde_json::json!({
            "kty": "oct",
            "k": "NK0ABg2FlJUVj9UIOrh4wOlLtlV3WL70SQYXSl4Kh0c",
        });
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();
        let err = PublicKey::try_from(&jwk).unwrap_err();

        assert_matches!(
            err,
            JwkError::UnexpectedKeyType {
                expected: KeyType::KeyPair,
                actual: KeyType::Symmetric,
            }
        );
    }

    #[test]
    fn incorrect_curve() {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed448",
            "x": "NK0ABg2FlJUVj9UIOrh4wOlLtlV3WL70SQYXSl4Kh0c",
        });
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();
        let err = PublicKey::try_from(&jwk).unwrap_err();

        assert_matches!(
            err,
            JwkError::UnexpectedValue { field, expected, actual }
                if field == "crv" && expected == "Ed25519" && actual == "Ed448"
        );
    }

    #[test]
    fn incorrect_x_len() {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "AQAB",
        });
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();
        let err = PublicKey::try_from(&jwk).unwrap_err();

        assert_matches!(
            err,
            JwkError::UnexpectedLen {
                field,
                expected: 32,
                actual: 3,
            } if field == "x"
        );
    }

    #[test]
    fn incorrect_scalar_len() {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "NK0ABg2FlJUVj9UIOrh4wOlLtlV3WL70SQYXSl4Kh0c",
            "d": "AQAB",
        });
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();
        let err = SecretKey::try_from(&jwk).map(drop).unwrap_err();

        assert_matches!(
            err,
            JwkError::UnexpectedLen {
                field,
                expected: 32,
                actual: 3,
            } if field == "d"
        );
    }

    #[test]
    fn key_mismatch() {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "t-bdv41MJXExXnpquHBuDn7n1YGyX7gLQchVHAoNu50",
            "d": "8fyd_fcp8v4cR2pj74QMiTxo7hcYz1jZ1FeyTgWnsGI",
        });
        let jwk: JsonWebKey = serde_json::from_value(jwk).unwrap();
        let err = SecretKey::try_from(&jwk).map(drop).unwrap_err();

        assert_matches!(err, JwkError::MismatchedKeys);
    }
}
