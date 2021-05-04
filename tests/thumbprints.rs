//! Checks key thumbprints. Reference thumbprint values are computed using [`jose`].
//!
//! [`jose`]: https://www.npmjs.com/package/jose

use const_decoder::Decoder::Hex;
use sha2::{digest::Digest, Sha256, Sha384, Sha512};

use jwt_compact::alg::{Hs256Key, ThumbprintKey};

fn key_thumbprint<D: Digest, K: ThumbprintKey>(key: &K) -> String {
    base64::encode_config(key.thumbprint::<D>(), base64::URL_SAFE_NO_PAD)
}

#[test]
fn hs256_key_thumbprint() {
    const KEY: &str =
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

    let key = base64::decode_config(KEY, base64::URL_SAFE_NO_PAD).unwrap();
    let key = Hs256Key::new(&key);

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

#[cfg(feature = "rsa")]
#[test]
fn rsa_key_thumbprint() {
    //! Taken from https://tools.ietf.org/html/rfc7638#section-3.1.

    use rsa::{BigUint, RSAPublicKey};

    const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2\
        aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi\
        FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65Y\
        GjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n\
        91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_x\
        BniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    let n = base64::decode_config(RSA_N, base64::URL_SAFE_NO_PAD).unwrap();
    let n = BigUint::from_bytes_be(&n);
    let public_key = RSAPublicKey::new(n, BigUint::from(65_537_u32)).unwrap();

    assert_eq!(
        key_thumbprint::<Sha256, _>(&public_key),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
}

#[cfg(feature = "es256k")]
#[test]
fn es256k_key_thumbprint() {
    use secp256k1::PublicKey;

    // Randomly generated.
    const KEY_BYTES: [u8; 65] = Hex.decode(
        b"0420c644561d2b431f9091f7cd46f74eb4cd1e52695612cea7f515cb5307782934\
         4c059f585e48d46f02292d0937444eda180f3e5cdba11b23548b827e37d899e2",
    );
    let public_key = PublicKey::from_slice(&KEY_BYTES[..]).unwrap();

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

#[cfg(any(
    feature = "exonum-crypto",
    feature = "ed25519-dalek",
    feature = "ed25519-compact"
))]
#[test]
fn ed25519_key_thumbprint() {
    use jwt_compact::{
        alg::{Ed25519, VerifyingKey},
        Algorithm,
    };

    type PK = <Ed25519 as Algorithm>::VerifyingKey;

    const KEY_BYTES: [u8; 32] =
        Hex.decode(b"b7e6ddbf8d4c2571315e7a6ab8706e0e7ee7d581b25fb80b41c8551c0a0dbb9d");
    let public_key = <PK as VerifyingKey<Ed25519>>::from_slice(&KEY_BYTES).unwrap();

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