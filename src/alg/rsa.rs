//! RSA-based JWT algorithms: `RS*` and `PS*`.

use core::{fmt, str::FromStr};

use rand_core::{CryptoRng, RngCore};
pub use rsa::{errors::Error as RsaError, RsaPrivateKey, RsaPublicKey};
use rsa::{
    traits::{PrivateKeyParts, PublicKeyParts},
    BoxedUint, Pkcs1v15Sign, Pss,
};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::{
    alg::{SecretBytes, StrongKey, WeakKeyError},
    alloc::{Cow, String, ToOwned, Vec},
    jwk::{JsonWebKey, JwkError, KeyType, RsaPrimeFactor, RsaPrivateParts},
    Algorithm, AlgorithmSignature,
};

/// RSA signature.
#[derive(Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
pub struct RsaSignature(Vec<u8>);

impl AlgorithmSignature for RsaSignature {
    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(RsaSignature(bytes.to_vec()))
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.0)
    }
}

/// RSA hash algorithm.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    fn digest(self, message: &[u8]) -> HashDigest {
        match self {
            Self::Sha256 => HashDigest::Sha256(Sha256::digest(message).into()),
            Self::Sha384 => HashDigest::Sha384(Sha384::digest(message).into()),
            Self::Sha512 => HashDigest::Sha512(Sha512::digest(message).into()),
        }
    }
}

/// Output of a [`HashAlg`].
#[derive(Debug)]
enum HashDigest {
    Sha256([u8; 32]),
    Sha384([u8; 48]),
    Sha512([u8; 64]),
}

impl AsRef<[u8]> for HashDigest {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Sha256(bytes) => bytes,
            Self::Sha384(bytes) => bytes,
            Self::Sha512(bytes) => bytes,
        }
    }
}

/// RSA padding algorithm.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Padding {
    Pkcs1v15,
    Pss,
}

#[derive(Debug)]
enum PaddingScheme {
    Pkcs1v15(Pkcs1v15Sign),
    Pss(Pss),
}

/// Bit length of an RSA key modulus (aka RSA key length).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
pub enum ModulusBits {
    /// 2048 bits. This is the minimum recommended key length as of 2020.
    TwoKibibytes,
    /// 3072 bits.
    ThreeKibibytes,
    /// 4096 bits.
    FourKibibytes,
}

impl ModulusBits {
    /// Converts this length to the numeric value.
    pub fn bits(self) -> usize {
        match self {
            Self::TwoKibibytes => 2_048,
            Self::ThreeKibibytes => 3_072,
            Self::FourKibibytes => 4_096,
        }
    }

    fn is_valid_bits(bits: u32) -> bool {
        matches!(bits, 2_048 | 3_072 | 4_096)
    }
}

impl TryFrom<usize> for ModulusBits {
    type Error = ModulusBitsError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            2_048 => Ok(Self::TwoKibibytes),
            3_072 => Ok(Self::ThreeKibibytes),
            4_096 => Ok(Self::FourKibibytes),
            _ => Err(ModulusBitsError(())),
        }
    }
}

/// Error type returned when a conversion of an integer into `ModulusBits` fails.
#[derive(Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
pub struct ModulusBitsError(());

impl fmt::Display for ModulusBitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "Unsupported bit length of RSA modulus; only lengths 2048, 3072 and 4096 \
            are supported.",
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ModulusBitsError {}

/// Integrity algorithm using [RSA] digital signatures.
///
/// Depending on the variation, the algorithm employs PKCS#1 v1.5 or PSS padding and
/// one of the hash functions from the SHA-2 family: SHA-256, SHA-384, or SHA-512.
/// See [RFC 7518] for more details. Depending on the chosen parameters,
/// the name of the algorithm is one of `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`:
///
/// - `R` / `P` denote the padding scheme: PKCS#1 v1.5 for `R`, PSS for `P`
/// - `256` / `384` / `512` denote the hash function
///
/// The length of RSA keys is not unequivocally specified by the algorithm; nevertheless,
/// it **MUST** be at least 2048 bits as per RFC 7518. To minimize risks of misconfiguration,
/// use [`StrongAlg`](super::StrongAlg) wrapper around `Rsa`:
///
/// ```
/// # use jwt_compact::alg::{StrongAlg, Rsa};
/// const ALG: StrongAlg<Rsa> = StrongAlg(Rsa::rs256());
/// // `ALG` will not support RSA keys with unsecure lengths by design!
/// ```
///
/// [RSA]: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
/// [RFC 7518]: https://www.rfc-editor.org/rfc/rfc7518.html
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
pub struct Rsa {
    hash_alg: HashAlg,
    padding_alg: Padding,
}

impl Algorithm for Rsa {
    type SigningKey = RsaPrivateKey;
    type VerifyingKey = RsaPublicKey;
    type Signature = RsaSignature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed(self.alg_name())
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        let digest = self.hash_alg.digest(message);
        let digest = digest.as_ref();
        let signing_result = match self.padding_scheme() {
            PaddingScheme::Pkcs1v15(padding) => signing_key.sign_with_rng(
                &mut rand_core::UnwrapErr(rand_core::OsRng),
                padding,
                digest,
            ),
            PaddingScheme::Pss(padding) => signing_key.sign_with_rng(
                &mut rand_core::UnwrapErr(rand_core::OsRng),
                padding,
                digest,
            ),
        };
        RsaSignature(signing_result.expect("Unexpected RSA signature failure"))
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        let digest = self.hash_alg.digest(message);
        let digest = digest.as_ref();
        let verify_result = match self.padding_scheme() {
            PaddingScheme::Pkcs1v15(padding) => verifying_key.verify(padding, digest, &signature.0),
            PaddingScheme::Pss(padding) => verifying_key.verify(padding, digest, &signature.0),
        };
        verify_result.is_ok()
    }
}

impl Rsa {
    const fn new(hash_alg: HashAlg, padding_alg: Padding) -> Self {
        Rsa {
            hash_alg,
            padding_alg,
        }
    }

    /// RSA with SHA-256 and PKCS#1 v1.5 padding.
    pub const fn rs256() -> Rsa {
        Rsa::new(HashAlg::Sha256, Padding::Pkcs1v15)
    }

    /// RSA with SHA-384 and PKCS#1 v1.5 padding.
    pub const fn rs384() -> Rsa {
        Rsa::new(HashAlg::Sha384, Padding::Pkcs1v15)
    }

    /// RSA with SHA-512 and PKCS#1 v1.5 padding.
    pub const fn rs512() -> Rsa {
        Rsa::new(HashAlg::Sha512, Padding::Pkcs1v15)
    }

    /// RSA with SHA-256 and PSS padding.
    pub const fn ps256() -> Rsa {
        Rsa::new(HashAlg::Sha256, Padding::Pss)
    }

    /// RSA with SHA-384 and PSS padding.
    pub const fn ps384() -> Rsa {
        Rsa::new(HashAlg::Sha384, Padding::Pss)
    }

    /// RSA with SHA-512 and PSS padding.
    pub const fn ps512() -> Rsa {
        Rsa::new(HashAlg::Sha512, Padding::Pss)
    }

    /// RSA based on the specified algorithm name.
    ///
    /// # Panics
    ///
    /// - Panics if the name is not one of the six RSA-based JWS algorithms. Prefer using
    ///   the [`FromStr`] trait if the conversion is potentially fallible.
    pub fn with_name(name: &str) -> Self {
        name.parse().unwrap()
    }

    fn padding_scheme(self) -> PaddingScheme {
        match self.padding_alg {
            Padding::Pkcs1v15 => PaddingScheme::Pkcs1v15(match self.hash_alg {
                HashAlg::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
                HashAlg::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
                HashAlg::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
            }),
            Padding::Pss => {
                // The salt length needs to be set to the size of hash function output;
                // see https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5.
                PaddingScheme::Pss(match self.hash_alg {
                    HashAlg::Sha256 => Pss::new_with_salt::<Sha256>(Sha256::output_size()),
                    HashAlg::Sha384 => Pss::new_with_salt::<Sha384>(Sha384::output_size()),
                    HashAlg::Sha512 => Pss::new_with_salt::<Sha512>(Sha512::output_size()),
                })
            }
        }
    }

    fn alg_name(self) -> &'static str {
        match (self.padding_alg, self.hash_alg) {
            (Padding::Pkcs1v15, HashAlg::Sha256) => "RS256",
            (Padding::Pkcs1v15, HashAlg::Sha384) => "RS384",
            (Padding::Pkcs1v15, HashAlg::Sha512) => "RS512",
            (Padding::Pss, HashAlg::Sha256) => "PS256",
            (Padding::Pss, HashAlg::Sha384) => "PS384",
            (Padding::Pss, HashAlg::Sha512) => "PS512",
        }
    }

    /// Generates a new key pair with the specified modulus bit length (aka key length).
    pub fn generate<R: CryptoRng + RngCore>(
        rng: &mut R,
        modulus_bits: ModulusBits,
    ) -> rsa::errors::Result<(StrongKey<RsaPrivateKey>, StrongKey<RsaPublicKey>)> {
        let signing_key = RsaPrivateKey::new(rng, modulus_bits.bits())?;
        let verifying_key = signing_key.to_public_key();
        Ok((StrongKey(signing_key), StrongKey(verifying_key)))
    }
}

impl FromStr for Rsa {
    type Err = RsaParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "RS256" => Self::rs256(),
            "RS384" => Self::rs384(),
            "RS512" => Self::rs512(),
            "PS256" => Self::ps256(),
            "PS384" => Self::ps384(),
            "PS512" => Self::ps512(),
            _ => return Err(RsaParseError(s.to_owned())),
        })
    }
}

/// Errors that can occur when parsing an [`Rsa`] algorithm from a string.
#[derive(Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
pub struct RsaParseError(String);

impl fmt::Display for RsaParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Invalid RSA algorithm name: {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RsaParseError {}

impl StrongKey<RsaPrivateKey> {
    /// Converts this private key to a public key.
    pub fn to_public_key(&self) -> StrongKey<RsaPublicKey> {
        StrongKey(self.0.to_public_key())
    }
}

impl TryFrom<RsaPrivateKey> for StrongKey<RsaPrivateKey> {
    type Error = WeakKeyError<RsaPrivateKey>;

    fn try_from(key: RsaPrivateKey) -> Result<Self, Self::Error> {
        if ModulusBits::is_valid_bits(key.n().bits()) {
            Ok(StrongKey(key))
        } else {
            Err(WeakKeyError(key))
        }
    }
}

impl TryFrom<RsaPublicKey> for StrongKey<RsaPublicKey> {
    type Error = WeakKeyError<RsaPublicKey>;

    fn try_from(key: RsaPublicKey) -> Result<Self, Self::Error> {
        if ModulusBits::is_valid_bits(key.n().bits()) {
            Ok(StrongKey(key))
        } else {
            Err(WeakKeyError(key))
        }
    }
}

impl<'a> From<&'a RsaPublicKey> for JsonWebKey<'a> {
    fn from(key: &'a RsaPublicKey) -> JsonWebKey<'a> {
        JsonWebKey::Rsa {
            modulus: Cow::Owned(key.n().to_be_bytes_trimmed_vartime().into()),
            public_exponent: Cow::Owned(key.e().to_be_bytes_trimmed_vartime().into()),
            private_parts: None,
        }
    }
}

#[allow(clippy::cast_possible_truncation)] // not triggered
fn secret_uint_from_slice(slice: &[u8], precision: u32) -> Result<BoxedUint, JwkError> {
    debug_assert!(precision <= RsaPublicKey::MAX_SIZE as u32);
    BoxedUint::from_be_slice(slice, precision).map_err(|err| JwkError::custom(anyhow::anyhow!(err)))
}

/// The caller must ensure that setting `precision` won't truncate the value.
fn secret_uint_to_slice(secret: &BoxedUint, precision: u32) -> SecretBytes<'static> {
    let bytes = secret.to_be_bytes();
    let precision_bytes = precision.div_ceil(8) as usize;
    SecretBytes::owned_slice(if bytes.len() > precision_bytes {
        let first_idx = bytes.len() - precision_bytes;
        bytes[first_idx..].into()
    } else {
        bytes
    })
}

fn pub_exponent_from_slice(slice: &[u8]) -> Result<BoxedUint, JwkError> {
    BoxedUint::from_be_slice(slice, RsaPublicKey::MAX_PUB_EXPONENT.ilog2() + 1)
        .map_err(|err| JwkError::custom(anyhow::anyhow!(err)))
}

impl TryFrom<&JsonWebKey<'_>> for RsaPublicKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        let JsonWebKey::Rsa {
            modulus,
            public_exponent,
            ..
        } = jwk
        else {
            return Err(JwkError::key_type(jwk, KeyType::Rsa));
        };

        let e = pub_exponent_from_slice(public_exponent)?;
        let n = BoxedUint::from_be_slice_vartime(modulus);
        Self::new(n, e).map_err(|err| JwkError::custom(anyhow::anyhow!(err)))
    }
}

/// ⚠ **Warning.** Contrary to [RFC 7518], this implementation does not set `dp`, `dq`, and `qi`
/// fields in the JWK root object, as well as `d` and `t` fields for additional factors
/// (i.e., in the `oth` array).
///
/// [RFC 7518]: https://tools.ietf.org/html/rfc7518#section-6.3.2
impl<'a> From<&'a RsaPrivateKey> for JsonWebKey<'a> {
    fn from(key: &'a RsaPrivateKey) -> JsonWebKey<'a> {
        const MSG: &str = "RsaPrivateKey must have at least 2 prime factors";

        let p = key.primes().first().expect(MSG);
        let q = key.primes().get(1).expect(MSG);
        // Truncate secret values to the modulus precision. We know that all secret values don't exceed the modulus,
        // so this is safe. `d` in particular does have q higher precision for multi-prime RSA keys
        // (e.g., it may have 2,176-bit precision for a 2,048-bit modulus), which would lead to excessive zero padding
        // and may lead to unnecessary deserialization errors.
        let precision = key.n().bits_precision();

        let private_parts = RsaPrivateParts {
            private_exponent: secret_uint_to_slice(key.d(), precision),
            prime_factor_p: secret_uint_to_slice(p, precision),
            prime_factor_q: secret_uint_to_slice(q, precision),
            p_crt_exponent: None,
            q_crt_exponent: None,
            q_crt_coefficient: None,
            other_prime_factors: key.primes()[2..]
                .iter()
                .map(|factor| RsaPrimeFactor {
                    factor: secret_uint_to_slice(factor, precision),
                    crt_exponent: None,
                    crt_coefficient: None,
                })
                .collect(),
        };

        JsonWebKey::Rsa {
            modulus: Cow::Owned(key.n().to_be_bytes_trimmed_vartime().into()),
            public_exponent: Cow::Owned(key.e().to_be_bytes_trimmed_vartime().into()),
            private_parts: Some(private_parts),
        }
    }
}

/// ⚠ **Warning.** Contrary to [RFC 7518] (at least, in spirit), this conversion ignores
/// `dp`, `dq`, and `qi` fields from JWK, as well as `d` and `t` fields for additional factors.
///
/// [RFC 7518]: https://www.rfc-editor.org/rfc/rfc7518.html
impl TryFrom<&JsonWebKey<'_>> for RsaPrivateKey {
    type Error = JwkError;

    fn try_from(jwk: &JsonWebKey<'_>) -> Result<Self, Self::Error> {
        let JsonWebKey::Rsa {
            modulus,
            public_exponent,
            private_parts,
        } = jwk
        else {
            return Err(JwkError::key_type(jwk, KeyType::Rsa));
        };

        let RsaPrivateParts {
            private_exponent: d,
            prime_factor_p,
            prime_factor_q,
            other_prime_factors,
            ..
        } = private_parts
            .as_ref()
            .ok_or_else(|| JwkError::NoField("d".into()))?;

        let e = pub_exponent_from_slice(public_exponent)?;
        let n = BoxedUint::from_be_slice_vartime(modulus);

        // Round `n` bitness up to the nearest value divisible by 8
        let precision = n.bits().div_ceil(8) * 8;
        if precision as usize > RsaPublicKey::MAX_SIZE {
            return Err(JwkError::Custom(anyhow::anyhow!(
                "Modulus precision ({got}) exceeds maximum supported value ({max})",
                got = n.bits(),
                max = RsaPublicKey::MAX_SIZE
            )));
        }

        let d = secret_uint_from_slice(d, precision)?;
        let mut factors = Vec::with_capacity(2 + other_prime_factors.len());
        factors.push(secret_uint_from_slice(prime_factor_p, precision)?);
        factors.push(secret_uint_from_slice(prime_factor_q, precision)?);
        for other_factor in other_prime_factors {
            factors.push(secret_uint_from_slice(&other_factor.factor, precision)?);
        }

        let key = Self::from_components(n, e, d, factors);
        let key = key.map_err(|err| JwkError::custom(anyhow::anyhow!(err)))?;
        key.validate()
            .map_err(|err| JwkError::custom(anyhow::anyhow!(err)))?;
        Ok(key)
    }
}
