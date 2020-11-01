//! Implementations of JWT signing / verification algorithms. Also contains generic traits
//! for signing and verifying keys.

#[cfg(feature = "secp256k1")]
mod es256k;
mod generic;
mod hmacs;
// Alternative EdDSA implementations.
#[cfg(feature = "ed25519-compact")]
mod eddsa_compact;
#[cfg(feature = "ed25519-dalek")]
mod eddsa_dalek;
#[cfg(feature = "exonum-crypto")]
mod eddsa_sodium;
#[cfg(feature = "rsa")]
mod rsa;

#[cfg(feature = "ed25519-compact")]
pub use self::eddsa_compact::*;
#[cfg(feature = "ed25519-dalek")]
pub use self::eddsa_dalek::Ed25519;
#[cfg(feature = "exonum-crypto")]
pub use self::eddsa_sodium::Ed25519;
#[cfg(feature = "secp256k1")]
pub use self::es256k::Es256k;
pub use self::generic::{SigningKey, VerifyingKey};
pub use self::hmacs::*;
#[cfg(feature = "rsa")]
pub use self::rsa::{
    ModulusBits, ModulusBitsError, RSAPrivateKey, RSAPublicKey, Rsa, RsaSignature,
};
