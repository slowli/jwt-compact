//! Implementations of JWT signing / verification algorithms.

#[cfg(feature = "secp256k1")]
mod es256k;
mod hmacs;
// Alternative EdDSA implementations.
#[cfg(feature = "ed25519-dalek")]
mod eddsa_dalek;
#[cfg(feature = "exonum-crypto")]
mod eddsa_sodium;

#[cfg(feature = "ed25519-dalek")]
pub use self::eddsa_dalek::Ed25519;
#[cfg(feature = "exonum-crypto")]
pub use self::eddsa_sodium::Ed25519;
#[cfg(feature = "secp256k1")]
pub use self::es256k::Es256k;
pub use self::hmacs::*;
