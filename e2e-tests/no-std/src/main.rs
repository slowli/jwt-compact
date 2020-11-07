//! Test application for JWTs.

#![no_std]
#![no_main]
#![feature(default_alloc_error_handler)]

extern crate alloc;

use alloc_cortex_m::CortexMHeap;
use anyhow::anyhow;
use chrono::{DateTime, Duration, TimeZone, Utc};
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln, syscall};
use panic_halt as _;
use serde::{Deserialize, Serialize};

use alloc::{borrow::ToOwned, string::String};
use core::convert::TryFrom;

use jwt_compact::{
    alg::{Ed25519, Hs256, Hs384, Hs512, SigningKey, VerifyingKey},
    prelude::*,
    Algorithm,
};

#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

/// Gets current time via a semihosting syscall.
fn now() -> DateTime<Utc> {
    let epoch_seconds = unsafe { syscall!(TIME) };
    Utc.timestamp(epoch_seconds as i64, 0)
}

/// Sample token claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SampleClaims {
    #[serde(rename = "sub")]
    subject: String,
    name: String,
    #[serde(default)]
    admin: bool,
}

#[derive(Debug)]
struct TokenChecker {
    time_options: TimeOptions,
}

impl TokenChecker {
    fn new() -> Self {
        Self {
            time_options: TimeOptions::new(Duration::seconds(15), now),
        }
    }

    fn extract_claims<'a>(
        &self,
        token: &'a Token<SampleClaims>,
    ) -> anyhow::Result<&'a SampleClaims> {
        Ok(&token
            .claims()
            .validate_expiration(&self.time_options)
            .map_err(|e| anyhow!(e))?
            .custom)
    }

    fn verify_token<T>(&self, token: &str, verifying_key: &[u8]) -> anyhow::Result<SampleClaims>
    where
        T: Algorithm + Default,
        T::VerifyingKey: VerifyingKey<T>,
    {
        let token = UntrustedToken::try_from(token).map_err(|e| anyhow!(e))?;
        let secret_key = <T::VerifyingKey>::from_slice(verifying_key)?;

        let token = T::default()
            .validate_integrity::<SampleClaims>(&token, &secret_key)
            .map_err(|e| anyhow!(e))?;
        let claims = self.extract_claims(&token)?;
        Ok(claims.to_owned())
    }

    fn create_token<T>(claims: SampleClaims, signing_key: &[u8]) -> anyhow::Result<String>
    where
        T: Algorithm + Default,
        T::SigningKey: SigningKey<T>,
    {
        let secret_key = <T::SigningKey>::from_slice(signing_key).map_err(|e| anyhow!(e))?;
        let mut claims = Claims::new(claims);
        let timestamp = now();
        claims.issued_at = Some(timestamp);
        claims.expiration_date = Some(timestamp + Duration::minutes(10));

        let token = T::default()
            .token(Header::default(), &claims, &secret_key)
            .map_err(|e| anyhow!(e))?;
        Ok(token)
    }

    fn roundtrip_alg<T>(&self, signing_key: &[u8], verifying_key: &[u8]) -> anyhow::Result<()>
    where
        T: Algorithm + Default,
        T::SigningKey: SigningKey<T>,
        T::VerifyingKey: VerifyingKey<T>,
    {
        hprintln!("Testing algorithm: {}", T::default().name()).unwrap();

        let claims = SampleClaims {
            subject: "j.doe@example.com".to_owned(),
            name: "John Doe".to_owned(),
            admin: false,
        };
        let token = Self::create_token::<T>(claims.clone(), signing_key)?;
        hprintln!("Created token: {}", token).unwrap();
        let recovered_claims = self.verify_token::<T>(&token, verifying_key)?;
        hprintln!("Verified token").unwrap();
        assert_eq!(claims, recovered_claims);
        Ok(())
    }
}

const HEAP_SIZE: usize = 16_384;

const HASH_SECRET_KEY: &[u8] = b"super_secret_key_donut_steel";

// We could use something like https://crates.io/crates/binary_macros, but it doesn't work
// with `no_std`.
const ED_PRIVATE_KEY_HEX: &str = "9e55d1e1aa1f455b8baad9fdf975503655f8b359d542fa7e4ce84106d625b352\
     06fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f61115075";

fn main_inner() -> anyhow::Result<()> {
    let token_checker = TokenChecker::new();
    token_checker.roundtrip_alg::<Hs256>(HASH_SECRET_KEY, HASH_SECRET_KEY)?;
    token_checker.roundtrip_alg::<Hs384>(HASH_SECRET_KEY, HASH_SECRET_KEY)?;
    token_checker.roundtrip_alg::<Hs512>(HASH_SECRET_KEY, HASH_SECRET_KEY)?;

    let ed_private_key = hex::decode(ED_PRIVATE_KEY_HEX).map_err(|e| anyhow!(e))?;
    token_checker.roundtrip_alg::<Ed25519>(&ed_private_key, &ed_private_key[32..])
}

#[entry]
fn main() -> ! {
    let start = cortex_m_rt::heap_start() as usize;
    unsafe {
        ALLOCATOR.init(start, HEAP_SIZE);
    }

    main_inner().unwrap();

    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}
