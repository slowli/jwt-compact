//! Test application for JWTs.

#![no_std]
#![no_main]

extern crate alloc;

use anyhow::anyhow;
use chrono::{DateTime, Duration, TimeZone, Utc};
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln, syscall};
use embedded_alloc::LlffHeap as Heap;
use panic_halt as _;
use serde::{Deserialize, Serialize};

use alloc::{borrow::ToOwned, string::String};

#[cfg(feature = "ed25519")]
use jwt_compact::alg::Ed25519;
#[cfg(feature = "rsa")]
use jwt_compact::alg::Rsa;
use jwt_compact::{
    alg::{Hs256, Hs384, Hs512, SigningKey, VerifyingKey},
    prelude::*,
    Algorithm,
};

#[global_allocator]
static ALLOCATOR: Heap = Heap::empty();

#[cfg(any(feature = "ed25519", feature = "rsa"))]
mod rsa_helpers {
    use getrandom::{register_custom_getrandom, Error as RandomError};
    use once_cell::unsync::Lazy;
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaChaRng,
    };

    static mut RNG: Lazy<ChaChaRng> = Lazy::new(|| {
        let epoch_seconds = unsafe { cortex_m_semihosting::syscall!(TIME) };
        // Using a timestamp as an RNG seed is unsecure and done for simplicity only.
        // Modern bare metal envs come with a hardware RNG peripheral that should be used instead.
        ChaChaRng::seed_from_u64(epoch_seconds as u64)
    });

    fn unsecure_getrandom_do_not_use_in_real_apps(dest: &mut [u8]) -> Result<(), RandomError> {
        unsafe {
            // SAFETY: we have a single-threaded context, so access to `RNG` is exclusive.
            RNG.fill_bytes(dest);
        }
        Ok(())
    }

    register_custom_getrandom!(unsecure_getrandom_do_not_use_in_real_apps);
}

/// Gets current time via a semihosting syscall.
fn now() -> DateTime<Utc> {
    let epoch_seconds = unsafe { syscall!(TIME) };
    Utc.timestamp_opt(epoch_seconds as i64, 0).unwrap()
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
            time_options: TimeOptions::new(Duration::try_seconds(15).unwrap(), now),
        }
    }

    fn extract_claims<'a>(
        &self,
        token: &'a Token<SampleClaims>,
    ) -> anyhow::Result<&'a SampleClaims> {
        Ok(&token
            .claims()
            .validate_expiration(&self.time_options)
            .map_err(|err| anyhow!(err))?
            .custom)
    }

    fn verify_token<T: Algorithm>(
        &self,
        alg: &T,
        token: &str,
        verifying_key: &T::VerifyingKey,
    ) -> anyhow::Result<SampleClaims> {
        let token = UntrustedToken::new(token).map_err(|err| anyhow!(err))?;
        let token = alg
            .validator::<SampleClaims>(verifying_key)
            .validate(&token)
            .map_err(|err| anyhow!(err))?;
        let claims = self.extract_claims(&token)?;
        Ok(claims.to_owned())
    }

    fn create_token<T: Algorithm>(
        &self,
        alg: &T,
        claims: SampleClaims,
        signing_key: &T::SigningKey,
    ) -> anyhow::Result<String> {
        let claims = Claims::new(claims)
            .set_duration_and_issuance(&self.time_options, Duration::try_minutes(10).unwrap());

        let token = alg
            .token(&Header::empty(), &claims, signing_key)
            .map_err(|err| anyhow!(err))?;
        Ok(token)
    }

    fn roundtrip_alg<T>(&self, signing_key: &[u8], verifying_key: &[u8]) -> anyhow::Result<()>
    where
        T: Algorithm + Default,
        T::SigningKey: SigningKey<T>,
        T::VerifyingKey: VerifyingKey<T>,
    {
        let alg = T::default();
        hprintln!("Testing algorithm: {}", alg.name());

        let claims = SampleClaims {
            subject: "j.doe@example.com".to_owned(),
            name: "John Doe".to_owned(),
            admin: false,
        };
        let signing_key = <T::SigningKey>::from_slice(signing_key).map_err(|err| anyhow!(err))?;
        let token = self.create_token(&alg, claims.clone(), &signing_key)?;
        hprintln!("Created token: {}", token);

        let verifying_key =
            <T::VerifyingKey>::from_slice(verifying_key).map_err(|err| anyhow!(err))?;
        let recovered_claims = self.verify_token(&alg, &token, &verifying_key)?;
        hprintln!("Verified token");
        assert_eq!(claims, recovered_claims);
        Ok(())
    }

    #[cfg(feature = "rsa")]
    fn roundtrip_rsa(&self, alg: &Rsa, private_key_der: &[u8]) -> anyhow::Result<()> {
        use jwt_compact::alg::{RsaPrivateKey, RsaPublicKey};
        use rsa::pkcs1::DecodeRsaPrivateKey;

        hprintln!("Testing algorithm: {}", alg.name());

        let claims = SampleClaims {
            subject: "j.doe@example.com".to_owned(),
            name: "John Doe".to_owned(),
            admin: false,
        };
        let signing_key =
            RsaPrivateKey::from_pkcs1_der(private_key_der).map_err(|err| anyhow!(err))?;
        let token = self.create_token(alg, claims.clone(), &signing_key)?;
        hprintln!("Created token: {}", token);

        let verifying_key = RsaPublicKey::from(signing_key);
        let recovered_claims = self.verify_token(alg, &token, &verifying_key)?;
        hprintln!("Verified token");
        assert_eq!(claims, recovered_claims);
        Ok(())
    }
}

const HEAP_SIZE: usize = 32_768;

const HASH_SECRET_KEY: &[u8] = b"super_secret_key_donut_steel";

#[cfg(feature = "ed25519")]
const ED_PRIVATE_KEY: [u8; 64] = const_decoder::Decoder::Hex.decode(
    b"9e55d1e1aa1f455b8baad9fdf975503655f8b359d542fa7e4ce84106d625b352\
     06fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f61115075",
);

#[cfg(feature = "rsa")]
const RSA_PRIVATE_KEY: [u8; 1190] = const_decoder::Pem::decode(
    br"-----BEGIN RSA PRIVATE KEY-----
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
       -----END RSA PRIVATE KEY-----",
);

fn main_inner() -> anyhow::Result<()> {
    let token_checker = TokenChecker::new();
    token_checker.roundtrip_alg::<Hs256>(HASH_SECRET_KEY, HASH_SECRET_KEY)?;
    token_checker.roundtrip_alg::<Hs384>(HASH_SECRET_KEY, HASH_SECRET_KEY)?;
    token_checker.roundtrip_alg::<Hs512>(HASH_SECRET_KEY, HASH_SECRET_KEY)?;

    #[cfg(feature = "ed25519")]
    token_checker.roundtrip_alg::<Ed25519>(&ED_PRIVATE_KEY, &ED_PRIVATE_KEY[32..])?;
    #[cfg(feature = "rsa")]
    token_checker.roundtrip_rsa(&Rsa::rs256(), &RSA_PRIVATE_KEY)?;

    Ok(())
}

#[entry]
fn main() -> ! {
    let start = cortex_m_rt::heap_start() as usize;
    unsafe {
        ALLOCATOR.init(start, HEAP_SIZE);
    }

    main_inner().unwrap();

    debug::exit(debug::EXIT_SUCCESS);
    unreachable!("Program must exit by this point");
}
