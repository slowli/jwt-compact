//! Module testing that the library can verify JWTs in WASM.

#![no_std]

extern crate alloc;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use alloc::string::{String, ToString};
use core::{convert::TryFrom, fmt};

use jwt_compact::{
    alg::{Ed25519, Hs256, Hs384, Hs512, RSAPublicKey, Rsa, VerifyingKey},
    Algorithm, AlgorithmExt, Token, UntrustedToken,
};

#[wasm_bindgen]
extern "C" {
    pub type Error;

    #[wasm_bindgen(constructor)]
    fn new(message: &str) -> Error;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SampleClaims {
    #[serde(rename = "sub")]
    subject: String,
    name: String,
    #[serde(default)]
    admin: bool,
}

fn to_js_error(e: impl fmt::Display) -> Error {
    Error::new(&e.to_string())
}

// FIXME: check expiration / not before.
fn extract_claims(token: &Token<SampleClaims>) -> Result<&SampleClaims, JsValue> {
    Ok(&token.claims().custom)
}

#[wasm_bindgen(js_name = "verifyHashToken")]
pub fn verify_hash_token(token: &str, secret_key: &[u8]) -> Result<JsValue, JsValue> {
    let token = UntrustedToken::try_from(token).map_err(to_js_error)?;
    match token.algorithm() {
        "HS256" => do_verify_hash_token::<Hs256>(&token, secret_key),
        "HS384" => do_verify_hash_token::<Hs384>(&token, secret_key),
        "HS512" => do_verify_hash_token::<Hs512>(&token, secret_key),
        _ => Err(to_js_error("Invalid algorithm").into()),
    }
}

fn do_verify_hash_token<T>(token: &UntrustedToken, secret_key: &[u8]) -> Result<JsValue, JsValue>
where
    T: Algorithm + Default,
    T::VerifyingKey: for<'a> From<&'a [u8]>,
{
    let secret_key = <T::VerifyingKey>::from(secret_key);

    let token = T::default()
        .validate_integrity::<SampleClaims>(token, &secret_key)
        .map_err(to_js_error)?;
    let claims = extract_claims(&token)?;
    Ok(JsValue::from_serde(claims).expect("Cannot serialize claims"))
}

#[wasm_bindgen(js_name = "verifyRsaToken")]
pub fn verify_rsa_token(token: &str, public_key_pem: &str) -> Result<JsValue, JsValue> {
    let public_key = pem::parse(public_key_pem).map_err(to_js_error)?.contents;
    let public_key = RSAPublicKey::from_pkcs8(&public_key).map_err(to_js_error)?;
    let token = UntrustedToken::try_from(token).map_err(to_js_error)?;

    let rsa = Rsa::with_name(token.algorithm());
    let token = rsa
        .validate_integrity::<SampleClaims>(&token, &public_key)
        .map_err(to_js_error)?;
    let claims = extract_claims(&token)?;
    Ok(JsValue::from_serde(claims).expect("Cannot serialize claims"))
}

#[wasm_bindgen(js_name = "verifyEdToken")]
pub fn verify_ed_token(token: &str, public_key: &[u8]) -> Result<JsValue, JsValue> {
    let public_key = VerifyingKey::from_slice(public_key).map_err(to_js_error)?;
    let token = UntrustedToken::try_from(token).map_err(to_js_error)?;

    let token = Ed25519
        .validate_integrity::<SampleClaims>(&token, &public_key)
        .map_err(to_js_error)?;
    let claims = extract_claims(&token)?;
    Ok(JsValue::from_serde(claims).expect("Cannot serialize claims"))
}
