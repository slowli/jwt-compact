//! Module testing that the library can verify JWTs in WASM.

#![no_std]

extern crate alloc;

use chrono::Duration;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Error as JsonError;
use wasm_bindgen::prelude::*;

use alloc::string::{String, ToString};
use core::{convert::TryFrom, fmt};

use jwt_compact::{
    alg::{Ed25519, Es256k, Hs256, Hs384, Hs512, Rsa},
    jwk::{JsonWebKey, JwkError},
    Algorithm, AlgorithmExt, Claims, Header, TimeOptions, Token, UntrustedToken,
};

#[wasm_bindgen]
extern "C" {
    type Error;

    #[wasm_bindgen(constructor)]
    fn new(message: &str) -> Error;

    // For some undecipherable reason, if both `wasm-bindgen/serde-serialize` and
    // `rand_core/getrandom` features are on, type inference breaks in the `der` crate
    // (specifically for the WASM target!). The simplest way to fix this is to manually wrap
    // `JSON` methods instead of using `serde-serialize`.
    #[wasm_bindgen(js_name = parse, js_namespace = JSON)]
    fn json_parse(s: &str) -> JsValue;

    #[wasm_bindgen(js_name = stringify, js_namespace = JSON)]
    fn json_stringify(value: &JsValue) -> String;
}

/// Sample token claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SampleClaims {
    #[serde(rename = "sub")]
    subject: String,
    name: String,
    #[serde(default)]
    admin: bool,
}

/// Converts type to a JS `Error`.
fn to_js_error(e: impl fmt::Display) -> Error {
    Error::new(&e.to_string())
}

fn from_serde<T: Serialize>(value: &T) -> Result<JsValue, JsonError> {
    let json_string = serde_json::to_string(value)?;
    Ok(json_parse(&json_string))
}

fn into_serde<T: DeserializeOwned>(value: &JsValue) -> Result<T, JsonError> {
    let json_string = json_stringify(value);
    serde_json::from_str(&json_string)
}

fn extract_claims(token: &Token<SampleClaims>) -> Result<&SampleClaims, JsValue> {
    Ok(&token
        .claims()
        .validate_expiration(&TimeOptions::default())
        .map_err(to_js_error)?
        .custom)
}

fn do_verify_token<T, J>(alg: &T, token: &UntrustedToken, jwk: J) -> Result<JsValue, JsValue>
where
    T: Algorithm,
    T::VerifyingKey: TryFrom<J, Error = JwkError>,
{
    let verifying_key = <T::VerifyingKey>::try_from(jwk).map_err(to_js_error)?;

    let token = alg
        .validate_integrity::<SampleClaims>(token, &verifying_key)
        .map_err(to_js_error)?;
    let claims = extract_claims(&token)?;
    Ok(from_serde(claims).expect("Cannot serialize claims"))
}

fn do_create_token<T, J>(alg: &T, claims: SampleClaims, jwk: J) -> Result<String, JsValue>
where
    T: Algorithm,
    T::SigningKey: TryFrom<J, Error = JwkError>,
{
    let secret_key = <T::SigningKey>::try_from(jwk).map_err(to_js_error)?;
    let claims = Claims::new(claims).set_duration(&TimeOptions::default(), Duration::hours(1));

    let token = alg
        .token(Header::default(), &claims, &secret_key)
        .map_err(to_js_error)?;
    Ok(token)
}

#[wasm_bindgen(js_name = "verifyHashToken")]
pub fn verify_hash_token(token: &str, secret_key: &JsValue) -> Result<JsValue, JsValue> {
    let token = UntrustedToken::new(token).map_err(to_js_error)?;
    let jwk: JsonWebKey<'_> = into_serde(secret_key).map_err(to_js_error)?;

    match token.algorithm() {
        "HS256" => do_verify_token(&Hs256, &token, &jwk),
        "HS384" => do_verify_token(&Hs384, &token, &jwk),
        "HS512" => do_verify_token(&Hs512, &token, &jwk),
        _ => Err(to_js_error("Invalid algorithm").into()),
    }
}

#[wasm_bindgen(js_name = "createHashToken")]
pub fn create_hash_token(
    claims: &JsValue,
    secret_key: &JsValue,
    alg: &str,
) -> Result<String, JsValue> {
    let jwk: JsonWebKey<'_> = into_serde(secret_key).map_err(to_js_error)?;
    let claims: SampleClaims = into_serde(claims).map_err(to_js_error)?;
    match alg {
        "HS256" => do_create_token(&Hs256, claims, &jwk),
        "HS384" => do_create_token(&Hs384, claims, &jwk),
        "HS512" => do_create_token(&Hs512, claims, &jwk),
        _ => Err(to_js_error("Invalid algorithm").into()),
    }
}

#[wasm_bindgen(js_name = "verifyRsaToken")]
pub fn verify_rsa_token(token: &str, public_key: &JsValue) -> Result<JsValue, JsValue> {
    let token = UntrustedToken::new(token).map_err(to_js_error)?;
    let alg = Rsa::with_name(token.algorithm());
    let jwk: JsonWebKey<'_> = into_serde(public_key).map_err(to_js_error)?;
    do_verify_token(&alg, &token, &jwk)
}

#[wasm_bindgen(js_name = "createRsaToken")]
pub fn create_rsa_token(
    claims: &JsValue,
    private_key: &JsValue,
    alg: &str,
) -> Result<String, JsValue> {
    let jwk: JsonWebKey<'_> = into_serde(private_key).map_err(to_js_error)?;
    let claims: SampleClaims = into_serde(claims).map_err(to_js_error)?;
    do_create_token(&Rsa::with_name(alg), claims, &jwk)
}

#[wasm_bindgen(js_name = "verifyEdToken")]
pub fn verify_ed_token(token: &str, public_key: &JsValue) -> Result<JsValue, JsValue> {
    let jwk: JsonWebKey<'_> = into_serde(public_key).map_err(to_js_error)?;
    let token = UntrustedToken::new(token).map_err(to_js_error)?;
    do_verify_token(&Ed25519, &token, &jwk)
}

#[wasm_bindgen(js_name = "createEdToken")]
pub fn create_ed_token(claims: &JsValue, private_key: &JsValue) -> Result<String, JsValue> {
    let jwk: JsonWebKey<'_> = into_serde(private_key).map_err(to_js_error)?;
    let claims: SampleClaims = into_serde(claims).map_err(to_js_error)?;
    do_create_token(&Ed25519, claims, &jwk)
}

#[wasm_bindgen(js_name = "verifyEs256kToken")]
pub fn verify_es256k_token(token: &str, public_key: &JsValue) -> Result<JsValue, JsValue> {
    let jwk: JsonWebKey<'_> = into_serde(public_key).map_err(to_js_error)?;
    let token = UntrustedToken::new(token).map_err(to_js_error)?;
    do_verify_token(&<Es256k>::default(), &token, &jwk)
}

#[wasm_bindgen(js_name = "createEs256kToken")]
pub fn create_es256k_token(claims: &JsValue, private_key: &JsValue) -> Result<String, JsValue> {
    let jwk: JsonWebKey<'_> = into_serde(private_key).map_err(to_js_error)?;
    let claims: SampleClaims = into_serde(claims).map_err(to_js_error)?;
    do_create_token(&<Es256k>::default(), claims, &jwk)
}
