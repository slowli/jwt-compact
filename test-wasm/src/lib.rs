use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use std::{convert::TryFrom, fmt};

use jwt_compact::{
    alg::{RSAPublicKey, Rsa},
    AlgorithmExt, UntrustedToken,
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

#[wasm_bindgen(js_name = "verifyRsaToken")]
pub fn verify_rsa_token(token: &str, public_key_der: &[u8]) -> Result<JsValue, JsValue> {
    let public_key = RSAPublicKey::from_pkcs8(public_key_der).map_err(to_js_error)?;
    let token = UntrustedToken::try_from(token).map_err(to_js_error)?;

    let rsa = Rsa::with_name(token.algorithm());
    let token = rsa
        .validate_integrity::<SampleClaims>(&token, &public_key)
        .map_err(to_js_error)?;
    let claims = &token.claims().custom;
    Ok(JsValue::from_serde(claims).expect("Cannot serialize claims"))
}
