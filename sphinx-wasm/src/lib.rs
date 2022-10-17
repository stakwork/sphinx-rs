use sphinx_ffi as cy;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn pubkey_from_secret_key(sec: &str) -> String {
    cy::pubkey_from_secret_key(sec.to_string()).unwrap_or_default()
}

#[wasm_bindgen]
pub fn build_control_request(msg: &str, secret: &str, nonce: u64) -> String {
    cy::build_request(msg.to_string(), secret.to_string(), nonce).unwrap_or_default()
}
