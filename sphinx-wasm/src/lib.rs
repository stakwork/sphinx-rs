use sphinx_ffi as cy;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn pubkey_from_secret_key(sec: &str) -> String {
    cy::pubkey_from_secret_key(sec.to_string()).unwrap_or_default()
}
