mod signer;

use sphinx_ffi as cy;
use wasm_bindgen::prelude::*;

type Result<T> = std::result::Result<T, JsError>;

#[wasm_bindgen]
pub fn init_logs() {
    wasm_logger::init(wasm_logger::Config::new(log::Level::Info));
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));
}

#[wasm_bindgen]
pub fn pubkey_from_secret_key(sec: &str) -> Result<String> {
    Ok(cy::pubkey_from_secret_key(sec.to_string())?)
}

#[wasm_bindgen]
pub fn build_control_request(msg: &str, secret: &str, nonce: u64) -> Result<String> {
    Ok(cy::build_request(
        msg.to_string(),
        secret.to_string(),
        nonce,
    )?)
}

#[wasm_bindgen]
pub fn parse_control_response(msg: &str) -> Result<String> {
    Ok(cy::parse_response(msg.to_string())?)
}

#[wasm_bindgen(getter_with_clone)]
pub struct Keys {
    pub secret: String,
    pub pubkey: String,
}

impl From<cy::Keys> for Keys {
    fn from(keys: cy::Keys) -> Self {
        Keys {
            secret: keys.secret,
            pubkey: keys.pubkey,
        }
    }
}

#[wasm_bindgen]
pub fn node_keys(net: &str, seed: &str) -> Result<Keys> {
    Ok(cy::node_keys(net.to_string(), seed.to_string())?.into())
}

#[wasm_bindgen]
pub fn mnemonic_from_entropy(seed: &str) -> Result<String> {
    Ok(cy::mnemonic_from_entropy(seed.to_string())?)
}

#[wasm_bindgen]
pub fn entropy_from_mnemonic(mnemonic: &str) -> Result<String> {
    Ok(cy::entropy_from_mnemonic(mnemonic.to_string())?)
}

#[wasm_bindgen]
pub fn mnemonic_to_seed(mnemonic: &str) -> Result<String> {
    Ok(cy::mnemonic_to_seed(mnemonic.to_string())?)
}

#[wasm_bindgen]
pub fn make_auth_token(ts: u32, secret: &str) -> Result<String> {
    Ok(cy::make_auth_token(ts, secret.to_string())?)
}
