use sphinx_ffi as cy;
use wasm_bindgen::prelude::*;

type Result<T> = std::result::Result<T, JsError>;

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

#[wasm_bindgen]
pub struct Keys {
    secret: String,
    pubkey: String,
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
impl Keys {
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> String {
        self.secret.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn pubkey(&self) -> String {
        self.pubkey.clone()
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
