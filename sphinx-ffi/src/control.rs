use crate::{parse, Result, SphinxError};
use sphinx_crypter::secp256k1::SecretKey;
use sphinx_glyph::control::{
    build_control_msg, control_msg_from_json, parse_control_response_to_json,
};
use sphinx_glyph::types::ControlMessage;

pub fn build_request(msg: String, secret: String, nonce: u64) -> Result<String> {
    let cm = match control_msg_from_json(msg.as_bytes()) {
        Ok(s) => s,
        Err(_) => return Err(SphinxError::BadRequest),
    };
    Ok(build_msg(cm, nonce, secret)?)
}

pub fn parse_response(inp: String) -> Result<String> {
    let v = match hex::decode(inp) {
        Ok(s) => s,
        Err(_) => return Err(SphinxError::BadResponse),
    };
    match parse_control_response_to_json(&v) {
        Ok(r) => Ok(r),
        Err(_) => Err(SphinxError::BadResponse),
    }
}

///////////
// UTILS //
///////////Policy

fn build_msg(msg: ControlMessage, nonce: u64, secret: String) -> Result<String> {
    let sk = parse_secret_key(secret)?;
    match build_control_msg(msg, nonce, &sk) {
        Ok(r) => Ok(hex::encode(r)),
        Err(_) => Err(SphinxError::BadRequest),
    }
}

fn parse_secret_key(secret: String) -> Result<SecretKey> {
    let secret_key = parse::parse_secret_string(secret)?;
    match SecretKey::from_slice(&secret_key[..]) {
        Ok(s) => Ok(s),
        Err(_) => Err(SphinxError::BadSecret),
    }
}
