use crate::{parse, Result, SphinxError};
use sphinx_crypter::secp256k1::SecretKey;
use sphinx_glyph::control::{
    build_control_msg, control_msg_from_json, parse_control_response_to_json,
};
use sphinx_glyph::sphinx_auther;
use sphinx_glyph::types::ControlMessage;

pub fn build_request(msg: String, secret: String, nonce: u64) -> Result<String> {
    let cm = control_msg_from_json(msg.as_bytes()).map_err(|_| SphinxError::BadRequest)?;
    Ok(build_msg(cm, nonce, secret)?)
}

pub fn parse_response(inp: String) -> Result<String> {
    let v = hex::decode(inp).map_err(|_| SphinxError::BadResponse)?;
    let r = parse_control_response_to_json(&v).map_err(|_| SphinxError::BadResponse)?;
    Ok(r)
}

pub fn make_auth_token(ts: u32, secret: String) -> Result<String> {
    let sk = parse_secret_key(secret)?;
    let t = sphinx_auther::token::Token::new_with_time(ts);
    Ok(t.sign_to_base64(&sk).map_err(|_| SphinxError::BadSecret)?)
}

///////////
// UTILS //
///////////Policy

fn build_msg(msg: ControlMessage, nonce: u64, secret: String) -> Result<String> {
    let sk = parse_secret_key(secret)?;
    let r = build_control_msg(msg, nonce, &sk).map_err(|_| SphinxError::BadRequest)?;
    Ok(hex::encode(r))
}

fn parse_secret_key(secret: String) -> Result<SecretKey> {
    let secret_key = parse::parse_secret_string(secret)?;
    let sk = SecretKey::from_slice(&secret_key[..]).map_err(|_| SphinxError::BadSecret)?;
    Ok(sk)
}
