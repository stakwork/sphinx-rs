use crate::{parse, CrypterError, Result};
use sphinx_crypter::secp256k1::SecretKey;
use sphinx_glyph::build_control_msg;
use sphinx_glyph::types::{ControlMessage, ControlResponse, Interval, Policy as RawPolicy};
use std::str::FromStr;

pub fn get_nonce_request(secret: String, nonce: u64) -> Result<String> {
    Ok(build_msg(ControlMessage::Nonce, nonce, secret)?)
}

pub fn get_nonce_response(inp: String) -> Result<u64> {
    let r = parse_response_bytes(inp)?;
    match r {
        ControlResponse::Nonce(n) => Ok(n),
        _ => Err(CrypterError::BadResponse),
    }
}

pub fn reset_wifi_request(secret: String, nonce: u64) -> Result<String> {
    Ok(build_msg(ControlMessage::ResetWifi, nonce, secret)?)
}

pub fn reset_wifi_response(inp: String) -> Result<()> {
    let r = parse_response_bytes(inp)?;
    match r {
        ControlResponse::ResetWifi => Ok(()),
        _ => Err(CrypterError::BadResponse),
    }
}

pub fn reset_keys_request(secret: String, nonce: u64) -> Result<String> {
    Ok(build_msg(ControlMessage::ResetKeys, nonce, secret)?)
}

pub fn reset_keys_response(inp: String) -> Result<()> {
    let r = parse_response_bytes(inp)?;
    match r {
        ControlResponse::ResetKeys => Ok(()),
        _ => Err(CrypterError::BadResponse),
    }
}

pub fn reset_all_request(secret: String, nonce: u64) -> Result<String> {
    Ok(build_msg(ControlMessage::ResetAll, nonce, secret)?)
}

pub fn reset_all_response(inp: String) -> Result<()> {
    let r = parse_response_bytes(inp)?;
    match r {
        ControlResponse::ResetAll => Ok(()),
        _ => Err(CrypterError::BadResponse),
    }
}

pub fn get_policy_request(secret: String, nonce: u64) -> Result<String> {
    Ok(build_msg(ControlMessage::QueryPolicy, nonce, secret)?)
}

pub fn get_policy_response(inp: String) -> Result<Policy> {
    let r = parse_response_bytes(inp)?;
    match r {
        ControlResponse::PolicyCurrent(p) => Ok(policy_to_dto(p)),
        _ => Err(CrypterError::BadResponse),
    }
}

pub fn update_policy_request(secret: String, nonce: u64, policy: Policy) -> Result<String> {
    let rp = dto_to_policy(policy)?;
    Ok(build_msg(ControlMessage::UpdatePolicy(rp), nonce, secret)?)
}

pub fn update_policy_response(inp: String) -> Result<Policy> {
    let r = parse_response_bytes(inp)?;
    match r {
        ControlResponse::PolicyUpdated(p) => Ok(policy_to_dto(p)),
        _ => Err(CrypterError::BadResponse),
    }
}

pub fn get_allowlist_request(secret: String, nonce: u64) -> Result<String> {
    Ok(build_msg(ControlMessage::QueryAllowlist, nonce, secret)?)
}

pub fn get_allowlist_response(inp: String) -> Result<Vec<String>> {
    let r = parse_response_bytes(inp)?;
    match r {
        ControlResponse::AllowlistCurrent(p) => Ok(p),
        _ => Err(CrypterError::BadResponse),
    }
}

pub fn update_allowlist_request(secret: String, nonce: u64, al: Vec<String>) -> Result<String> {
    Ok(build_msg(
        ControlMessage::UpdateAllowlist(al),
        nonce,
        secret,
    )?)
}

pub fn update_allowlist_response(inp: String) -> Result<Vec<String>> {
    let r = parse_response_bytes(inp)?;
    match r {
        ControlResponse::AllowlistUpdated(p) => Ok(p),
        _ => Err(CrypterError::BadResponse),
    }
}

// UTILS

pub struct Policy {
    pub sat_limit: u64,
    pub interval: String,
    pub htlc_limit: u64,
}

fn policy_to_dto(p: RawPolicy) -> Policy {
    Policy {
        sat_limit: p.sat_limit,
        interval: p.interval.as_str().to_string(),
        htlc_limit: p.htlc_limit,
    }
}
fn dto_to_policy(p: Policy) -> Result<RawPolicy> {
    let interval = match Interval::from_str(&p.interval) {
        Ok(i) => i,
        Err(_) => return Err(CrypterError::BadRequest),
    };
    Ok(RawPolicy {
        sat_limit: p.sat_limit,
        interval,
        htlc_limit: p.htlc_limit,
    })
}

fn build_msg(msg: ControlMessage, nonce: u64, secret: String) -> Result<String> {
    let sk = parse_secret_key(secret)?;
    match build_control_msg(msg, nonce, &sk) {
        Ok(r) => Ok(hex::encode(r)),
        Err(_) => Err(CrypterError::BadRequest),
    }
}

fn parse_secret_key(secret: String) -> Result<SecretKey> {
    let secret_key = parse::parse_secret_string(secret)?;
    match SecretKey::from_slice(&secret_key[..]) {
        Ok(s) => Ok(s),
        Err(_) => Err(CrypterError::BadSecret),
    }
}
fn parse_response_bytes(inp: String) -> Result<ControlResponse> {
    let v = match hex::decode(inp) {
        Ok(s) => s,
        Err(_) => return Err(CrypterError::BadResponse),
    };
    match sphinx_glyph::parse_control_response(&v) {
        Ok(r) => Ok(r),
        Err(_) => Err(CrypterError::BadResponse),
    }
}
