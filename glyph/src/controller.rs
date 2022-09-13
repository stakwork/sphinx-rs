use crate::types::{ControlMessage, ControlResponse};
use sphinx_auther::{nonce, secp256k1::SecretKey};

pub fn build_control_msg(
    msg: ControlMessage,
    nonce: u64,
    secret: &SecretKey,
) -> anyhow::Result<Vec<u8>> {
    let data = rmp_serde::to_vec(&msg)?;
    let ret = nonce::build_msg(&data, secret, nonce)?;
    Ok(ret)
}

pub fn parse_control_response(input: &[u8]) -> anyhow::Result<ControlResponse> {
    Ok(rmp_serde::from_slice(input)?)
}
