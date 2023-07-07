use crate::{Result, SphinxError};
use sphinx_glyph::serde_json;
use sphinx_signer::mobile;

pub type VlsResponse = mobile::RunReturn;

pub fn run_init_1(args_string: String, msg1: Vec<u8>) -> Result<VlsResponse> {
    let args: mobile::Args =
        serde_json::from_str(&args_string).map_err(|_| SphinxError::BadArgs)?;
    let ret = mobile::run_init_1(args, msg1).map_err(|_| SphinxError::InitFailed)?;
    Ok(ret.0)
}

pub fn run_init_2(args_string: String, msg1: Vec<u8>, msg2: Vec<u8>) -> Result<VlsResponse> {
    let args: mobile::Args =
        serde_json::from_str(&args_string).map_err(|_| SphinxError::BadArgs)?;
    let ret = mobile::run_init_2(args, msg1, msg2).map_err(|_| SphinxError::InitFailed)?;
    Ok(ret.0)
}

pub fn run_vls(
    args_string: String,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    vls_msg: Vec<u8>,
) -> Result<VlsResponse> {
    let args: mobile::Args =
        serde_json::from_str(&args_string).map_err(|_| SphinxError::BadArgs)?;
    let ret = mobile::run_vls(args, msg1, msg2, vls_msg).map_err(|_| SphinxError::InitFailed)?;
    Ok(ret)
}

pub fn run_lss(
    args_string: String,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    lss_msg: Vec<u8>,
    prev_vls: Vec<u8>,
    prev_lss: Vec<u8>,
) -> Result<VlsResponse> {
    let args: mobile::Args =
        serde_json::from_str(&args_string).map_err(|_| SphinxError::BadArgs)?;
    let ret = mobile::run_lss(args, msg1, msg2, lss_msg, prev_vls, prev_lss)
        .map_err(|_| SphinxError::InitFailed)?;
    Ok(ret)
}
