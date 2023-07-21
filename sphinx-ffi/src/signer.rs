use crate::{Result, SphinxError};
use sphinx_glyph::serde_json;
use sphinx_signer::mobile;

pub type VlsResponse = mobile::RunReturn;

pub fn run_init_1(args_string: String, state_mp: Vec<u8>, msg1: Vec<u8>) -> Result<VlsResponse> {
    let args = args_from_json(&args_string)?;
    let state = state_from_mp(&state_mp)?;
    let ret = mobile::run_init_1(args, state, msg1).map_err(|e| SphinxError::InitFailed {
        r: format!("{:?}", e),
    })?;
    Ok(ret.0)
}

pub fn run_init_2(
    args_string: String,
    state_mp: Vec<u8>,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_string)?;
    let state = state_from_mp(&state_mp)?;
    let ret = mobile::run_init_2(args, state, msg1, msg2).map_err(|e| SphinxError::InitFailed {
        r: format!("{:?}", e),
    })?;
    Ok(ret.0)
}

pub fn run_vls(
    args_string: String,
    state_mp: Vec<u8>,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    vls_msg: Vec<u8>,
    expected_sequence: Option<u16>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_string)?;
    let state = state_from_mp(&state_mp)?;
    let ret =
        mobile::run_vls(args, state, msg1, msg2, vls_msg, expected_sequence).map_err(|e| {
            SphinxError::InitFailed {
                r: format!("{:?}", e),
            }
        })?;
    Ok(ret)
}

pub fn run_lss(
    args_string: String,
    state_mp: Vec<u8>,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    lss_msg: Vec<u8>,
    prev_vls: Vec<u8>,
    prev_lss: Vec<u8>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_string)?;
    let state = state_from_mp(&state_mp)?;
    let ret =
        mobile::run_lss(args, state, msg1, msg2, lss_msg, prev_vls, prev_lss).map_err(|e| {
            SphinxError::InitFailed {
                r: format!("{:?}", e),
            }
        })?;
    Ok(ret)
}

fn state_from_mp(state_mp: &[u8]) -> Result<mobile::State> {
    let state: mobile::State =
        rmp_utils::deserialize_state_map(state_mp).map_err(|e| SphinxError::BadState {
            r: format!("{:?}", e),
        })?;
    Ok(state)
}
fn args_from_json(args_string: &str) -> Result<mobile::Args> {
    let args: mobile::Args =
        serde_json::from_str(args_string).map_err(|e| SphinxError::BadArgs {
            r: format!("{:?}", e),
        })?;
    Ok(args)
}
