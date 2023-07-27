use crate::{Result, SphinxError};
use sphinx_glyph::serde_json;
use sphinx_signer::lss_connector;
use sphinx_signer::mobile;
use std::collections::BTreeMap;
use std::convert::TryInto;

// last 4 bytes of the Vec<u8> is the version u64
pub type EasyState = BTreeMap<String, Vec<u8>>;

pub type Muts = Vec<(String, (u64, Vec<u8>))>;

pub struct VlsResponse {
    pub topic: String,
    pub vls_bytes: Option<Vec<u8>>,
    pub lss_bytes: Option<Vec<u8>>,
    pub sequence: u16,
    pub cmd: String,
    pub velocity: Option<Vec<u8>>,
    pub state: Option<Vec<u8>>,
}

pub fn run_init_1(args_json: String, easy_state: Vec<u8>, msg1: Vec<u8>) -> Result<VlsResponse> {
    let args = args_from_json(&args_json)?;
    let state = state_from_easy_mp(&easy_state)?;
    let ret = mobile::run_init_1(args, state, msg1).map_err(|e| SphinxError::InitFailed {
        r: format!("{:?}", e),
    })?;
    Ok(VlsResponse::new(ret.0, None))
}

pub fn run_init_2(
    args_json: String,
    easy_state: Vec<u8>,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_json)?;
    let state = state_from_easy_mp(&easy_state)?;
    let ret = mobile::run_init_2(args, state, msg1, msg2).map_err(|e| SphinxError::InitFailed {
        r: format!("{:?}", e),
    })?;
    let muts = ser_state(&ret.0.lss_bytes)?;
    Ok(VlsResponse::new(ret.0, muts))
}

pub fn run_lss(
    args_json: String,
    easy_state: Vec<u8>,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    lss_msg: Vec<u8>,
    prev_vls: Vec<u8>,
    prev_lss: Vec<u8>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_json)?;
    let state = state_from_easy_mp(&easy_state)?;
    let ret =
        mobile::run_lss(args, state, msg1, msg2, lss_msg, prev_vls, prev_lss).map_err(|e| {
            SphinxError::LssFailed {
                r: format!("{:?}", e),
            }
        })?;
    let muts = ser_state(&ret.lss_bytes)?;
    Ok(VlsResponse::new(ret, muts))
}

pub fn run_vls(
    args_json: String,
    easy_state: Vec<u8>,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    vls_msg: Vec<u8>,
    sequence: Option<u16>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_json)?;
    let state = state_from_easy_mp(&easy_state)?;
    let ran = mobile::run_vls(args, state, msg1, msg2, vls_msg, sequence);
    let ret = ran.map_err(|e| SphinxError::VlsFailed {
        r: format!("{:?}", e),
    })?;
    let muts = ser_state(&ret.lss_bytes)?;
    Ok(VlsResponse::new(ret, muts))
}

fn ser_state(lss_bytes: &Option<Vec<u8>>) -> Result<Option<Vec<u8>>> {
    match state_from_lss_bytes(lss_bytes) {
        Some(es) => {
            let sr = rmp_utils::serialize_simple_state_map(&es);
            let s = sr.map_err(|e| SphinxError::BadState {
                r: format!("{:?}", e),
            })?;
            Ok(Some(s))
        }
        None => Ok(None),
    }
}

fn state_from_lss_bytes(lss_bytes: &Option<Vec<u8>>) -> Option<EasyState> {
    let mut muts = None;
    if let Some(r) = lss_bytes {
        if let Ok(b) = lss_connector::Response::from_slice(&r) {
            if let Ok(m) = b.get_muts() {
                muts = Some(easy_muts(m));
            }
        }
    }
    muts
}

fn easy_muts(m: Muts) -> EasyState {
    let mut h = BTreeMap::new();
    for mm in m {
        let vv = mm.1;
        let bs = vv.0.to_be_bytes();
        let mut val = vv.1;
        val.extend_from_slice(&bs);
        h.insert(mm.0, val);
    }
    h
}

fn state_from_easy_mp(state_mp: &[u8]) -> Result<mobile::State> {
    let mut s: mobile::State = BTreeMap::new();
    let es: EasyState =
        rmp_utils::deserialize_simple_state_map(state_mp).map_err(|e| SphinxError::BadState {
            r: format!("{:?}", e),
        })?;
    for (k, mut vv) in es {
        let bs = vv.split_off(vv.len() - 8);
        let b8: [u8; 8] = bs.try_into().map_err(|e| SphinxError::BadState {
            r: format!("{:?}", e),
        })?;
        let ver = u64::from_be_bytes(b8);
        s.insert(k, (ver, vv));
    }
    Ok(s)
}

impl VlsResponse {
    pub fn new(ret: mobile::RunReturn, state: Option<Vec<u8>>) -> Self {
        Self {
            topic: ret.topic,
            vls_bytes: ret.vls_bytes,
            lss_bytes: ret.lss_bytes,
            sequence: ret.sequence,
            cmd: ret.cmd,
            velocity: ret.velocity,
            state,
        }
    }
}

pub fn run_init_1_og(
    args_string: String,
    state_mp: Vec<u8>,
    msg1: Vec<u8>,
) -> Result<mobile::RunReturn> {
    let args = args_from_json(&args_string)?;
    let state = state_from_mp(&state_mp)?;
    let ret = mobile::run_init_1(args, state, msg1).map_err(|e| SphinxError::InitFailed {
        r: format!("{:?}", e),
    })?;
    Ok(ret.0)
}

pub fn run_init_2_og(
    args_string: String,
    state_mp: Vec<u8>,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
) -> Result<mobile::RunReturn> {
    let args = args_from_json(&args_string)?;
    let state = state_from_mp(&state_mp)?;
    let ret = mobile::run_init_2(args, state, msg1, msg2).map_err(|e| SphinxError::InitFailed {
        r: format!("{:?}", e),
    })?;
    Ok(ret.0)
}

pub fn run_vls_og(
    args_string: String,
    state_mp: Vec<u8>,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    vls_msg: Vec<u8>,
    sequence: Option<u16>,
) -> Result<mobile::RunReturn> {
    let args = args_from_json(&args_string)?;
    let state = state_from_mp(&state_mp)?;
    let ret = mobile::run_vls(args, state, msg1, msg2, vls_msg, sequence);
    Ok(ret.map_err(|e| SphinxError::VlsFailed {
        r: format!("{:?}", e),
    })?)
}

pub fn run_lss_og(
    args_string: String,
    state_mp: Vec<u8>,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    lss_msg: Vec<u8>,
    prev_vls: Vec<u8>,
    prev_lss: Vec<u8>,
) -> Result<mobile::RunReturn> {
    let args = args_from_json(&args_string)?;
    let state = state_from_mp(&state_mp)?;
    let ret =
        mobile::run_lss(args, state, msg1, msg2, lss_msg, prev_vls, prev_lss).map_err(|e| {
            SphinxError::LssFailed {
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
