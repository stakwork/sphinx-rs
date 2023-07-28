use crate::{Result, SphinxError};
use sphinx_glyph::serde_json;
use sphinx_glyph::topics;
use sphinx_signer::lss_connector;
use sphinx_signer::mobile;
use std::collections::BTreeMap;
use std::convert::TryInto;

// last 4 bytes of the Vec<u8> is the version u64
pub type EasyState = BTreeMap<String, Vec<u8>>;

pub type Muts = Vec<(String, (u64, Vec<u8>))>;

pub struct VlsResponse {
    pub topic: String,
    pub bytes: Vec<u8>,
    pub sequence: u16,
    pub cmd: String,
    pub velocity: Option<Vec<u8>>,
    pub state: Vec<u8>,
}

pub const MSG_1: &str = "MSG_1";
pub const MSG_2: &str = "MSG_2";
pub const PREV_VLS: &str = "PREV_VLS";
pub const PREV_LSS: &str = "PREV_LSS";

pub fn run_init_1(
    args_json: String,
    easy_state_mp: Vec<u8>,
    msg1: Vec<u8>,
    _sequence: Option<u16>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_json)?;
    let mut easy_state = easy_state_from_mp(&easy_state_mp)?;
    let _ = pull_from(&mut easy_state, MSG_1);
    let _ = pull_from(&mut easy_state, MSG_2);
    let _ = pull_from(&mut easy_state, PREV_VLS);
    let _ = pull_from(&mut easy_state, PREV_LSS);
    let state = state_from_easy_state(easy_state)?;
    let ret = mobile::run_init_1(args, state, &msg1).map_err(|e| SphinxError::InitFailed {
        r: format!("{:?}", e),
    })?;
    let mut extras = BTreeMap::new();
    extras.insert(MSG_1.to_string(), msg1);
    let muts = ser_state(&None, extras)?;
    Ok(VlsResponse::new(ret.0, muts)?)
}

pub fn run_init_2(
    args_json: String,
    easy_state_mp: Vec<u8>,
    msg2: Vec<u8>,
    _sequence: Option<u16>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_json)?;
    let mut easy_state = easy_state_from_mp(&easy_state_mp)?;
    let msg1 = pull_from(&mut easy_state, MSG_1)?;
    let _ = pull_from(&mut easy_state, MSG_2);
    let _ = pull_from(&mut easy_state, PREV_VLS);
    let _ = pull_from(&mut easy_state, PREV_LSS);
    let state = state_from_easy_state(easy_state)?;
    let ret =
        mobile::run_init_2(args, state, &msg1, &msg2).map_err(|e| SphinxError::InitFailed {
            r: format!("{:?}", e),
        })?;
    let mut extras = BTreeMap::new();
    extras.insert(MSG_2.to_string(), msg2);
    let muts = ser_state(&ret.0.lss_bytes, extras)?;
    Ok(VlsResponse::new(ret.0, muts)?)
}

pub fn run_vls(
    args_json: String,
    easy_state_mp: Vec<u8>,
    vls_msg: Vec<u8>,
    sequence: Option<u16>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_json)?;
    let mut easy_state = easy_state_from_mp(&easy_state_mp)?;
    let msg1 = pull_from(&mut easy_state, MSG_1)?;
    let msg2 = pull_from(&mut easy_state, MSG_2)?;
    let _ = pull_from(&mut easy_state, PREV_VLS);
    let _ = pull_from(&mut easy_state, PREV_LSS);
    let state = state_from_easy_state(easy_state)?;
    let ran = mobile::run_vls(args, state, &msg1, &msg2, &vls_msg, sequence);
    let ret = ran.map_err(|e| SphinxError::VlsFailed {
        r: format!("{:?}", e),
    })?;
    let mut extras = BTreeMap::new();
    extras.insert(
        PREV_VLS.to_string(),
        ret.vls_bytes.clone().unwrap_or(Vec::new()),
    );
    extras.insert(
        PREV_LSS.to_string(),
        ret.lss_bytes.clone().unwrap_or(Vec::new()),
    );
    let muts = ser_state(&ret.lss_bytes, extras)?;
    Ok(VlsResponse::new(ret, muts)?)
}

pub fn run_lss(
    args_json: String,
    easy_state_mp: Vec<u8>,
    lss_msg: Vec<u8>,
    _sequence: Option<u16>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_json)?;
    let mut easy_state = easy_state_from_mp(&easy_state_mp)?;
    let msg1 = pull_from(&mut easy_state, MSG_1)?;
    let msg2 = pull_from(&mut easy_state, MSG_2)?;
    let prev_vls = pull_from(&mut easy_state, PREV_VLS)?;
    let prev_lss = pull_from(&mut easy_state, PREV_LSS)?;
    let state = state_from_easy_state(easy_state)?;
    let ret = mobile::run_lss(args, state, &msg1, &msg2, &lss_msg, &prev_vls, &prev_lss).map_err(
        |e| SphinxError::LssFailed {
            r: format!("{:?}", e),
        },
    )?;
    let muts = ser_state(&ret.lss_bytes, BTreeMap::new())?;
    Ok(VlsResponse::new(ret, muts)?)
}

pub fn pull_from(easy_state: &mut EasyState, key: &str) -> Result<Vec<u8>> {
    let msg = easy_state.remove(key).ok_or(SphinxError::BadState {
        r: format!("missing {}", key),
    })?;
    Ok(msg)
}

fn ser_state(lss_bytes: &Option<Vec<u8>>, extras: EasyState) -> Result<Vec<u8>> {
    let state_and_extras = match state_from_lss_bytes(lss_bytes) {
        Some(mut es) => {
            for (k, v) in extras {
                es.insert(k, v);
            }
            es
        }
        None => extras,
    };
    let sr = rmp_utils::serialize_simple_state_map(&state_and_extras);
    let s = sr.map_err(|e| SphinxError::BadState {
        r: format!("{:?}", e),
    })?;
    Ok(s)
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

fn easy_state_from_mp(state_mp: &[u8]) -> Result<EasyState> {
    let es: EasyState =
        rmp_utils::deserialize_simple_state_map(state_mp).map_err(|e| SphinxError::BadState {
            r: format!("{:?}", e),
        })?;
    Ok(es)
}

fn state_from_easy_state(es: EasyState) -> Result<mobile::State> {
    let mut s: mobile::State = BTreeMap::new();
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
    pub fn new(ret: mobile::RunReturn, state: Vec<u8>) -> Result<Self> {
        let bytes_opt = if ret.topic == topics::VLS_RES {
            ret.vls_bytes
        } else {
            ret.lss_bytes
        };
        let bytes = bytes_opt.ok_or(SphinxError::BadState {
            r: format!("missing bytes"),
        })?;
        Ok(Self {
            topic: ret.topic,
            bytes: bytes,
            sequence: ret.sequence,
            cmd: ret.cmd,
            velocity: ret.velocity,
            state,
        })
    }
}

pub fn run_init_1_og(
    args_string: String,
    state_mp: Vec<u8>,
    msg1: Vec<u8>,
) -> Result<mobile::RunReturn> {
    let args = args_from_json(&args_string)?;
    let state = state_from_mp(&state_mp)?;
    let ret = mobile::run_init_1(args, state, &msg1).map_err(|e| SphinxError::InitFailed {
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
    let ret =
        mobile::run_init_2(args, state, &msg1, &msg2).map_err(|e| SphinxError::InitFailed {
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
    let ret = mobile::run_vls(args, state, &msg1, &msg2, &vls_msg, sequence);
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
    let ret = mobile::run_lss(args, state, &msg1, &msg2, &lss_msg, &prev_vls, &prev_lss).map_err(
        |e| SphinxError::LssFailed {
            r: format!("{:?}", e),
        },
    )?;
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
