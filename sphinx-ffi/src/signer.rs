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
    pub state: Vec<u8>,
}

pub const MSG_1: &str = "MSG_1";
pub const MSG_2: &str = "MSG_2";
pub const MSG_3: &str = "MSG_3";
pub const PREV_VLS: &str = "PREV_VLS";
pub const PREV_LSS: &str = "PREV_LSS";
pub const VELOCITY: &str = "VELOCITY";

pub fn run(
    topic: String,
    args_json: String,
    easy_mp: Vec<u8>,
    msg: Vec<u8>,
    sequence: Option<u16>,
) -> Result<VlsResponse> {
    let last = topic.split("/").last().unwrap_or("");
    match last {
        topics::INIT_1_MSG => Ok(run_init_1(args_json, easy_mp, msg, sequence)?),
        topics::INIT_2_MSG => Ok(run_init_2(args_json, easy_mp, msg, sequence)?),
        topics::INIT_3_MSG => Ok(run_init_3(args_json, easy_mp, msg, sequence)?),
        topics::VLS => Ok(run_vls(args_json, easy_mp, msg, sequence)?),
        topics::LSS_MSG => Ok(run_lss(args_json, easy_mp, msg, sequence)?),
        _ => Err(SphinxError::BadTopic {
            r: format!("{:?}", topic),
        }),
    }
}

fn run_init_1(
    args_json: String,
    easy_mp: Vec<u8>,
    msg1: Vec<u8>,
    _sequence: Option<u16>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_json)?;
    let mut easy = easy_from_mp(&easy_mp)?;
    pull_unchecked(
        &mut easy,
        &[MSG_1, MSG_2, MSG_3, PREV_VLS, PREV_LSS, VELOCITY],
    );
    let state = state_from_easy(easy)?;
    let ret =
        mobile::run_init_1(args, state, &msg1, None).map_err(|e| SphinxError::InitFailed {
            r: format!("{:?}", e),
        })?;
    let mut extras = BTreeMap::new();
    extras.insert(MSG_1.to_string(), msg1);
    let muts = ser_state(&None, extras)?;
    Ok(VlsResponse::new(ret.0, muts)?)
}

fn run_init_2(
    args_json: String,
    easy_mp: Vec<u8>,
    msg2: Vec<u8>,
    _sequence: Option<u16>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_json)?;
    let mut easy = easy_from_mp(&easy_mp)?;
    let msg1 = pull_from(&mut easy, MSG_1)?;
    pull_unchecked(&mut easy, &[MSG_2, MSG_3, PREV_VLS, PREV_LSS, VELOCITY]);
    let state = state_from_easy(easy)?;
    let ret = mobile::run_init_2(args, state, &msg1, &msg2, None).map_err(|e| {
        SphinxError::InitFailed {
            r: format!("{:?}", e),
        }
    })?;
    let mut extras = BTreeMap::new();
    extras.insert(MSG_2.to_string(), msg2);
    let muts = ser_state(&ret.0.lss_bytes, extras)?;
    Ok(VlsResponse::new(ret.0, muts)?)
}

fn run_init_3(
    args_json: String,
    easy_mp: Vec<u8>,
    msg3: Vec<u8>,
    _sequence: Option<u16>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_json)?;
    let mut easy = easy_from_mp(&easy_mp)?;
    let msg1 = pull_from(&mut easy, MSG_1)?;
    let msg2 = pull_from(&mut easy, MSG_2)?;
    pull_unchecked(&mut easy, &[MSG_3, PREV_VLS, PREV_LSS, VELOCITY]);
    let state = state_from_easy(easy)?;
    let ret = mobile::run_init_3(args, state, &msg1, &msg2, &msg3, None).map_err(|e| {
        SphinxError::InitFailed {
            r: format!("{:?}", e),
        }
    })?;
    let mut extras = BTreeMap::new();
    extras.insert(MSG_3.to_string(), msg3);
    let muts = ser_state(&ret.0.lss_bytes, extras)?;
    Ok(VlsResponse::new(ret.0, muts)?)
}

fn run_vls(
    args_json: String,
    easy_mp: Vec<u8>,
    vls_msg: Vec<u8>,
    sequence: Option<u16>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_json)?;
    let mut easy = easy_from_mp(&easy_mp)?;
    let msg1 = pull_from(&mut easy, MSG_1)?;
    let msg2 = pull_from(&mut easy, MSG_2)?;
    let msg3 = pull_from(&mut easy, MSG_3)?;
    pull_unchecked(&mut easy, &[PREV_VLS, PREV_LSS]);
    let vel = pull_from(&mut easy, VELOCITY).ok();
    let velocity = vel_from_mp(vel)?;
    let state = state_from_easy(easy)?;
    let ran = mobile::run_vls(
        args, state, &msg1, &msg2, &msg3, &vls_msg, sequence, velocity,
    );
    let ret = ran.map_err(|e| SphinxError::VlsFailed {
        r: format!("{:?}", e),
    })?;
    let mut extras = BTreeMap::new();
    let vlsb = ret.vls_bytes.clone().unwrap_or(Vec::new());
    extras.insert(PREV_VLS.to_string(), vlsb);
    let lssb = match ret.server_hmac {
        Some(bs) => bs.to_vec(),
        None => Vec::new(),
    };
    extras.insert(PREV_LSS.to_string(), lssb);
    if let Some(vel) = ser_velocity(&ret.velocity)? {
        extras.insert(VELOCITY.to_string(), vel);
    }
    let muts = ser_state(&ret.lss_bytes, extras)?;
    Ok(VlsResponse::new(ret, muts)?)
}

fn run_lss(
    args_json: String,
    easy_mp: Vec<u8>,
    lss_msg: Vec<u8>,
    _sequence: Option<u16>,
) -> Result<VlsResponse> {
    let args = args_from_json(&args_json)?;
    let mut easy = easy_from_mp(&easy_mp)?;
    let msg1 = pull_from(&mut easy, MSG_1)?;
    let msg2 = pull_from(&mut easy, MSG_2)?;
    let prev_vls = pull_from(&mut easy, PREV_VLS)?;
    let prev_lss = pull_from(&mut easy, PREV_LSS)?;
    pull_unchecked(&mut easy, &[VELOCITY]);
    let state = state_from_easy(easy)?;
    let ret = mobile::run_lss(args, state, &msg1, &msg2, &lss_msg, &prev_vls, &prev_lss).map_err(
        |e| SphinxError::LssFailed {
            r: format!("{:?}", e),
        },
    )?;
    let muts = ser_state(&ret.lss_bytes, BTreeMap::new())?;
    Ok(VlsResponse::new(ret, muts)?)
}

fn pull_unchecked(easy: &mut EasyState, keys: &[&str]) {
    for k in keys {
        let _ = pull_from(easy, k);
    }
}

fn pull_from(easy: &mut EasyState, key: &str) -> Result<Vec<u8>> {
    let msg = easy.remove(key).ok_or(SphinxError::BadState {
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

fn easy_from_mp(state_mp: &[u8]) -> Result<EasyState> {
    let es: EasyState =
        rmp_utils::deserialize_simple_state_map(state_mp).map_err(|e| SphinxError::BadState {
            r: format!("{:?}", e),
        })?;
    Ok(es)
}

fn state_from_easy(es: EasyState) -> Result<mobile::State> {
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

fn ser_velocity(velocity: &Option<(u64, Vec<u64>)>) -> Result<Option<Vec<u8>>> {
    Ok(match velocity {
        Some(v) => Some(
            rmp_utils::serialize_velocity(v).map_err(|e| SphinxError::BadState {
                r: format!("bad velocity {:?}", e),
            })?,
        ),
        None => None,
    })
}

impl VlsResponse {
    fn new(ret: mobile::RunReturn, state: Vec<u8>) -> Result<Self> {
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
            state,
        })
    }
}

fn _run_init_1_manual(
    args_string: String,
    state_mp: Vec<u8>,
    msg1: Vec<u8>,
    vel: Option<Vec<u8>>,
) -> Result<mobile::RunReturn> {
    let args = args_from_json(&args_string)?;
    let state = _state_from_mp(&state_mp)?;
    let velocity = vel_from_mp(vel)?;
    let ret =
        mobile::run_init_1(args, state, &msg1, velocity).map_err(|e| SphinxError::InitFailed {
            r: format!("{:?}", e),
        })?;
    Ok(ret.0)
}

fn _run_init_2_manual(
    args_string: String,
    state_mp: Vec<u8>,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    vel: Option<Vec<u8>>,
) -> Result<mobile::RunReturn> {
    let args = args_from_json(&args_string)?;
    let state = _state_from_mp(&state_mp)?;
    let velocity = vel_from_mp(vel)?;
    let ret = mobile::run_init_2(args, state, &msg1, &msg2, velocity).map_err(|e| {
        SphinxError::InitFailed {
            r: format!("{:?}", e),
        }
    })?;
    Ok(ret.0)
}

fn _run_vls_manual(
    args_string: String,
    state_mp: Vec<u8>,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    msg3: Vec<u8>,
    vls_msg: Vec<u8>,
    sequence: Option<u16>,
    vel: Option<Vec<u8>>,
) -> Result<mobile::RunReturn> {
    let args = args_from_json(&args_string)?;
    let state = _state_from_mp(&state_mp)?;
    let velocity = vel_from_mp(vel)?;
    let ret = mobile::run_vls(
        args, state, &msg1, &msg2, &msg3, &vls_msg, sequence, velocity,
    );
    Ok(ret.map_err(|e| SphinxError::VlsFailed {
        r: format!("{:?}", e),
    })?)
}

fn _run_lss_manual(
    args_string: String,
    state_mp: Vec<u8>,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    lss_msg: Vec<u8>,
    prev_vls: Vec<u8>,
    prev_lss: Vec<u8>,
) -> Result<mobile::RunReturn> {
    let args = args_from_json(&args_string)?;
    let state = _state_from_mp(&state_mp)?;
    let ret = mobile::run_lss(args, state, &msg1, &msg2, &lss_msg, &prev_vls, &prev_lss).map_err(
        |e| SphinxError::LssFailed {
            r: format!("{:?}", e),
        },
    )?;
    Ok(ret)
}

fn _state_from_mp(state_mp: &[u8]) -> Result<mobile::State> {
    let state: mobile::State =
        rmp_utils::deserialize_state_map(state_mp).map_err(|e| SphinxError::BadState {
            r: format!("{:?}", e),
        })?;
    Ok(state)
}
fn vel_from_mp(vel_mp: Option<Vec<u8>>) -> Result<Option<(u64, Vec<u64>)>> {
    Ok(match vel_mp {
        Some(v) => {
            let vs = rmp_utils::deserialize_velocity(&v).map_err(|e| SphinxError::BadVelocity {
                r: format!("{:?}", e),
            })?;
            Some(vs)
        }
        None => None,
    })
}
fn args_from_json(args_string: &str) -> Result<mobile::Args> {
    let args: mobile::Args =
        serde_json::from_str(args_string).map_err(|e| SphinxError::BadArgs {
            r: format!("{:?}", e),
        })?;
    Ok(args)
}
