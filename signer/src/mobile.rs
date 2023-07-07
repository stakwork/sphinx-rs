use crate::persist::ThreadMemoPersister;
use crate::root::{builder_inner, handle_with_lss};
use anyhow::Result;
use lightning_signer::bitcoin::Network;
use lightning_signer::prelude::SendSync;
use lightning_signer::signer::StartingTimeFactory;
use lightning_signer::util::clock::Clock;
use lss_connector::secp256k1::PublicKey;
use lss_connector::{handle_lss_msg, LssSigner, Msg};
use serde::{Deserialize, Serialize};
use sphinx_glyph::topics;
use sphinx_glyph::types::{Policy, Velocity};
use std::sync::Arc;
use std::time::Duration;
use vls_protocol_signer::handler::{RootHandler, RootHandlerBuilder};
use vls_protocol_signer::lightning_signer;

// fully create a VLS node run the command on it
// returning muts to be stored in phone persistence
// 1. get initial lss init_1 message:
//     - store it on phone
//     - run_init_1(args, msg1)
//     - return lss_bytes
// 2. get further lss init_2 message:
//     - store it on phone
//     - run_init_2(args, msg1, msg2)
//     - return lss_bytes
// 3. get VLS msg:
//     - run_vls(args, msg1, msg2, vls_msg)
//     - if topic==LSS_RES store result on phone (both bytes), and return lss_bytes
//     - else return vls_bytes
// 4. get LSS msg:
//     - run_lss(args, msg1, msg2, lss_msg, prev_vls, prev_lss)

#[derive(Serialize, Deserialize, Debug)]
pub struct Args {
    seed: [u8; 32],
    network: Network,
    policy: Policy,
    velocity: Option<Velocity>,
    allowlist: Vec<String>,
    timestamp: Duration,
}
pub struct RunReturn {
    pub topic: String,
    pub vls_bytes: Option<Vec<u8>>,
    pub lss_bytes: Option<Vec<u8>>,
}

pub fn run_init_1(
    args: Args,
    lss_msg1: Vec<u8>,
) -> Result<(RunReturn, RootHandlerBuilder, LssSigner)> {
    let init = Msg::from_slice(&lss_msg1)?.as_init()?;
    let server_pubkey = PublicKey::from_slice(&init.server_pubkey)?;

    let rhb = root_handler_builder(args)?;
    let (lss_signer, res1) = LssSigner::new(&rhb, &server_pubkey);
    Ok((
        RunReturn::new_lss(topics::INIT_1_RES, res1),
        rhb,
        lss_signer,
    ))
}

pub fn run_init_2(
    args: Args,
    lss_msg1: Vec<u8>,
    lss_msg2: Vec<u8>,
) -> Result<(RunReturn, RootHandler, LssSigner)> {
    let (_res1, rhb, lss_signer) = run_init_1(args, lss_msg1)?;
    let created = Msg::from_slice(&lss_msg2)?.as_created()?;
    let (root_handler, res2) = lss_signer.build_with_lss(created, rhb)?;
    Ok((
        RunReturn::new_lss(topics::INIT_2_RES, res2),
        root_handler,
        lss_signer,
    ))
}

pub fn run_vls(
    args: Args,
    lss_msg1: Vec<u8>,
    lss_msg2: Vec<u8>,
    vls_msg: Vec<u8>,
) -> Result<RunReturn> {
    let (_res, rh, lss_signer) = run_init_2(args, lss_msg1, lss_msg2)?;

    let (vls_res, lss_res) = handle_with_lss(&rh, &lss_signer, vls_msg, false)?;
    let ret = if lss_res.is_empty() {
        RunReturn::new_vls(topics::VLS_RES, vls_res)
    } else {
        RunReturn::new(topics::LSS_RES, vls_res, lss_res)
    };
    Ok(ret)
}

pub fn run_lss(
    args: Args,
    lss_msg1: Vec<u8>,
    lss_msg2: Vec<u8>,
    lss_msg: Vec<u8>,
    previous_vls: Vec<u8>,
    previous_lss: Vec<u8>,
) -> Result<RunReturn> {
    let (_res, _rh, lss_signer) = run_init_2(args, lss_msg1, lss_msg2)?;

    let prev = (previous_vls, previous_lss);
    let (topic, res) = handle_lss_msg(&lss_msg, &Some(prev), &lss_signer)?;
    let ret = if &topic == topics::VLS_RES {
        RunReturn::new_vls(&topic, res)
    } else {
        RunReturn::new_lss(&topic, res)
    };
    Ok(ret)
}

fn root_handler_builder(args: Args) -> Result<RootHandlerBuilder> {
    let persister = Arc::new(ThreadMemoPersister {});
    // FIXME load up persister with all state
    let clock = Arc::new(NowClock::new(args.timestamp));
    let stf = Arc::new(NowStartingTimeFactory::new(args.timestamp));
    let (rhb, _approver) = builder_inner(
        args.seed,
        args.network,
        args.policy,
        args.velocity,
        args.allowlist,
        persister,
        clock,
        stf,
    )?;
    Ok(rhb)
}

impl RunReturn {
    pub fn new(topic: &str, vls_bytes: Vec<u8>, lss_bytes: Vec<u8>) -> Self {
        Self {
            topic: topic.to_string(),
            vls_bytes: Some(vls_bytes),
            lss_bytes: Some(lss_bytes),
        }
    }
    pub fn new_vls(topic: &str, vls_bytes: Vec<u8>) -> Self {
        Self {
            topic: topic.to_string(),
            vls_bytes: Some(vls_bytes),
            lss_bytes: None,
        }
    }
    pub fn new_lss(topic: &str, lss_bytes: Vec<u8>) -> Self {
        Self {
            topic: topic.to_string(),
            vls_bytes: None,
            lss_bytes: Some(lss_bytes),
        }
    }
}

pub struct NowClock(Duration);

impl SendSync for NowClock {}

impl Clock for NowClock {
    fn now(&self) -> Duration {
        self.0
    }
}

impl NowClock {
    pub fn new(now: Duration) -> Self {
        NowClock(now)
    }
}

pub struct NowStartingTimeFactory(Duration);

impl SendSync for NowStartingTimeFactory {}

impl StartingTimeFactory for NowStartingTimeFactory {
    fn starting_time(&self) -> (u64, u32) {
        let now = self.0;
        (now.as_secs(), now.subsec_nanos())
    }
}

impl NowStartingTimeFactory {
    pub fn new(d: Duration) -> NowStartingTimeFactory {
        NowStartingTimeFactory(d)
    }
}
