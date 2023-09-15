use crate::approver::SphinxApprover;
use crate::root::{builder_inner, handle_with_lss};
use anyhow::{Error, Result};
use lightning_signer::bitcoin::Network;
use lightning_signer::persist::{Mutations, Persist};
use lightning_signer::prelude::SendSync;
use lightning_signer::signer::StartingTimeFactory;
use lightning_signer::util::clock::Clock;
use lightning_signer::Arc;
use lss_connector::secp256k1::PublicKey;
use lss_connector::{handle_lss_msg, LssSigner, Msg};
use serde::{Deserialize, Serialize};
use sphinx_glyph::topics;
use sphinx_glyph::types::{Policy, Velocity};
use std::collections::BTreeMap;
use std::time::Duration;
use vls_persist::kvv::cloud::CloudKVVStore;
pub use vls_persist::kvv::memory::MemoryKVVStore;
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
//     - persist on phone!
// 3. get VLS msg:
//     - run_vls(args, msg1, msg2, vls_msg)
//     - if topic==LSS_RES store result on phone (both bytes), and return lss_bytes
//     - else return vls_bytes
//     - persist mutations on phone!
// 4. get LSS msg:
//     - run_lss(args, msg1, msg2, lss_msg, prev_vls, prev_lss)

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Args {
    seed: [u8; 32],
    network: Network,
    policy: Policy,
    allowlist: Vec<String>,
    timestamp: u64, // number of seconds
    lss_nonce: [u8; 32],
    signer_id: [u8; 16],
}

pub type State = BTreeMap<String, (u64, Vec<u8>)>;

#[derive(Debug)]
pub struct RunReturn {
    pub topic: String,
    pub vls_bytes: Option<Vec<u8>>,
    pub lss_bytes: Option<Vec<u8>>,
    pub sequence: u16,
    pub cmd: String,
    pub velocity: Option<Velocity>,
}

pub fn run_init_1(
    args: Args,
    state: State,
    lss_msg1: &[u8],
    velocity: Option<Velocity>,
) -> Result<(
    RunReturn,
    RootHandlerBuilder,
    Arc<SphinxApprover>,
    LssSigner,
)> {
    let init = Msg::from_slice(lss_msg1)?.into_init()?;
    let server_pubkey = PublicKey::from_slice(&init.server_pubkey).map_err(Error::msg)?;
    let nonce = args.lss_nonce.clone();
    let (rhb, approver) = root_handler_builder(args, state, velocity)?;
    let (lss_signer, res1) = LssSigner::new(&rhb, &server_pubkey, Some(nonce));
    Ok((
        RunReturn::new_lss(topics::INIT_1_RES, res1, "LssInit".to_string()),
        rhb,
        approver,
        lss_signer,
    ))
}

pub fn run_init_2(
    args: Args,
    state: State,
    lss_msg1: &[u8],
    lss_msg2: &[u8],
    velocity: Option<Velocity>,
) -> Result<(RunReturn, RootHandler, Arc<SphinxApprover>, LssSigner)> {
    let (_res1, rhb, approver, lss_signer) = run_init_1(args, state.clone(), lss_msg1, velocity)?;
    let created = Msg::from_slice(&lss_msg2)?.into_created()?;
    let (root_handler, res2) = lss_signer.build_with_lss(created, rhb, Some(state))?;
    Ok((
        RunReturn::new_lss(topics::INIT_2_RES, res2, "LssCreated".to_string()),
        root_handler,
        approver,
        lss_signer,
    ))
}

pub fn run_vls(
    args: Args,
    state: State,
    lss_msg1: &[u8],
    lss_msg2: &[u8],
    vls_msg: &[u8],
    expected_sequence: Option<u16>,
    velocity: Option<Velocity>,
) -> Result<RunReturn> {
    let (_res, rh, approver, lss_signer) = run_init_2(args, state, lss_msg1, lss_msg2, velocity)?;
    let s1 = approver.control().get_state();
    let (vls_res, lss_res, sequence, cmd) =
        handle_with_lss(&rh, &lss_signer, vls_msg.to_vec(), expected_sequence, true)
            .map_err(Error::msg)?;
    let mut ret = if lss_res.is_empty() {
        RunReturn::new_vls(topics::VLS_RES, vls_res, sequence, cmd)
    } else {
        RunReturn::new(topics::LSS_RES, vls_res, lss_res, sequence, cmd)
    };
    let s2 = approver.control().get_state();
    if s1 != s2 {
        ret.set_velocity(s2);
    }
    // rh.commit();
    Ok(ret)
}

pub fn run_lss(
    args: Args,
    state: State,
    lss_msg1: &[u8],
    lss_msg2: &[u8],
    lss_msg: &[u8],
    previous_vls: &[u8],
    previous_lss: &[u8],
) -> Result<RunReturn> {
    let (_res, _rh, _approver, lss_signer) = run_init_2(args, state, lss_msg1, lss_msg2, None)?;

    let prev = (previous_vls.to_vec(), previous_lss.to_vec());
    let (topic, res) = handle_lss_msg(&lss_msg, Some(prev), &lss_signer)?;
    let ret = if &topic == topics::VLS_RES {
        RunReturn::new_vls(&topic, res, u16::default(), "VLS".to_string())
    } else {
        RunReturn::new_lss(&topic, res, "LssStore".to_string())
    };
    Ok(ret)
}

fn root_handler_builder(
    args: Args,
    state: State,
    velocity: Option<Velocity>,
) -> Result<(RootHandlerBuilder, Arc<SphinxApprover>)> {
    use std::time::UNIX_EPOCH;

    let memstore = MemoryKVVStore::new(args.signer_id).0;
    let persister = CloudKVVStore::new(memstore);

    let muts: Vec<_> = state
        .iter()
        .map(|(k, (v, vv))| (k.clone(), (*v, vv.clone())))
        .collect();
    persister
        .put_batch_unlogged(Mutations::from_vec(muts))
        .map_err(|_| anyhow::anyhow!("could not hydrate MemoryKVVStore"))?;

    let st = UNIX_EPOCH + Duration::from_secs(args.timestamp);
    let d = st.duration_since(UNIX_EPOCH).unwrap();

    let persister = Arc::new(persister);
    let clock = Arc::new(NowClock::new(d));
    let stf = Arc::new(NowStartingTimeFactory::new(d));
    let (rhb, approver) = builder_inner(
        args.seed,
        args.network,
        args.policy,
        args.allowlist,
        velocity,
        persister,
        clock,
        stf,
    )?;
    // let muts = tmp.prepare();
    // if !muts.is_empty() {
    //     log::info!("root_handler_builder MUTS: {:?}", muts);
    // }
    Ok((rhb, approver))
}

impl RunReturn {
    pub fn new(
        topic: &str,
        vls_bytes: Vec<u8>,
        lss_bytes: Vec<u8>,
        sequence: u16,
        cmd: String,
    ) -> Self {
        Self {
            topic: topic.to_string(),
            vls_bytes: Some(vls_bytes),
            lss_bytes: Some(lss_bytes),
            sequence,
            cmd,
            velocity: None,
        }
    }
    pub fn new_vls(topic: &str, vls_bytes: Vec<u8>, sequence: u16, cmd: String) -> Self {
        Self {
            topic: topic.to_string(),
            vls_bytes: Some(vls_bytes),
            lss_bytes: None,
            sequence,
            cmd,
            velocity: None,
        }
    }
    pub fn new_lss(topic: &str, lss_bytes: Vec<u8>, cmd: String) -> Self {
        Self {
            topic: topic.to_string(),
            vls_bytes: None,
            lss_bytes: Some(lss_bytes),
            sequence: u16::default(),
            cmd,
            velocity: None,
        }
    }
    pub fn set_velocity(&mut self, velocity: Velocity) {
        self.velocity = Some(velocity);
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

// contacts and chats stored in LSS (encrypted?)
// one giant LDK multitenant lightning node?
// can we get VLS to not reveal TLVs to node?
// a "lite" sphinx user keeps their key/contacts/chats themselves
// LSP cant receive without them online - and cant impersonate
#[cfg(test)]
mod tests {
    use super::*;

    // cargo test test_msg -- --nocapture
    #[test]
    fn test_msg() {
        use vls_protocol::msgs::{self, read_serial_request_header, Message};
        use vls_protocol_signer::lightning_signer::io::Cursor;
        #[rustfmt::skip]
        // let m = vec![170, 85, 0, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 80, 0, 8, 5, 70, 1, 18, 14, 13, 8, 26, 4, 16, 1, 20, 27, 8, 12, 12, 20, 20, 15, 3, 4, 16, 5, 24, 15, 15, 2, 5, 19, 28, 6, 20, 27, 29, 23, 22, 8, 16, 11, 7, 3, 2, 16, 25, 13, 0, 0, 5, 5, 11, 27, 27, 13, 19, 3, 8, 2, 28, 22, 12, 10, 8, 12, 0, 1, 1, 20, 15, 28, 31, 14, 8, 28, 11, 30, 6, 25, 28, 13, 11, 18, 4, 1, 30, 28, 14, 29, 8, 0, 13, 19, 24, 26, 7, 27, 21, 13, 0, 26, 11, 3, 0, 19, 3, 18, 2, 5, 5, 31, 21, 17, 31, 3, 12, 20, 15, 0, 10, 25, 0, 13, 3, 5, 13, 13, 18, 23, 18, 28, 27, 5, 13, 25, 18, 3, 20, 8, 3, 27, 4, 9, 26, 7, 18, 28, 3, 5, 4, 8, 29, 3, 2, 12, 1, 12, 4, 9, 25, 22, 10, 27, 19, 4, 12, 21, 25, 2, 4, 14, 19, 27, 4, 9, 24, 7, 10, 24, 18, 31, 13, 13, 18, 23, 18, 8, 17, 26, 4, 8, 24, 3, 4, 25, 9, 18, 12, 8, 26, 6, 2, 13, 25, 24, 6, 12, 27, 3, 10, 13, 25, 20, 12, 20, 28, 19, 10, 12, 1, 20, 12, 20, 28, 3, 12, 12, 9, 19, 6, 5, 18, 6, 8, 24, 17, 21, 6, 25, 19, 3, 2, 12, 1, 21, 12, 25, 18, 22, 4, 24, 9, 17, 12, 21, 17, 6, 10, 25, 17, 18, 6, 4, 26, 19, 2, 13, 17, 24, 6, 17, 17, 22, 6, 25, 19, 2, 12, 5, 17, 6, 12, 12, 1, 17, 6, 4, 26, 6, 2, 12, 11, 3, 6, 28, 27, 18, 4, 11, 1, 2, 14, 9, 23, 23, 10, 29, 3, 5, 11, 29, 20, 6, 18, 27, 19, 20, 4, 8, 29, 2, 4, 12, 1, 18, 6, 28, 25, 19, 12, 25, 9, 23, 12, 17, 16, 22, 8, 14, 1, 19, 12, 16, 27, 19, 4, 12, 1, 21, 7, 0, 25, 3, 12, 13, 17, 20, 7, 5, 19, 6, 6, 12, 9, 23, 12, 17, 17, 3, 12, 13, 25, 18, 12, 13, 18, 19, 0, 14, 3, 6, 7, 1, 18, 19, 16, 13, 27, 1, 6, 9, 17, 3, 8, 13, 27, 3, 6, 28, 27, 19, 16, 13, 11, 3, 12, 13, 17, 6, 12, 13, 25, 25, 12, 24, 25, 3, 8, 25, 9, 25, 6, 5, 18, 6, 4, 12, 1, 26, 6, 4, 24, 3, 18, 14, 9, 21, 6, 12, 28, 19, 12, 13, 25, 23, 6, 4, 28, 3, 10, 8, 17, 12, 4, 9, 17, 22, 30, 27, 19, 20, 12, 5, 17, 23, 8, 23, 27, 11, 12, 21, 28, 18, 4, 14, 17, 2, 9, 21, 4, 20, 18, 16, 18, 3, 12, 29, 5, 20, 6, 16, 10, 17, 8, 21, 0, 23, 4, 13, 19, 14, 8, 16, 26, 19, 6, 27, 27, 17, 8, 16, 24, 18, 30, 29, 27, 17, 6, 13, 3, 20, 10, 16, 17, 20, 8, 4, 24, 6, 14, 27, 19, 12, 9, 9, 0, 22, 24, 20, 27, 11, 13, 1, 24, 7, 18, 21, 19, 8, 11, 8, 27, 22, 16, 26, 11, 21, 9, 13, 21, 22, 2, 29, 27, 10, 14, 4, 21, 19, 10, 19, 11, 4, 9, 25, 10, 23, 2, 12, 11, 10, 7, 1, 23, 3, 18, 27, 19, 19, 13, 29, 7, 21, 20, 17, 27, 17, 14, 25, 10, 20, 14, 25, 11, 4, 9, 5, 23, 20, 24, 26, 10, 20, 6, 17, 23, 21, 20, 16, 18, 16, 10, 17, 3, 5, 16, 18, 18, 4, 10, 12, 27, 5, 16, 14, 9, 15, 6, 5, 20, 21, 0, 17, 2, 16, 10, 21, 8, 3, 18, 19, 27, 6, 10, 17, 23, 20, 16, 28, 27, 6, 6, 9, 27, 4, 20, 20, 26, 22, 8, 9, 2, 4, 28, 21, 10, 26, 9, 5, 27, 18, 22, 26, 19, 23, 8, 9, 11, 22, 26, 17, 3, 9, 8, 12, 21, 22, 28, 18, 2, 4, 14, 1, 9, 4, 26, 22, 10, 9, 11, 9, 2, 21, 6, 28, 3, 10, 6, 25, 22, 6, 2, 28, 2, 13, 10, 25, 25, 20, 10, 25, 3, 6, 5, 12, 24, 20, 14, 18, 19, 24, 5, 29, 18, 3, 8, 13, 19, 20, 10, 13, 9, 21, 10, 26, 9, 25, 12, 21, 5, 3, 18, 17, 2, 4, 10, 13, 18, 20, 30, 24, 11, 1, 6, 17, 2, 4, 6, 20, 19, 20, 8, 21, 17, 3, 14, 13, 3, 15, 8, 13, 20, 23, 4, 30, 10, 16, 6, 8, 26, 20, 22, 21, 10, 26, 6, 12, 28, 21, 20, 20, 19, 14, 11, 9, 21, 7, 4, 29, 1, 25, 9, 29, 12, 7, 2, 17, 27, 11, 9, 5, 11, 23, 6, 28, 18, 3, 9, 8, 27, 6, 24, 24, 26, 7, 8, 21, 4, 23, 12, 14, 10, 15, 9, 9, 12, 22, 12, 16, 25, 11, 10, 29, 1, 20, 20, 18, 2, 19, 13, 21, 4, 4, 30, 10, 26, 8, 9, 21, 0, 20, 30, 27, 19, 7, 9, 24, 28, 22, 2, 13, 18, 20, 14, 5, 3, 20, 20, 29, 1, 15, 1, 3, 13, 4, 20, 4, 18, 18, 14, 14, 1, 10, 3, 10, 21, 18, 3, 9, 21, 10, 5, 20, 29, 10, 10, 14, 17, 10, 22, 10, 14, 2, 17, 5, 13, 18, 21, 8, 30, 19, 14, 15, 1, 4, 7, 6, 26, 19, 19, 9, 25, 6, 4, 16, 20, 17, 15, 9, 5, 17, 7, 10, 13, 11, 9, 8, 20, 26, 6, 22, 26, 11, 5, 10, 17, 22, 3, 14, 29, 27, 8, 9, 9, 8, 7, 0, 25, 17, 24, 13, 17, 11, 23, 4, 20, 19, 22, 6, 29, 17, 22, 22, 11, 25, 11, 10, 17, 4, 23, 6, 19, 26, 20, 9, 16, 23, 22, 22, 13, 26, 13, 14, 29, 20, 20, 6, 20, 17, 17, 13, 12, 28, 23, 2, 21, 11, 26, 12, 13, 11, 21, 4, 20, 10, 9, 8, 17, 0, 21, 2, 16, 10, 2, 4, 8, 2, 2, 2, 4, 24, 11, 12, 13, 5, 16, 23, 6, 8, 17, 26, 4, 9, 5, 7, 10, 27, 3, 5, 14, 12, 17, 7, 26, 31, 11, 4, 6, 29, 17, 19, 8, 28, 27, 9, 6, 28, 27, 19, 14, 13, 3, 21, 14, 21, 24, 23, 16, 28, 3, 23, 13, 25, 29, 6, 8, 13, 27, 9, 14, 9, 25, 22, 14, 14, 9, 19, 12, 17, 29, 7, 20, 26, 11, 17, 13, 20, 24, 23, 4, 26, 3, 3, 7, 5, 28, 7, 14, 24, 11, 3, 6, 5, 19, 22, 14, 25, 3, 26, 14, 21, 26, 22, 14, 12, 11, 17, 14, 21, 24, 22, 18, 14, 9, 21, 14, 17, 27, 19, 12, 25, 17, 25, 13, 0, 27, 3, 12, 25, 11, 10, 7, 1, 16, 22, 22, 14, 9, 22, 14, 9, 25, 22, 22, 13, 19, 20, 14, 21, 28, 2, 2, 12, 12, 11, 26, 15, 4, 28, 22, 6, 25, 19, 21, 13, 1, 25, 22, 18, 30, 3, 25, 14, 13, 23, 22, 8, 13, 11, 23, 12, 25, 28, 23, 2, 25, 27, 5, 6, 29, 29, 3, 8, 6, 0, 4, 18, 14, 20, 0, 24, 0, 1, 18, 3, 2, 18, 0, 8, 30, 23, 1, 28, 23, 23, 13, 20, 20, 3, 24, 27, 2, 14, 11, 0, 8, 9, 29, 24, 29, 2, 16, 5, 23, 11, 19, 22, 7, 30, 22, 16, 5, 18, 7, 21, 17, 4, 13, 4, 3, 0, 20, 10, 25, 8, 1, 2, 30, 27, 23, 30, 3, 2, 6, 27, 16, 0, 0, 4, 6, 24, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 14, 0, 0, 10, 0, 5, 0, 6, 1, 0, 4, 16, 8, 0, 0, 4, 108, 110, 98, 99];
        // let m = vec![170, 85, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 138, 0, 8, 6, 128, 1, 18, 14, 12, 14, 14, 13, 16, 1, 20, 22, 24, 15, 27, 7, 7, 23, 25, 7, 5, 25, 27, 12, 11, 15, 20, 2, 22, 24, 28, 26, 27, 24, 11, 18, 2, 31, 31, 30, 16, 27, 0, 0, 29, 12, 17, 25, 11, 14, 12, 21, 17, 17, 1, 11, 31, 0, 13, 25, 1, 7, 16, 1, 1, 20, 9, 20, 1, 8, 7, 2, 20, 11, 0, 9, 4, 3, 20, 22, 9, 10, 9, 8, 15, 16, 28, 0, 3, 6, 19, 16, 25, 20, 8, 3, 15, 22, 24, 9, 20, 15, 13, 31, 24, 4, 16, 29, 3, 6, 23, 23, 4, 31, 26, 4, 27, 16, 13, 15, 20, 13, 13, 18, 23, 18, 28, 27, 5, 13, 25, 18, 3, 20, 8, 3, 27, 4, 9, 26, 7, 18, 28, 3, 5, 4, 8, 29, 3, 0, 11, 1, 2, 12, 13, 20, 6, 2, 29, 1, 2, 7, 9, 29, 18, 4, 29, 11, 21, 13, 5, 18, 2, 4, 14, 17, 2, 5, 25, 13, 4, 30, 21, 18, 22, 10, 29, 1, 3, 18, 25, 11, 24, 15, 1, 12, 20, 16, 17, 19, 1, 12, 20, 28, 6, 14, 18, 19, 10, 8, 17, 2, 5, 0, 16, 17, 13, 6, 29, 22, 4, 18, 28, 26, 2, 13, 25, 7, 6, 8, 12, 17, 18, 12, 17, 6, 23, 16, 13, 25, 22, 11, 1, 21, 7, 16, 28, 27, 7, 14, 1, 12, 3, 8, 30, 2, 16, 13, 17, 21, 7, 12, 29, 3, 6, 11, 1, 27, 22, 16, 12, 19, 3, 13, 8, 27, 4, 24, 21, 3, 3, 9, 25, 12, 20, 8, 18, 27, 9, 13, 25, 19, 21, 8, 26, 9, 13, 11, 1, 11, 23, 10, 16, 26, 3, 9, 21, 9, 5, 8, 12, 3, 11, 13, 25, 12, 23, 2, 20, 10, 10, 14, 13, 25, 20, 8, 8, 17, 12, 4, 9, 23, 6, 2, 27, 11, 5, 4, 8, 29, 2, 4, 16, 27, 1, 14, 9, 23, 6, 18, 29, 19, 15, 14, 9, 18, 18, 30, 8, 2, 11, 12, 21, 26, 6, 30, 8, 1, 2, 5, 16, 17, 7, 8, 30, 11, 16, 12, 20, 17, 3, 20, 12, 19, 29, 5, 16, 17, 6, 26, 25, 11, 19, 14, 13, 16, 22, 14, 25, 9, 2, 7, 9, 29, 18, 4, 26, 11, 4, 4, 8, 29, 3, 6, 13, 25, 22, 6, 16, 24, 19, 2, 11, 1, 2, 14, 21, 26, 22, 18, 25, 1, 2, 7, 8, 17, 6, 14, 27, 27, 7, 11, 1, 9, 21, 14, 27, 18, 24, 14, 21, 0, 20, 20, 25, 19, 13, 7, 1, 7, 5, 2, 29, 27, 18, 14, 13, 2, 6, 30, 19, 17, 2, 5, 16, 17, 6, 6, 27, 27, 14, 14, 17, 18, 22, 28, 29, 1, 2, 7, 8, 17, 6, 12, 30, 3, 1, 11, 5, 18, 23, 2, 24, 27, 16, 10, 25, 21, 22, 14, 12, 26, 25, 10, 12, 28, 19, 8, 17, 18, 11, 6, 20, 27, 20, 8, 19, 17, 17, 10, 4, 28, 23, 20, 18, 27, 7, 8, 5, 19, 19, 4, 29, 3, 4, 8, 25, 26, 6, 18, 27, 10, 16, 7, 1, 6, 19, 12, 21, 17, 17, 9, 29, 22, 23, 8, 30, 18, 19, 8, 29, 11, 4, 28, 22, 2, 25, 13, 17, 6, 7, 6, 27, 18, 4, 9, 24, 21, 20, 10, 13, 2, 20, 12, 25, 26, 18, 22, 18, 26, 3, 14, 29, 4, 20, 28, 13, 18, 24, 6, 9, 3, 22, 14, 25, 18, 25, 8, 17, 23, 3, 6, 17, 3, 12, 13, 9, 13, 4, 14, 28, 26, 16, 13, 8, 26, 7, 16, 17, 9, 11, 8, 25, 20, 18, 22, 20, 18, 2, 9, 9, 6, 18, 22, 12, 27, 23, 13, 21, 18, 3, 14, 17, 11, 22, 10, 1, 18, 22, 18, 16, 26, 24, 9, 9, 17, 23, 8, 19, 1, 16, 10, 12, 24, 19, 18, 12, 11, 24, 11, 1, 11, 4, 6, 18, 11, 6, 7, 1, 26, 21, 10, 25, 19, 23, 5, 29, 26, 6, 10, 29, 1, 24, 15, 8, 24, 21, 10, 20, 10, 9, 9, 5, 7, 20, 18, 30, 11, 4, 10, 29, 11, 21, 12, 10, 26, 20, 14, 13, 17, 22, 4, 27, 2, 15, 12, 9, 8, 21, 4, 24, 26, 5, 5, 29, 25, 20, 30, 18, 3, 8, 12, 21, 24, 6, 28, 14, 10, 18, 8, 13, 24, 2, 30, 27, 17, 18, 15, 9, 13, 3, 8, 27, 26, 9, 13, 9, 22, 7, 12, 27, 27, 23, 6, 8, 27, 19, 18, 22, 9, 18, 11, 1, 18, 3, 4, 13, 19, 1, 8, 5, 5, 21, 10, 27, 10, 1, 6, 5, 20, 7, 12, 29, 2, 8, 13, 24, 25, 20, 4, 27, 26, 18, 6, 13, 2, 7, 6, 13, 19, 10, 10, 4, 28, 3, 12, 28, 19, 13, 15, 1, 11, 5, 14, 19, 10, 8, 6, 17, 11, 21, 8, 21, 1, 17, 14, 29, 12, 20, 6, 20, 10, 3, 9, 0, 24, 23, 8, 28, 3, 13, 15, 8, 24, 22, 22, 17, 26, 10, 14, 1, 1, 22, 24, 22, 3, 17, 5, 29, 6, 6, 6, 21, 11, 16, 13, 1, 4, 5, 18, 20, 2, 15, 14, 1, 23, 21, 16, 20, 27, 9, 14, 20, 24, 5, 2, 21, 11, 15, 13, 13, 10, 18, 30, 18, 10, 26, 14, 13, 17, 22, 28, 14, 3, 15, 6, 13, 6, 4, 28, 25, 27, 14, 14, 25, 29, 3, 2, 29, 27, 5, 6, 12, 21, 23, 12, 29, 26, 7, 13, 9, 18, 2, 30, 30, 10, 11, 9, 13, 23, 22, 18, 18, 17, 11, 14, 21, 27, 7, 10, 22, 9, 24, 12, 25, 8, 6, 20, 26, 11, 21, 8, 5, 23, 20, 4, 29, 19, 21, 12, 29, 25, 5, 16, 17, 26, 15, 9, 25, 9, 22, 28, 19, 2, 11, 13, 13, 1, 20, 26, 29, 3, 1, 11, 1, 23, 4, 28, 16, 9, 29, 7, 20, 17, 2, 24, 8, 19, 1, 13, 21, 23, 23, 10, 27, 19, 20, 4, 8, 29, 3, 2, 12, 3, 29, 5, 16, 17, 7, 6, 25, 11, 14, 12, 17, 18, 23, 4, 8, 17, 26, 15, 12, 17, 7, 0, 29, 11, 2, 11, 29, 21, 22, 10, 30, 9, 2, 7, 8, 17, 3, 0, 12, 27, 1, 7, 5, 16, 19, 16, 25, 1, 25, 6, 20, 25, 22, 12, 25, 9, 23, 6, 16, 27, 22, 8, 12, 3, 4, 12, 16, 28, 19, 8, 25, 3, 4, 6, 13, 17, 19, 10, 13, 17, 23, 12, 17, 18, 6, 6, 13, 9, 24, 6, 16, 26, 19, 2, 12, 9, 16, 6, 5, 18, 19, 18, 14, 1, 23, 12, 20, 25, 6, 8, 12, 19, 2, 12, 24, 27, 22, 2, 13, 3, 4, 6, 5, 18, 19, 2, 12, 3, 1, 6, 9, 17, 19, 16, 14, 11, 6, 12, 24, 25, 19, 16, 8, 17, 12, 4, 9, 24, 6, 10, 28, 19, 19, 13, 29, 23, 2, 4, 14, 17, 2, 14, 1, 18, 22, 30, 28, 3, 12, 12, 20, 23, 7, 6, 28, 3, 8, 13, 5, 23, 7, 16, 11, 19, 3, 13, 1, 16, 23, 8, 11, 27, 3, 12, 16, 28, 22, 8, 27, 9, 21, 14, 21, 16, 19, 10, 25, 19, 4, 14, 17, 25, 22, 20, 12, 19, 3, 6, 9, 22, 22, 16, 12, 1, 2, 5, 16, 17, 6, 2, 27, 3, 9, 12, 5, 25, 18, 4, 14, 17, 2, 10, 1, 16, 23, 10, 27, 1, 2, 5, 16, 17, 7, 4, 27, 27, 12, 12, 20, 17, 3, 20, 13, 9, 12, 4, 9, 24, 6, 16, 27, 27, 20, 13, 29, 15, 23, 10, 28, 19, 12, 4, 8, 29, 2, 4, 26, 3, 20, 14, 17, 24, 7, 6, 14, 17, 15, 5, 29, 22, 22, 10, 27, 11, 5, 14, 12, 23, 7, 6, 28, 3, 8, 13, 5, 23, 7, 16, 11, 19, 3, 13, 1, 16, 23, 8, 11, 27, 16, 14, 21, 17, 6, 24, 26, 11, 3, 5, 29, 20, 22, 2, 19, 11, 14, 12, 9, 21, 20, 28, 25, 26, 6, 6, 21, 7, 7, 16, 21, 2, 3, 9, 20, 25, 5, 4, 20, 2, 4, 10, 25, 1, 4, 10, 13, 27, 24, 13, 1, 11, 23, 10, 11, 9, 22, 14, 17, 26, 20, 2, 29, 18, 2, 6, 4, 24, 6, 10, 16, 11, 8, 8, 29, 5, 19, 14, 20, 9, 29, 4, 9, 30, 23, 26, 25, 3, 8, 6, 29, 20, 22, 26, 30, 11, 24, 14, 17, 19, 6, 6, 26, 17, 21, 12, 9, 23, 7, 14, 27, 11, 15, 14, 29, 18, 6, 6, 14, 3, 10, 15, 1, 24, 6, 14, 24, 19, 16, 12, 25, 20, 19, 2, 29, 9, 23, 13, 13, 23, 6, 20, 29, 3, 16, 6, 29, 19, 3, 2, 25, 19, 25, 13, 25, 18, 19, 16, 24, 27, 21, 12, 17, 25, 6, 28, 28, 27, 20, 15, 5, 29, 7, 16, 12, 11, 15, 14, 16, 25, 22, 4, 28, 19, 13, 14, 21, 18, 7, 18, 27, 27, 7, 6, 25, 28, 3, 18, 29, 11, 10, 12, 5, 23, 22, 30, 29, 3, 23, 14, 1, 22, 22, 28, 28, 3, 4, 6, 29, 16, 19, 2, 14, 1, 21, 14, 9, 19, 6, 4, 25, 1, 25, 12, 21, 27, 22, 18, 30, 19, 1, 13, 13, 28, 3, 14, 25, 11, 24, 12, 17, 26, 0, 6, 0, 4, 18, 14, 20, 0, 24, 0, 1, 18, 5, 0, 6, 1, 0, 4, 16, 8, 0, 0, 4, 108, 110, 98, 99];
        let m = vec![170, 85, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 72, 0, 8, 5, 62, 1, 18, 14, 17, 19, 17, 16, 16, 1, 20, 6, 11, 27, 4, 22, 11, 0, 24, 12, 31, 17, 23, 21, 15, 9, 12, 15, 6, 29, 1, 29, 10, 6, 25, 22, 10, 24, 16, 16, 26, 21, 4, 16, 2, 11, 0, 1, 27, 27, 26, 29, 28, 7, 9, 15, 2, 18, 15, 18, 12, 25, 0, 1, 1, 20, 5, 26, 15, 10, 16, 19, 27, 13, 8, 12, 9, 13, 2, 30, 14, 31, 1, 8, 7, 2, 4, 28, 31, 28, 14, 9, 1, 14, 3, 10, 6, 7, 3, 14, 12, 11, 5, 7, 13, 6, 21, 24, 26, 5, 9, 29, 28, 8, 28, 0, 29, 16, 13, 2, 29, 13, 13, 18, 23, 18, 28, 27, 5, 13, 25, 18, 3, 20, 8, 3, 27, 4, 9, 26, 7, 18, 28, 3, 5, 4, 8, 29, 3, 2, 12, 9, 12, 4, 9, 25, 22, 10, 27, 19, 4, 12, 21, 25, 2, 4, 14, 19, 27, 4, 9, 24, 7, 10, 24, 18, 31, 13, 13, 18, 23, 18, 8, 17, 26, 4, 8, 24, 3, 4, 12, 17, 25, 6, 0, 27, 19, 2, 13, 3, 4, 12, 21, 16, 22, 12, 25, 1, 16, 12, 13, 17, 3, 6, 12, 27, 4, 6, 9, 17, 6, 10, 12, 27, 2, 6, 24, 25, 19, 8, 25, 19, 3, 7, 4, 27, 19, 14, 24, 9, 25, 7, 1, 16, 19, 18, 24, 25, 25, 12, 25, 16, 19, 2, 25, 3, 4, 6, 25, 17, 19, 10, 12, 27, 3, 12, 24, 24, 19, 14, 25, 1, 25, 7, 5, 17, 3, 6, 13, 9, 16, 12, 12, 24, 3, 16, 24, 25, 22, 6, 29, 17, 2, 4, 11, 1, 2, 12, 13, 23, 22, 28, 29, 3, 1, 12, 13, 26, 5, 30, 26, 27, 5, 15, 4, 17, 3, 20, 8, 18, 13, 9, 5, 4, 20, 4, 16, 27, 7, 9, 13, 1, 20, 2, 20, 10, 5, 8, 4, 24, 20, 2, 12, 18, 19, 6, 17, 23, 3, 6, 27, 3, 25, 12, 9, 22, 5, 10, 20, 3, 8, 13, 29, 4, 22, 20, 28, 11, 7, 6, 13, 9, 5, 0, 25, 27, 1, 15, 9, 22, 7, 0, 30, 10, 20, 15, 1, 10, 6, 14, 28, 1, 25, 5, 29, 17, 22, 6, 18, 17, 22, 14, 16, 21, 22, 16, 25, 27, 25, 14, 16, 28, 22, 18, 21, 26, 16, 9, 17, 2, 5, 14, 18, 11, 13, 5, 13, 10, 21, 2, 17, 11, 4, 14, 25, 28, 22, 18, 26, 10, 4, 9, 9, 4, 2, 30, 19, 19, 15, 5, 13, 9, 19, 18, 29, 19, 11, 13, 8, 23, 23, 12, 30, 10, 22, 8, 9, 8, 5, 6, 20, 10, 2, 13, 9, 0, 23, 10, 24, 9, 24, 11, 1, 8, 21, 16, 16, 26, 5, 13, 8, 28, 6, 16, 12, 19, 19, 8, 25, 20, 3, 16, 12, 27, 9, 8, 5, 9, 7, 2, 21, 19, 1, 10, 25, 10, 7, 12, 13, 1, 24, 15, 9, 9, 4, 24, 17, 3, 20, 10, 13, 7, 6, 2, 26, 9, 25, 11, 5, 18, 6, 8, 29, 17, 24, 9, 29, 6, 19, 0, 12, 10, 25, 7, 0, 24, 3, 18, 17, 3, 11, 14, 9, 17, 19, 2, 16, 27, 13, 14, 1, 6, 22, 28, 29, 9, 24, 6, 21, 21, 21, 8, 12, 18, 21, 9, 1, 18, 7, 10, 11, 26, 9, 14, 25, 9, 21, 8, 30, 18, 25, 9, 21, 5, 4, 30, 24, 19, 24, 6, 21, 12, 6, 8, 22, 2, 5, 12, 9, 7, 3, 8, 20, 10, 25, 10, 21, 13, 5, 12, 16, 9, 22, 10, 12, 27, 4, 20, 14, 10, 19, 10, 25, 21, 7, 16, 13, 27, 17, 11, 9, 21, 3, 16, 22, 1, 22, 14, 1, 23, 7, 16, 10, 26, 6, 14, 5, 11, 7, 14, 20, 3, 26, 10, 29, 12, 7, 0, 29, 3, 14, 12, 13, 6, 5, 6, 24, 26, 11, 13, 5, 4, 7, 18, 14, 1, 22, 12, 21, 6, 20, 22, 21, 18, 11, 9, 17, 18, 20, 8, 26, 18, 7, 6, 5, 23, 22, 14, 17, 11, 7, 14, 29, 20, 19, 14, 29, 27, 2, 12, 21, 20, 23, 8, 25, 2, 20, 6, 5, 4, 4, 18, 30, 17, 25, 14, 9, 3, 4, 28, 18, 25, 15, 6, 4, 26, 23, 0, 20, 26, 23, 14, 21, 1, 7, 8, 26, 27, 20, 8, 13, 17, 20, 12, 22, 19, 4, 14, 29, 10, 22, 14, 25, 18, 20, 7, 1, 18, 4, 30, 18, 3, 20, 14, 13, 28, 6, 4, 10, 26, 24, 7, 4, 25, 21, 12, 22, 17, 21, 8, 13, 9, 6, 6, 25, 19, 12, 6, 1, 8, 4, 30, 30, 17, 24, 8, 29, 4, 5, 4, 19, 2, 9, 13, 29, 8, 4, 26, 17, 27, 15, 13, 29, 12, 4, 22, 16, 27, 14, 14, 5, 6, 5, 8, 27, 1, 17, 8, 9, 17, 7, 8, 19, 19, 21, 6, 16, 28, 20, 4, 17, 11, 18, 13, 8, 23, 19, 16, 29, 27, 1, 9, 13, 8, 7, 14, 18, 10, 4, 8, 5, 8, 20, 2, 16, 17, 2, 5, 16, 17, 6, 2, 27, 3, 9, 12, 5, 25, 18, 4, 14, 17, 2, 8, 21, 27, 6, 2, 27, 17, 2, 5, 16, 17, 7, 0, 26, 3, 15, 14, 17, 23, 21, 30, 29, 11, 18, 13, 16, 17, 3, 20, 8, 19, 8, 14, 17, 26, 7, 0, 28, 25, 26, 5, 28, 23, 22, 26, 25, 11, 13, 12, 21, 25, 18, 28, 28, 27, 16, 13, 1, 20, 22, 28, 30, 1, 14, 12, 13, 20, 6, 2, 29, 1, 15, 14, 1, 26, 22, 4, 27, 3, 9, 12, 12, 23, 19, 0, 30, 10, 24, 15, 5, 19, 22, 14, 20, 11, 17, 14, 17, 0, 21, 2, 19, 17, 21, 12, 12, 24, 20, 18, 18, 19, 23, 14, 9, 3, 23, 6, 21, 27, 17, 14, 29, 4, 20, 26, 20, 19, 14, 13, 1, 18, 5, 4, 12, 19, 8, 6, 29, 6, 5, 2, 26, 3, 25, 6, 9, 21, 23, 18, 27, 10, 5, 7, 20, 17, 7, 26, 31, 11, 18, 13, 24, 26, 22, 20, 13, 11, 24, 13, 29, 25, 3, 6, 13, 3, 26, 12, 8, 27, 6, 14, 25, 19, 1, 6, 13, 23, 22, 20, 27, 9, 17, 14, 8, 28, 7, 14, 28, 19, 3, 13, 20, 27, 7, 10, 25, 9, 20, 12, 21, 24, 23, 14, 25, 17, 25, 12, 17, 25, 19, 10, 28, 19, 11, 12, 9, 17, 22, 14, 28, 3, 23, 6, 25, 20, 23, 2, 29, 3, 15, 15, 1, 19, 19, 8, 14, 11, 10, 6, 17, 21, 7, 8, 26, 17, 23, 6, 21, 20, 22, 28, 30, 11, 9, 15, 8, 25, 22, 6, 27, 11, 5, 6, 28, 25, 23, 2, 13, 11, 18, 6, 21, 17, 7, 18, 26, 3, 18, 13, 9, 29, 6, 4, 30, 9, 23, 14, 9, 19, 6, 20, 25, 17, 21, 13, 25, 29, 6, 28, 27, 9, 22, 7, 5, 17, 7, 10, 29, 11, 3, 14, 9, 19, 23, 0, 6, 0, 4, 18, 14, 20, 0, 24, 0, 1, 18, 3, 2, 18, 0, 8, 30, 23, 1, 28, 23, 23, 13, 20, 20, 3, 24, 27, 2, 14, 11, 0, 8, 9, 29, 24, 29, 2, 16, 5, 23, 11, 19, 22, 7, 30, 22, 16, 5, 18, 7, 21, 17, 4, 13, 4, 3, 0, 20, 10, 25, 8, 12, 30, 27, 23, 30, 3, 2, 7, 13, 8, 0, 0, 18, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 14, 0, 0, 10, 0, 5, 0, 6, 1, 0, 4, 16, 8, 0, 0, 4, 108, 110, 98, 99];

        // use bech32::convert_bits;
        let mut msg = Cursor::new(m);
        let msgs::SerialRequestHeader {
            sequence: _sequence,
            peer_id: _peer_id,
            dbid: _dbid,
        } = read_serial_request_header(&mut &mut msg).unwrap();
        let message = msgs::read(&mut &mut msg).unwrap();
        println!("MSG {:?}", message);
        let (u5bytes, hrp_bytes) = match message {
            Message::SignInvoice(si) => (si.u5bytes, si.hrp),
            _ => panic!("nope"),
        };

        let hrp = String::from_utf8_lossy(&hrp_bytes.0);
        println!("hrp {:?}", hrp);
        println!("BYTES {:?}", u5bytes.0);

        use lightning_signer::bitcoin::bech32::u5;
        let data: Vec<_> = u5bytes
            .clone()
            .into_iter()
            .map(|b| u5::try_from_u8(b).expect("invoice not base32"))
            .collect();

        // use lightning_signer::bitcoin::consensus::Decodable;
        // let mut bbb = u5bytes;
        // Decodable::consensus_decode(&mut bbb);
        use bech32::{self, Variant};
        let inv = bech32::encode(&hrp, data, Variant::Bech32).unwrap();
        println!("INVOICE {:?}", inv);
    }

    // cargo test test_msg_decode -- --nocapture
    #[test]
    fn test_msg_decode() {
        #[rustfmt::skip]
        // let u5bytes_hex = "01120e11131110100114060b1b04160b00180c1f1117150f090c0f061d011d0a0619160a1810101a150410020b00011b1b1a1d1c07090f02120f120c1900010114051a0f0a10131b0d080c090d021e0e1f01080702041c1f1c0e09010e030a0607030e0c0b05070d0615181a05091d1c081c001d100d021d0d0d1217121c1b050d1912031408031b04091a07121c030504081d03020c090c040919160a1b13040c151902040e131b040918070a18121f0d0d12171208111a04081803040c111906001b13020d03040c1510160c1901100c0d1103060c1b04060911060a0c1b02061819130819130307041b130e18091907011013121819190c19101302190304061911130a0c1b030c1818130e19011907051103060d09100c0c180310181916061d1102040b01020c0d17161c1d03010c0d1a051e1a1b050f0411031408120d0905041404101b07090d011402140a0508041814020c121306111703061b03190c0916050a1403080d1d0416141c0b07060d090500191b010f091607001e0a140f010a060e1c0119051d1116061211160e10151610191b190e101c1612151a10091102050e120b0d050d0a1502110b040e191c16121a0a04090904021e13130f050d0913121d130b0d0817170c1e0a160809080506140a020d0900170a1809180b01081510101a050d081c06100c131308191403100c1b0908050907021513010a190a070c0d01180f090904181103140a0d0706021a09190b051206081d1118091d0613000c0a19070018031211030b0e09111302101b0d0e0106161c1d091806151515080c1215090112070a0b1a090e190915081e1219091505041e18131806150c06081602050c09070308140a190a150d050c1009160a0c1b04140e0a130a191507100d1b110b091503101601160e011707100a1a060e050b070e14031a0a1d0c07001d030e0c0d060506181a0b0d050407120e01160c1506141615120b09111214081a1207060517160e110b070e1d14130e1d1b020c1514170819021406050404121e11190e0903041c12190f06041a1700141a170e150107081a1b14080d11140c1613040e1d0a160e191214070112041e1203140e0d1c06040a1a18070419150c161115080d09060619130c060108041e1e1118081d0405041302090d1d08041a111b0f0d1d0c0416101b0e0e050605081b0111080911070813131506101c1404110b120d081713101d1b01090d08070e120a04080508140210110205101106021b03090c051912040e110208151b06021b110205101107001a030f0e1117151e1d0b120d101103140813080e111a07001c191a051c17161a190b0d0c1519121c1c1b100d0114161c1e010e0c0d1406021d010f0e011a16041b03090c0c1713001e0a180f0513160e140b110e110015021311150c0c1814121213170e09031706151b110e1d04141a14130e0d011205040c1308061d0605021a031906091517121b0a05071411071a1f0b120d181a16140d0b180d1d1903060d031a0c081b060e191301060d1716141b09110e081c070e1c13030d141b070a1909140c1518170e1911190c1119130a1c130b0c0911160e1c031706191417021d030f0f011313080e0b0a06111507081a1117061514161c1e0b090f081916061b0b05061c1917020d0b1206151107121a03120d091d06041e09170e091306141911150d191d061c1b0916070511070a1d0b030e09131700060004120e14001800011203021200081e17011c17170d141403181b020e0b0008091d181d021005170b1316071e16100512071511040d040300140a19080c1e1b171e0302070d080000120f1000000000000000000000000000170e00000a00050006010004100800";
        let u5bytes_hex = "0e11131110100114060b1b04160b00180c1f1117150f090c0f061d011d0a0619160a1810101a150410020b00011b1b1a1d1c07090f02120f120c1900010114051a0f0a10131b0d080c090d021e0e1f01080702041c1f1c0e09010e030a0607030e0c0b05070d0615181a05091d1c081c001d100d021d0d0d1217121c1b050d1912031408031b04091a07121c030504081d03020c090c040919160a1b13040c151902040e131b040918070a18121f0d0d12171208111a04081803040c111906001b13020d03040c1510160c1901100c0d1103060c1b04060911060a0c1b02061819130819130307041b130e18091907011013121819190c19101302190304061911130a0c1b030c1818130e19011907051103060d09100c0c180310181916061d1102040b01020c0d17161c1d03010c0d1a051e1a1b050f0411031408120d0905041404101b07090d011402140a0508041814020c121306111703061b03190c0916050a1403080d1d0416141c0b07060d090500191b010f091607001e0a140f010a060e1c0119051d1116061211160e10151610191b190e101c1612151a10091102050e120b0d050d0a1502110b040e191c16121a0a04090904021e13130f050d0913121d130b0d0817170c1e0a160809080506140a020d0900170a1809180b01081510101a050d081c06100c131308191403100c1b0908050907021513010a190a070c0d01180f090904181103140a0d0706021a09190b051206081d1118091d0613000c0a19070018031211030b0e09111302101b0d0e0106161c1d091806151515080c1215090112070a0b1a090e190915081e1219091505041e18131806150c06081602050c09070308140a190a150d050c1009160a0c1b04140e0a130a191507100d1b110b091503101601160e011707100a1a060e050b070e14031a0a1d0c07001d030e0c0d060506181a0b0d050407120e01160c1506141615120b09111214081a1207060517160e110b070e1d14130e1d1b020c1514170819021406050404121e11190e0903041c12190f06041a1700141a170e150107081a1b14080d11140c1613040e1d0a160e191214070112041e1203140e0d1c06040a1a18070419150c161115080d09060619130c060108041e1e1118081d0405041302090d1d08041a111b0f0d1d0c0416101b0e0e050605081b0111080911070813131506101c1404110b120d081713101d1b01090d08070e120a04080508140210110205101106021b03090c051912040e110208151b06021b110205101107001a030f0e1117151e1d0b120d101103140813080e111a07001c191a051c17161a190b0d0c1519121c1c1b100d0114161c1e010e0c0d1406021d010f0e011a16041b03090c0c1713001e0a180f0513160e140b110e110015021311150c0c1814121213170e09031706151b110e1d04141a14130e0d011205040c1308061d0605021a031906091517121b0a05071411071a1f0b120d181a16140d0b180d1d1903060d031a0c081b060e191301060d1716141b09110e081c070e1c13030d141b070a1909140c1518170e1911190c1119130a1c130b0c0911160e1c031706191417021d030f0f011313080e0b0a06111507081a1117061514161c1e0b090f081916061b0b05061c1917020d0b1206151107121a03120d091d06041e09170e091306141911150d191d061c1b0916070511070a1d0b030e09131700060004120e14001800011203021200081e17011c17170d141403181b020e0b0008091d181d021005170b1316071e16100512071511040d040300140a19080c1e1b171e0302070d080000120f1000000000000000000000000000170e00000a00050006010004100800";
        let u5bytes = hex::decode(u5bytes_hex).unwrap();
        let hrp_bytes = hex::decode("6c6e6263").unwrap();
        let hrp = String::from_utf8_lossy(&hrp_bytes);
        use bech32::{self, ToBase32, Variant};
        let inv = bech32::encode(&hrp, u5bytes.to_base32(), Variant::Bech32).unwrap();
        println!("INVOICE {:?}", inv);
    }

    // cargo test test_args_der --no-default-features --features no-std,persist,broker-test -- --nocapture
    #[test]
    fn test_args_der() {
        let ts = "1111111111";
        let j = format!("{{\"seed\":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],\"network\":\"regtest\",\"policy\":{{\"msat_per_interval\":21000000000,\"interval\":\"daily\",\"htlc_limit_msat\":1000000000}},\"allowlist\":[],\"timestamp\":{},\"lss_nonce\":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]}}", ts);
        let a: Args = sphinx_glyph::serde_json::from_str(&j).unwrap();
        println!("ARGS {:?}", a);
    }

    // cargo test test_map --no-default-features --features no-std,persist,broker-test -- --nocapture
    #[test]
    fn test_map() {
        let mut state = BTreeMap::new();
        // let state_mutex = Arc::new(Mutex::new(state));
        for i in 0..10 {
            let s = state.clone();
            println!("STATE {:?}", s);

            // let s = state_mutex.clone();
            // let s_ = s.lock().unwrap();
            // let mut fin = s_.clone();
            state.insert(i, "hi".to_string());

            let s = state.clone();
            println!("STATE {:?}", s);
        }
    }

    #[cfg(feature = "broker-test")]
    use lss_connector::{tokio, Init, LssBroker, Msg, Response};

    #[cfg(feature = "broker-test")]
    fn empty_args() -> Args {
        use std::time::SystemTime;
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        Args {
            seed: [1; 32],
            network: Network::Regtest,
            policy: Default::default(),
            allowlist: vec![],
            timestamp: ts.as_secs(),
            lss_nonce: [32; 32],
        }
    }

    // rm -rf ~/.lss
    // in vls/lightning-storage-server: ./target/debug/lssd
    // cargo tree --no-default-features --features no-std,persist -e features
    // cargo test test_mobile --no-default-features --features no-std,persist,broker-test -- --nocapture
    #[cfg(feature = "broker-test")]
    #[tokio::test]
    async fn test_mobile() -> anyhow::Result<()> {
        use log::LevelFilter;
        use simple_logger::SimpleLogger;
        use std::collections::BTreeMap;

        SimpleLogger::new()
            .with_level(LevelFilter::Info)
            .with_module_level("lightning_storage_server", LevelFilter::Warn)
            .with_module_level("vls_protocol_signer", LevelFilter::Warn)
            .with_module_level("lightning_signer", LevelFilter::Warn)
            .init()
            .unwrap();

        let lss_uri = "http://127.0.0.1:55551";

        let args = empty_args();
        let mut state: State = BTreeMap::new();

        let spk = match LssBroker::get_server_pubkey(lss_uri).await {
            Ok(pk) => pk,
            Err(_) => {
                println!("[WARN]: test_mobile skipped");
                return Ok(());
            }
        }
        .0;
        println!("init");
        let bi1 = Msg::Init(Init {
            server_pubkey: spk.serialize(),
        })
        .to_vec()?;

        let (res1, _rhb, _approver, _lss_signer) =
            run_init_1(args.clone(), state.clone(), &bi1, None)?;
        let lss_bytes = res1.lss_bytes.unwrap();

        let si1 = Response::from_slice(&lss_bytes)?.into_init()?;

        let lss_broker = LssBroker::new(lss_uri, si1.clone(), spk).await?;

        let bi2 = lss_broker.get_created_state_msg(&si1).await?;

        let (res2, _rh, _approver, _lss_signer) =
            run_init_2(args.clone(), state.clone(), &bi1, &bi2, None)?;
        let lss_bytes2 = res2.lss_bytes.unwrap();

        let si2 = Response::from_slice(&lss_bytes2)?.into_created()?;
        for (lss_key, version_value) in si2.muts.clone().into_iter() {
            state.insert(lss_key, version_value);
        }

        lss_broker.handle(Response::Created(si2)).await?;

        let mut expected_sequence = 0;
        for m in msgs().into_iter() {
            let rr = run_vls(
                args.clone(),
                state.clone(),
                &bi1,
                &bi2,
                &m,
                Some(expected_sequence),
                None,
            )?;
            expected_sequence = expected_sequence + 1;
            println!("===> SEQ {:?}", rr.sequence);
            // std::thread::sleep(std::time::Duration::from_millis(999));
            if rr.topic == topics::LSS_RES && rr.lss_bytes.is_some() {
                let lss_res = Response::from_slice(&rr.lss_bytes.clone().unwrap())?;
                let vls_muts = lss_res.clone().into_vls_muts()?;
                for (lss_key, version_value) in vls_muts.muts.into_iter() {
                    state.insert(lss_key, version_value);
                }

                let lss_msg = lss_broker.handle(lss_res).await?;
                let lss_msg_bytes = lss_msg.to_vec()?;
                let _lss_rr = run_lss(
                    args.clone(),
                    state.clone(),
                    &bi1,
                    &bi2,
                    &lss_msg_bytes,
                    &rr.vls_bytes.unwrap(),
                    &rr.lss_bytes.unwrap(),
                )?;
                // println!("lss rr {:?}", lss_rr);
            }
        }

        Ok(())
    }

    #[cfg(feature = "broker-test")]
    #[rustfmt::skip]
    fn msgs() -> Vec<Vec<u8>> {
        vec![
            // HsmdInit
            vec![170, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 0, 11, 4, 53, 135, 207, 4, 53, 131, 148, 6, 34, 110, 70, 17, 26, 11, 89, 202, 175, 18, 96, 67, 235, 91, 191, 40, 195, 79, 58, 94, 51, 42, 31, 199, 178, 183, 60, 241, 136, 145, 15, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 3],
            // DeriveSecret
            vec![170, 85, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 27, 0, 19, 98, 111, 108, 116, 49, 50, 45, 105, 110, 118, 111, 105, 99, 101, 45, 98, 97, 115, 101],
            // DeriveSecret
            vec![170, 85, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 0, 27, 0, 10, 115, 99, 98, 32, 115, 101, 99, 114, 101, 116],
            // DeriveSecret
            vec![170, 85, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 27, 0, 8, 99, 111, 109, 109, 97, 110, 100, 111],
            // DeriveSecret
            vec![170, 85, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 27, 0, 19, 98, 111, 108, 116, 49, 50, 45, 105, 110, 118, 111, 105, 99, 101, 45, 98, 97, 115, 101],
            // Ecdh
            vec![170, 85, 0, 5, 2, 199, 4, 109, 32, 246, 32, 18, 54, 44, 207, 131, 95, 229, 180, 212, 161, 112, 142, 81, 133, 146, 242, 22, 175, 238, 250, 190, 173, 252, 32, 21, 75, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 0, 1, 2, 135, 185, 124, 85, 121, 26, 24, 74, 164, 218, 56, 78, 13, 76, 86, 61, 101, 245, 60, 115, 61, 121, 16, 65, 57, 135, 226, 243, 43, 105, 101, 98],
            // NewChannel
            vec![170, 85, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 43, 0, 30, 3, 131, 170, 128, 151, 20, 31, 79, 232, 237, 219, 10, 111, 139, 135, 26, 59, 77, 107, 165, 221, 95, 202, 100, 188, 11, 93, 97, 248, 172, 230, 253, 175, 0, 0, 0, 0, 0, 0, 0, 1],
            // GetChannelBasepoints
            vec![170, 85, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 43, 0, 10, 3, 131, 170, 128, 151, 20, 31, 79, 232, 237, 219, 10, 111, 139, 135, 26, 59, 77, 107, 165, 221, 95, 202, 100, 188, 11, 93, 97, 248, 172, 230, 253, 175, 0, 0, 0, 0, 0, 0, 0, 1],
            // GetPerCommitmentPoint
            vec![170, 85, 0, 8, 3, 131, 170, 128, 151, 20, 31, 79, 232, 237, 219, 10, 111, 139, 135, 26, 59, 77, 107, 165, 221, 95, 202, 100, 188, 11, 93, 97, 248, 172, 230, 253, 175, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 10, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0],
            // ReadyChannel
            vec![170, 85, 0, 9, 3, 131, 170, 128, 151, 20, 31, 79, 232, 237, 219, 10, 111, 139, 135, 26, 59, 77, 107, 165, 221, 95, 202, 100, 188, 11, 93, 97, 248, 172, 230, 253, 175, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 231, 0, 31, 1, 0, 0, 0, 0, 0, 1, 134, 160, 0, 0, 0, 0, 0, 0, 0, 0, 76, 127, 129, 83, 56, 166, 54, 87, 1, 229, 193, 15, 178, 248, 92, 150, 162, 94, 133, 76, 93, 150, 142, 98, 125, 140, 2, 233, 223, 30, 243, 230, 0, 1, 0, 6, 0, 0, 0, 3, 92, 131, 255, 70, 102, 230, 101, 246, 129, 170, 194, 213, 186, 250, 7, 50, 239, 106, 18, 39, 201, 43, 230, 241, 205, 33, 105, 231, 223, 178, 29, 67, 2, 66, 116, 109, 95, 103, 127, 179, 166, 106, 240, 53, 252, 107, 24, 195, 199, 51, 48, 137, 176, 230, 107, 86, 164, 195, 167, 128, 219, 138, 179, 149, 48, 2, 82, 99, 215, 162, 179, 99, 83, 137, 111, 57, 114, 140, 237, 100, 163, 37, 8, 42, 43, 69, 205, 189, 136, 8, 213, 101, 174, 255, 131, 21, 111, 138, 3, 16, 190, 203, 14, 167, 172, 61, 206, 194, 129, 251, 71, 255, 58, 8, 25, 99, 82, 206, 165, 250, 84, 189, 149, 250, 42, 53, 165, 225, 29, 165, 22, 2, 5, 135, 202, 153, 175, 141, 163, 16, 224, 128, 156, 148, 94, 150, 229, 6, 134, 2, 209, 207, 34, 160, 51, 137, 31, 227, 126, 200, 151, 169, 90, 188, 0, 6, 0, 0, 0, 2, 16, 0],
        ]
    }
}
