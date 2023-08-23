use crate::approver::SphinxApprover;
use crate::root::{builder_inner, handle_with_lss};
use anyhow::{Error, Result};
use lightning_signer::bitcoin::Network;
use lightning_signer::persist::Persist;
use lightning_signer::prelude::{Mutex, SendSync};
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
pub use vls_persist::thread_memo_persister::ThreadMemoPersister;
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

    let tmp = ThreadMemoPersister {};

    let persist_ctx = tmp.enter(Arc::new(Mutex::new(state)));

    let st = UNIX_EPOCH + Duration::from_secs(args.timestamp);
    let d = st.duration_since(UNIX_EPOCH).unwrap();

    let persister = Arc::new(tmp);
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
    let muts = persist_ctx.exit();
    if !muts.is_empty() {
        log::info!("root_handler_builder MUTS: {:?}", muts);
    }
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
        let m = vec![170, 85, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 138, 0, 8, 6, 128, 1, 18, 14, 12, 14, 14, 13, 16, 1, 20, 22, 24, 15, 27, 7, 7, 23, 25, 7, 5, 25, 27, 12, 11, 15, 20, 2, 22, 24, 28, 26, 27, 24, 11, 18, 2, 31, 31, 30, 16, 27, 0, 0, 29, 12, 17, 25, 11, 14, 12, 21, 17, 17, 1, 11, 31, 0, 13, 25, 1, 7, 16, 1, 1, 20, 9, 20, 1, 8, 7, 2, 20, 11, 0, 9, 4, 3, 20, 22, 9, 10, 9, 8, 15, 16, 28, 0, 3, 6, 19, 16, 25, 20, 8, 3, 15, 22, 24, 9, 20, 15, 13, 31, 24, 4, 16, 29, 3, 6, 23, 23, 4, 31, 26, 4, 27, 16, 13, 15, 20, 13, 13, 18, 23, 18, 28, 27, 5, 13, 25, 18, 3, 20, 8, 3, 27, 4, 9, 26, 7, 18, 28, 3, 5, 4, 8, 29, 3, 0, 11, 1, 2, 12, 13, 20, 6, 2, 29, 1, 2, 7, 9, 29, 18, 4, 29, 11, 21, 13, 5, 18, 2, 4, 14, 17, 2, 5, 25, 13, 4, 30, 21, 18, 22, 10, 29, 1, 3, 18, 25, 11, 24, 15, 1, 12, 20, 16, 17, 19, 1, 12, 20, 28, 6, 14, 18, 19, 10, 8, 17, 2, 5, 0, 16, 17, 13, 6, 29, 22, 4, 18, 28, 26, 2, 13, 25, 7, 6, 8, 12, 17, 18, 12, 17, 6, 23, 16, 13, 25, 22, 11, 1, 21, 7, 16, 28, 27, 7, 14, 1, 12, 3, 8, 30, 2, 16, 13, 17, 21, 7, 12, 29, 3, 6, 11, 1, 27, 22, 16, 12, 19, 3, 13, 8, 27, 4, 24, 21, 3, 3, 9, 25, 12, 20, 8, 18, 27, 9, 13, 25, 19, 21, 8, 26, 9, 13, 11, 1, 11, 23, 10, 16, 26, 3, 9, 21, 9, 5, 8, 12, 3, 11, 13, 25, 12, 23, 2, 20, 10, 10, 14, 13, 25, 20, 8, 8, 17, 12, 4, 9, 23, 6, 2, 27, 11, 5, 4, 8, 29, 2, 4, 16, 27, 1, 14, 9, 23, 6, 18, 29, 19, 15, 14, 9, 18, 18, 30, 8, 2, 11, 12, 21, 26, 6, 30, 8, 1, 2, 5, 16, 17, 7, 8, 30, 11, 16, 12, 20, 17, 3, 20, 12, 19, 29, 5, 16, 17, 6, 26, 25, 11, 19, 14, 13, 16, 22, 14, 25, 9, 2, 7, 9, 29, 18, 4, 26, 11, 4, 4, 8, 29, 3, 6, 13, 25, 22, 6, 16, 24, 19, 2, 11, 1, 2, 14, 21, 26, 22, 18, 25, 1, 2, 7, 8, 17, 6, 14, 27, 27, 7, 11, 1, 9, 21, 14, 27, 18, 24, 14, 21, 0, 20, 20, 25, 19, 13, 7, 1, 7, 5, 2, 29, 27, 18, 14, 13, 2, 6, 30, 19, 17, 2, 5, 16, 17, 6, 6, 27, 27, 14, 14, 17, 18, 22, 28, 29, 1, 2, 7, 8, 17, 6, 12, 30, 3, 1, 11, 5, 18, 23, 2, 24, 27, 16, 10, 25, 21, 22, 14, 12, 26, 25, 10, 12, 28, 19, 8, 17, 18, 11, 6, 20, 27, 20, 8, 19, 17, 17, 10, 4, 28, 23, 20, 18, 27, 7, 8, 5, 19, 19, 4, 29, 3, 4, 8, 25, 26, 6, 18, 27, 10, 16, 7, 1, 6, 19, 12, 21, 17, 17, 9, 29, 22, 23, 8, 30, 18, 19, 8, 29, 11, 4, 28, 22, 2, 25, 13, 17, 6, 7, 6, 27, 18, 4, 9, 24, 21, 20, 10, 13, 2, 20, 12, 25, 26, 18, 22, 18, 26, 3, 14, 29, 4, 20, 28, 13, 18, 24, 6, 9, 3, 22, 14, 25, 18, 25, 8, 17, 23, 3, 6, 17, 3, 12, 13, 9, 13, 4, 14, 28, 26, 16, 13, 8, 26, 7, 16, 17, 9, 11, 8, 25, 20, 18, 22, 20, 18, 2, 9, 9, 6, 18, 22, 12, 27, 23, 13, 21, 18, 3, 14, 17, 11, 22, 10, 1, 18, 22, 18, 16, 26, 24, 9, 9, 17, 23, 8, 19, 1, 16, 10, 12, 24, 19, 18, 12, 11, 24, 11, 1, 11, 4, 6, 18, 11, 6, 7, 1, 26, 21, 10, 25, 19, 23, 5, 29, 26, 6, 10, 29, 1, 24, 15, 8, 24, 21, 10, 20, 10, 9, 9, 5, 7, 20, 18, 30, 11, 4, 10, 29, 11, 21, 12, 10, 26, 20, 14, 13, 17, 22, 4, 27, 2, 15, 12, 9, 8, 21, 4, 24, 26, 5, 5, 29, 25, 20, 30, 18, 3, 8, 12, 21, 24, 6, 28, 14, 10, 18, 8, 13, 24, 2, 30, 27, 17, 18, 15, 9, 13, 3, 8, 27, 26, 9, 13, 9, 22, 7, 12, 27, 27, 23, 6, 8, 27, 19, 18, 22, 9, 18, 11, 1, 18, 3, 4, 13, 19, 1, 8, 5, 5, 21, 10, 27, 10, 1, 6, 5, 20, 7, 12, 29, 2, 8, 13, 24, 25, 20, 4, 27, 26, 18, 6, 13, 2, 7, 6, 13, 19, 10, 10, 4, 28, 3, 12, 28, 19, 13, 15, 1, 11, 5, 14, 19, 10, 8, 6, 17, 11, 21, 8, 21, 1, 17, 14, 29, 12, 20, 6, 20, 10, 3, 9, 0, 24, 23, 8, 28, 3, 13, 15, 8, 24, 22, 22, 17, 26, 10, 14, 1, 1, 22, 24, 22, 3, 17, 5, 29, 6, 6, 6, 21, 11, 16, 13, 1, 4, 5, 18, 20, 2, 15, 14, 1, 23, 21, 16, 20, 27, 9, 14, 20, 24, 5, 2, 21, 11, 15, 13, 13, 10, 18, 30, 18, 10, 26, 14, 13, 17, 22, 28, 14, 3, 15, 6, 13, 6, 4, 28, 25, 27, 14, 14, 25, 29, 3, 2, 29, 27, 5, 6, 12, 21, 23, 12, 29, 26, 7, 13, 9, 18, 2, 30, 30, 10, 11, 9, 13, 23, 22, 18, 18, 17, 11, 14, 21, 27, 7, 10, 22, 9, 24, 12, 25, 8, 6, 20, 26, 11, 21, 8, 5, 23, 20, 4, 29, 19, 21, 12, 29, 25, 5, 16, 17, 26, 15, 9, 25, 9, 22, 28, 19, 2, 11, 13, 13, 1, 20, 26, 29, 3, 1, 11, 1, 23, 4, 28, 16, 9, 29, 7, 20, 17, 2, 24, 8, 19, 1, 13, 21, 23, 23, 10, 27, 19, 20, 4, 8, 29, 3, 2, 12, 3, 29, 5, 16, 17, 7, 6, 25, 11, 14, 12, 17, 18, 23, 4, 8, 17, 26, 15, 12, 17, 7, 0, 29, 11, 2, 11, 29, 21, 22, 10, 30, 9, 2, 7, 8, 17, 3, 0, 12, 27, 1, 7, 5, 16, 19, 16, 25, 1, 25, 6, 20, 25, 22, 12, 25, 9, 23, 6, 16, 27, 22, 8, 12, 3, 4, 12, 16, 28, 19, 8, 25, 3, 4, 6, 13, 17, 19, 10, 13, 17, 23, 12, 17, 18, 6, 6, 13, 9, 24, 6, 16, 26, 19, 2, 12, 9, 16, 6, 5, 18, 19, 18, 14, 1, 23, 12, 20, 25, 6, 8, 12, 19, 2, 12, 24, 27, 22, 2, 13, 3, 4, 6, 5, 18, 19, 2, 12, 3, 1, 6, 9, 17, 19, 16, 14, 11, 6, 12, 24, 25, 19, 16, 8, 17, 12, 4, 9, 24, 6, 10, 28, 19, 19, 13, 29, 23, 2, 4, 14, 17, 2, 14, 1, 18, 22, 30, 28, 3, 12, 12, 20, 23, 7, 6, 28, 3, 8, 13, 5, 23, 7, 16, 11, 19, 3, 13, 1, 16, 23, 8, 11, 27, 3, 12, 16, 28, 22, 8, 27, 9, 21, 14, 21, 16, 19, 10, 25, 19, 4, 14, 17, 25, 22, 20, 12, 19, 3, 6, 9, 22, 22, 16, 12, 1, 2, 5, 16, 17, 6, 2, 27, 3, 9, 12, 5, 25, 18, 4, 14, 17, 2, 10, 1, 16, 23, 10, 27, 1, 2, 5, 16, 17, 7, 4, 27, 27, 12, 12, 20, 17, 3, 20, 13, 9, 12, 4, 9, 24, 6, 16, 27, 27, 20, 13, 29, 15, 23, 10, 28, 19, 12, 4, 8, 29, 2, 4, 26, 3, 20, 14, 17, 24, 7, 6, 14, 17, 15, 5, 29, 22, 22, 10, 27, 11, 5, 14, 12, 23, 7, 6, 28, 3, 8, 13, 5, 23, 7, 16, 11, 19, 3, 13, 1, 16, 23, 8, 11, 27, 16, 14, 21, 17, 6, 24, 26, 11, 3, 5, 29, 20, 22, 2, 19, 11, 14, 12, 9, 21, 20, 28, 25, 26, 6, 6, 21, 7, 7, 16, 21, 2, 3, 9, 20, 25, 5, 4, 20, 2, 4, 10, 25, 1, 4, 10, 13, 27, 24, 13, 1, 11, 23, 10, 11, 9, 22, 14, 17, 26, 20, 2, 29, 18, 2, 6, 4, 24, 6, 10, 16, 11, 8, 8, 29, 5, 19, 14, 20, 9, 29, 4, 9, 30, 23, 26, 25, 3, 8, 6, 29, 20, 22, 26, 30, 11, 24, 14, 17, 19, 6, 6, 26, 17, 21, 12, 9, 23, 7, 14, 27, 11, 15, 14, 29, 18, 6, 6, 14, 3, 10, 15, 1, 24, 6, 14, 24, 19, 16, 12, 25, 20, 19, 2, 29, 9, 23, 13, 13, 23, 6, 20, 29, 3, 16, 6, 29, 19, 3, 2, 25, 19, 25, 13, 25, 18, 19, 16, 24, 27, 21, 12, 17, 25, 6, 28, 28, 27, 20, 15, 5, 29, 7, 16, 12, 11, 15, 14, 16, 25, 22, 4, 28, 19, 13, 14, 21, 18, 7, 18, 27, 27, 7, 6, 25, 28, 3, 18, 29, 11, 10, 12, 5, 23, 22, 30, 29, 3, 23, 14, 1, 22, 22, 28, 28, 3, 4, 6, 29, 16, 19, 2, 14, 1, 21, 14, 9, 19, 6, 4, 25, 1, 25, 12, 21, 27, 22, 18, 30, 19, 1, 13, 13, 28, 3, 14, 25, 11, 24, 12, 17, 26, 0, 6, 0, 4, 18, 14, 20, 0, 24, 0, 1, 18, 5, 0, 6, 1, 0, 4, 16, 8, 0, 0, 4, 108, 110, 98, 99];
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
        use bech32::{self, ToBase32, Variant};
        let inv = bech32::encode(&hrp, u5bytes.0.to_base32(), Variant::Bech32).unwrap();
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
