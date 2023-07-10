use crate::root::{builder_inner, handle_with_lss};
use anyhow::Result;
use lightning_signer::bitcoin::Network;
use lightning_signer::persist::Persist;
use lightning_signer::prelude::SendSync;
use lightning_signer::signer::StartingTimeFactory;
use lightning_signer::util::clock::Clock;
use lss_connector::secp256k1::PublicKey;
use lss_connector::{handle_lss_msg, LssSigner, Msg};
use serde::{Deserialize, Serialize};
use sphinx_glyph::topics;
use sphinx_glyph::types::{Policy, Velocity};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
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
// 3. get VLS msg:
//     - run_vls(args, msg1, msg2, vls_msg)
//     - if topic==LSS_RES store result on phone (both bytes), and return lss_bytes
//     - else return vls_bytes
// 4. get LSS msg:
//     - run_lss(args, msg1, msg2, lss_msg, prev_vls, prev_lss)

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Args {
    seed: [u8; 32],
    network: Network,
    policy: Policy,
    velocity: Option<Velocity>,
    allowlist: Vec<String>,
    timestamp: Duration,
    lss_nonce: [u8; 32],
}

pub type State = BTreeMap<String, (u64, Vec<u8>)>;
pub struct RunReturn {
    pub topic: String,
    pub vls_bytes: Option<Vec<u8>>,
    pub lss_bytes: Option<Vec<u8>>,
}

pub fn run_init_1(
    args: Args,
    state: State,
    lss_msg1: Vec<u8>,
) -> Result<(RunReturn, RootHandlerBuilder, LssSigner)> {
    let init = Msg::from_slice(&lss_msg1)?.as_init()?;
    let server_pubkey = PublicKey::from_slice(&init.server_pubkey)?;

    let nonce = args.lss_nonce.clone();
    let rhb = root_handler_builder(args, state)?;
    let (lss_signer, res1) = LssSigner::new(&rhb, &server_pubkey, Some(nonce));
    Ok((
        RunReturn::new_lss(topics::INIT_1_RES, res1),
        rhb,
        lss_signer,
    ))
}

pub fn run_init_2(
    args: Args,
    state: State,
    lss_msg1: Vec<u8>,
    lss_msg2: Vec<u8>,
) -> Result<(RunReturn, RootHandler, LssSigner)> {
    let (_res1, rhb, lss_signer) = run_init_1(args, state, lss_msg1)?;
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
    state: State,
    lss_msg1: Vec<u8>,
    lss_msg2: Vec<u8>,
    vls_msg: Vec<u8>,
) -> Result<RunReturn> {
    let (_res, rh, lss_signer) = run_init_2(args, state, lss_msg1, lss_msg2)?;

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
    state: State,
    lss_msg1: Vec<u8>,
    lss_msg2: Vec<u8>,
    lss_msg: Vec<u8>,
    previous_vls: Vec<u8>,
    previous_lss: Vec<u8>,
) -> Result<RunReturn> {
    let (_res, _rh, lss_signer) = run_init_2(args, state, lss_msg1, lss_msg2)?;

    let prev = (previous_vls, previous_lss);
    let (topic, res) = handle_lss_msg(&lss_msg, &Some(prev), &lss_signer)?;
    let ret = if &topic == topics::VLS_RES {
        RunReturn::new_vls(&topic, res)
    } else {
        RunReturn::new_lss(&topic, res)
    };
    Ok(ret)
}

fn root_handler_builder(args: Args, state: State) -> Result<RootHandlerBuilder> {
    // FIXME no threads in WASM
    let tmp = ThreadMemoPersister {};
    // enter here? exit where?
    let persist_ctx = tmp.enter(Arc::new(Mutex::new(state)));
    let persister = Arc::new(tmp);
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
    let muts = persist_ctx.exit();
    println!("MUTS {:?}", muts);
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

// contacts and chats stored in LSS (encrypted?)
// one giant LDK multitenant lightning node?
// can we get VLS to not reveal TLVs to node?
// a "lite" sphinx user keeps their key/contacts/chats themselves
// LSP cant receive without them online - and cant impersonate
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "broker-test")]
    use lss_connector::{tokio, Init, LssBroker, Msg, Response};

    fn empty_args() -> Args {
        use std::time::SystemTime;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        Args {
            seed: [1; 32],
            network: Network::Regtest,
            policy: Default::default(),
            velocity: None,
            allowlist: vec![],
            timestamp,
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
        use std::collections::BTreeMap;

        let lss_uri = "http://127.0.0.1:55551";

        let args = empty_args();
        let state: State = BTreeMap::new();

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

        let (res1, _rhb, _lss_signer) = run_init_1(args.clone(), state.clone(), bi1.clone())?;
        let lss_bytes = res1.lss_bytes.unwrap();

        let si1 = Response::from_slice(&lss_bytes)?.as_init()?;

        let lss_broker = LssBroker::new(lss_uri, si1.clone(), spk).await?;

        let bi2 = lss_broker.get_created_state_msg(&si1).await?;

        let (res2, _rh, _lss_signer) =
            run_init_2(args.clone(), state.clone(), bi1.clone(), bi2.clone())?;
        let lss_bytes2 = res2.lss_bytes.unwrap();

        let si2 = Response::from_slice(&lss_bytes2)?.as_created()?;

        lss_broker.handle(Response::Created(si2)).await?;

        // test VLS

        // test LSS

        Ok(())
    }
}
