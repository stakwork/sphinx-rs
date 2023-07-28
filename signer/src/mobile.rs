use crate::approver::SphinxApprover;
use crate::root::{builder_inner, handle_with_lss};
use anyhow::Result;
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
    velocity: Option<Velocity>,
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
    pub velocity: Option<Vec<u8>>,
}

pub fn run_init_1(
    args: Args,
    state: State,
    lss_msg1: &[u8],
) -> Result<(
    RunReturn,
    RootHandlerBuilder,
    Arc<SphinxApprover>,
    LssSigner,
)> {
    let init = Msg::from_slice(lss_msg1)?.into_init()?;
    let server_pubkey = PublicKey::from_slice(&init.server_pubkey)?;
    let nonce = args.lss_nonce.clone();
    let (rhb, approver) = root_handler_builder(args, state)?;
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
) -> Result<(RunReturn, RootHandler, Arc<SphinxApprover>, LssSigner)> {
    let (_res1, rhb, approver, lss_signer) = run_init_1(args, state.clone(), lss_msg1)?;
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
) -> Result<RunReturn> {
    let (_res, rh, _approver, lss_signer) = run_init_2(args, state, lss_msg1, lss_msg2)?;

    let (vls_res, lss_res, sequence, cmd) =
        handle_with_lss(&rh, &lss_signer, vls_msg.to_vec(), expected_sequence, true)?;
    let ret = if lss_res.is_empty() {
        RunReturn::new_vls(topics::VLS_RES, vls_res, sequence, cmd)
    } else {
        RunReturn::new(topics::LSS_RES, vls_res, lss_res, sequence, cmd)
    };
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
    let (_res, _rh, _approver, lss_signer) = run_init_2(args, state, lss_msg1, lss_msg2)?;

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
        args.velocity,
        args.allowlist,
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
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        Args {
            seed: [1; 32],
            network: Network::Regtest,
            policy: Default::default(),
            velocity: None,
            allowlist: vec![],
            timestamp: ts.as_secs(),
            lss_nonce: [32; 32],
        }
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

        let (res1, _rhb, _approver, _lss_signer) = run_init_1(args.clone(), state.clone(), &bi1)?;
        let lss_bytes = res1.lss_bytes.unwrap();

        let si1 = Response::from_slice(&lss_bytes)?.into_init()?;

        let lss_broker = LssBroker::new(lss_uri, si1.clone(), spk).await?;

        let bi2 = lss_broker.get_created_state_msg(&si1).await?;

        let (res2, _rh, _approver, _lss_signer) =
            run_init_2(args.clone(), state.clone(), &bi1, &bi2)?;
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
