mod logger;
mod lss;
mod mqtt;
mod persist;
mod routes;

use crate::routes::{ChannelReply, ChannelRequest};
use anyhow::{Error, Result};
use dotenv::dotenv;
use glyph::control::{ControlPersist, Controller};
use glyph::ser::{serialize_controlresponse, ByteBuf};
use lss::init_lss;
use rocket::tokio::sync::{broadcast, mpsc, oneshot};
use sphinx_signer::kvv::{CloudKVVStore, FsKVVStore};
use sphinx_signer::lightning_signer::bitcoin::Network;
use sphinx_signer::lightning_signer::wallet::Wallet;
use sphinx_signer::policy::update_controls;
use sphinx_signer::Handler;
use sphinx_signer::{self, approver::SphinxApprover, root, sphinx_glyph as glyph, RootHandler};
use std::env;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const ROOT_STORE: &str = "teststore";

// requests from incoming VLS messages
#[derive(Debug)]
pub struct VlsChanMsg {
    pub message: Vec<u8>,
    pub expected_sequence: Option<u16>,
    pub reply_tx: oneshot::Sender<Result<(Vec<u8>, Vec<u8>, u16, String)>>,
}
impl VlsChanMsg {
    pub fn new(
        message: Vec<u8>,
        expected_sequence: Option<u16>,
    ) -> (
        Self,
        oneshot::Receiver<Result<(Vec<u8>, Vec<u8>, u16, String)>>,
    ) {
        let (reply_tx, reply_rx) = oneshot::channel();
        (
            Self {
                message,
                expected_sequence,
                reply_tx,
            },
            reply_rx,
        )
    }
}

// requests from incoming LSS messages
// they include the "previous" VLS and LSS bytes
#[derive(Debug)]
pub struct LssChanMsg {
    pub message: Vec<u8>,
    // the previous VLS msgs
    pub previous: Option<(Vec<u8>, Vec<u8>)>,
    // topic, payload
    pub reply_tx: oneshot::Sender<Result<(String, Vec<u8>)>>,
}
impl LssChanMsg {
    pub fn new(
        message: Vec<u8>,
        previous: Option<(Vec<u8>, Vec<u8>)>,
    ) -> (Self, oneshot::Receiver<Result<(String, Vec<u8>)>>) {
        let (reply_tx, reply_rx) = oneshot::channel();
        (
            Self {
                message,
                previous,
                reply_tx,
            },
            reply_rx,
        )
    }
}

#[rocket::launch]
async fn rocket() -> _ {
    dotenv().ok();

    let (ctrl_tx, ctrl_rx) = mpsc::channel(1000);
    let (error_tx, error_rx) = broadcast::channel(1000);

    logger::setup_logs(error_tx.clone());

    let net_str = env::var("NETWORK").unwrap_or("regtest".to_string());
    let network = Network::from_str(&net_str).expect("invalid network");
    let seed_string: String = env::var("SEED").expect("no seed");
    let seed = hex::decode(seed_string).expect("couldnt decode seed");
    let (pk, sk) = sphinx_signer::derive_node_keys(&network, &seed);
    println!("PUBKEY {}", hex::encode(pk.serialize()));

    let ctrlr_db = persist::ControlPersister::new("vls_mqtt_data");
    let initial_policy = ctrlr_db.read_policy().unwrap_or_default();
    let initial_velocity = ctrlr_db.read_velocity().ok();
    let ctrlr_db_mutex = Arc::new(Mutex::new(ctrlr_db));
    let mut ctrlr = Controller::new_with_persister(sk, pk, ctrlr_db_mutex.clone());
    // let node_id = ctrlr.pubkey();

    let seed32: [u8; 32] = seed.try_into().expect("invalid seed");
    let store_path = env::var("STORE_PATH").unwrap_or(ROOT_STORE.to_string());

    let kvv_store = FsKVVStore::new(&store_path, None).0;
    let fs_persister = CloudKVVStore::new(kvv_store);
    // FIXME initial allowlist
    let initial_allowlist = Vec::new();
    // let initial_allowlist = match fs_persister.get_node_allowlist(&node_id) {
    //     Ok(al) => al,
    //     Err(_) => {
    //         log::warn!("no allowlist found in fs persister!");
    //         Vec::new()
    //     }
    // };

    // let lss_persister = ThreadMemoPersister {};
    // let persister = Arc::new(BackupPersister::new(fs_persister, lss_persister));

    let persister = Arc::new(fs_persister);

    let (handler_builder, approver) = root::builder(
        seed32,
        network,
        initial_policy,
        initial_allowlist,
        initial_velocity,
        persister,
    )
    .expect("failed to init signer");

    let (vls_tx, mut vls_rx) = mpsc::channel::<VlsChanMsg>(1000);
    let vls_tx_ = vls_tx.clone();
    let (lss_tx, lss_rx) = mpsc::channel::<LssChanMsg>(1000);
    let lss_tx_ = lss_tx.clone();
    let error_tx_ = error_tx.clone();
    rocket::tokio::spawn(async move {
        mqtt::start(vls_tx_, &pk, &sk, error_tx_, lss_tx_)
            .await
            .expect("mqtt crash");
    });

    // LSS initialization
    let (root_handler, lss_signer) = init_lss(handler_builder, lss_rx).await.unwrap();

    let root_network = root_handler.node().network();
    log::info!("root network {:?}", root_network);
    logger::log_errors(error_rx);

    let rh = Arc::new(root_handler);
    let rh_ = rh.clone();
    let approver_ = approver.clone();
    let ctrldb_ = ctrlr.persister();
    rocket::tokio::spawn(async move {
        while let Some(msg) = vls_rx.recv().await {
            let s1 = approver.control().get_state();
            let res_res =
                root::handle_with_lss(&rh_, &lss_signer, msg.message, msg.expected_sequence, false)
                    .map_err(Error::msg);
            let s2 = approver.control().get_state();
            if s1 != s2 {
                log::info!("===> VelocityApprover state updated");
                let mut ctrldb_ = ctrldb_.lock().unwrap();
                if let Err(e) = ctrldb_.write_velocity(s2) {
                    log::error!("failed to set velocity state {:?}", e);
                }
                drop(ctrldb_);
            }
            let _ = msg.reply_tx.send(res_res);
            rh_.commit();
        }
    });

    let rh_ = rh.clone();
    rocket::tokio::spawn(async move {
        listen_for_commands(&mut ctrlr, ctrl_rx, &rh_, &approver_).await
    });

    rocket::tokio::spawn(async move {
        loop {
            rocket::tokio::time::sleep(Duration::from_secs(60)).await;
            // let _ = rh.node().get_heartbeat();
        }
    });

    routes::launch_rocket(ctrl_tx, error_tx)
}

async fn listen_for_commands(
    ctrlr: &mut Controller,
    mut ctrl_rx: mpsc::Receiver<ChannelRequest>,
    rh: &RootHandler,
    approver: &SphinxApprover,
) {
    while let Some(msg) = ctrl_rx.recv().await {
        match ctrlr.handle(&msg.message) {
            Ok((cmsg, cres)) => {
                let (res2, muts) = update_controls(rh, cmsg, cres, approver);
                if let Some(_) = muts {
                    log::warn!("some mutations that need to be sent to LSS!");
                }
                let mut bb = ByteBuf::new();
                serialize_controlresponse(&mut bb, &res2).expect("failed serialize_lssresponse");
                let _ = msg.reply_tx.send(ChannelReply {
                    reply: bb.into_vec(),
                });
            }
            Err(e) => log::warn!("error parsing ctrl msg {:?}", e),
        };
    }
}
