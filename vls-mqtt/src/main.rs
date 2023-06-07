mod logger;
mod lss;
mod mqtt;
mod persist;
mod routes;

use crate::routes::{ChannelReply, ChannelRequest};
use anyhow::Result;
use dotenv::dotenv;
use glyph::control::{ControlPersist, Controller};
use lss::init_lss;
use rocket::tokio::sync::{broadcast, mpsc, oneshot};
use sphinx_signer::lightning_signer::bitcoin::Network;
// use sphinx_signer::lightning_signer::persist::Persist;
use sphinx_signer::lightning_signer::wallet::Wallet;
use sphinx_signer::persist::{BackupPersister, FsPersister, ThreadMemoPersister};
use sphinx_signer::policy::update_controls;
use sphinx_signer::Handler;
use sphinx_signer::{self, root, sphinx_glyph as glyph, RootHandler};
use std::env;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

pub const ROOT_STORE: &str = "teststore";

// requests from incoming VLS messages
#[derive(Debug)]
pub struct VlsChanMsg {
    pub message: Vec<u8>,
    pub reply_tx: oneshot::Sender<Result<(Vec<u8>, Vec<u8>)>>,
}
impl VlsChanMsg {
    pub fn new(message: Vec<u8>) -> (Self, oneshot::Receiver<Result<(Vec<u8>, Vec<u8>)>>) {
        let (reply_tx, reply_rx) = oneshot::channel();
        (Self { message, reply_tx }, reply_rx)
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

    let pers = persist::ControlPersister::new("vls_mqtt_data");
    let initial_policy = pers.read_policy().unwrap_or_default();
    let pers_arc = Arc::new(Mutex::new(pers));
    let mut ctrlr = Controller::new_with_persister(sk, pk, pers_arc);

    let seed32: [u8; 32] = seed.try_into().expect("invalid seed");
    let store_path = env::var("STORE_PATH").unwrap_or(ROOT_STORE.to_string());

    let fs_persister = FsPersister::new(&store_path, None);
    let lss_persister = ThreadMemoPersister {};
    let persister = Arc::new(BackupPersister::new(fs_persister, lss_persister));

    let node_id = ctrlr.pubkey();
    let (handler_builder, approver) =
        root::builder(seed32, network, &initial_policy, persister, &node_id)
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
    rocket::tokio::spawn(async move {
        while let Some(msg) = vls_rx.recv().await {
            let s1 = approver.control().get_state();
            let res_res = root::handle_with_lss(&rh_, &lss_signer, msg.message, true);
            let s2 = approver.control().get_state();
            if s1 != s2 {
                log::info!("===> VelocityApprover state updated");
                // FIXME store the "buckets" in persistence
            }
            let _ = msg.reply_tx.send(res_res);
        }
    });

    rocket::tokio::spawn(
        async move { listen_for_commands(&mut ctrlr, ctrl_rx, &rh, network).await },
    );

    routes::launch_rocket(ctrl_tx, error_tx)
}

async fn listen_for_commands(
    ctrlr: &mut Controller,
    mut ctrl_rx: mpsc::Receiver<ChannelRequest>,
    rh: &RootHandler,
    network: Network,
) {
    while let Some(msg) = ctrl_rx.recv().await {
        match ctrlr.handle(&msg.message) {
            Ok((cmsg, cres)) => {
                let res2 = update_controls(rh, network, cmsg, cres);
                let reply = rmp_serde::to_vec_named(&res2).unwrap();
                let _ = msg.reply_tx.send(ChannelReply { reply });
            }
            Err(e) => log::warn!("error parsing ctrl msg {:?}", e),
        };
    }
}
