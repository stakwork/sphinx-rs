mod logger;
mod mqtt;
mod persist;
mod routes;

use crate::routes::{ChannelReply, ChannelRequest};
use anyhow::{anyhow, Result};
use dotenv::dotenv;
use glyph::control::{ControlPersist, Controller};
use lss_connector::{
    msgs as lss_msgs, secp256k1::PublicKey, LssSigner, Msg as LssMsg, Response as LssRes,
};
use rocket::tokio::sync::{broadcast, mpsc, oneshot};
use sphinx_signer::lightning_signer::bitcoin::Network;
use sphinx_signer::lightning_signer::persist::Persist;
use sphinx_signer::lightning_signer::wallet::Wallet;
use sphinx_signer::persist::{FsPersister, ThreadMemoPersister};
use sphinx_signer::policy::update_controls;
use sphinx_signer::Handler;
use sphinx_signer::{self, root, sphinx_glyph as glyph, RootHandler, RootHandlerBuilder};
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
    let persister: Arc<dyn Persist> = if env::var("USE_FS_PERSISTER").is_ok() {
        let store_path = env::var("STORE_PATH").unwrap_or(ROOT_STORE.to_string());
        Arc::new(FsPersister::new(&store_path, None))
    } else {
        // used by LSS to catch muts
        Arc::new(ThreadMemoPersister {})
    };
    let handler_builder =
        root::builder(seed32, network, &initial_policy, persister).expect("failed to init signer");

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
            let res_res = root::handle(&rh_, &lss_signer, msg.message, true);
            let _ = msg.reply_tx.send(res_res);
        }
    });

    rocket::tokio::spawn(
        async move { listen_for_commands(&mut ctrlr, ctrl_rx, &rh, network).await },
    );

    routes::launch_rocket(ctrl_tx, error_tx)
}

async fn init_lss(
    handler_builder: RootHandlerBuilder,
    mut lss_rx: mpsc::Receiver<LssChanMsg>,
) -> Result<(RootHandler, LssSigner)> {
    use sphinx_signer::sphinx_glyph::topics;
    let res_topic = topics::LSS_RES.to_string();

    let first_lss_msg = lss_rx.recv().await.ok_or(anyhow!("couldnt receive"))?;
    let init = lss_msgs::Msg::from_slice(&first_lss_msg.message)?.as_init()?;
    let server_pubkey = PublicKey::from_slice(&init.server_pubkey)?;

    let (lss_signer, res1) = LssSigner::new(&handler_builder, &server_pubkey);
    if let Err(e) = first_lss_msg.reply_tx.send(Ok((res_topic.clone(), res1))) {
        log::warn!("could not send on first_lss_msg.reply_tx, {:?}", e);
    }

    let second_lss_msg = lss_rx.recv().await.ok_or(anyhow!("couldnt receive"))?;
    let created = lss_msgs::Msg::from_slice(&second_lss_msg.message)?.as_created()?;

    // build the root handler
    let (root_handler, res2) = lss_signer.build_with_lss(created, handler_builder)?;
    println!("root handler built!!!!!");
    if let Err(e) = second_lss_msg.reply_tx.send(Ok((res_topic, res2))) {
        log::warn!("could not send on second_lss_msg.reply_tx, {:?}", e);
    }

    let lss_signer_ = lss_signer.clone();
    rocket::tokio::spawn(async move {
        while let Some(msg) = lss_rx.recv().await {
            let ret = handle_lss_msg(&msg, &lss_signer_).await;
            let _ = msg.reply_tx.send(ret);
        }
    });

    Ok((root_handler, lss_signer))
}

// return the original VLS bytes
// FIXME handle reconnects from broker restarting (init, created msgs)
// return the return_topic and bytes
async fn handle_lss_msg(msg: &LssChanMsg, lss_signer: &LssSigner) -> Result<(String, Vec<u8>)> {
    use sphinx_signer::sphinx_glyph::topics;

    // println!("LssMsg::from_slice {:?}", &msg.message);
    let lssmsg = LssMsg::from_slice(&msg.message)?;
    println!("incoming ?LSS msg {:?}", lssmsg);
    match lssmsg {
        LssMsg::Init(_) => {
            let bs = lss_signer.reconnect_init_response();
            Ok((topics::LSS_RES.to_string(), bs))
        }
        LssMsg::Created(bm) => {
            if lss_signer.check_hmac(&bm) {
                let bs = lss_signer.empty_created();
                Ok((topics::LSS_RES.to_string(), bs))
            } else {
                Err(anyhow!("Invalid server hmac"))
            }
        }
        LssMsg::Stored(mut bm) => {
            if let None = msg.previous {
                return Err(anyhow!("should be previous msg bytes"));
            }
            let previous = msg.previous.clone().unwrap();
            // get the previous vls msg (where i sent signer muts)
            // println!("LssRes::from_slice {:?}", &previous.1);
            let prev_lssmsg = LssRes::from_slice(&previous.1)?;
            println!("previous lss res: {:?}", prev_lssmsg);
            let sm = prev_lssmsg.as_vls_muts()?;
            if sm.muts.is_empty() {
                // empty muts? dont need to check server hmac
                Ok((topics::VLS_RETURN.to_string(), previous.0))
            } else {
                // check the original muts
                bm.muts = sm.muts;
                // send back the original VLS response finally
                if lss_signer.check_hmac(&bm) {
                    Ok((topics::VLS_RETURN.to_string(), previous.0))
                } else {
                    Err(anyhow!("Invalid server hmac"))
                }
            }
        }
    }
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
