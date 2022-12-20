mod logger;
mod mqtt;
mod persist;
mod routes;

use crate::routes::{ChannelReply, ChannelRequest};
use dotenv::dotenv;
use glyph::control::Controller;
use rocket::tokio::sync::{broadcast, mpsc};
use sphinx_signer::lightning_signer::bitcoin::Network;
use sphinx_signer::lightning_signer::persist::Persist;
use sphinx_signer::persist::FsPersister;
use sphinx_signer::policy::update_controls;
use sphinx_signer::{self, root, sphinx_glyph as glyph, RootHandler};
use std::env;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

pub const ROOT_STORE: &str = "teststore";

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
    let pers_arc = Arc::new(Mutex::new(pers));
    let mut ctrlr = Controller::new_with_persister(sk, pk, pers_arc);

    let seed32: [u8; 32] = seed.try_into().expect("invalid seed");
    let store_path = env::var("STORE_PATH").unwrap_or(ROOT_STORE.to_string());
    let persister: Arc<dyn Persist> = Arc::new(FsPersister::new(&store_path, None));
    let root_handler =
        root::init(seed32, network, &Default::default(), persister).expect("failed to init signer");

    logger::log_errors(error_rx);

    let rh = Arc::new(root_handler);
    let error_tx_ = error_tx.clone();
    let rh_ = rh.clone();
    rocket::tokio::spawn(async move {
        mqtt::start(&rh_, &pk, &sk, error_tx_)
            .await
            .expect("mqtt crash");
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
                let reply =
                    rmp_serde::to_vec_named(&res2).expect("could not build control response");
                msg.reply_tx
                    .send(ChannelReply { reply })
                    .expect("couldnt send ctrl reply");
            }
            Err(e) => log::warn!("error parsing ctrl msg {:?}", e),
        };
    }
}
