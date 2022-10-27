mod mqtt;
mod routes;

use crate::routes::ChannelRequest;
use dotenv::dotenv;
use glyph::control::Controller;
use rocket::tokio::sync::{broadcast, mpsc};
use sphinx_signer::lightning_signer::bitcoin::Network;
use sphinx_signer::lightning_signer::persist::Persist;
use sphinx_signer::persist::FsPersister;
use sphinx_signer::policy::update_controls;
use sphinx_signer::{self, sphinx_glyph as glyph, InitResponse, RootHandler};
use std::sync::Arc;

pub const ROOT_STORE: &str = "teststore";

#[rocket::launch]
async fn rocket() -> _ {
    dotenv().ok();

    let (ctrl_tx, ctrl_rx) = mpsc::channel(1000);
    let (error_tx, _error_rx) = broadcast::channel(1000);

    let network = Network::Regtest;
    let seed_string: String = std::env::var("SEED").expect("no seed");
    let seed = hex::decode(seed_string).expect("couldnt decode seed");
    let (pk, sk) = sphinx_signer::derive_node_keys(&network, &seed);
    let mut ctrlr = Controller::new(sk, pk, 0);

    let seed32: [u8; 32] = seed.try_into().expect("wrong seed");
    let init_msg = sphinx_signer::make_init_msg(network, seed32).expect("failed to make init msg");
    let store_path = std::env::var("STORE_PATH").unwrap_or(ROOT_STORE.to_string());
    let persister: Arc<dyn Persist> = Arc::new(FsPersister::new(&store_path, None));
    let InitResponse {
        root_handler,
        init_reply: _,
    } = sphinx_signer::init(init_msg, network, &Default::default(), persister)
        .expect("failed to init signer");

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
            Ok((msg, res)) => {
                let res2 = update_controls(rh, network, msg, res);
                let _res_data = rmp_serde::to_vec(&res2).expect("could not build control response");
            }
            Err(e) => log::warn!("error parsing ctrl msg {:?}", e),
        };
    }
}
