mod mqtt;
mod routes;

use crate::routes::ChannelRequest;
use dotenv::dotenv;
use glyph::control::Controller;
use rocket::tokio::sync::{broadcast, mpsc};
use sphinx_signer::lightning_signer::bitcoin::Network;
use sphinx_signer::sphinx_glyph as glyph;

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

    let error_tx_ = error_tx.clone();
    rocket::tokio::spawn(async move {
        mqtt::start(&seed, network, &pk, &sk, error_tx_)
            .await
            .expect("mqtt crash");
    });

    rocket::tokio::spawn(async move { listen_for_commands(&mut ctrlr, ctrl_rx).await });

    routes::launch_rocket(ctrl_tx, error_tx)
}

async fn listen_for_commands(ctrlr: &mut Controller, mut ctrl_rx: mpsc::Receiver<ChannelRequest>) {
    while let Some(msg) = ctrl_rx.recv().await {
        match ctrlr.handle(&msg.message) {
            Ok((_msg, res)) => {
                let _res_data = rmp_serde::to_vec(&res).expect("could not build control response");
            }
            Err(e) => log::warn!("error parsing ctrl msg {:?}", e),
        };
    }
}
