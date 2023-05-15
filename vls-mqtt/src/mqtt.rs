use sphinx_auther::secp256k1::{PublicKey, SecretKey};
use sphinx_auther::token::Token;
use sphinx_signer::sphinx_glyph::{sphinx_auther, topics};

use rocket::tokio::sync::broadcast;
use rumqttc::{self, AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS};
use sphinx_signer::{self, root, RootHandler};
use std::env;
use std::error::Error;
use std::time::Duration;

pub async fn start(
    root_handler: &RootHandler,
    pubkey: &PublicKey,
    secret: &SecretKey,
    error_tx: broadcast::Sender<Vec<u8>>,
) -> Result<(), Box<dyn Error>> {
    // alternate between "reconnection" and "handler"
    loop {
        let mut try_i = 0;

        let pubkey = hex::encode(pubkey.serialize());
        let t = Token::new();
        let token = t.sign_to_base64(&secret)?;

        let client_id = format!("sphinx-{}", random_word(8));
        let broker: String = env::var("BROKER").unwrap_or("localhost:1883".to_string());

        println!(".......... start eventloop ..........");
        let (client, eventloop) = loop {
            let mut mqtturl = format!("{}?client_id={}", broker, client_id);
            if !(mqtturl.starts_with("mqtt://") || mqtturl.starts_with("mqtts://")) {
                let scheme = if mqtturl.contains("8883") {
                    "mqtts"
                } else {
                    "mqtt"
                };
                mqtturl = format!("{}://{}", scheme, mqtturl);
            }
            println!("===> connect to {}", mqtturl);

            let mut mqttoptions = MqttOptions::parse_url(mqtturl).unwrap();

            // let mut mqttoptions = MqttOptions::new(&client_id, broker_[0], broker_port);
            mqttoptions.set_credentials(pubkey.clone(), token.clone());
            mqttoptions.set_keep_alive(Duration::from_secs(5));
            let (client, mut eventloop) = AsyncClient::new(mqttoptions, 10);
            match eventloop.poll().await {
                Ok(event) => {
                    if let Some(_) = incoming_conn_ack(event) {
                        println!("==========> MQTT connected!");
                        break (client, eventloop);
                    }
                }
                Err(e) => {
                    try_i = try_i + 1;
                    println!("reconnect.... {} {:?}", try_i, e);
                    rocket::tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };

        let vls_topic = format!("{}/{}", client_id, topics::VLS);
        client
            .subscribe(vls_topic, QoS::AtMostOnce)
            .await
            .expect("could not subscribe VLS");
        let ctrl_topic = format!("{}/{}", client_id, topics::CONTROL);
        client
            .subscribe(ctrl_topic, QoS::AtMostOnce)
            .await
            .expect("could not subscribe CTRL");
        let lss_res_topic = format!("{}/{}", client_id, topics::LSS_RES);
        client
            .subscribe(lss_res_topic, QoS::AtMostOnce)
            .await
            .expect("could not subscribe LSS");

        run_main(
            root_handler,
            eventloop,
            &client,
            error_tx.clone(),
            client_id,
        )
        .await;
    }
}

use rand::{distributions::Alphanumeric, Rng};

// use crate::mqtt;
pub fn random_word(n: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(n)
        .map(char::from)
        .collect()
}

async fn run_main(
    root_handler: &RootHandler,
    mut eventloop: EventLoop,
    client: &AsyncClient,
    error_tx: broadcast::Sender<Vec<u8>>,
    client_id: String,
) {
    loop {
        match eventloop.poll().await {
            Ok(event) => {
                if let Some((topic, msg_bytes)) = incoming_bytes(event) {
                    if topic.ends_with(topics::VLS) {
                        // println!("Got VLS message of length: {}", msg_bytes.len());
                        match root::handle(root_handler, msg_bytes, true) {
                            Ok(b) => {
                                let return_topic = format!("{}/{}", &client_id, topics::VLS_RETURN);
                                client
                                    .publish(return_topic, QoS::AtLeastOnce, false, b)
                                    .await
                                    .expect("could not publish init response")
                            }
                            Err(e) => {
                                let error_topic = format!("{}/{}", &client_id, topics::ERROR);
                                // publish errors back to broker AND locally
                                client
                                    .publish(
                                        error_topic,
                                        QoS::AtLeastOnce,
                                        false,
                                        e.to_string().as_bytes(),
                                    )
                                    .await
                                    .expect("could not publish error response");
                                let _ = error_tx.send(e.to_string().as_bytes().to_vec());
                            }
                        };
                    } else if topic.ends_with(topics::LSS_RES) {
                        // check hmac
                        // update local state
                    } else if topic.ends_with(topics::CONTROL) {
                        //
                    } else {
                        log::info!("invalid topic");
                    }
                }
            }
            Err(e) => {
                log::warn!("diconnected {:?}", e);
                rocket::tokio::time::sleep(Duration::from_secs(1)).await;
                break; // break out of this loop to reconnect
            }
        }
    }
}

fn incoming_bytes(event: Event) -> Option<(String, Vec<u8>)> {
    if let Event::Incoming(packet) = event {
        if let Packet::Publish(p) = packet {
            return Some((p.topic, p.payload.to_vec()));
        }
    }
    None
}

fn incoming_conn_ack(event: Event) -> Option<()> {
    if let Event::Incoming(packet) = event {
        if let Packet::ConnAck(_) = packet {
            return Some(());
        }
    }
    None
}
