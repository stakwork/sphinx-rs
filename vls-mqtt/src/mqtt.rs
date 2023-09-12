use crate::{LssChanMsg, VlsChanMsg};
use anyhow::Result;
use sphinx_auther::secp256k1::{PublicKey, SecretKey};
use sphinx_auther::token::Token;
use sphinx_signer::sphinx_glyph::{sphinx_auther, topics};

use rocket::tokio::sync::{broadcast, mpsc};
use rumqttc::{self, AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS};
use std::env;
use std::error::Error;
use std::process::exit;
use std::time::Duration;

pub async fn start(
    vls_tx: mpsc::Sender<VlsChanMsg>,
    pubkey: &PublicKey,
    secret: &SecretKey,
    error_tx: broadcast::Sender<Vec<u8>>,
    lss_tx: mpsc::Sender<LssChanMsg>,
) -> Result<(), Box<dyn Error>> {
    // alternate between "reconnection" and "handler"
    loop {
        let mut try_i = 0;

        let pubkey = hex::encode(pubkey.serialize());
        let t = Token::new();
        let token = t.sign_to_base64(&secret)?;

        let client_id = random_word(8);
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
            mqttoptions.set_max_packet_size(262144, 262144); // 1024*256
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
        let lss_topic = format!("{}/{}", client_id, topics::LSS_MSG);
        client
            .subscribe(lss_topic, QoS::AtMostOnce)
            .await
            .expect("could not subscribe LSS");
        let init_1_topic = format!("{}/{}", client_id, topics::INIT_1_MSG);
        client
            .subscribe(init_1_topic, QoS::AtMostOnce)
            .await
            .expect("could not subscribe LSS 1");
        let init_2_topic = format!("{}/{}", client_id, topics::INIT_2_MSG);
        client
            .subscribe(init_2_topic, QoS::AtMostOnce)
            .await
            .expect("could not subscribe LSS 2");

        main_listener(
            vls_tx.clone(),
            eventloop,
            &client,
            error_tx.clone(),
            client_id,
            lss_tx.clone(),
        )
        .await;
    }
}

async fn main_listener(
    vls_tx: mpsc::Sender<VlsChanMsg>,
    mut eventloop: EventLoop,
    client: &AsyncClient,
    error_tx: broadcast::Sender<Vec<u8>>,
    client_id: String,
    lss_tx: mpsc::Sender<LssChanMsg>,
) {
    // say hello to start
    publish(client, &client_id, topics::HELLO, &[]).await;

    let mut expected_sequence: Option<u16> = None;
    let mut msgs: Option<(Vec<u8>, Vec<u8>)> = None;
    loop {
        match eventloop.poll().await {
            Ok(event) => {
                if let Some((topic, msg_bytes)) = incoming_bytes(event) {
                    let (return_topic, bytes, sequence) = got_msg(
                        &topic,
                        &msg_bytes,
                        expected_sequence,
                        &vls_tx,
                        &lss_tx,
                        &mut msgs,
                    )
                    .await;
                    if return_topic == topics::ERROR {
                        let _ = error_tx.send(bytes.clone());
                        let error_msg = String::from_utf8(bytes.clone()).unwrap();
                        if error_msg.starts_with("invalid sequence") {
                            exit(0);
                        }
                    } else {
                        if let Some(seq) = sequence {
                            expected_sequence = Some(seq + 1);
                        }
                    }
                    // println!("publish back to broker! {}", &return_topic);
                    publish(client, &client_id, &return_topic, &bytes).await;
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

// VLS->(vls handle)->LSS_RES (lss_bytes)
// LSS_MSG->(lss check hmac)->VLS_RETURN (vls_bytes)

async fn got_msg(
    topic: &str,
    msg_bytes: &[u8],
    expected_sequence: Option<u16>,
    vls_tx: &mpsc::Sender<VlsChanMsg>,
    lss_tx: &mpsc::Sender<LssChanMsg>,
    msgs: &mut Option<(Vec<u8>, Vec<u8>)>,
) -> (String, Vec<u8>, Option<u16>) {
    // println!("GOT MSG on {} {:?}", topic, msg_bytes);
    if topic.ends_with(topics::VLS) {
        let (vls_msg, reply_rx) = VlsChanMsg::new(msg_bytes.to_vec(), expected_sequence);
        let _ = vls_tx.send(vls_msg).await;
        match reply_rx.await.unwrap() {
            Ok((vls_bytes, lss_bytes, sequence, cmd)) => {
                println!("RAN: {:?}", cmd);
                if lss_bytes.len() == 0 {
                    // no muts, respond directly back!
                    (topics::VLS_RES.to_string(), vls_bytes, Some(sequence))
                } else {
                    println!("THERE ARE MUTATIONS!!!!");
                    // muts! do LSS first!
                    *msgs = Some((vls_bytes, lss_bytes.clone()));
                    (topics::LSS_RES.to_string(), lss_bytes, Some(sequence))
                }
            }
            Err(e) => {
                println!("ERROR: {:?}", e);
                (
                    topics::ERROR.to_string(),
                    e.to_string().as_bytes().to_vec(),
                    None,
                )
            }
        }
    } else if topic.ends_with(topics::LSS_MSG)
        || topic.ends_with(topics::INIT_1_MSG)
        || topic.ends_with(topics::INIT_2_MSG)
    {
        let (lss_msg, reply_rx) = LssChanMsg::new(msg_bytes.to_vec(), msgs.clone());
        let _ = lss_tx.send(lss_msg).await;
        match reply_rx.await.unwrap() {
            // these are the vls bytes from before
            Ok((topic, payload)) => {
                // println!("got something back from LSS Helper to send on {}", &topic);
                *msgs = None;
                (topic, payload.to_vec(), None)
            }
            Err(e) => {
                println!("LSS ERROR {:?}", e);
                (
                    topics::ERROR.to_string(),
                    e.to_string().as_bytes().to_vec(),
                    None,
                )
            }
        }
    } else {
        log::warn!("unrecognized topic {}", topic);
        let err = format!("=> bad topic {}", topic);
        (topics::ERROR.to_string(), err.as_bytes().to_vec(), None)
    }
}

async fn publish(client: &AsyncClient, client_id: &str, topic: &str, bytes: &[u8]) {
    let res_topic = format!("{}/{}", &client_id, topic);
    client
        .publish(res_topic, QoS::AtLeastOnce, false, bytes)
        .await
        .expect(&format!("could not publish to {}", topic));
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

use rand::{distributions::Alphanumeric, Rng};

// use crate::mqtt;
pub fn random_word(n: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(n)
        .map(char::from)
        .collect()
}
