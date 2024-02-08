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
    client_id: &str,
    error_tx: broadcast::Sender<Vec<u8>>,
    lss_tx: mpsc::Sender<LssChanMsg>,
    commit_tx: mpsc::Sender<()>,
) -> Result<(), Box<dyn Error>> {
    // alternate between "reconnection" and "handler"
    loop {
        let mut try_i = 0;

        let pubkey = hex::encode(pubkey.serialize());
        let t = Token::new();
        let token = t.sign_to_base64(secret)?;

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
                    if incoming_conn_ack(event).is_some() {
                        println!("==========> MQTT connected!");
                        break (client, eventloop);
                    }
                }
                Err(e) => {
                    try_i += 1;
                    println!("reconnect.... {} {:?}", try_i, e);
                    rocket::tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };

        for t in topics::SIGNER_SUBS {
            let top = format!("{}/{}", client_id, t);
            client
                .subscribe(top, QoS::AtMostOnce)
                .await
                .expect("could not subscribe");
        }

        main_listener(
            vls_tx.clone(),
            eventloop,
            &client,
            error_tx.clone(),
            client_id,
            lss_tx.clone(),
            commit_tx.clone(),
        )
        .await;
    }
}

async fn main_listener(
    vls_tx: mpsc::Sender<VlsChanMsg>,
    mut eventloop: EventLoop,
    client: &AsyncClient,
    error_tx: broadcast::Sender<Vec<u8>>,
    client_id: &str,
    lss_tx: mpsc::Sender<LssChanMsg>,
    commit_tx: mpsc::Sender<()>,
) {
    // say hello to start
    publish(client, client_id, topics::HELLO, &[]).await;

    let mut expected_sequence: Option<u16> = None;
    let mut msgs: Option<(Vec<u8>, [u8; 32])> = None;
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
                        &commit_tx,
                        &mut msgs,
                    )
                    .await;
                    if return_topic == topics::ERROR {
                        let _ = error_tx.send(bytes.clone());
                        let error_msg = String::from_utf8(bytes.clone()).unwrap();
                        log::error!("ERROR {}", error_msg);
                        if error_msg.starts_with("invalid sequence") {
                            exit(0);
                        }
                        // if error_msg.contains("PutConflict") {
                        //     exit(0);
                        // }
                    } else if let Some(seq) = sequence {
                        expected_sequence = Some(seq + 1);
                    }
                    // println!("publish back to broker! {}", &return_topic);
                    publish(client, client_id, &return_topic, &bytes).await;
                    if return_topic == topics::LSS_CONFLICT_RES {
                        log::warn!("LSS PUT CONFLICT... RESTART");
                        exit(0);
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

// VLS->(vls handle)->LSS_RES (lss_bytes)
// LSS_MSG->(lss check hmac)->VLS_RETURN (vls_bytes)

async fn got_msg(
    topic: &str,
    msg_bytes: &[u8],
    expected_sequence: Option<u16>,
    vls_tx: &mpsc::Sender<VlsChanMsg>,
    lss_tx: &mpsc::Sender<LssChanMsg>,
    commit_tx: &mpsc::Sender<()>,
    msgs: &mut Option<(Vec<u8>, [u8; 32])>,
) -> (String, Vec<u8>, Option<u16>) {
    // println!("GOT MSG on {} {:?}", topic, msg_bytes);
    if topic.ends_with(topics::VLS) {
        let (vls_msg, reply_rx) = VlsChanMsg::new(msg_bytes.to_vec(), expected_sequence);
        let _ = vls_tx.send(vls_msg).await;
        match reply_rx.await.unwrap() {
            Ok((vls_bytes, lss_bytes, sequence, cmd, server_hmac)) => {
                println!("RAN: {:?}", cmd);
                if let Some(shmac) = server_hmac {
                    // muts! do LSS first!
                    // do not commit until LSS storage is verified...
                    *msgs = Some((vls_bytes, shmac));
                    (topics::LSS_RES.to_string(), lss_bytes, Some(sequence))
                } else {
                    // commit immediately if no muts
                    let _ = commit_tx.send(()).await;
                    // no muts, respond directly back!
                    (topics::VLS_RES.to_string(), vls_bytes, Some(sequence))
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
        || topic.ends_with(topics::INIT_3_MSG)
        || topic.ends_with(topics::LSS_CONFLICT)
    {
        let (lss_msg, reply_rx) = LssChanMsg::new(msg_bytes.to_vec(), msgs.clone());
        let _ = lss_tx.send(lss_msg).await;
        match reply_rx.await.unwrap() {
            // these are the vls bytes from before
            Ok((ret_topic, payload)) => {
                *msgs = None;
                // if it was Ok, hmac was matched for BrokerMutations
                if topic.ends_with(topics::LSS_MSG) {
                    let _ = commit_tx.send(()).await;
                }
                (ret_topic, payload.to_vec(), None)
            }
            Err(e) => (
                topics::ERROR.to_string(),
                e.to_string().as_bytes().to_vec(),
                None,
            ),
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
        .unwrap_or_else(|_| panic!("could not publish to {}", topic));
}

fn incoming_bytes(event: Event) -> Option<(String, Vec<u8>)> {
    if let Event::Incoming(Packet::Publish(p)) = event {
        return Some((p.topic, p.payload.to_vec()));
    }
    None
}

fn incoming_conn_ack(event: Event) -> Option<()> {
    if let Event::Incoming(Packet::ConnAck(_)) = event {
        return Some(());
    }
    None
}

// use rand::{distributions::Alphanumeric, Rng};

// pub fn random_word(n: usize) -> String {
//     rand::thread_rng()
//         .sample_iter(&Alphanumeric)
//         .take(n)
//         .map(char::from)
//         .collect()
// }
