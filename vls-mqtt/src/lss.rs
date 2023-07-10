use crate::LssChanMsg;
use anyhow::{anyhow, Result};
use lss_connector::{handle_lss_msg, secp256k1::PublicKey, LssSigner, Msg};
use rocket::tokio::sync::mpsc;
use sphinx_signer::{self, RootHandler, RootHandlerBuilder};

pub async fn init_lss(
    handler_builder: RootHandlerBuilder,
    mut lss_rx: mpsc::Receiver<LssChanMsg>,
) -> Result<(RootHandler, LssSigner)> {
    use sphinx_signer::sphinx_glyph::topics;

    println!("INIT LSS!");

    let first_lss_msg = lss_rx.recv().await.ok_or(anyhow!("couldnt receive"))?;
    let init = Msg::from_slice(&first_lss_msg.message)?.as_init()?;
    let server_pubkey = PublicKey::from_slice(&init.server_pubkey)?;

    let (lss_signer, res1) = LssSigner::new(&handler_builder, &server_pubkey, None);
    let res_topic_1 = topics::INIT_1_RES.to_string();
    if let Err(e) = first_lss_msg.reply_tx.send(Ok((res_topic_1, res1))) {
        log::warn!("could not send on first_lss_msg.reply_tx, {:?}", e);
    }

    let second_lss_msg = lss_rx.recv().await.ok_or(anyhow!("couldnt receive"))?;
    let created = Msg::from_slice(&second_lss_msg.message)?.as_created()?;
    println!("GOT THE CREATED MSG! {:?}", created);

    // build the root handler
    let (root_handler, res2) = lss_signer.build_with_lss(created, handler_builder)?;
    println!("root handler built!!!!!");
    let res_topic_2 = topics::INIT_2_RES.to_string();
    if let Err(e) = second_lss_msg.reply_tx.send(Ok((res_topic_2, res2))) {
        log::warn!("could not send on second_lss_msg.reply_tx, {:?}", e);
    }

    let lss_signer_ = lss_signer.clone();
    rocket::tokio::spawn(async move {
        while let Some(msg) = lss_rx.recv().await {
            let ret = handle_lss_msg(&msg.message, &msg.previous, &lss_signer_);
            let _ = msg.reply_tx.send(ret);
        }
    });

    Ok((root_handler, lss_signer))
}
