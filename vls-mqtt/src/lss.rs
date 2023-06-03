use crate::LssChanMsg;
use anyhow::{anyhow, Result};
use lss_connector::{secp256k1::PublicKey, LssSigner, Msg as LssMsg, Response as LssRes};
use rocket::tokio::sync::mpsc;
use sphinx_signer::{self, RootHandler, RootHandlerBuilder};

pub async fn init_lss(
    handler_builder: RootHandlerBuilder,
    mut lss_rx: mpsc::Receiver<LssChanMsg>,
) -> Result<(RootHandler, LssSigner)> {
    use sphinx_signer::sphinx_glyph::topics;
    let res_topic = topics::LSS_RES.to_string();

    let first_lss_msg = lss_rx.recv().await.ok_or(anyhow!("couldnt receive"))?;
    let init = LssMsg::from_slice(&first_lss_msg.message)?.as_init()?;
    let server_pubkey = PublicKey::from_slice(&init.server_pubkey)?;

    let (lss_signer, res1) = LssSigner::new(&handler_builder, &server_pubkey);
    if let Err(e) = first_lss_msg.reply_tx.send(Ok((res_topic.clone(), res1))) {
        log::warn!("could not send on first_lss_msg.reply_tx, {:?}", e);
    }

    let second_lss_msg = lss_rx.recv().await.ok_or(anyhow!("couldnt receive"))?;
    let created = LssMsg::from_slice(&second_lss_msg.message)?.as_created()?;
    println!("GOT THE CREATED MSG! {:?}", created);

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
// handles reconnects from broker restarting (init, created msgs)
// return the return_topic and bytes
pub async fn handle_lss_msg(msg: &LssChanMsg, lss_signer: &LssSigner) -> Result<(String, Vec<u8>)> {
    use sphinx_signer::sphinx_glyph::topics;

    // println!("LssMsg::from_slice {:?}", &msg.message);
    let lssmsg = LssMsg::from_slice(&msg.message)?;
    println!("incoming LSS msg {:?}", lssmsg);
    match lssmsg {
        LssMsg::Init(_) => {
            let bs = lss_signer.reconnect_init_response();
            Ok((topics::LSS_RES.to_string(), bs))
        }
        LssMsg::Created(bm) => {
            // dont need to check muts if theyre empty
            if !bm.muts.is_empty() {
                if !lss_signer.check_hmac(&bm) {
                    return Err(anyhow!("Invalid server hmac"));
                }
            }
            let bs = lss_signer.empty_created();
            Ok((topics::LSS_RES.to_string(), bs))
        }
        LssMsg::Stored(bm) => {
            if let None = msg.previous {
                return Err(anyhow!("should be previous msg bytes"));
            }
            let previous = msg.previous.clone().unwrap();
            // get the previous vls msg (where i sent signer muts)
            let prev_lssmsg = LssRes::from_slice(&previous.1)?;
            // println!("previous lss res: {:?}", prev_lssmsg);
            let sm = prev_lssmsg.as_vls_muts()?;
            if sm.muts.is_empty() {
                // empty muts? dont need to check server hmac
                Ok((topics::VLS_RETURN.to_string(), previous.0))
            } else {
                let shmac: [u8; 32] = bm
                    .server_hmac
                    .try_into()
                    .map_err(|_| anyhow!("Invalid server hmac (not 32 bytes)"))?;
                // check the original muts
                let server_hmac = lss_signer.server_hmac(&sm.muts);
                // send back the original VLS response finally
                if server_hmac == shmac {
                    Ok((topics::VLS_RETURN.to_string(), previous.0))
                } else {
                    Err(anyhow!("Invalid server hmac"))
                }
            }
        }
    }
}
