use crate::approver::{create_approver, SphinxApprover};
use crate::policy::make_policy;
use sphinx_glyph::types;
use types::{Policy, Velocity};

use anyhow::anyhow;
use lightning_signer::bitcoin::blockdata::constants::ChainHash;
use lightning_signer::bitcoin::Network;
use lightning_signer::node::NodeServices;
use lightning_signer::persist::Persist;
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::signer::StartingTimeFactory;
use lightning_signer::util::clock::{Clock, StandardClock};
use lightning_signer::wallet::Wallet;
use lss_connector::{
    msgs::{Response as LssResponse, SignerMutations},
    LssSigner,
};
use std::sync::Arc;
use vls_protocol::model::PubKey;
use vls_protocol::msgs::{self, read_serial_request_header, write_serial_response_header, Message};
use vls_protocol_signer::handler::{Handler, RootHandler, RootHandlerBuilder};
use vls_protocol_signer::lightning_signer;

pub fn builder(
    seed: [u8; 32],
    network: Network,
    initial_policy: Policy,
    initial_velocity: Option<Velocity>,
    initial_allowlist: Vec<String>,
    persister: Arc<dyn Persist>,
) -> anyhow::Result<(RootHandlerBuilder, Arc<SphinxApprover>)> {
    let clock = Arc::new(StandardClock());
    let random_time_factory = crate::rst::RandomStartingTimeFactory::new();
    Ok(builder_inner(
        seed,
        network,
        initial_policy,
        initial_velocity,
        initial_allowlist,
        persister,
        clock,
        random_time_factory,
    )?)
}

pub fn builder_inner(
    seed: [u8; 32],
    network: Network,
    initial_policy: Policy,
    initial_velocity: Option<Velocity>,
    initial_allowlist: Vec<String>,
    persister: Arc<dyn Persist>,
    clock: Arc<dyn Clock>,
    starting_time_factory: Arc<dyn StartingTimeFactory>,
) -> anyhow::Result<(RootHandlerBuilder, Arc<SphinxApprover>)> {
    //
    let policy = make_policy(network, &initial_policy);
    let validator_factory = Arc::new(SimpleValidatorFactory::new_with_policy(policy));

    let services = NodeServices {
        validator_factory,
        starting_time_factory,
        persister,
        clock: clock.clone(),
    };

    log::info!("create root handler builder with network {:?}", network);
    let mut handler_builder =
        RootHandlerBuilder::new(network, 0, services, seed).allowlist(initial_allowlist);
    // FIXME set up a manual approver (ui_approver)
    let approv = create_approver(clock.clone(), initial_policy, initial_velocity);
    let approver = Arc::new(approv);
    // FIXME need to be able to update approvder velocity control on the fly
    handler_builder = handler_builder.approver(approver.clone());
    Ok((handler_builder, approver))
}

// returns the VLS return msg and the muts
fn handle_inner(
    root_handler: &RootHandler,
    mut bytes: Vec<u8>,
    do_log: bool,
) -> anyhow::Result<(Vec<u8>, Vec<(String, (u64, Vec<u8>))>)> {
    //println!("Signer is handling these bytes: {:?}", bytes);
    let msgs::SerialRequestHeader {
        sequence,
        peer_id,
        dbid,
    } = read_serial_request_header(&mut bytes)
        .map_err(|e| anyhow!("failed read_serial_request_header {:?}", e))?;
    let message = msgs::read(&mut bytes).map_err(|e| anyhow!("failed msgs::read: {:?}", e))?;

    if let Message::HsmdInit(ref m) = message {
        if ChainHash::using_genesis_block(root_handler.node().network()).as_bytes()
            != &m.chain_params.0
        {
            log::warn!("chain network {:?}", &m.chain_params.0);
            log::warn!("root handler network {:?}", root_handler.node().network());
            log::error!("The network setting of CLN and VLS don't match!");
            panic!("The network setting of CLN and VLS don't match!");
        }
    }

    if do_log {
        vls_log(&message);
        // log::info!("VLS: {:?}", message);
        // println!("VLS msg: {:?}", message);
    }
    let reply = if dbid > 0 {
        let handler = root_handler.for_new_client(dbid, PubKey(peer_id), dbid);
        match handler.handle(message) {
            Ok(r) => r,
            Err(e) => {
                return Err(anyhow!("client {} handler error: {:?}", dbid, e));
            }
        }
    } else {
        match root_handler.handle(message) {
            Ok(r) => r,
            Err(e) => return Err(anyhow!("root handler error: {:?}", e)),
        }
    };
    let (vls_msg, muts) = reply;
    // make the VLS message bytes
    let mut buf = Vec::new();
    write_serial_response_header(&mut &mut buf, sequence)
        .map_err(|e| anyhow!("failed write_serial_response_header: {:?}", e))?;
    msgs::write_vec(&mut &mut buf, vls_msg.as_vec())
        .map_err(|e| anyhow!("failed msgs::write_vec: {:?}", e))?;
    //println!("handled message, replying with: {:?}", out_md);
    Ok((buf, muts.into_inner()))
}

pub fn handle(root_handler: &RootHandler, bytes: Vec<u8>, do_log: bool) -> anyhow::Result<Vec<u8>> {
    let (out_bytes, _muts) = handle_inner(root_handler, bytes, do_log)?;
    Ok(out_bytes)
}

pub fn handle_with_lss(
    root_handler: &RootHandler,
    lss_signer: &LssSigner,
    bytes: Vec<u8>,
    do_log: bool,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let (out_bytes, muts) = handle_inner(root_handler, bytes, do_log)?;
    let lss_bytes = if muts.is_empty() {
        Vec::new()
    } else {
        let client_hmac = lss_signer.client_hmac(muts.clone());
        let lss_msg = LssResponse::VlsMuts(SignerMutations { client_hmac, muts });
        lss_msg.to_vec()?
    };
    Ok((out_bytes, lss_bytes))
}

pub fn parse_ping_and_form_response(mut msg_bytes: Vec<u8>) -> Vec<u8> {
    let msgs::SerialRequestHeader {
        sequence,
        peer_id: _,
        dbid: _,
    } = msgs::read_serial_request_header(&mut msg_bytes).expect("read ping header");
    let ping: msgs::Ping = msgs::read_message(&mut msg_bytes).expect("failed to read ping message");
    let mut buf = Vec::new();
    msgs::write_serial_response_header(&mut &mut buf, sequence)
        .expect("failed to write_serial_request_header");
    let pong = msgs::Pong {
        id: ping.id,
        message: ping.message,
    };
    msgs::write(&mut &mut buf, pong).expect("failed to serial write");
    buf
}

fn vls_log(msg: &Message) {
    let m = match msg {
        Message::Ping(_) => "Ping",
        Message::Pong(_) => "Pong",
        Message::HsmdInit(_) => "HsmdInit",
        // HsmdInitReplyV1(HsmdInitReplyV1),
        #[allow(deprecated)]
        Message::HsmdInitReplyV2(_) => "HsmdInitReplyV2",
        Message::HsmdInitReplyV4(_) => "HsmdInitReplyV4",
        Message::HsmdInit2(_) => "HsmdInit2",
        Message::HsmdInit2Reply(_) => "HsmdInit2Reply",
        Message::ClientHsmFd(_) => "ClientHsmFd",
        Message::ClientHsmFdReply(_) => "ClientHsmFdReply",
        Message::SignInvoice(_) => "SignInvoice",
        Message::SignInvoiceReply(_) => "SignInvoiceReply",
        Message::SignWithdrawal(_) => "SignWithdrawal",
        Message::SignWithdrawalReply(_) => "SignWithdrawalReply",
        Message::Ecdh(_) => "Ecdh",
        Message::EcdhReply(_) => "EcdhReply",
        Message::Memleak(_) => "Memleak",
        Message::MemleakReply(_) => "MemleakReply",
        Message::CheckFutureSecret(_) => "CheckFutureSecret",
        Message::CheckFutureSecretReply(_) => "CheckFutureSecretReply",
        Message::SignBolt12(_) => "SignBolt12",
        Message::SignBolt12Reply(_) => "SignBolt12Reply",
        Message::PreapproveInvoice(_) => "PreapproveInvoice",
        Message::PreapproveInvoiceReply(_) => "PreapproveInvoiceReply",
        Message::PreapproveKeysend(_) => "PreapproveKeysend",
        Message::PreapproveKeysendReply(_) => "PreapproveKeysendReply",
        Message::DeriveSecret(_) => "DeriveSecret",
        Message::DeriveSecretReply(_) => "DeriveSecretReply",
        Message::CheckPubKey(_) => "CheckPubKey",
        Message::CheckPubKeyReply(_) => "CheckPubKeyReply",
        Message::SignMessage(_) => "SignMessage",
        Message::SignMessageReply(_) => "SignMessageReply",
        Message::SignChannelUpdate(_) => "SignChannelUpdate",
        Message::SignChannelUpdateReply(_) => "SignChannelUpdateReply",
        Message::SignChannelAnnouncement(_) => "SignChannelAnnouncement",
        Message::SignChannelAnnouncementReply(_) => "SignChannelAnnouncementReply",
        Message::SignNodeAnnouncement(_) => "SignNodeAnnouncement",
        Message::SignNodeAnnouncementReply(_) => "SignNodeAnnouncementReply",
        Message::GetPerCommitmentPoint(_) => "GetPerCommitmentPoint",
        Message::GetPerCommitmentPointReply(_) => "GetPerCommitmentPointReply",
        Message::GetPerCommitmentPoint2(_) => "GetPerCommitmentPoint2",
        Message::GetPerCommitmentPoint2Reply(_) => "GetPerCommitmentPoint2Reply",
        Message::ReadyChannel(_) => "ReadyChannel",
        Message::ReadyChannelReply(_) => "ReadyChannelReply",
        Message::ValidateCommitmentTx(_) => "ValidateCommitmentTx",
        Message::ValidateCommitmentTx2(_) => "ValidateCommitmentTx2",
        Message::ValidateCommitmentTxReply(_) => "ValidateCommitmentTxReply",
        Message::ValidateRevocation(_) => "ValidateRevocation",
        Message::ValidateRevocationReply(_) => "ValidateRevocationReply",
        Message::SignRemoteCommitmentTx(_) => "SignRemoteCommitmentTx",
        Message::SignRemoteCommitmentTx2(_) => "SignRemoteCommitmentTx2",
        Message::SignCommitmentTxWithHtlcsReply(_) => "SignCommitmentTxWithHtlcsReply",
        Message::SignDelayedPaymentToUs(_) => "SignDelayedPaymentToUs",
        Message::SignAnyDelayedPaymentToUs(_) => "SignAnyDelayedPaymentToUs",
        Message::SignRemoteHtlcToUs(_) => "SignRemoteHtlcToUs",
        Message::SignAnyRemoteHtlcToUs(_) => "SignAnyRemoteHtlcToUs",
        Message::SignLocalHtlcTx(_) => "SignLocalHtlcTx",
        Message::SignAnyLocalHtlcTx(_) => "SignAnyLocalHtlcTx",
        Message::SignCommitmentTx(_) => "SignCommitmentTx",
        Message::SignLocalCommitmentTx2(_) => "SignLocalCommitmentTx2",
        Message::SignGossipMessage(_) => "SignGossipMessage",
        Message::SignMutualCloseTx(_) => "SignMutualCloseTx",
        Message::SignMutualCloseTx2(_) => "SignMutualCloseTx2",
        Message::SignTxReply(_) => "SignTxReply",
        Message::SignCommitmentTxReply(_) => "SignCommitmentTxReply",
        Message::GetChannelBasepoints(_) => "GetChannelBasepoints",
        Message::GetChannelBasepointsReply(_) => "GetChannelBasepointsReply",
        Message::NewChannel(_) => "NewChannel",
        Message::NewChannelReply(_) => "NewChannelReply",
        Message::SignRemoteHtlcTx(_) => "SignRemoteHtlcTx",
        Message::SignPenaltyToUs(_) => "SignPenaltyToUs",
        Message::SignAnyPenaltyToUs(_) => "SignAnyPenaltyToUs",
        Message::TipInfo(_) => "TipInfo",
        Message::TipInfoReply(_) => "TipInfoReply",
        Message::ForwardWatches(_) => "ForwardWatches",
        Message::ForwardWatchesReply(_) => "ForwardWatchesReply",
        Message::ReverseWatches(_) => "ReverseWatches",
        Message::ReverseWatchesReply(_) => "ReverseWatchesReply",
        Message::AddBlock(_) => "AddBlock",
        Message::AddBlockReply(_) => "AddBlockReply",
        Message::RemoveBlock(_) => "RemoveBlock",
        Message::RemoveBlockReply(_) => "RemoveBlockReply",
        Message::GetHeartbeat(_) => "GetHeartbeat",
        Message::GetHeartbeatReply(_) => "GetHeartbeatReply",
        Message::NodeInfo(_) => "NodeInfo",
        Message::NodeInfoReply(_) => "NodeInfoReply",
        Message::Unknown(_) => "Unknown",
    };
    log::info!("VLS: => {}", m);
}
