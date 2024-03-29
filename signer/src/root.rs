use crate::approver::{create_approver, SphinxApprover};
use sphinx_glyph::types;
use types::{Interval, Policy, Velocity};

use lightning_signer::bitcoin::blockdata::constants::ChainHash;
use lightning_signer::bitcoin::Network;
use lightning_signer::io::Cursor;
use lightning_signer::node::NodeServices;
use lightning_signer::persist::{Mutations, Persist};
use lightning_signer::policy::filter::PolicyFilter;
use lightning_signer::policy::simple_validator::{
    make_simple_policy, SimplePolicy, SimpleValidatorFactory,
};
use lightning_signer::signer::StartingTimeFactory;
use lightning_signer::util::clock::Clock;
use lightning_signer::util::velocity::VelocityControlIntervalType;
use lightning_signer::wallet::Wallet;
use lightning_signer::Arc;
use lss_connector::{LssSigner, Response as LssResponse, SignerMutations};
use thiserror::Error;
use vls_protocol::model::PubKey;
use vls_protocol::msgs::{self, read_serial_request_header, write_serial_response_header, Message};
#[cfg(feature = "lowmemory")]
use vls_protocol::serde_bolt::NonContiguousOctets;
use vls_protocol_signer::handler::{Handler, HandlerBuilder, InitHandler, RootHandler};
use vls_protocol_signer::lightning_signer;

#[cfg(feature = "lowmemory")]
pub type MsgBytes = NonContiguousOctets<1024>;
#[cfg(not(feature = "lowmemory"))]
pub type MsgBytes = Vec<u8>;

#[derive(Error, Debug)]
pub enum VlsHandlerError {
    #[error("failed read_serial_request_header: {0}")]
    HeaderRead(String),
    #[error("failed msgs::read: {0}")]
    MsgRead(String),
    #[error("failed write_serial_response_header: {0}")]
    HeaderWrite(String),
    #[error("failed msgs::write_vec: {0}")]
    MsgWrite(String),
    #[error("failed lss_msg.to_vec: {0}")]
    LssWrite(String),
    // vls-mqtt tests against "invalid sequence" at the start of the error
    // message to detect a bad sequence error, exit(0), and restart the signer
    #[error("invalid sequence: {0}, expected {1}")]
    BadSequence(u16, u16),
    #[error("client {0} handler error: {1}")]
    ClientHandle(u64, String),
    #[error("root handler error: {0}")]
    RootHandle(String),
}

pub fn builder(
    seed: [u8; 32],
    network: Network,
    initial_policy: Policy,
    initial_allowlist: Vec<String>,
    initial_velocity: Option<Velocity>,
    persister: Arc<dyn Persist>,
) -> anyhow::Result<(HandlerBuilder, Arc<SphinxApprover>)> {
    let clock = make_clock();
    let random_time_factory = crate::rst::RandomStartingTimeFactory::new();
    builder_inner(
        seed,
        network,
        initial_policy,
        initial_allowlist,
        initial_velocity,
        persister,
        clock,
        random_time_factory,
    )
}

fn make_clock() -> Arc<dyn Clock> {
    #[cfg(not(feature = "no-native"))]
    {
        Arc::new(lightning_signer::util::clock::StandardClock())
    }
    #[cfg(feature = "no-native")]
    {
        use lightning_signer::util::clock::ManualClock;
        use std::time::SystemTime;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        Arc::new(ManualClock::new(timestamp))
    }
}

#[allow(clippy::too_many_arguments)]
pub fn builder_inner(
    seed: [u8; 32],
    network: Network,
    initial_policy: Policy,
    initial_allowlist: Vec<String>,
    initial_velocity: Option<Velocity>,
    persister: Arc<dyn Persist>,
    clock: Arc<dyn Clock>,
    starting_time_factory: Arc<dyn StartingTimeFactory>,
) -> anyhow::Result<(HandlerBuilder, Arc<SphinxApprover>)> {
    //
    let policy = make_policy(network, &initial_policy);
    let validator_factory = Arc::new(SimpleValidatorFactory::new_with_policy(policy));

    let services = NodeServices {
        validator_factory,
        starting_time_factory,
        persister,
        clock: clock.clone(),
    };

    log::debug!("create handler builder with network {:?}", network);
    let mut handler_builder =
        HandlerBuilder::new(network, 0, services, seed).allowlist(initial_allowlist);
    // FIXME set up a manual approver (ui_approver)
    let approv = create_approver(clock.clone(), initial_policy, initial_velocity);
    let approver = Arc::new(approv);
    handler_builder = handler_builder.approver(approver.clone());
    Ok((handler_builder, approver))
}

pub fn make_policy(network: Network, _po: &Policy) -> SimplePolicy {
    let mut p = make_simple_policy(network);
    // let mut p = make_simple_policy(network);
    // p.max_htlc_value_sat = po.htlc_limit_msat;
    p.filter = PolicyFilter::new_permissive();
    // FIXME for prod use a nempty filter
    p
}

pub fn policy_interval(int: Interval) -> VelocityControlIntervalType {
    match int {
        Interval::Hourly => VelocityControlIntervalType::Hourly,
        Interval::Daily => VelocityControlIntervalType::Daily,
    }
}

pub fn handle_init(
    init_handler: &mut InitHandler,
    bytes: Vec<u8>,
    do_log: bool,
) -> Result<(Vec<u8>, bool, String), VlsHandlerError> {
    let mut bytes = Cursor::new(bytes);
    let msgs::SerialRequestHeader {
        sequence,
        peer_id: _,
        dbid: _,
    } = read_serial_request_header(&mut bytes)
        .map_err(|e| VlsHandlerError::HeaderRead(format!("{:?}", e)))?;
    let message =
        msgs::read(&mut bytes).map_err(|e| VlsHandlerError::MsgRead(format!("{:?}", e)))?;
    if let Message::HsmdInit(ref m) = message {
        if ChainHash::using_genesis_block(init_handler.node().network()).as_bytes()
            != m.chain_params.as_ref()
        {
            log::warn!("chain network {:?}", m.chain_params.as_ref());
            log::warn!("init handler network {:?}", init_handler.node().network());
            log::error!("The network setting of CLN and VLS don't match!");
            panic!("The network setting of CLN and VLS don't match!");
        }
    }
    let cmd = vls_cmd(&message);
    if do_log {
        log::info!("VLS INIT: => {}", &cmd);
    }
    let (is_done, vls_msg) = init_handler.handle(message).expect("handle");
    let mut buf = Vec::with_capacity(8usize + vls_msg.as_vec().len());
    write_serial_response_header(&mut buf, sequence)
        .map_err(|e| VlsHandlerError::HeaderWrite(format!("{:?}", e)))?;
    msgs::write_vec(&mut buf, vls_msg.as_vec())
        .map_err(|e| VlsHandlerError::MsgWrite(format!("{:?}", e)))?;
    Ok((buf, is_done, cmd))
}

// returns the VLS return msg and the muts
fn handle_inner(
    root_handler: &RootHandler,
    #[cfg(feature = "lowmemory")] mut bytes: MsgBytes,
    #[cfg(not(feature = "lowmemory"))] bytes: MsgBytes,
    expected_sequence: Option<u16>,
    do_log: bool,
) -> Result<(Vec<u8>, Mutations, u16, String), VlsHandlerError> {
    // println!("Signer is handling these bytes: {:?}", bytes);
    #[cfg(not(feature = "lowmemory"))]
    let mut bytes = Cursor::new(bytes);
    let msgs::SerialRequestHeader {
        sequence,
        peer_id,
        dbid,
    } = read_serial_request_header(&mut bytes)
        .map_err(|e| VlsHandlerError::HeaderRead(format!("{:?}", e)))?;
    log::info!("=> handler sequence: {}", sequence);
    if let Some(expected) = expected_sequence {
        if expected != sequence {
            return Err(VlsHandlerError::BadSequence(sequence, expected));
        }
    }
    let message =
        msgs::read(&mut bytes).map_err(|e| VlsHandlerError::MsgRead(format!("{:?}", e)))?;
    let cmd = vls_cmd(&message);
    if do_log {
        log::info!("VLS: => {}", &cmd);
    }
    let reply = if dbid > 0 {
        let handler = root_handler.for_new_client(dbid, PubKey(peer_id), dbid);
        match handler.handle(message) {
            Ok(r) => r,
            Err(e) => {
                return Err(VlsHandlerError::ClientHandle(dbid, format!("{:?}", e)));
            }
        }
    } else {
        match root_handler.handle(message) {
            Ok(r) => r,
            Err(e) => return Err(VlsHandlerError::RootHandle(format!("{:?}", e))),
        }
    };
    let (vls_msg, mutations) = reply;
    // make the VLS message bytes
    let mut buf = Vec::with_capacity(8usize + vls_msg.as_vec().len());
    write_serial_response_header(&mut buf, sequence)
        .map_err(|e| VlsHandlerError::HeaderWrite(format!("{:?}", e)))?;
    msgs::write_vec(&mut buf, vls_msg.as_vec())
        .map_err(|e| VlsHandlerError::MsgWrite(format!("{:?}", e)))?;
    //println!("handled message, replying with: {:?}", out_md);
    Ok((buf, mutations, sequence, cmd))
}

pub fn handle(
    root_handler: &RootHandler,
    bytes: MsgBytes,
    expected_sequence: Option<u16>,
    do_log: bool,
) -> Result<(Vec<u8>, u16), VlsHandlerError> {
    let (out_bytes, _muts, sequence, _cmd) =
        handle_inner(root_handler, bytes, expected_sequence, do_log)?;
    Ok((out_bytes, sequence))
}

#[allow(clippy::type_complexity)]
pub fn handle_with_lss(
    root_handler: &RootHandler,
    lss_signer: &LssSigner,
    bytes: MsgBytes,
    expected_sequence: Option<u16>,
    do_log: bool,
) -> Result<(Vec<u8>, Vec<u8>, u16, String, Option<[u8; 32]>), VlsHandlerError> {
    let (out_bytes, mutations, sequence, cmd) =
        handle_inner(root_handler, bytes, expected_sequence, do_log)?;
    let mut server_hmac = None;
    let lss_bytes = if mutations.is_empty() {
        Vec::new()
    } else {
        let client_hmac = lss_signer.client_hmac(&mutations);
        // also make server hmac to store for checking later
        server_hmac = Some(lss_signer.server_hmac(&mutations));

        let lss_msg = LssResponse::VlsMuts(SignerMutations {
            client_hmac,
            muts: mutations.into_inner(),
        });

        lss_msg
            .to_vec()
            .map_err(|e| VlsHandlerError::LssWrite(format!("{:?}", e)))?
    };
    Ok((out_bytes, lss_bytes, sequence, cmd, server_hmac))
}

pub fn parse_ping_and_form_response(msg_bytes: Vec<u8>) -> Vec<u8> {
    let mut cursor = Cursor::new(msg_bytes);
    let msgs::SerialRequestHeader {
        sequence,
        peer_id: _,
        dbid: _,
    } = msgs::read_serial_request_header(&mut cursor).expect("read ping header");
    let ping: msgs::Ping = msgs::read_message(&mut cursor).expect("failed to read ping message");
    let mut buf = Vec::new();
    msgs::write_serial_response_header(&mut buf, sequence)
        .expect("failed to write_serial_request_header");
    let pong = msgs::Pong {
        id: ping.id,
        message: ping.message,
    };
    msgs::write(&mut buf, pong).expect("failed to serial write");
    buf
}

fn vls_cmd(msg: &Message) -> String {
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
        Message::SetupChannel(_) => "SetupChannel",
        Message::SetupChannelReply(_) => "SetupChannelReply",
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
        Message::SignAnchorspend(_) => "SignAnchorspend",
        Message::SignAnchorspendReply(_) => "SignAnchorspendReply",
        Message::SignSpliceTx(_) => "SignAnchorspendReply",
        Message::SignHtlcTxMingle(_) => "SignHtlcTxMingle",
        Message::SignHtlcTxMingleReply(_) => "SignHtlcTxMingleReply",
        Message::BlockChunk(_) => "BlockChunk",
        Message::BlockChunkReply(_) => "BlockChunkReply",
        Message::SignerError(_) => "SignerError",
        Message::CheckOutpoint(_) => "CheckOutpoint",
        Message::CheckOutpointReply(_) => "CheckOutpointReply",
        Message::LockOutpoint(_) => "LockOutpoint",
        Message::LockOutpointReply(_) => "LockOutpointReply",
        Message::ForgetChannel(_) => "ForgetChannel",
        Message::ForgetChannelReply(_) => "ForgetChannelReply",
        Message::RevokeCommitmentTx(_) => "RevokeCommitmentTx",
        Message::RevokeCommitmentTxReply(_) => "RevokeCommitmentTxReply",
    };
    m.to_string()
}
