use crate::parser::MsgDriver;
use crate::policy::{make_policy, policy_interval};
use lss_connector::secp256k1::PublicKey;
use sphinx_glyph::types;
use types::Policy;

use anyhow::anyhow;
use lightning_signer::bitcoin::blockdata::constants::ChainHash;
use lightning_signer::node::NodeServices;
use lightning_signer::persist::Persist;
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::util::clock::StandardClock;
use lightning_signer::util::velocity::{VelocityControl, VelocityControlSpec};
use lss_connector::{
    msgs::{Response as LssResponse, SignerMutations},
    LssSigner,
};
use std::sync::Arc;
use vls_protocol::model::PubKey;
use vls_protocol::msgs::{self, read_serial_request_header, write_serial_response_header, Message};
use vls_protocol_signer::approver::{NegativeApprover, VelocityApprover};
use vls_protocol_signer::handler::{Handler, RootHandler, RootHandlerBuilder};
use vls_protocol_signer::lightning_signer;
use vls_protocol_signer::lightning_signer::bitcoin::Network;
use vls_protocol_signer::lightning_signer::wallet::Wallet;

pub fn builder(
    seed: [u8; 32],
    network: Network,
    po: &Policy,
    persister: Arc<dyn Persist>,
    node_id: &PublicKey,
) -> anyhow::Result<(RootHandlerBuilder, Arc<VelocityApprover<NegativeApprover>>)> {
    let allowlist = match persister.get_node_allowlist(node_id) {
        Ok(al) => al,
        Err(_) => {
            log::warn!("no allowlist found in persister!");
            Vec::new()
        }
    };

    let policy = make_policy(network, po);
    let validator_factory = Arc::new(SimpleValidatorFactory::new_with_policy(policy));
    let random_time_factory = crate::rst::RandomStartingTimeFactory::new();
    let clock = Arc::new(StandardClock());
    let services = NodeServices {
        validator_factory,
        starting_time_factory: random_time_factory,
        persister,
        clock: clock.clone(),
    };

    log::info!("create root handler builder with network {:?}", network);
    let mut handler_builder =
        RootHandlerBuilder::new(network, 0, services, seed).allowlist(allowlist);
    // FIXME set up a manual approver (ui_approver)
    let delegate = NegativeApprover();
    let spec = VelocityControlSpec {
        limit_msat: po.msat_per_interval,
        interval_type: policy_interval(po.interval),
    };
    let control = VelocityControl::new(spec);
    // FIXME hydrate state into VelocityApprover
    // VelocityControl::load_from_state(spec, state);
    let approver = Arc::new(VelocityApprover::new(clock.clone(), control, delegate));
    // FIXME need to be able to update approvder velocity control on the fly
    handler_builder = handler_builder.approver(approver.clone());
    // FIXME need to update stored buckets every time?
    // approver.control().get_state()
    Ok((handler_builder, approver))
}

// returns the VLS return msg and the muts
fn handle_inner(
    root_handler: &RootHandler,
    bytes: Vec<u8>,
    do_log: bool,
) -> anyhow::Result<(Vec<u8>, Vec<(String, (u64, Vec<u8>))>)> {
    let mut md = MsgDriver::new(bytes);
    let msgs::SerialRequestHeader {
        sequence,
        peer_id,
        dbid,
    } = read_serial_request_header(&mut md)?;
    let message = msgs::read(&mut md)?;

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
        log::info!("VLS msg: {:?}", message);
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
    let mut out_md = MsgDriver::new_empty();
    write_serial_response_header(&mut out_md, sequence)?;
    msgs::write_vec(&mut out_md, vls_msg.as_vec())?;
    Ok((out_md.bytes(), muts))
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
        let client_hmac = lss_signer.client_hmac(&muts);
        let lss_msg = LssResponse::VlsMuts(SignerMutations { client_hmac, muts });
        lss_msg.to_vec()?
    };
    Ok((out_bytes, lss_bytes))
}

pub fn parse_ping_and_form_response(msg_bytes: Vec<u8>) -> Vec<u8> {
    let mut m = MsgDriver::new(msg_bytes);
    let msgs::SerialRequestHeader {
        sequence,
        peer_id: _,
        dbid: _,
    } = msgs::read_serial_request_header(&mut m).expect("read ping header");
    let ping: msgs::Ping = msgs::read_message(&mut m).expect("failed to read ping message");
    let mut md = MsgDriver::new_empty();
    msgs::write_serial_response_header(&mut md, sequence)
        .expect("failed to write_serial_request_header");
    let pong = msgs::Pong {
        id: ping.id,
        message: ping.message,
    };
    msgs::write(&mut md, pong).expect("failed to serial write");
    md.bytes()
}
