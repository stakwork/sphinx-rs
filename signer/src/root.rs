use crate::parser::MsgDriver;
use crate::policy::make_policy;
use sphinx_glyph::types;
use types::Policy;

use anyhow::anyhow;
use lightning_signer::bitcoin::blockdata::constants::ChainHash;
use lightning_signer::node::NodeServices;
use lightning_signer::persist::Persist;
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::util::clock::StandardClock;
use std::sync::Arc;
use vls_protocol::model::PubKey;
use vls_protocol::msgs::{self, read_serial_request_header, write_serial_response_header, Message};
use vls_protocol_signer::handler::{Handler, RootHandler, RootHandlerBuilder};
use vls_protocol_signer::lightning_signer;
use vls_protocol_signer::lightning_signer::bitcoin::Network;
use vls_protocol_signer::lightning_signer::wallet::Wallet;

pub fn init(
    seed: [u8; 32],
    network: Network,
    po: &Policy,
    persister: Arc<dyn Persist>,
) -> anyhow::Result<RootHandler> {
    // FIXME initial allowlist?
    let allowlist = vec![];
    let policy = make_policy(network, po);
    let validator_factory = Arc::new(SimpleValidatorFactory::new_with_policy(policy));
    let random_time_factory = crate::rst::RandomStartingTimeFactory::new();
    let clock = Arc::new(StandardClock());
    let services = NodeServices {
        validator_factory,
        starting_time_factory: random_time_factory,
        persister,
        clock,
    };
    let handler_builder = RootHandlerBuilder::new(network, 0, services, seed).allowlist(allowlist);

    log::info!("create root handler now");
    let (root_handler, _muts) = handler_builder.build();
    // let root_handler = RootHandler::new(network, 0, Some(seed), allowlist, services);
    log::info!("root_handler created");
    Ok(root_handler)
}

pub fn handle(
    root_handler: &RootHandler,
    bytes: Vec<u8>,
    do_log: bool,
) -> anyhow::Result<Vec<u8>> {
    let mut md = MsgDriver::new(bytes);
    let msgs::SerialRequestHeader { sequence, peer_id, dbid } = read_serial_request_header(&mut md).expect("read request header");
    let message = msgs::read(&mut md).expect("message read failed");

    if let Message::HsmdInit(ref m) = message {
        if ChainHash::using_genesis_block(root_handler.node().network()).as_bytes()
            != &m.chain_params.0
        {
            log::error!("The network setting of CLN and VLS don't match!");
            panic!("The network setting of CLN and VLS don't match!");
        }
    }

    if do_log {
        log::info!("VLS msg: {:?}", message);
    }
    let reply = if dbid > 0 {
        let handler = root_handler.for_new_client(dbid, PubKey(peer_id), dbid);
        match handler.handle(message) {
            Ok(r) => r,
            Err(e) => return Err(anyhow!("client {} handler error: {:?}", dbid, e)),
        }
    } else {
        match root_handler.handle(message) {
            Ok(r) => r,
            Err(e) => return Err(anyhow!("root handler error: {:?}", e)),
        }
    };
    if do_log {
        log::info!("VLS msg handled");
    }
    let mut out_md = MsgDriver::new_empty();
    write_serial_response_header(&mut out_md, sequence).expect("write reply header");
    msgs::write_vec(&mut out_md, reply.0.as_vec()).expect("write reply");
    Ok(out_md.bytes())
}

pub fn parse_ping_and_form_response(msg_bytes: Vec<u8>) -> Vec<u8> {
    let mut m = MsgDriver::new(msg_bytes);
    let msgs::SerialRequestHeader { sequence, peer_id: _, dbid: _ } = msgs::read_serial_request_header(&mut m).expect("read ping header");
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
