pub mod derive;
pub mod persist;
pub mod policy;
mod rst;

use anyhow::anyhow;
use lightning_signer::bitcoin::blockdata::constants::ChainHash;
use lightning_signer::node::NodeServices;
use lightning_signer::persist::Persist;
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::util::clock::StandardClock;
use std::sync::Arc;
use vls_protocol::model::{PubKey, Secret};
use vls_protocol::msgs::{self, read_serial_request_header, write_serial_response_header, Message};
use vls_protocol::serde_bolt::WireString;
pub use vls_protocol_signer::handler::{Handler, RootHandler, RootHandlerBuilder};
pub use vls_protocol_signer::lightning_signer;
use vls_protocol_signer::lightning_signer::bitcoin::Network;
use vls_protocol_signer::lightning_signer::wallet::Wallet;
pub use vls_protocol_signer::vls_protocol;

pub use derive::node_keys as derive_node_keys;
use parser::MsgDriver;
use policy::make_policy;
use sphinx_glyph::{parser, types};
use types::Policy;

pub struct InitResponse {
    pub root_handler: RootHandler,
    pub init_reply: Vec<u8>,
}

pub fn init(
    bytes: Vec<u8>,
    network: Network,
    po: &Policy,
    persister: Arc<dyn Persist>,
) -> anyhow::Result<InitResponse> {
    // let persister: Arc<dyn Persist> = Arc::new(DummyPersister);
    let mut md = MsgDriver::new(bytes);
    let (sequence, dbid) = read_serial_request_header(&mut md).expect("read init header");
    assert_eq!(dbid, 0);
    assert_eq!(sequence, 0);
    let init: msgs::HsmdInit2 = msgs::read_message(&mut md).expect("failed to read init message");
    log::info!("init {:?}", init);

    let seed = init.dev_seed.as_ref().map(|s| s.0).expect("no seed");
    let allowlist = init
        .dev_allowlist
        .iter()
        .map(|s| from_wire_string(s))
        .collect::<Vec<_>>();
    log::info!("allowlist {:?}", allowlist);
    let policy = make_policy(network, po);
    let validator_factory = Arc::new(SimpleValidatorFactory::new_with_policy(policy));
    let random_time_factory = rst::RandomStartingTimeFactory::new();
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
    let init_reply = root_handler
        .handle(Message::HsmdInit2(init))
        .expect("handle init");
    let mut reply = MsgDriver::new_empty();
    write_serial_response_header(&mut reply, sequence).expect("write init header");
    msgs::write_vec(&mut reply, init_reply.0.as_vec()).expect("write init reply");
    Ok(InitResponse {
        root_handler,
        init_reply: reply.bytes(),
    })
}

pub fn handle(
    root_handler: &RootHandler,
    bytes: Vec<u8>,
    dummy_peer: PubKey,
    do_log: bool,
) -> anyhow::Result<Vec<u8>> {
    let mut md = MsgDriver::new(bytes);
    let (sequence, dbid) = read_serial_request_header(&mut md).expect("read request header");
    let mut message = msgs::read(&mut md).expect("message read failed");

    // Override the peerid when it is passed in certain messages
    match message {
        Message::NewChannel(ref mut m) => m.node_id = dummy_peer.clone(),
        Message::ClientHsmFd(ref mut m) => m.peer_id = dummy_peer.clone(),
        Message::GetChannelBasepoints(ref mut m) => m.node_id = dummy_peer.clone(),
        Message::SignCommitmentTx(ref mut m) => m.peer_id = dummy_peer.clone(),
        _ => {}
    };

    if let Message::HsmdInit(ref m) = message {
        if ChainHash::using_genesis_block(root_handler.node.network()).as_bytes()
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
        let handler = root_handler.for_new_client(dbid, dummy_peer.clone(), dbid);
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

pub fn make_init_msg(network: Network, seed: [u8; 32]) -> anyhow::Result<Vec<u8>> {
    let allowlist = Vec::new();
    log::info!("allowlist {:?} seed {:?}", allowlist, seed);
    let init = msgs::HsmdInit2 {
        derivation_style: 0,
        network_name: WireString(network.to_string().as_bytes().to_vec()),
        dev_seed: Some(Secret(seed)),
        dev_allowlist: allowlist,
    };
    let sequence = 0;
    let mut md = MsgDriver::new_empty();
    msgs::write_serial_request_header(&mut md, sequence, 0)?;
    msgs::write(&mut md, init)?;
    Ok(md.bytes())
}

fn from_wire_string(s: &WireString) -> String {
    String::from_utf8(s.0.to_vec()).expect("malformed string")
}
