use fsdb::{Bucket, DoubleBucket, Fsdb};
use lightning_signer::bitcoin::secp256k1::PublicKey;
use lightning_signer::chain::tracker::ChainTracker;
use lightning_signer::channel::{Channel, ChannelId, ChannelStub};
use lightning_signer::monitor::ChainMonitor;
use lightning_signer::node::{NodeConfig, NodeState as CoreNodeState};
use lightning_signer::persist::model::{
    ChannelEntry as CoreChannelEntry, NodeEntry as CoreNodeEntry,
};
use lightning_signer::persist::ChainTrackerListenerEntry;
use lightning_signer::persist::Persist;
use lightning_signer::policy::validator::{EnforcementState, ValidatorFactory};
use lightning_signer::Arc;
use lightning_signer::SendSync;
use std::string::String;
use vls_persist::model::{
    AllowlistItemEntry, ChainTrackerEntry, ChannelEntry, NodeEntry, NodeStateEntry,
};
use vls_protocol_signer::lightning_signer;
use vls_protocol_signer::lightning_signer::persist::Error;

pub use vls_persist::backup_persister::BackupPersister;
pub use vls_persist::thread_memo_persister::ThreadMemoPersister;

pub struct FsPersister {
    nodes: Bucket<NodeEntry>,
    states: Bucket<NodeStateEntry>,
    channels: DoubleBucket<ChannelEntry>,
    allowlist: Bucket<AllowlistItemEntry>,
    chaintracker: Bucket<ChainTrackerEntry>,
    pubkeys: Bucket<PublicKey>,
}

impl SendSync for FsPersister {}

impl FsPersister {
    pub fn new(dir: &str, maxsize: Option<usize>) -> Self {
        let db = Fsdb::new(dir).expect("could not create db");
        Self {
            nodes: db.bucket("nodes", maxsize).expect("fail nodes"),
            states: db.bucket("states", maxsize).expect("fail states"),
            channels: db.double_bucket("channel", maxsize).expect("fail channel"),
            allowlist: db.bucket("allowlis", maxsize).expect("fail allowlis"),
            chaintracker: db.bucket("chaintra", maxsize).expect("fail chaintra"),
            pubkeys: db.bucket("pubkey", maxsize).expect("fail pubkey"),
        }
    }
}

fn get_channel_key(channel_id: &[u8]) -> &[u8] {
    let length = channel_id.len();
    channel_id.get(length - 11..length - 7).unwrap()
}

impl Persist for FsPersister {
    fn new_node(
        &self,
        node_id: &PublicKey,
        config: &NodeConfig,
        state: &CoreNodeState,
    ) -> Result<(), Error> {
        let pk = hex::encode(node_id.serialize());
        let state_entry = state.into();
        let _ = self.states.put(&pk, &state_entry);
        let node_entry = NodeEntry {
            key_derivation_style: config.key_derivation_style as u8,
            network: config.network.to_string(),
        };
        let _ = self.nodes.put(&pk, &node_entry);
        let _ = self.pubkeys.put(&pk, &node_id);
        Ok(())
    }
    fn update_node(&self, node_id: &PublicKey, state: &CoreNodeState) -> Result<(), Error> {
        let pk = hex::encode(node_id.serialize());
        let state_entry = state.into();
        let _ = self.states.put(&pk, &state_entry);
        Ok(())
    }
    fn delete_node(&self, node_id: &PublicKey) -> Result<(), Error> {
        let pk = hex::encode(node_id.serialize());
        // clear all channel entries within "pk" sub-bucket
        let _ = self.channels.clear(&pk);
        let _ = self.nodes.remove(&pk);
        let _ = self.pubkeys.remove(&pk);
        Ok(())
    }
    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), Error> {
        let pk = hex::encode(node_id.serialize());
        let chan_id = hex::encode(get_channel_key(stub.id0.as_slice()));
        // this breaks things...
        // if let Ok(_) = self.channels.get(&pk, &chan_id) {
        //     log::error!("persister: failed to create new_channel: already exists");
        //     // return Err(()); // already exists
        // }
        let entry = ChannelEntry {
            id: Some(stub.id0.clone()),
            channel_value_satoshis: 0,
            channel_setup: None,
            enforcement_state: EnforcementState::new(0),
            blockheight: Some(stub.blockheight),
        };
        let _ = self.channels.put(&pk, &chan_id, &entry);
        Ok(())
    }
    fn delete_channel(&self, node_id: &PublicKey, channel: &ChannelId) -> Result<(), Error> {
        let pk = hex::encode(node_id.serialize());
        let chan_id = hex::encode(get_channel_key(channel.as_slice()));
        let _ = self.channels.remove(&pk, &chan_id);
        Ok(())
    }
    fn new_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error> {
        let pk = hex::encode(node_id.serialize());
        let _ = self.chaintracker.put(&pk, &tracker.into());
        Ok(())
    }
    fn update_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error> {
        log::info!("=> update_tracker");
        let pk = hex::encode(node_id.serialize());
        let _ = self.chaintracker.put(&pk, &tracker.into());
        log::info!("=> update_tracker complete");
        Ok(())
    }
    fn get_tracker(
        &self,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
    ) -> Result<(ChainTracker<ChainMonitor>, Vec<ChainTrackerListenerEntry>), Error> {
        let pk = hex::encode(node_id.serialize());
        let ret: ChainTrackerEntry = match self.chaintracker.get(&pk) {
            Ok(ct) => ct,
            Err(_) => {
                log::error!("persister: failed to get_tracker");
                return Err(Error::NotFound("Failed on get_tracker".to_string()));
            }
        };
        Ok(ret.into_tracker(node_id, validator_factory))
    }
    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), Error> {
        // log::info!("=> update_channel");
        let pk = hex::encode(node_id.serialize());
        let chan_id = hex::encode(get_channel_key(channel.id0.as_slice()));
        // this breaks things...
        // if let Err(_) = self.channels.get(&pk, &chan_id) {
        //     log::error!("persister: failed to update_channel");
        //     // return Err(()); // not found
        // }
        let entry = ChannelEntry {
            id: Some(channel.id0.clone()),
            channel_value_satoshis: channel.setup.channel_value_sat,
            channel_setup: Some(channel.setup.clone()),
            enforcement_state: channel.enforcement_state.clone(),
            blockheight: None,
        };
        let _ = self.channels.put(&pk, &chan_id, &entry);
        // log::info!("=> update_channel complete!");
        Ok(())
    }
    fn get_channel(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<CoreChannelEntry, Error> {
        let pk = hex::encode(node_id.serialize());
        let chan_id = hex::encode(get_channel_key(channel_id.as_slice()));
        let ret: ChannelEntry = match self.channels.get(&pk, &chan_id) {
            Ok(ce) => ce,
            Err(_) => {
                log::error!("persister: failed to get_channel");
                return Err(Error::NotFound("Failed on get_channel".to_string()));
            }
        };
        Ok(ret.into())
    }
    fn get_node_channels(
        &self,
        node_id: &PublicKey,
    ) -> Result<Vec<(ChannelId, CoreChannelEntry)>, Error> {
        let mut res = Vec::new();
        let pk = hex::encode(node_id.serialize());
        let list = match self.channels.list(&pk) {
            Ok(l) => l,
            Err(_) => return Ok(res),
        };
        for channel in list {
            if let Ok(entry) = self.channels.get(&pk, &channel) {
                let id = entry.id.clone().unwrap();
                res.push((id, entry.into()));
            };
        }
        Ok(res)
    }
    fn update_node_allowlist(
        &self,
        node_id: &PublicKey,
        allowlist: Vec<String>,
    ) -> Result<(), Error> {
        let pk = hex::encode(node_id.serialize());
        let entry = AllowlistItemEntry { allowlist };
        let _ = self.allowlist.put(&pk, &entry);
        Ok(())
    }
    fn get_node_allowlist(&self, node_id: &PublicKey) -> Result<Vec<String>, Error> {
        let pk = hex::encode(node_id.serialize());
        let entry: AllowlistItemEntry = match self.allowlist.get(&pk) {
            Ok(e) => e,
            Err(_) => return Ok(Vec::new()),
        };
        Ok(entry.allowlist)
    }
    fn get_nodes(&self) -> Result<Vec<(PublicKey, CoreNodeEntry)>, Error> {
        let mut res = Vec::new();
        let list = match self.nodes.list() {
            Ok(ns) => ns,
            Err(_) => return Ok(res),
        };
        log::info!("NODE LIST LEN {}", list.len());
        for pk in list {
            if let Ok(pubkey) = self.pubkeys.get(&pk) {
                if let Ok(node) = self.nodes.get(&pk) {
                    if let Ok(state_entry) = self.states.get(&pk) {
                        let state = CoreNodeState {
                            invoices: Default::default(),
                            issued_invoices: Default::default(),
                            payments: Default::default(),
                            excess_amount: 0,
                            log_prefix: "".to_string(),
                            velocity_control: state_entry.velocity_control.into(),
                            fee_velocity_control: state_entry.fee_velocity_control.into(),
                            last_summary: String::new(),
                        };
                        let entry = CoreNodeEntry {
                            key_derivation_style: node.key_derivation_style,
                            network: node.network,
                            state,
                        };
                        res.push((pubkey, entry));
                    }
                }
            }
        }
        Ok(res)
    }
    fn clear_database(&self) -> Result<(), Error> {
        let _ = self.nodes.clear();
        let _ = self.channels.clear_all();
        let _ = self.allowlist.clear();
        let _ = self.chaintracker.clear();
        let _ = self.pubkeys.clear();
        Ok(())
    }
    fn recovery_required(&self) -> bool {
        self.nodes.list().unwrap_or(Vec::new()).len() == 0
    }
}
