use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
pub use vls_protocol_signer::lightning_signer::persist::{ExternalPersistHelper, SimpleEntropy};

#[derive(Clone)]
pub struct LssSigner {
    pub state: Arc<Mutex<BTreeMap<String, (u64, Vec<u8>)>>>,
    pub helper: Option<ExternalPersistHelper>,
}

impl LssSigner {
    pub fn new(&self) -> Self {
        // let pubkey = keys.get_persistence_pubkey();
        // let shared_secret = keys.get_persistence_shared_secret(&server_pubkey);
        // let mut helper = ExternalPersistHelper::new(shared_secret);
        let state = Arc::new(Mutex::new(BTreeMap::new()));
        Self {
            state,
            helper: None,
        }
    }
}
