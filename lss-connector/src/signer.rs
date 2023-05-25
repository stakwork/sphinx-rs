use crate::msgs::*;
use anyhow::{anyhow, Result};
use lightning_signer::persist::{ExternalPersistHelper, SimpleEntropy};
use secp256k1::PublicKey;
use std::collections::BTreeMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use vls_protocol_signer::handler::{RootHandler, RootHandlerBuilder};
use vls_protocol_signer::lightning_signer;

#[derive(Clone)]
pub struct LssSigner {
    pub state: Arc<Mutex<BTreeMap<String, (u64, Vec<u8>)>>>,
    pub helper: ExternalPersistHelper,
    pub emitter: mpsc::Sender<Vec<u8>>,
}

impl LssSigner {
    pub fn new(
        builder: &RootHandlerBuilder,
        server_pubkey: &PublicKey,
        emitter: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        let (keys_manager, _node_id) = builder.build_keys_manager();
        let client_id = keys_manager.get_persistence_pubkey();
        let shared_secret = keys_manager.get_persistence_shared_secret(server_pubkey);
        let auth_token = keys_manager.get_persistence_auth_token(server_pubkey);

        let mut helper = ExternalPersistHelper::new(shared_secret);

        let entropy = SimpleEntropy::new();
        // send client_id and auth_token back to broker
        let msg = Response::Init(InitResponse {
            client_id: hex::encode(client_id.serialize()),
            auth_token: auth_token.to_vec(),
            nonce: helper.new_nonce(&entropy),
        });
        if let Err(e) = emitter.send(msg.to_vec().unwrap()) {
            log::warn!("emitter failed to send {:?}", e);
        }

        let state = Arc::new(Mutex::new(Default::default()));
        Self {
            state,
            helper,
            emitter,
        }
    }
    pub fn build_with_lss(
        &self,
        c: BrokerMutations,
        handler_builder: RootHandlerBuilder,
    ) -> Result<RootHandler> {
        let success = self.helper.check_hmac(&c.muts, c.server_hmac);
        if !success {
            return Err(anyhow!("invalid server hmac"));
        }
        let mut local = self.state.lock().unwrap();
        for (key, version_value) in c.muts.into_iter() {
            local.insert(key, version_value);
        }
        drop(local);
        let handler_builder = handler_builder.lss_state(self.state.clone());
        let (handler, muts) = handler_builder.build();
        let client_hmac = self.helper.client_hmac(&muts);

        let res = Response::Created(SignerMutations { muts, client_hmac });
        self.emit(res)?;

        Ok(handler)
    }
    pub fn emit(&self, res: Response) -> Result<()> {
        let d = res.to_vec()?;
        self.emitter.send(d)?;
        Ok(())
    }
    pub fn handle(&self, msg: Msg) -> Result<()> {
        match msg {
            Msg::Init(_) => (),
            Msg::Created(_) => (),
        }
        Ok(())
    }
}
