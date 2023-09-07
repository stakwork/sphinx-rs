use crate::msgs::*;
use anyhow::{anyhow, Result};
use lightning_signer::persist::ExternalPersistHelper;
use lightning_signer::persist::Mutations;
use secp256k1::PublicKey;
use std::collections::BTreeMap;
use vls_protocol_signer::handler::{RootHandler, RootHandlerBuilder};
use vls_protocol_signer::lightning_signer;

#[cfg(not(feature = "no-native"))]
pub use lightning_signer::persist::SimpleEntropy;

#[cfg(feature = "no-native")]
use crate::not_entropy::NotEntropy;

#[derive(Clone)]
pub struct LssSigner {
    pub helper: ExternalPersistHelper,
    pub client_id: PublicKey,
    pub auth_token: [u8; 32],
}

impl LssSigner {
    pub fn new(
        builder: &RootHandlerBuilder,
        server_pubkey: &PublicKey,
        _nonce: Option<[u8; 32]>,
    ) -> (Self, Vec<u8>) {
        let (keys_manager, _node_id) = builder.build_keys_manager();
        let client_id = keys_manager.get_persistence_pubkey();
        let shared_secret = keys_manager.get_persistence_shared_secret(server_pubkey);
        let auth_token = keys_manager.get_persistence_auth_token(server_pubkey);

        let mut helper = ExternalPersistHelper::new(shared_secret);

        #[allow(unused_assignments)]
        let mut new_nonce = [0; 32];
        #[cfg(not(feature = "no-native"))]
        {
            let entropy = SimpleEntropy::new();
            new_nonce = helper.new_nonce(&entropy);
        }
        #[cfg(feature = "no-native")]
        {
            let n = _nonce.expect("nonce must be provided in no-std mode");
            let entropy = NotEntropy::new(n);
            new_nonce = helper.new_nonce(&entropy);
        }

        // send client_id and auth_token back to broker
        let msg = Response::Init(InitResponse {
            client_id: client_id.serialize(),
            auth_token,
            nonce: Some(new_nonce),
        });
        let msg_bytes = msg.to_vec().unwrap();

        (
            Self {
                helper,
                client_id,
                auth_token,
            },
            msg_bytes,
        )
    }
    // on reconnection (broker died?)
    pub fn reconnect_init_response(&self) -> Vec<u8> {
        let msg = Response::Init(InitResponse {
            client_id: self.client_id.serialize(),
            auth_token: self.auth_token,
            nonce: None,
        });
        println!("===> reconnect_init_response {:?}", msg);
        msg.to_vec().unwrap()
    }
    // on reconnection, empty muts and no hmac
    pub fn empty_created(&self) -> Vec<u8> {
        let res = Response::Created(SignerMutations {
            muts: Vec::new(),
            client_hmac: [0; 32],
        });
        res.to_vec().unwrap()
    }
    pub fn build_with_lss(
        &self,
        c: BrokerMutations,
        handler_builder: RootHandlerBuilder,
        state: Option<BTreeMap<String, (u64, Vec<u8>)>>,
    ) -> Result<(RootHandler, Vec<u8>)> {
        // let helper = self.helper.lock().unwrap();
        let muts = Mutations::from_vec(c.muts);
        let success = self.helper.check_hmac(
            &muts,
            c.server_hmac
                .ok_or(anyhow!("build_with_lss: server_hmac is none"))?
                .to_vec(),
        );
        if !success {
            return Err(anyhow!("invalid server hmac"));
        }

        let mut sta = BTreeMap::new(); // state.unwrap_or_default();
        for (key, version_value) in muts.into_iter() {
            sta.insert(key, version_value);
        }
        if let Some(stat) = state {
            for (key, version_value) in stat {
                sta.insert(key, version_value);
            }
        }

        let muts: Vec<_> = sta
            .iter()
            .map(|(k, (v, vv))| (k.clone(), (*v, vv.clone())))
            .collect();
        let persister = handler_builder.persister();
        persister
            .put_batch_unlogged(Mutations::from_vec(muts))
            .expect("put_batch_unlogged");

        // let st = Arc::new(Mutex::new(sta));
        // let handler_builder = handler_builder.lss_state(st);
        let (handler, muts) = handler_builder
            .build()
            .map_err(|_| anyhow!("failed to build"))?;
        persister
            .commit()
            .map_err(|_| anyhow!("failed to commit"))?;
        let client_hmac = self.helper.client_hmac(&muts);

        let res = Response::Created(SignerMutations {
            muts: muts.into_inner(),
            client_hmac,
        });
        let res_bytes = res.to_vec()?;

        Ok((handler, res_bytes))
    }
    pub fn client_hmac(&self, mutations: &Mutations) -> [u8; 32] {
        self.helper.client_hmac(mutations)
    }
    pub fn server_hmac(&self, mutations: &Mutations) -> [u8; 32] {
        self.helper.server_hmac(mutations)
    }
    pub fn check_hmac(&self, bm: BrokerMutations) -> bool {
        match bm.server_hmac {
            Some(hmac) => self
                .helper
                .check_hmac(&Mutations::from_vec(bm.muts), hmac.to_vec()),
            None => false,
        }
    }
}

// return the original VLS bytes
// handles reconnects from broker restarting (init, created msgs)
// return the return_topic and bytes
pub fn handle_lss_msg(
    msg: &[u8],
    previous: Option<(Vec<u8>, Vec<u8>)>,
    lss_signer: &LssSigner,
) -> Result<(String, Vec<u8>)> {
    use sphinx_glyph::topics;

    // println!("LssMsg::from_slice {:?}", &msg.message);
    let lssmsg = Msg::from_slice(&msg)?;
    // println!("incoming LSS msg {:?}", lssmsg);
    match lssmsg {
        Msg::Init(_) => {
            let bs = lss_signer.reconnect_init_response();
            Ok((topics::INIT_1_RES.to_string(), bs))
        }
        Msg::Created(bm) => {
            // dont need to check muts if theyre empty
            if !bm.muts.is_empty() {
                if !lss_signer.check_hmac(bm) {
                    return Err(anyhow!("Invalid server hmac"));
                }
            }
            let bs = lss_signer.empty_created();
            Ok((topics::INIT_2_RES.to_string(), bs))
        }
        Msg::Stored(bm) => {
            let previous = previous.ok_or(anyhow!("should be previous msg bytes"))?;
            // get the previous lss msg (where i sent signer muts)
            let prev_lssmsg = Response::from_slice(&previous.1)?;
            // println!("previous lss res: {:?}", prev_lssmsg);
            let sm = prev_lssmsg.into_vls_muts()?;
            if sm.muts.is_empty() {
                // empty muts? dont need to check server hmac
                Ok((topics::VLS_RES.to_string(), previous.0))
            } else {
                let shmac: [u8; 32] = bm
                    .server_hmac
                    .ok_or(anyhow!("muts are not empty, but server_hmac is none"))?;
                // check the original muts
                let server_hmac = lss_signer.server_hmac(&Mutations::from_vec(sm.muts));
                // send back the original VLS response finally
                if server_hmac == shmac {
                    Ok((topics::VLS_RES.to_string(), previous.0))
                } else {
                    Err(anyhow!("Invalid server hmac"))
                }
            }
        }
    }
}
