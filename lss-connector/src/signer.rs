use crate::msgs::*;
use anyhow::{anyhow, Result};
use lightning_signer::persist::{ExternalPersistHelper, SimpleEntropy};
use secp256k1::PublicKey;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use vls_protocol_signer::handler::{RootHandler, RootHandlerBuilder};
use vls_protocol_signer::lightning_signer;

#[derive(Clone)]
pub struct LssSigner {
    pub state: Arc<Mutex<BTreeMap<String, (u64, Vec<u8>)>>>,
    pub helper: ExternalPersistHelper,
    pub client_id: PublicKey,
    pub auth_token: [u8; 32],
}

impl LssSigner {
    pub fn new(builder: &RootHandlerBuilder, server_pubkey: &PublicKey) -> (Self, Vec<u8>) {
        let (keys_manager, _node_id) = builder.build_keys_manager();
        let client_id = keys_manager.get_persistence_pubkey();
        let shared_secret = keys_manager.get_persistence_shared_secret(server_pubkey);
        let auth_token = keys_manager.get_persistence_auth_token(server_pubkey);

        let mut helper = ExternalPersistHelper::new(shared_secret);

        let entropy = SimpleEntropy::new();
        // send client_id and auth_token back to broker
        let msg = Response::Init(InitResponse {
            client_id: client_id.serialize(),
            auth_token: auth_token.to_vec(),
            nonce: Some(helper.new_nonce(&entropy)),
        });
        let msg_bytes = msg.to_vec().unwrap();

        let state = Arc::new(Mutex::new(Default::default()));
        // let helper = Arc::new(Mutex::new(helper));
        (
            Self {
                state,
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
            auth_token: self.auth_token.to_vec(),
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
    ) -> Result<(RootHandler, Vec<u8>)> {
        // let helper = self.helper.lock().unwrap();
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
        let res_bytes = res.to_vec()?;

        Ok((handler, res_bytes))
    }
    pub fn client_hmac(&self, muts: &Muts) -> [u8; 32] {
        self.helper.client_hmac(muts)
    }
    pub fn server_hmac(&self, muts: &Muts) -> [u8; 32] {
        self.helper.server_hmac(muts)
    }
    pub fn check_hmac(&self, bm: &BrokerMutations) -> bool {
        self.helper.check_hmac(&bm.muts, bm.server_hmac.clone())
    }
}

// return the original VLS bytes
// handles reconnects from broker restarting (init, created msgs)
// return the return_topic and bytes
pub async fn handle_lss_msg(
    msg: &[u8],
    previous: &Option<(Vec<u8>, Vec<u8>)>,
    lss_signer: &LssSigner,
) -> Result<(String, Vec<u8>)> {
    use sphinx_glyph::topics;
    use std::convert::TryInto;

    // println!("LssMsg::from_slice {:?}", &msg.message);
    let lssmsg = Msg::from_slice(&msg)?;
    println!("incoming LSS msg {:?}", lssmsg);
    match lssmsg {
        Msg::Init(_) => {
            let bs = lss_signer.reconnect_init_response();
            Ok((topics::LSS_RES.to_string(), bs))
        }
        Msg::Created(bm) => {
            // dont need to check muts if theyre empty
            if !bm.muts.is_empty() {
                if !lss_signer.check_hmac(&bm) {
                    return Err(anyhow!("Invalid server hmac"));
                }
            }
            let bs = lss_signer.empty_created();
            Ok((topics::LSS_RES.to_string(), bs))
        }
        Msg::Stored(bm) => {
            if let None = previous {
                return Err(anyhow!("should be previous msg bytes"));
            }
            let previous = previous.clone().unwrap();
            // get the previous lss msg (where i sent signer muts)
            let prev_lssmsg = Response::from_slice(&previous.1)?;
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
