use crate::msgs::*;

use anyhow::Result;
use lightning_storage_server::client::Auth;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use vls_frontend::external_persist::lss::Client as LssClient;
use vls_frontend::external_persist::ExternalPersist;

pub struct LssBroker {
    lss_client: Arc<Mutex<Box<dyn ExternalPersist>>>,
    emitter: mpsc::Sender<Vec<u8>>,
}

// broker emits Msg
// and receives Response
impl LssBroker {
    pub async fn get_server_pubkey_and_emit_init(
        uri: &str,
        emitter: mpsc::Sender<Vec<u8>>,
    ) -> Result<()> {
        let spk = LssClient::get_server_pubkey(uri).await?;
        let server_pubkey = hex::encode(spk.serialize());
        let msg = Msg::Init(Init { server_pubkey }).to_vec()?;
        emitter.send(msg)?;
        Ok(())
    }
    pub async fn new(uri: &str, ir: InitResponse, emitter: mpsc::Sender<Vec<u8>>) -> Result<Self> {
        let pk_slice = hex::decode(ir.client_id)?;
        let client_id = secp256k1::PublicKey::from_slice(&pk_slice)?;
        let auth = Auth {
            client_id: client_id,
            token: ir.auth_token,
        };
        let client = LssClient::new(uri, &client_id, auth).await?;
        let (muts, server_hmac) = client.get("".to_string(), &ir.nonce).await.unwrap();
        log::info!("connected to LSS provider {}", uri);

        let msg = Msg::Created(BrokerMutations { muts, server_hmac });
        emitter.send(msg.to_vec()?)?;

        let lss_client = Arc::new(Mutex::new(Box::new(client) as Box<dyn ExternalPersist>));

        Ok(Self {
            lss_client,
            emitter,
        })
    }
    pub fn emit(&self, msg: Msg) -> Result<()> {
        let d = msg.to_vec()?;
        self.emitter.send(d)?;
        Ok(())
    }
    pub async fn handle(&self, res: Response) -> Result<()> {
        match res {
            Response::Init(_) => (),
            Response::Created(cm) => {
                let client = self.lss_client.lock().unwrap();
                client.put(cm.muts, &cm.client_hmac).await?;
            }
        };
        Ok(())
    }
}
