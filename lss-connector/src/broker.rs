use crate::msgs::*;

use anyhow::Result;
use lightning_storage_server::client::Auth;
use std::sync::{Arc, Mutex};
use vls_frontend::external_persist::lss::Client as LssClient;
use vls_frontend::external_persist::ExternalPersist;
pub struct LssBroker {
    uri: String,
    lss_client: Option<Arc<Mutex<Box<dyn ExternalPersist>>>>,
}

// broker emits Msg
// and receives Response
impl LssBroker {
    pub async fn new(uri: String) -> Result<Self> {
        let spk = LssClient::get_server_pubkey(&uri).await?;
        let broker = Self {
            lss_client: None,
            uri: uri.clone(),
        };
        let server_pubkey = hex::encode(spk.serialize());
        broker.emit(Msg::Init(Init { server_pubkey }))?;
        Ok(broker)
    }
    pub fn emit(&self, msg: Msg) -> Result<()> {
        let d = msg.to_vec()?;
        Ok(())
    }
    pub async fn handle(&mut self, res: Response) -> Result<()> {
        match res {
            Response::Init(ir) => {
                let pk_slice = hex::decode(ir.client_id)?;
                let client_id = secp256k1::PublicKey::from_slice(&pk_slice)?;
                let auth = Auth {
                    client_id: client_id,
                    token: ir.auth_token,
                };
                let client = LssClient::new(&self.uri, &client_id, auth).await?;
                log::info!("connected to LSS provider {}", &self.uri);

                let lss_client = Arc::new(Mutex::new(Box::new(client) as Box<dyn ExternalPersist>));
                self.lss_client = Some(lss_client)
            }
        };
        Ok(())
    }
}
