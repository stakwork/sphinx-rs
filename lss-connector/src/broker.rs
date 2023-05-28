use crate::msgs::*;

use anyhow::Result;
use lightning_storage_server::client::Auth;
use secp256k1::PublicKey;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;
use vls_frontend::external_persist::lss::Client as LssClient;
use vls_frontend::external_persist::ExternalPersist;

pub struct LssBroker {
    lss_client: Arc<AsyncMutex<Box<dyn ExternalPersist>>>,
}

// broker emits Msg
// and receives Response
impl LssBroker {
    // returns server pubkey and msg to send to signer
    pub async fn get_server_pubkey(uri: &str) -> Result<(PublicKey, Vec<u8>)> {
        let spk = LssClient::get_server_pubkey(uri).await?;
        let server_pubkey = spk.serialize();
        let msg = Msg::Init(Init { server_pubkey }).to_vec()?;
        Ok((spk, msg))
    }
    // returns Self and the msg to send to signer
    pub async fn new(uri: &str, ir: InitResponse, spk: PublicKey) -> Result<(Self, Vec<u8>)> {
        let client_id = secp256k1::PublicKey::from_slice(&ir.client_id)?;
        let auth = Auth {
            client_id: client_id,
            token: ir.auth_token,
        };
        let client = LssClient::new(uri, &spk, auth).await?;
        let (muts, server_hmac) = client.get("".to_string(), &ir.nonce).await.unwrap();
        log::info!("connected to LSS provider {}", uri);

        let msg = Msg::Created(BrokerMutations { muts, server_hmac }).to_vec()?;

        let lss_client = Arc::new(AsyncMutex::new(Box::new(client) as Box<dyn ExternalPersist>));

        Ok((Self { lss_client }, msg))
    }
    pub async fn put_muts(&self, cm: SignerMutations) -> Result<Vec<u8>> {
        Ok(if !cm.muts.is_empty() {
            let client = self.lss_client.lock().await;
            client.put(cm.muts, &cm.client_hmac).await?
        } else {
            vec![]
        })
    }
    pub async fn handle(&self, res: Response) -> Result<Vec<u8>> {
        match res {
            Response::Init(_) => Ok(vec![]),
            Response::Created(cm) => self.put_muts(cm).await,
            Response::VlsMuts(vlsm) => self.put_muts(vlsm).await,
        }
    }
}
