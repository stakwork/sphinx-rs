use crate::msgs::*;

use anyhow::Result;
use lightning_storage_server::client::Auth;
use secp256k1::PublicKey;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;
use vls_frontend::external_persist::lss::Client as LssClient;
use vls_frontend::external_persist::ExternalPersist;

pub type LssPersister = Arc<AsyncMutex<Box<dyn ExternalPersist>>>;

#[derive(Clone)]
pub struct LssBroker {
    uri: String,
    lss_client: LssPersister,
}

// broker emits Msg
// and receives Response
impl LssBroker {
    pub fn persister(&self) -> LssPersister {
        self.lss_client.clone()
    }

    // returns server pubkey and msg to send to signer
    pub async fn get_server_pubkey(uri: &str) -> Result<(PublicKey, Vec<u8>)> {
        let spk = LssClient::get_server_pubkey(uri).await?;
        let server_pubkey = spk.serialize();
        let msg = Msg::Init(Init { server_pubkey }).to_vec()?;
        Ok((spk, msg))
    }
    // returns Self and the msg to send to signer
    pub async fn new(uri: &str, ir: InitResponse, spk: PublicKey) -> Result<Self> {
        let client_id = secp256k1::PublicKey::from_slice(&ir.client_id)?;
        let auth = Auth {
            client_id: client_id,
            token: ir.auth_token,
        };
        let client = LssClient::new(uri, &spk, auth).await?;
        log::info!("connected to LSS provider {}", uri);

        // let (muts, server_hmac) = client.get("".to_string(), &ir.nonce).await.unwrap();
        // let msg = Msg::Created(BrokerMutations { muts, server_hmac }).to_vec()?;

        let lss_client = Arc::new(AsyncMutex::new(Box::new(client) as Box<dyn ExternalPersist>));
        Ok(Self {
            lss_client,
            uri: uri.to_string(),
        })
    }
    // on reconnection
    pub async fn make_init_msg(&self) -> Result<Vec<u8>> {
        let spk = LssClient::get_server_pubkey(&self.uri).await?;
        let server_pubkey = spk.serialize();
        Ok(Msg::Init(Init { server_pubkey }).to_vec()?)
    }
    // on reconnection
    // if no nonce was sent the the signer does not need state update
    pub async fn get_created_state_msg(&self, ir: &InitResponse) -> Result<Vec<u8>> {
        let bm: BrokerMutations = if let Some(nonce) = ir.nonce {
            self.get_created_state_from_nonce(&nonce).await?
        } else {
            // send empty if not needed
            Default::default()
        };
        Ok(Msg::Created(bm).to_vec()?)
    }
    pub async fn get_created_state_from_nonce(&self, nonce: &[u8]) -> Result<BrokerMutations> {
        let client = self.lss_client.lock().await;
        let (muts, server_hmac) = client.get("".to_string(), nonce).await?;
        Ok(BrokerMutations { muts, server_hmac })
    }
    pub async fn put_muts(&self, cm: SignerMutations) -> Result<Vec<u8>> {
        Ok(if cm.muts.is_empty() {
            Vec::new()
        } else {
            let client = self.lss_client.lock().await;
            client.put(cm.muts, &cm.client_hmac).await?
        })
    }
    pub async fn handle_bytes(&self, resb: &[u8]) -> Result<Vec<u8>> {
        let res = Response::from_slice(resb)?;
        log::info!("HANDLE LSS {:?}", res);
        let msg = self.handle(res).await?;
        log::info!("MSG TO SIGNER: {:?}", msg);
        Ok(msg.to_vec()?)
    }
    pub async fn handle(&self, res: Response) -> Result<Msg> {
        match res {
            Response::Init(_) => Ok(Msg::Created(BrokerMutations {
                muts: Vec::new(),        // empty
                server_hmac: Vec::new(), // empty
            })),
            Response::Created(cm) => {
                let server_hmac = self.put_muts(cm).await?;
                Ok(Msg::Created(BrokerMutations {
                    muts: Vec::new(),
                    server_hmac,
                }))
            }
            Response::VlsMuts(vlsm) => {
                let server_hmac = self.put_muts(vlsm).await?;
                Ok(Msg::Stored(BrokerMutations {
                    muts: Vec::new(),
                    server_hmac,
                }))
            }
        }
    }
}

pub async fn lss_handle(lss: &LssPersister, msg: &[u8]) -> Result<Vec<u8>> {
    log::info!("MSG {:?}", msg);
    let res = Response::from_slice(msg)?.as_vls_muts()?;
    log::info!("res::: {:?}", res);
    let client = lss.lock().await;
    let bm: BrokerMutations = if res.muts.is_empty() {
        Default::default()
    } else {
        let server_hmac = client.put(res.muts, &res.client_hmac).await?;
        BrokerMutations {
            muts: Vec::new(),
            server_hmac,
        }
    };
    Ok(Msg::Stored(bm).to_vec()?)
}
