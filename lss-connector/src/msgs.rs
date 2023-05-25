use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum Msg {
    Init(Init),
    Created(BrokerMutations),
}

#[derive(Serialize, Deserialize)]
pub enum Response {
    Init(InitResponse),
    Created(SignerMutations),
}

pub type Muts = Vec<(String, (u64, Vec<u8>))>;

#[derive(Serialize, Deserialize)]
pub struct Init {
    pub server_pubkey: String,
}

#[derive(Serialize, Deserialize)]
pub struct BrokerMutations {
    pub muts: Muts,
    pub server_hmac: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct SignerMutations {
    pub muts: Muts,
    pub client_hmac: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct InitResponse {
    pub client_id: String,
    pub auth_token: Vec<u8>,
    pub nonce: [u8; 32],
}

impl Msg {
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(rmp_serde::to_vec_named(&self)?)
    }
    pub fn from_slice(s: &[u8]) -> Result<Self> {
        Ok(rmp_serde::from_slice(s)?)
    }
}
impl Response {
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(rmp_serde::to_vec_named(&self)?)
    }
    pub fn from_slice(s: &[u8]) -> Result<Self> {
        Ok(rmp_serde::from_slice(s)?)
    }
}
