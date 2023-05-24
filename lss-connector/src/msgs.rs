use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum Msg {
    Init(Init),
}

#[derive(Serialize, Deserialize)]
pub enum Response {
    Init(InitResponse),
}

#[derive(Serialize, Deserialize)]
pub struct Init {
    pub server_pubkey: String,
}

#[derive(Serialize, Deserialize)]
pub struct InitResponse {
    pub client_id: String,
    pub auth_token: Vec<u8>,
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
