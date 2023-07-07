use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Msg {
    Init(Init),
    Created(BrokerMutations),
    Stored(BrokerMutations),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Response {
    Init(InitResponse),
    Created(SignerMutations),
    VlsMuts(SignerMutations),
}

pub type Muts = Vec<(String, (u64, Vec<u8>))>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Init {
    #[serde(with = "BigArray")]
    pub server_pubkey: [u8; 33],
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BrokerMutations {
    pub muts: Muts,
    pub server_hmac: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignerMutations {
    pub muts: Muts,
    pub client_hmac: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InitResponse {
    #[serde(with = "BigArray")]
    pub client_id: [u8; 33],
    pub auth_token: Vec<u8>,
    pub nonce: Option<[u8; 32]>,
}

impl Msg {
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let arr: Box<[u8]> = Box::new([0u8; 9000]);
        let mut buff = std::io::Cursor::new(arr);
        rmp_serde::encode::write_named(&mut buff, &self)?;
        let ret = buff.into_inner().into_vec();
        Ok(ret)
    }
    pub fn from_slice(s: &[u8]) -> Result<Self> {
        let ret = rmp_serde::from_slice(s)?;
        Ok(ret)
    }
    pub fn as_init(&self) -> Result<Init> {
        match self {
            Msg::Init(i) => Ok(i.clone()),
            _ => Err(anyhow!("not an init msg")),
        }
    }
    pub fn as_created(&self) -> Result<BrokerMutations> {
        match self {
            Msg::Created(m) => Ok(m.clone()),
            _ => Err(anyhow!("not a created msg")),
        }
    }
    pub fn as_stored(&self) -> Result<BrokerMutations> {
        match self {
            Msg::Stored(m) => Ok(m.clone()),
            _ => Err(anyhow!("not a stored msg")),
        }
    }
}
impl Response {
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let arr: Box<[u8]> = Box::new([0u8; 9000]);
        let mut buff = std::io::Cursor::new(arr);
        rmp_serde::encode::write_named(&mut buff, &self)?;
        let ret = buff.into_inner().into_vec();
        Ok(ret)
    }
    pub fn from_slice(s: &[u8]) -> Result<Self> {
        let ret = rmp_serde::from_slice(s)?;
        Ok(ret)
    }
    pub fn as_init(&self) -> Result<InitResponse> {
        match self {
            Response::Init(i) => Ok(i.clone()),
            _ => Err(anyhow!("not an init msg")),
        }
    }
    pub fn as_created(&self) -> Result<SignerMutations> {
        match self {
            Response::Created(m) => Ok(m.clone()),
            _ => Err(anyhow!("not a created msg")),
        }
    }
    pub fn as_vls_muts(&self) -> Result<SignerMutations> {
        match self {
            Response::VlsMuts(m) => Ok(m.clone()),
            _ => Err(anyhow!("not a VlsMuts msg")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lss_msg() -> anyhow::Result<()> {
        let m1 = Msg::Created(BrokerMutations {
            muts: Vec::new(),
            server_hmac: Vec::new(),
        });
        println!("M1 {:?}", m1.to_vec()?);
        // let s = vec![];
        // println!("LEN {:?}", s.len());
        // let m = Msg::from_slice(&s)?;
        // println!("M {:?}", m);
        Ok(())
    }
}
