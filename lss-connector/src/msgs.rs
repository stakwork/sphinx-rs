use anyhow::{anyhow, Result};
use rmp_serde::encode::Error as RmpError;
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
    pub server_hmac: Vec<u8>,
    pub muts: Muts,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignerMutations {
    pub client_hmac: [u8; 32],
    pub muts: Muts,
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
        let mut size = 1000;
        let mut arr = vec![0u8; size].into_boxed_slice();
        let mut buff = std::io::Cursor::new(arr);
        loop {
            match rmp_serde::encode::write_named(&mut buff, &self) {
                Ok(()) => break Ok(()),
                Err(RmpError::InvalidValueWrite(_)) => {
                    size = size + 1000;
                    drop(buff);
                    arr = vec![0u8; size].into_boxed_slice();
                    buff = std::io::Cursor::new(arr);
                }
                Err(e) => break Err(e),
            }
        }?;
        let ret = buff.into_inner().into_vec();
        Ok(ret)
    }
    pub fn from_slice(s: &[u8]) -> Result<Self> {
        let ret = rmp_serde::from_slice(s)?;
        Ok(ret)
    }
    pub fn into_init(self) -> Result<Init> {
        match self {
            Msg::Init(i) => Ok(i),
            _ => Err(anyhow!("not an init msg")),
        }
    }
    pub fn into_created(self) -> Result<BrokerMutations> {
        match self {
            Msg::Created(m) => Ok(m),
            _ => Err(anyhow!("not a created msg")),
        }
    }
    pub fn into_stored(self) -> Result<BrokerMutations> {
        match self {
            Msg::Stored(m) => Ok(m),
            _ => Err(anyhow!("not a stored msg")),
        }
    }
}
impl Response {
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let mut size = 1000;
        let mut arr = vec![0u8; size].into_boxed_slice();
        let mut buff = std::io::Cursor::new(arr);
        loop {
            match rmp_serde::encode::write_named(&mut buff, &self) {
                Ok(()) => break Ok(()),
                Err(RmpError::InvalidValueWrite(_)) => {
                    size = size + 1000;
                    drop(buff);
                    arr = vec![0u8; size].into_boxed_slice();
                    buff = std::io::Cursor::new(arr);
                }
                Err(e) => break Err(e),
            }
        }?;
        let ret = buff.into_inner().into_vec();
        Ok(ret)
    }
    pub fn from_slice(s: &[u8]) -> Result<Self> {
        let ret = rmp_serde::from_slice(s)?;
        Ok(ret)
    }
    pub fn into_init(self) -> Result<InitResponse> {
        match self {
            Response::Init(i) => Ok(i),
            _ => Err(anyhow!("not an init msg")),
        }
    }
    pub fn into_created(self) -> Result<SignerMutations> {
        match self {
            Response::Created(m) => Ok(m),
            _ => Err(anyhow!("not a created msg")),
        }
    }
    pub fn into_vls_muts(self) -> Result<SignerMutations> {
        match self {
            Response::VlsMuts(m) => Ok(m),
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

    #[test]
    fn test_muts() -> anyhow::Result<()> {
        let m = vec![("hi".to_string(), (23, vec![1, 2, 3]))];
        let bytes = rmp_serde::to_vec_named(&m);
        println!("bytes {:?}", bytes);
        Ok(())
    }
}
