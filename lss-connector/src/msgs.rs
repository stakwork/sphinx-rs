extern crate alloc;
use alloc::string::String;
use anyhow::{anyhow, Error, Result};
use rmp::{
    decode::{self, RmpRead},
    encode,
};
use rmp_serde::encode::Error as RmpError;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
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

fn serialize_lssmsg(msg: &Msg) -> Result<Vec<u8>> {
    let mut buff = encode::buffer::ByteBuf::new();
    match msg {
        Msg::Init(init) => {
            encode::write_map_len(&mut buff, 1u32).map_err(Error::msg)?;
            encode::write_str(&mut buff, "Init").map_err(Error::msg)?;
            encode::write_bin(&mut buff, &init.server_pubkey).map_err(Error::msg)?;
            Ok(buff.into_vec())
        }
        Msg::Created(bm) => todo!(),
        Msg::Stored(bm) => todo!(),
    }
}

fn deserialize_lssmsg(b: &[u8]) -> Result<Msg> {
    let mut bytes = decode::bytes::Bytes::new(b);
    let length =
        decode::read_map_len(&mut bytes).map_err(|_| Error::msg("could not read map lenght"));
    let mut buff = vec![0u8; 64];
    let variant =
        decode::read_str(&mut bytes, &mut buff).map_err(|_| Error::msg("could not read str"))?;
    match variant {
        "Init" => {
            let length = decode::read_bin_len(&mut bytes)
                .map_err(|_| Error::msg("could not read bin length"))?;
            assert!(length == 33);
            let mut server_pubkey = [0u8; 33];
            bytes
                .read_exact_buf(&mut server_pubkey)
                .map_err(Error::msg)?;
            Ok(Msg::Init(Init { server_pubkey }))
        }
        "Created" => todo!(),
        "Stored" => todo!(),
        m => panic!("wrong: {:?}", m),
    }
}

fn serialize_lssres(res: &Response) -> Result<Vec<u8>> {
    match res {
        Response::Init(init_response) => todo!(),
        Response::Created(sm) => todo!(),
        Response::VlsMuts(sm) => todo!(),
    }
}

fn deserialize_lssres(b: &[u8]) -> Result<Response> {
    todo!();
}

pub type Muts = Vec<(String, (u64, Vec<u8>))>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Init {
    #[serde(with = "BigArray")]
    pub server_pubkey: [u8; 33],
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
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

    #[test]
    fn test_msginit_serde() {
        let test = Msg::Init(Init {
            server_pubkey: [u8::MAX; 33],
        });
        let bytes = serialize_lssmsg(&test).unwrap();
        let object = deserialize_lssmsg(&bytes).unwrap();
        assert_eq!(test, object);
    }
}
