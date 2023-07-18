extern crate alloc;
use alloc::string::String;
use anyhow::{anyhow, Error, Result};
use rmp_utils as rmp;

#[derive(Debug, Clone, PartialEq)]
pub enum Msg {
    Init(Init),
    Created(BrokerMutations),
    Stored(BrokerMutations),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    Init(InitResponse),
    Created(SignerMutations),
    VlsMuts(SignerMutations),
}

pub type Muts = Vec<(String, (u64, Vec<u8>))>;

#[derive(Debug, Clone, PartialEq)]
pub struct Init {
    pub server_pubkey: [u8; 33],
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct BrokerMutations {
    pub server_hmac: [u8; 32],
    pub muts: Muts,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignerMutations {
    pub client_hmac: [u8; 32],
    pub muts: Muts,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InitResponse {
    pub client_id: [u8; 33],
    pub auth_token: [u8; 32],
    pub nonce: Option<[u8; 32]>,
}

pub fn serialize_lssmsg(msg: &Msg) -> Result<Vec<u8>> {
    let mut buff = rmp::ByteBuf::new();
    match msg {
        Msg::Init(init) => {
            rmp::serialize_map_len(&mut buff, 1u32)?;
            rmp::serialize_field_name(&mut buff, Some("Init"))?;
            rmp::serialize_map_len(&mut buff, 1u32)?;
            rmp::serialize_bin(
                &mut buff,
                Some("server_pubkey"),
                init.server_pubkey.to_vec(),
            )?;
            Ok(buff.into_vec())
        }
        Msg::Created(bm) => {
            serialize_muts(
                &mut buff,
                "Created",
                "server_hmac",
                bm.server_hmac,
                &bm.muts,
            )?;
            Ok(buff.into_vec())
        }
        Msg::Stored(bm) => {
            serialize_muts(&mut buff, "Stored", "server_hmac", bm.server_hmac, &bm.muts)?;
            Ok(buff.into_vec())
        }
    }
}

pub fn serialize_lssres(res: &Response) -> Result<Vec<u8>> {
    let mut buff = rmp::ByteBuf::new();
    match res {
        Response::Init(init) => {
            rmp::serialize_map_len(&mut buff, 1u32)?;
            rmp::serialize_field_name(&mut buff, Some("Init"))?;
            rmp::serialize_map_len(&mut buff, 3u32)?;
            rmp::serialize_bin(&mut buff, Some("client_id"), init.client_id.to_vec())?;
            rmp::serialize_bin(&mut buff, Some("auth_token"), init.auth_token.to_vec())?;
            if let Some(arr) = init.nonce {
                rmp::serialize_bin(&mut buff, Some("nonce"), arr.to_vec())?;
            } else {
                rmp::serialize_none(&mut buff, Some("nonce"))?;
            }
            Ok(buff.into_vec())
        }
        Response::Created(sm) => {
            serialize_muts(
                &mut buff,
                "Created",
                "client_hmac",
                sm.client_hmac,
                &sm.muts,
            )?;
            Ok(buff.into_vec())
        }
        Response::VlsMuts(sm) => {
            serialize_muts(
                &mut buff,
                "VlsMuts",
                "client_hmac",
                sm.client_hmac,
                &sm.muts,
            )?;
            Ok(buff.into_vec())
        }
    }
}

fn serialize_muts(
    buff: &mut rmp::ByteBuf,
    variant: &str,
    hmac_type: &str,
    hmac: [u8; 32],
    muts: &Muts,
) -> Result<()> {
    rmp::serialize_map_len(buff, 1u32)?;
    rmp::serialize_field_name(buff, Some(variant))?;
    rmp::serialize_map_len(buff, 2u32)?;
    rmp::serialize_bin(buff, Some(hmac_type), hmac.to_vec())?;
    rmp::serialize_state_vec(buff, Some("muts"), muts).map_err(Error::msg)?;
    Ok(())
}

pub fn deserialize_lssmsg(b: &[u8]) -> Result<Msg> {
    let mut bytes = rmp::Bytes::new(b);
    rmp::deserialize_map_len(&mut bytes, 1)?;
    let variant = rmp::deserialize_variant(&mut bytes)?;
    match variant.as_str() {
        "Init" => {
            rmp::deserialize_map_len(&mut bytes, 1)?;
            let mut server_pubkey = [0u8; 33];
            let binary = rmp::deserialize_bin(&mut bytes, Some("server_pubkey"), 33)?
                .ok_or(anyhow!("deserialize_bin: expected Some(Vec<u8>) got None"))?;
            server_pubkey.copy_from_slice(&binary[..]);
            Ok(Msg::Init(Init { server_pubkey }))
        }
        "Created" => Ok(Msg::Created(
            deserialize_brokermuts(&mut bytes).map_err(Error::msg)?,
        )),
        "Stored" => Ok(Msg::Stored(
            deserialize_brokermuts(&mut bytes).map_err(Error::msg)?,
        )),
        m => Err(anyhow!("deserialize_lssmg: not an lssmsg variant {:?}", m)),
    }
}

pub fn deserialize_lssres(b: &[u8]) -> Result<Response> {
    let mut bytes = rmp::Bytes::new(b);
    rmp::deserialize_map_len(&mut bytes, 1)?;
    let variant = rmp::deserialize_variant(&mut bytes)?;
    match variant.as_str() {
        "Init" => {
            rmp::deserialize_map_len(&mut bytes, 3)?;
            // client_id
            let mut client_id = [0u8; 33];
            let binary = rmp::deserialize_bin(&mut bytes, Some("client_id"), 33)?
                .ok_or(anyhow!("deserialize_bin: expected Some(Vec<u8>) got None"))?;
            client_id.copy_from_slice(&binary[..]);
            // auth_token
            let mut auth_token = [0u8; 32];
            let binary = rmp::deserialize_bin(&mut bytes, Some("auth_token"), 32)?
                .ok_or(anyhow!("deserialize_bin: expected Some(Vec<u8>) got None"))?;
            auth_token.copy_from_slice(&binary[..]);
            // nonce
            let mut nonce = None;
            if let Some(binary) = rmp::deserialize_bin(&mut bytes, Some("nonce"), 32)? {
                let mut buff = [0u8; 32];
                buff.copy_from_slice(&binary[..]);
                nonce = Some(buff);
            }
            Ok(Response::Init(InitResponse {
                client_id,
                auth_token,
                nonce,
            }))
        }
        "Created" => Ok(Response::Created(
            deserialize_signermuts(&mut bytes).map_err(Error::msg)?,
        )),
        "VlsMuts" => Ok(Response::VlsMuts(
            deserialize_signermuts(&mut bytes).map_err(Error::msg)?,
        )),
        m => Err(anyhow!("deserialize_lssres: not an lssres variant {:?}", m)),
    }
}

enum MutsDeserializeVariant {
    Broker,
    Signer,
}

fn deserialize_brokermuts(bytes: &mut rmp::Bytes) -> Result<BrokerMutations> {
    let (server_hmac, muts) = deserialize_lssmuts(bytes, MutsDeserializeVariant::Broker)?;
    Ok(BrokerMutations { server_hmac, muts })
}

fn deserialize_signermuts(bytes: &mut rmp::Bytes) -> Result<SignerMutations> {
    let (client_hmac, muts) = deserialize_lssmuts(bytes, MutsDeserializeVariant::Signer)?;
    Ok(SignerMutations { client_hmac, muts })
}

fn deserialize_lssmuts(
    bytes: &mut rmp::Bytes,
    variant: MutsDeserializeVariant,
) -> Result<([u8; 32], Muts)> {
    rmp::deserialize_map_len(bytes, 2)?;
    let binary = match variant {
        self::MutsDeserializeVariant::Broker => {
            rmp::deserialize_bin(bytes, Some("server_hmac"), 32)?
                .ok_or(anyhow!("deserialize_bin: expected Some(Vec<u8>) got None"))?
        }
        self::MutsDeserializeVariant::Signer => {
            rmp::deserialize_bin(bytes, Some("client_hmac"), 32)?
                .ok_or(anyhow!("deserialize_bin: expected Some(Vec<u8>) got None"))?
        }
    };
    let mut hmac = [0u8; 32];
    hmac.copy_from_slice(&binary[..]);
    let muts = rmp::deserialize_state_vec(bytes, Some("muts"))?;
    Ok((hmac, muts))
}

impl Msg {
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        serialize_lssmsg(&self)
    }
    pub fn from_slice(s: &[u8]) -> Result<Self> {
        deserialize_lssmsg(s)
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
        serialize_lssres(&self)
    }
    pub fn from_slice(s: &[u8]) -> Result<Self> {
        deserialize_lssres(s)
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
            server_hmac: [0u8; 32],
        });
        println!("M1 {:?}", m1.to_vec()?);
        // let s = vec![];
        // println!("LEN {:?}", s.len());
        // let m = Msg::from_slice(&s)?;
        // println!("M {:?}", m);
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

    #[test]
    fn test_msgcreated_serde() {
        let muts = vec![
            ("aaaa".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
            ("bbbb".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
            ("cccc".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
        ];
        let test = Msg::Created(BrokerMutations {
            server_hmac: [u8::MAX; 32],
            muts,
        });
        let bytes = serialize_lssmsg(&test).unwrap();
        let object = deserialize_lssmsg(&bytes).unwrap();
        assert_eq!(test, object);
    }

    #[test]
    fn test_msgstored_serde() {
        let muts = vec![
            ("aaaa".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
            ("bbbb".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
            ("cccc".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
        ];
        let test = Msg::Stored(BrokerMutations {
            server_hmac: [u8::MAX; 32],
            muts,
        });
        let bytes = serialize_lssmsg(&test).unwrap();
        let object = deserialize_lssmsg(&bytes).unwrap();
        assert_eq!(test, object);
    }

    #[test]
    fn test_resinit_serde() {
        let test = Response::Init(InitResponse {
            client_id: [u8::MAX; 33],
            auth_token: [u8::MAX; 32],
            nonce: Some([u8::MAX; 32]),
        });
        let bytes = serialize_lssres(&test).unwrap();
        let object = deserialize_lssres(&bytes).unwrap();
        assert_eq!(test, object);

        let test = Response::Init(InitResponse {
            client_id: [u8::MAX; 33],
            auth_token: [u8::MAX; 32],
            nonce: None,
        });
        let bytes = serialize_lssres(&test).unwrap();
        let object = deserialize_lssres(&bytes).unwrap();
        assert_eq!(test, object);
    }

    #[test]
    fn test_rescreated_serde() {
        let muts = vec![
            ("aaaa".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
            ("bbbb".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
            ("cccc".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
        ];
        let test = Response::Created(SignerMutations {
            client_hmac: [u8::MAX; 32],
            muts,
        });
        let bytes = serialize_lssres(&test).unwrap();
        let object = deserialize_lssres(&bytes).unwrap();
        assert_eq!(test, object);
    }

    #[test]
    fn test_resvlsmuts_serde() {
        let muts = vec![
            ("aaaa".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
            ("bbbb".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
            ("cccc".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
        ];
        let test = Response::VlsMuts(SignerMutations {
            client_hmac: [u8::MAX; 32],
            muts,
        });
        let bytes = serialize_lssres(&test).unwrap();
        let object = deserialize_lssres(&bytes).unwrap();
        assert_eq!(test, object);
    }
}
