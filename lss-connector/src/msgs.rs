extern crate alloc;
use alloc::string::String;
use anyhow::{anyhow, Error, Result};
use rmp_utils as rmp;

#[derive(Debug, Clone, PartialEq)]
pub enum Msg {
    Init(Init),
    Created(BrokerMutations),
    Stored(BrokerMutations),
    PutConflict,
}

impl std::fmt::Display for Msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Msg::Init(_) => write!(f, "Init"),
            Msg::Created(_) => write!(f, "Created"),
            Msg::Stored(_) => write!(f, "Stored"),
            Msg::PutConflict => write!(f, "PutConflict"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    Init(InitResponse),
    Created(SignerMutations),
    VlsMuts(SignerMutations),
    PutConflictConfirmed,
}

impl std::fmt::Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Response::Init(_) => write!(f, "Init"),
            Response::Created(_) => write!(f, "Created"),
            Response::VlsMuts(_) => write!(f, "VlsMuts"),
            Response::PutConflictConfirmed => write!(f, "PutConflictConfirmed"),
        }
    }
}

pub type Muts = Vec<(String, (u64, Vec<u8>))>;

#[derive(Debug, Clone, PartialEq)]
pub struct Init {
    pub server_pubkey: [u8; 33],
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct BrokerMutations {
    pub server_hmac: Option<[u8; 32]>,
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
            rmp::serialize_bin(&mut buff, Some("server_pubkey"), &init.server_pubkey)?;
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
        Msg::PutConflict => {
            rmp::serialize_map_len(&mut buff, 1u32)?;
            rmp::serialize_field_name(&mut buff, Some("PutConflict"))?;
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
            rmp::serialize_bin(&mut buff, Some("client_id"), &init.client_id)?;
            rmp::serialize_bin(&mut buff, Some("auth_token"), &init.auth_token)?;
            if let Some(arr) = init.nonce {
                rmp::serialize_bin(&mut buff, Some("nonce"), &arr)?;
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
                Some(sm.client_hmac),
                &sm.muts,
            )?;
            Ok(buff.into_vec())
        }
        Response::VlsMuts(sm) => {
            serialize_muts(
                &mut buff,
                "VlsMuts",
                "client_hmac",
                Some(sm.client_hmac),
                &sm.muts,
            )?;
            Ok(buff.into_vec())
        }
        Response::PutConflictConfirmed => {
            rmp::serialize_map_len(&mut buff, 1u32)?;
            rmp::serialize_field_name(&mut buff, Some("PutConflictConfirmed"))?;
            Ok(buff.into_vec())
        }
    }
}

fn serialize_muts(
    buff: &mut rmp::ByteBuf,
    variant: &str,
    hmac_type: &str,
    hmac: Option<[u8; 32]>,
    muts: &Muts,
) -> Result<()> {
    rmp::serialize_map_len(buff, 1u32)?;
    rmp::serialize_field_name(buff, Some(variant))?;
    rmp::serialize_map_len(buff, 2u32)?;
    match hmac {
        Some(hmac) => rmp::serialize_bin(buff, Some(hmac_type), &hmac)?,
        None => rmp::serialize_none(buff, Some(hmac_type))?,
    }
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
            let binary = rmp::deserialize_bin(&mut bytes, Some("server_pubkey"), 33)?;
            server_pubkey.copy_from_slice(&binary[..]);
            Ok(Msg::Init(Init { server_pubkey }))
        }
        "Created" => Ok(Msg::Created(
            deserialize_brokermuts(&mut bytes).map_err(Error::msg)?,
        )),
        "Stored" => Ok(Msg::Stored(
            deserialize_brokermuts(&mut bytes).map_err(Error::msg)?,
        )),
        "PutConflict" => Ok(Msg::PutConflict),
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
            let binary = rmp::deserialize_bin(&mut bytes, Some("client_id"), 33)?;
            client_id.copy_from_slice(&binary[..]);
            // auth_token
            let mut auth_token = [0u8; 32];
            let binary = rmp::deserialize_bin(&mut bytes, Some("auth_token"), 32)?;
            auth_token.copy_from_slice(&binary[..]);
            // nonce
            let nonce = if rmp::peek_is_none(&mut bytes, Some("nonce"))? {
                rmp::deserialize_none(&mut bytes, Some("nonce"))?;
                None
            } else {
                let mut nonce = [0u8; 32];
                let binary = rmp::deserialize_bin(&mut bytes, Some("nonce"), 32)?;
                nonce.copy_from_slice(&binary[..]);
                Some(nonce)
            };

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
        "PutConflictConfirmed" => Ok(Response::PutConflictConfirmed),
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
    let client_hmac = client_hmac.ok_or(anyhow!("deserialize_signermuts: client_hmac is none"))?;
    Ok(SignerMutations { client_hmac, muts })
}

fn deserialize_lssmuts(
    bytes: &mut rmp::Bytes,
    variant: MutsDeserializeVariant,
) -> Result<(Option<[u8; 32]>, Muts)> {
    rmp::deserialize_map_len(bytes, 2)?;
    let hmac = match variant {
        self::MutsDeserializeVariant::Broker => {
            if rmp::peek_is_none(bytes, Some("server_hmac"))? {
                rmp::deserialize_none(bytes, Some("server_hmac"))?;
                None
            } else {
                let mut server_hmac = [0u8; 32];
                let binary = rmp::deserialize_bin(bytes, Some("server_hmac"), 32)?;
                server_hmac.copy_from_slice(&binary[..]);
                Some(server_hmac)
            }
        }
        self::MutsDeserializeVariant::Signer => {
            let mut client_hmac = [0u8; 32];
            let binary = rmp::deserialize_bin(bytes, Some("client_hmac"), 32)?;
            client_hmac.copy_from_slice(&binary[..]);
            Some(client_hmac)
        }
    };
    let muts = rmp::deserialize_state_vec(bytes, Some("muts"))?;
    Ok((hmac, muts))
}

impl Msg {
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        serialize_lssmsg(self)
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
        serialize_lssres(self)
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
    pub fn get_muts(self) -> Result<Muts> {
        match self {
            Response::Created(m) => Ok(m.muts),
            Response::VlsMuts(m) => Ok(m.muts),
            _ => Err(anyhow!("no muts msg")),
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
            server_hmac: None,
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
    fn test_msgputconflict_serde() {
        let test = Msg::PutConflict;
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
            server_hmac: Some([u8::MAX; 32]),
            muts,
        });
        let bytes = serialize_lssmsg(&test).unwrap();
        let object = deserialize_lssmsg(&bytes).unwrap();
        assert_eq!(test, object);

        let test = Msg::Created(BrokerMutations {
            server_hmac: None,
            muts: Vec::new(),
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
            server_hmac: Some([u8::MAX; 32]),
            muts,
        });
        let bytes = serialize_lssmsg(&test).unwrap();
        let object = deserialize_lssmsg(&bytes).unwrap();
        assert_eq!(test, object);

        let test = Msg::Stored(BrokerMutations {
            server_hmac: None,
            muts: Vec::new(),
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
            nonce: Some([2u8; 32]),
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

    #[test]
    fn test_resputconflict_serde() {
        let test = Response::PutConflictConfirmed;
        let bytes = serialize_lssres(&test).unwrap();
        let object = deserialize_lssres(&bytes).unwrap();
        assert_eq!(test, object);
    }
}
