extern crate alloc;
use alloc::string::String;
use anyhow::{anyhow, Error, Result};
use rmp::{
    decode::{self, RmpRead},
    encode::{self, RmpWrite},
    Marker,
};
use rmp_utils::*;

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
    pub server_hmac: Vec<u8>,
    pub muts: Muts,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignerMutations {
    pub client_hmac: Vec<u8>,
    pub muts: Muts,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InitResponse {
    pub client_id: [u8; 33],
    pub auth_token: Vec<u8>,
    pub nonce: Option<[u8; 32]>,
}

fn serialize_lssmsg(msg: &Msg) -> Result<Vec<u8>> {
    let mut buff = encode::buffer::ByteBuf::new();
    match msg {
        Msg::Init(init) => {
            encode::write_map_len(&mut buff, 1u32).map_err(Error::msg)?;
            encode::write_str(&mut buff, "Init").map_err(Error::msg)?;
            encode::write_map_len(&mut buff, 1u32).map_err(Error::msg)?;
            encode::write_str(&mut buff, "server_pubkey").map_err(Error::msg)?;
            encode::write_bin(&mut buff, &init.server_pubkey).map_err(Error::msg)?;
            Ok(buff.into_vec())
        }
        Msg::Created(bm) => {
            serialize_muts(
                &mut buff,
                "Created",
                "server_hmac",
                &bm.server_hmac,
                &bm.muts,
            )?;
            Ok(buff.into_vec())
        }
        Msg::Stored(bm) => {
            serialize_muts(
                &mut buff,
                "Stored",
                "server_hmac",
                &bm.server_hmac,
                &bm.muts,
            )?;
            Ok(buff.into_vec())
        }
    }
}

fn serialize_lssres(res: &Response) -> Result<Vec<u8>> {
    let mut buff = encode::buffer::ByteBuf::new();
    match res {
        Response::Init(init) => {
            encode::write_map_len(&mut buff, 1u32).map_err(Error::msg)?;
            encode::write_str(&mut buff, "Init").map_err(Error::msg)?;
            encode::write_map_len(&mut buff, 3u32).map_err(Error::msg)?;
            encode::write_str(&mut buff, "client_id").map_err(Error::msg)?;
            encode::write_bin(&mut buff, &init.client_id).map_err(Error::msg)?;
            encode::write_str(&mut buff, "auth_token").map_err(Error::msg)?;
            encode::write_bin(&mut buff, &init.auth_token).map_err(Error::msg)?;
            encode::write_str(&mut buff, "nonce").map_err(Error::msg)?;
            if let Some(arr) = init.nonce {
                encode::write_bin(&mut buff, &arr).map_err(Error::msg)?;
            } else {
                buff.write_u8(Marker::Null.to_u8()).map_err(Error::msg)?;
            }
            Ok(buff.into_vec())
        }
        Response::Created(sm) => {
            serialize_muts(
                &mut buff,
                "Created",
                "client_hmac",
                &sm.client_hmac,
                &sm.muts,
            )?;
            Ok(buff.into_vec())
        }
        Response::VlsMuts(sm) => {
            serialize_muts(
                &mut buff,
                "VlsMuts",
                "client_hmac",
                &sm.client_hmac,
                &sm.muts,
            )?;
            Ok(buff.into_vec())
        }
    }
}

fn serialize_muts(
    buff: &mut encode::buffer::ByteBuf,
    variant: &str,
    hmac_type: &str,
    hmac: &Vec<u8>,
    muts: &Muts,
) -> Result<()> {
    encode::write_map_len(buff, 1u32).map_err(Error::msg)?;
    encode::write_str(buff, variant).map_err(Error::msg)?;
    encode::write_map_len(buff, 2u32).map_err(Error::msg)?;
    encode::write_str(buff, hmac_type).map_err(Error::msg)?;
    encode::write_bin(buff, hmac).map_err(Error::msg)?;
    encode::write_str(buff, "muts").map_err(Error::msg)?;
    serialize_state_vec(buff, muts).map_err(Error::msg)?;
    Ok(())
}

fn deserialize_lssmsg(b: &[u8]) -> Result<Msg> {
    let mut bytes = decode::bytes::Bytes::new(b);
    let length =
        decode::read_map_len(&mut bytes).map_err(|_| Error::msg("could not read map length"))?;
    assert!(length == 1);
    let mut buff = vec![0u8; 64];
    let variant =
        decode::read_str(&mut bytes, &mut buff).map_err(|_| Error::msg("could not read str"))?;
    match variant {
        "Init" => {
            let length = decode::read_map_len(&mut bytes)
                .map_err(|_| Error::msg("could not read map length"))?;
            assert!(length == 1);
            let mut buff = vec![0u8; 64];
            let field_name = decode::read_str(&mut bytes, &mut buff)
                .map_err(|_| Error::msg("could not read str"))?;
            assert!(field_name == "server_pubkey");
            let length = decode::read_bin_len(&mut bytes)
                .map_err(|_| Error::msg("could not read bin length"))?;
            assert!(length == 33);
            let mut server_pubkey = [0u8; 33];
            bytes
                .read_exact_buf(&mut server_pubkey)
                .map_err(Error::msg)?;
            Ok(Msg::Init(Init { server_pubkey }))
        }
        "Created" => Ok(Msg::Created(
            deserialize_brokermuts(&mut bytes).map_err(Error::msg)?,
        )),
        "Stored" => Ok(Msg::Stored(
            deserialize_brokermuts(&mut bytes).map_err(Error::msg)?,
        )),
        m => panic!("wrong: {:?}", m),
    }
}

fn deserialize_lssres(b: &[u8]) -> Result<Response> {
    let mut bytes = decode::bytes::Bytes::new(b);
    let length =
        decode::read_map_len(&mut bytes).map_err(|_| Error::msg("could not read map length"))?;
    assert!(length == 1);
    let mut buff = vec![0u8; 64];
    let variant =
        decode::read_str(&mut bytes, &mut buff).map_err(|_| Error::msg("could not read str"))?;
    match variant {
        "Init" => {
            let length = decode::read_map_len(&mut bytes)
                .map_err(|_| Error::msg("could not read map length"))?;
            println!("{}", length);
            assert!(length == 3);

            // client_id
            let mut buff = vec![0u8; 64];
            let field_name = decode::read_str(&mut bytes, &mut buff)
                .map_err(|_| Error::msg("could not read str"))?;
            assert!(field_name == "client_id");
            let length = decode::read_bin_len(&mut bytes)
                .map_err(|_| Error::msg("could not read bin length"))?;
            assert!(length == 33);
            let mut client_id = [0u8; 33];
            bytes.read_exact_buf(&mut client_id).map_err(Error::msg)?;

            // auth_token
            let mut buff = vec![0u8; 64];
            let field_name = decode::read_str(&mut bytes, &mut buff)
                .map_err(|_| Error::msg("could not read str"))?;
            assert!(field_name == "auth_token");
            let length = decode::read_bin_len(&mut bytes)
                .map_err(|_| Error::msg("could not read bin length"))?;
            assert!(length == 32);
            let mut auth_token = [0u8; 32];
            bytes.read_exact_buf(&mut auth_token).map_err(Error::msg)?;
            let auth_token = auth_token.to_vec();

            // nonce
            let mut buff = vec![0u8; 64];
            let field_name = decode::read_str(&mut bytes, &mut buff)
                .map_err(|_| Error::msg("could not read str"))?;
            assert!(field_name == "nonce");
            let peek = blocks::peek_byte(&mut bytes)?;
            let nonce = if peek == blocks::null_marker_byte() {
                None
            } else {
                let length = decode::read_bin_len(&mut bytes)
                    .map_err(|_| Error::msg("could not read bin length"))?;
                let mut arr = [0u8; 32];
                bytes.read_exact_buf(&mut arr).map_err(Error::msg)?;
                Some(arr)
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
        m => panic!("wrong: {:?}", m),
    }
}

enum MutsDeserializeVariant {
    Broker,
    Signer,
}

fn deserialize_brokermuts(bytes: &mut decode::bytes::Bytes) -> Result<BrokerMutations> {
    let (server_hmac, muts) = deserialize_lssmuts(bytes, MutsDeserializeVariant::Broker)?;
    Ok(BrokerMutations { server_hmac, muts })
}

fn deserialize_signermuts(bytes: &mut decode::bytes::Bytes) -> Result<SignerMutations> {
    let (client_hmac, muts) = deserialize_lssmuts(bytes, MutsDeserializeVariant::Signer)?;
    Ok(SignerMutations { client_hmac, muts })
}

fn deserialize_lssmuts(
    bytes: &mut decode::bytes::Bytes,
    variant: MutsDeserializeVariant,
) -> Result<(Vec<u8>, Muts)> {
    let length =
        decode::read_map_len(bytes).map_err(|_| Error::msg("could not read map length"))?;
    assert!(length == 2);
    let mut buff = vec![0u8; 64];
    let field_name =
        decode::read_str(bytes, &mut buff).map_err(|_| Error::msg("could not read str"))?;
    match variant {
        self::MutsDeserializeVariant::Broker => assert!(field_name == "server_hmac"),
        self::MutsDeserializeVariant::Signer => assert!(field_name == "client_hmac"),
    }
    let length =
        decode::read_bin_len(bytes).map_err(|_| Error::msg("could not read bin length"))?;
    assert!(length == 32);
    let mut hmac = [0u8; 32];
    bytes.read_exact_buf(&mut hmac).map_err(Error::msg)?;
    let field_name =
        decode::read_str(bytes, &mut buff).map_err(|_| Error::msg("could not read str"))?;
    assert!(field_name == "muts");
    let hmac = hmac.to_vec();
    let muts = deserialize_state_vec(bytes).map_err(Error::msg)?;
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
            server_hmac: [u8::MAX; 32].to_vec(),
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
            server_hmac: [u8::MAX; 32].to_vec(),
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
            auth_token: [u8::MAX; 32].to_vec(),
            nonce: Some([u8::MAX; 32]),
        });
        let bytes = serialize_lssres(&test).unwrap();
        let object = deserialize_lssres(&bytes).unwrap();
        assert_eq!(test, object);

        let test = Response::Init(InitResponse {
            client_id: [u8::MAX; 33],
            auth_token: [u8::MAX; 32].to_vec(),
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
            client_hmac: [u8::MAX; 32].to_vec(),
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
            client_hmac: [u8::MAX; 32].to_vec(),
            muts,
        });
        let bytes = serialize_lssres(&test).unwrap();
        let object = deserialize_lssres(&bytes).unwrap();
        assert_eq!(test, object);
    }
}
