pub use crate::types::{Config, ControlMessage, ControlResponse, Interval, OtaParams, Policy};
use anyhow::Result;
use sphinx_auther::nonce;
use sphinx_auther::secp256k1::{PublicKey, SecretKey};
use sphinx_auther::token::Token;
use std::sync::{Arc, Mutex};

// u64 is the nonce. Each signature must have a higher nonce
pub struct Controller(SecretKey, PublicKey, u64, Arc<Mutex<dyn ControlPersist>>);

impl Controller {
    pub fn new(sk: SecretKey, pk: PublicKey, nonce: u64) -> Self {
        Self(sk, pk, nonce, Arc::new(Mutex::new(DummyPersister)))
    }
    pub fn new_with_persister(
        sk: SecretKey,
        pk: PublicKey,
        per: Arc<Mutex<dyn ControlPersist>>,
    ) -> Self {
        let store1 = per.clone();
        let store = store1.lock().unwrap();
        let nonce = store.read_nonce().unwrap_or(0);
        Self(sk, pk, nonce, per)
    }
    pub fn make_auth_token(&self) -> Result<String> {
        let t = Token::new();
        Ok(t.sign_to_base64(&self.0)?)
    }
    pub fn pubkey(&self) -> PublicKey {
        self.1
    }
    pub fn nonce(&self) -> u64 {
        self.2
    }
    pub fn build_msg(&mut self, msg: ControlMessage) -> anyhow::Result<Vec<u8>> {
        let data = rmp_serde::to_vec_named(&msg)?;
        self.2 = self.2 + 1;
        let ret = nonce::build_msg(&data, &self.0, self.2)?;
        Ok(ret)
    }
    pub fn build_response(&self, msg: ControlResponse) -> anyhow::Result<Vec<u8>> {
        Ok(rmp_serde::to_vec_named(&msg)?)
    }
    pub fn parse_msg(&mut self, input: &[u8]) -> anyhow::Result<ControlMessage> {
        let msg = nonce::parse_msg(input, &self.1, self.2)?;
        let ret = rmp_serde::from_slice(&msg)?;
        self.2 = self.2 + 1;
        Ok(ret)
    }
    pub fn parse_msg_no_nonce(&mut self, input: &[u8]) -> anyhow::Result<(ControlMessage, u64)> {
        let (msg, nonce) = nonce::parse_msg_no_nonce(input, &self.1)?;
        let ret = rmp_serde::from_slice(&msg)?;
        Ok((ret, nonce))
    }
    pub fn parse_response(&self, input: &[u8]) -> anyhow::Result<ControlResponse> {
        Ok(rmp_serde::from_slice(input)?)
    }
    // return the OG message for further processing
    pub fn handle(&mut self, input: &[u8]) -> anyhow::Result<(ControlMessage, ControlResponse)> {
        let msg_nonce = self.parse_msg_no_nonce(input)?;
        let msg = msg_nonce.0;
        // nonce must be higher each time
        if msg_nonce.1 <= self.2 {
            return Err(anyhow::anyhow!("invalid nonce"));
        }
        // increment the nonce EXCEPT for Nonce requests
        let mut store = self.3.lock().unwrap();
        match msg {
            ControlMessage::Nonce => (),
            _ => {
                self.2 = self.2 + 1;
                store.set_nonce(self.2)?;
            }
        }
        let res = match msg.clone() {
            ControlMessage::Nonce => ControlResponse::Nonce(self.2),
            ControlMessage::ResetWifi => {
                store.remove_config()?;
                ControlResponse::ResetWifi
            }
            ControlMessage::ResetKeys => {
                store.remove_seed()?;
                ControlResponse::ResetKeys
            }
            ControlMessage::ResetAll => {
                store.remove_config()?;
                store.remove_seed()?;
                store.remove_policy()?;
                store.set_nonce(0)?;
                ControlResponse::ResetAll
            }
            ControlMessage::QueryPolicy => {
                let p = store.read_policy().unwrap_or_default();
                ControlResponse::PolicyCurrent(p)
            }
            ControlMessage::UpdatePolicy(np) => {
                store.write_policy(np.clone())?;
                ControlResponse::PolicyUpdated(np)
            }
            ControlMessage::QueryAllowlist => ControlResponse::AllowlistCurrent(vec![]),
            ControlMessage::UpdateAllowlist(na) => ControlResponse::AllowlistUpdated(na),
            ControlMessage::Ota(params) => ControlResponse::OtaConfirm(params),
        };
        Ok((msg, res))
    }
}

pub fn build_control_msg(
    msg: ControlMessage,
    nonce: u64,
    secret: &SecretKey,
) -> anyhow::Result<Vec<u8>> {
    let data = rmp_serde::to_vec_named(&msg)?;
    let ret = nonce::build_msg(&data, secret, nonce)?;
    Ok(ret)
}

pub fn parse_control_response(input: &[u8]) -> anyhow::Result<ControlResponse> {
    Ok(rmp_serde::from_slice(input)?)
}

pub fn parse_control_response_to_json(input: &[u8]) -> anyhow::Result<String> {
    let res: ControlResponse = rmp_serde::from_slice(input)?;
    Ok(serde_json::to_string(&res)?)
}

pub fn control_msg_from_json(msg: &[u8]) -> anyhow::Result<ControlMessage> {
    let data: ControlMessage = serde_json::from_slice(msg)?;
    Ok(data)
}

#[derive(Debug)]
pub enum FlashKey {
    Config,
    Seed,
    Nonce,
    Policy,
}
impl FlashKey {
    pub fn as_str(&self) -> &'static str {
        match self {
            FlashKey::Config => "config",
            FlashKey::Seed => "seed",
            FlashKey::Nonce => "nonce",
            FlashKey::Policy => "policy",
        }
    }
}

pub trait ControlPersist: Sync + Send {
    fn read_nonce(&self) -> Result<u64>;
    fn set_nonce(&mut self, nonce: u64) -> Result<()>;
    fn read_config(&self) -> Result<Config>;
    fn write_config(&mut self, c: Config) -> Result<()>;
    fn remove_config(&mut self) -> Result<()>;
    fn read_seed(&self) -> Result<[u8; 32]>;
    fn write_seed(&mut self, s: [u8; 32]) -> Result<()>;
    fn remove_seed(&mut self) -> Result<()>;
    fn read_policy(&self) -> Result<Policy>;
    fn write_policy(&mut self, s: Policy) -> Result<()>;
    fn remove_policy(&mut self) -> Result<()>;
}

pub struct DummyPersister;

impl ControlPersist for DummyPersister {
    fn read_nonce(&self) -> Result<u64> {
        Ok(0u64)
    }
    fn set_nonce(&mut self, _nonce: u64) -> Result<()> {
        Ok(())
    }
    fn read_config(&self) -> Result<Config> {
        Ok(Default::default())
    }
    fn write_config(&mut self, _conf: Config) -> Result<()> {
        Ok(())
    }
    fn remove_config(&mut self) -> Result<()> {
        Ok(())
    }
    fn read_seed(&self) -> Result<[u8; 32]> {
        Ok([0; 32])
    }
    fn write_seed(&mut self, _s: [u8; 32]) -> Result<()> {
        Ok(())
    }
    fn remove_seed(&mut self) -> Result<()> {
        Ok(())
    }
    fn read_policy(&self) -> Result<Policy> {
        Ok(Default::default())
    }
    fn write_policy(&mut self, _s: Policy) -> Result<()> {
        Ok(())
    }
    fn remove_policy(&mut self) -> Result<()> {
        Ok(())
    }
}

// cargo test controller::tests::test_ctrl_json -- --exact
mod tests {

    #[test]
    fn test_ctrl_json() {
        use crate::control::control_msg_from_json;

        let msg = "{}";
        let res = control_msg_from_json(msg.as_bytes());
        if let Ok(_) = res {
            panic!("should have failed");
        }

        let msg = "{\"type\":\"Nonce\"}";
        let _m1 = control_msg_from_json(msg.as_bytes()).expect("Nonce failed");

        let msg = "{\"type\":\"UpdatePolicy\", \"content\":{\"sat_limit\":0, \"interval\":\"hourly\", \"htlc_limit\":10}}";
        control_msg_from_json(msg.as_bytes()).expect("Nonce failed");
    }

    #[test]
    fn test_ctrl_msg() {
        use crate::types::ControlMessage;
        let msg = ControlMessage::Nonce;
        let data = rmp_serde::to_vec_named(&msg).unwrap();
        let _msg: ControlMessage =
            rmp_serde::from_slice(&data).expect("failed to parse ControlMessage from slice");
    }

    #[test]
    fn test_controller() {
        use crate::control::*;
        use sphinx_auther::secp256k1::rand::rngs::OsRng;
        use sphinx_auther::secp256k1::Secp256k1;

        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);

        let msg = "{\"type\":\"Nonce\"}";
        let m1 = control_msg_from_json(msg.as_bytes()).expect("Nonce failed");
        let m2 = build_control_msg(m1, 1, &secret_key).expect("FAIL");

        let mut ctrlr = Controller::new(secret_key, public_key, 0);

        let (_, res) = ctrlr.handle(&m2).expect("failed to handle");
        let built_res = ctrlr.build_response(res).expect("failed to build res");
        let _r = parse_control_response(&built_res).expect("cant parse res");
    }
}
