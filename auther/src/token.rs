use crate::{recover_pubkey, sign_message, verify_message};

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE, Engine};
use secp256k1::{PublicKey, SecretKey};
use std::convert::TryInto;

#[derive(Debug)]
pub struct Token(u32, Option<[u8; 65]>);

fn now() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs() as u32
}

pub fn u32_to_bytes(input: u32) -> [u8; 4] {
    input.to_be_bytes()
}
pub fn bytes_to_u32(bytes: [u8; 4]) -> u32 {
    u32::from_be_bytes(bytes)
}

pub fn base64_encode(input: &[u8]) -> String {
    URL_SAFE.encode(input)
}
pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let r = URL_SAFE
        .decode(input)
        .map_err(|e| anyhow!("base64_decode failed: {:?}", e))?;
    Ok(r)
}

impl Token {
    /// Creates a new token with current timestamp
    pub fn new() -> Self {
        Self(now(), None)
    }
    pub fn set_sig(&mut self, sig: [u8; 65]) {
        self.1 = Some(sig)
    }
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = base64_decode(s)?;
        if bytes.len() != 69 {
            return Err(anyhow!("wrong length".to_string()));
        }
        let ts: [u8; 4] = bytes[..4].try_into()?;
        let sig: [u8; 65] = bytes[4..].try_into()?;
        Ok(Self(bytes_to_u32(ts), Some(sig)))
    }
    pub fn expected_len(&self) -> usize {
        69
    }
    /// Sign a lightning token
    pub fn sign(&self, secret_key: &SecretKey) -> Result<Vec<u8>> {
        let mut ts = u32_to_bytes(self.0).to_vec();
        let sig = sign_message(&ts, secret_key)?;
        ts.extend(sig);
        assert_eq!(ts.len(), self.expected_len());
        Ok(ts)
    }
    /// Sign a lightning token
    pub fn sign_to_base64(&self, secret_key: &SecretKey) -> Result<String> {
        let s = self.sign(secret_key)?;
        Ok(base64_encode(&s))
    }
    /// Verify signed token
    pub fn verify(&self, public_key: &PublicKey) -> Result<()> {
        if let None = self.1 {
            return Err(anyhow!("no sig".to_string()));
        }
        let msg = u32_to_bytes(self.0);
        verify_message(&msg.to_vec(), &self.1.unwrap(), public_key)
    }
    /// Recover pubkey from signed token
    pub fn recover(&self) -> Result<PublicKey> {
        if let None = self.1 {
            return Err(anyhow!("no sig".to_string()));
        }
        let msg = u32_to_bytes(self.0);
        recover_pubkey(&msg.to_vec(), &self.1.unwrap())
    }
    /// Recover pubkey from signed token, and check timestamp
    pub fn recover_within(&self, secs: u32) -> Result<PublicKey> {
        if let None = self.1 {
            return Err(anyhow!("no sig".to_string()));
        }
        if self.0 < now() - secs {
            return Err(anyhow!("expired".to_string()));
        }
        let msg = u32_to_bytes(self.0);
        recover_pubkey(&msg.to_vec(), &self.1.unwrap())
    }
}

#[cfg(test)]
mod tests {
    use crate::token::*;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn secret_key() -> SecretKey {
        SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order")
    }

    fn a_token() -> String {
        "YvM0wyAZBWdHaVsS4sqy-ub3X0JRx7zVTY9O6aL0q_CIV9zOKykO_grPE4DSelinHNX9pTFZ3wEoLhg5QT7EVZpOlj0x".to_string()
    }

    #[test]
    fn test_token() {
        let sk = secret_key();
        let mut t = Token::new();
        let res = t.sign(&sk).expect("couldnt make token");
        println!("===> {}", base64_encode(&res));
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &sk);
        let sig: [u8; 65] = res[4..].try_into().expect("wrong sig length");
        t.set_sig(sig);
        t.verify(&public_key).expect("couldnt verify");
    }

    #[test]
    fn test_decode() {
        let sk = secret_key();
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &sk);
        let t = Token::from_base64(&a_token()).expect("couldnt parse base64");
        t.verify(&public_key).expect("failed to verify");
    }

    #[test]
    fn test_recover() {
        let sk = secret_key();
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &sk);
        let t = Token::from_base64(&a_token()).expect("couldnt parse base64");
        let pk2 = t.recover().expect("failed to verify");
        assert_eq!(public_key, pk2);
    }
    #[test]
    fn test_recover_within() {
        let sk = secret_key();
        let t1 = Token::new();
        let res = t1.sign(&sk).expect("couldnt make token");
        let token = base64_encode(&res);
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &sk);
        let t = Token::from_base64(&token).expect("couldnt parse base64");
        let pk2 = t.recover_within(10).expect("failed to verify");
        assert_eq!(public_key, pk2);
    }

    #[test]
    fn test_check_timestamp() {
        let sk = secret_key();
        let t1 = Token::new();
        let token = t1.sign_to_base64(&sk).expect("couldnt make token");
        // let token = base64_encode(&res);
        let t = Token::from_base64(&token).expect("couldnt parse base64");
        std::thread::sleep(std::time::Duration::from_secs(2));
        if t.recover_within(1).is_ok() {
            panic!("should have expired")
        }
    }

    #[test]
    fn test_tribe() {
        let pk = hex::decode("02290714deafd0cb33d2be3b634fc977a98a9c9fa1dd6c53cf17d99b350c08c67b")
            .expect("hex fail");
        let pubkey = PublicKey::from_slice(&pk[..]).expect("couldnt extract pubkey");
        let tribe = "XuOp5B9kC3CcL52svtl_LJJJFbV1OTgnq7thtOjdKJMnOuETIw_hlLkVfonozVIwz5wADlya_i946GiKFZAgMto0cDuk";
        let token = Token::from_base64(tribe).expect("couldnt parse base64");
        token.verify(&pubkey).expect("nope verify");
        let pk2 = token.recover().expect("recover failed");
        assert_eq!(pubkey, pk2);
    }

    #[test]
    fn test_decode_again() {
        use std::str::FromStr;
        let public_key = PublicKey::from_str(
            "03a769efb79e88f7b6ec0db2d02187cb7dd1b52f930289d0a16849e55f573f2261",
        )
        .expect("boo");
        let tok = "Yy3k2R-sD5A0XDzoHewiYxUu4xC7ArV7hYkE67wG_zxiMJKA7Vz26z9lNEbklPOAoNQlEqG6TlE-SUDgaxLnAceT1SDq";
        let bytes = base64_decode(tok).expect("asdfasdf");
        let ts: [u8; 4] = bytes[..4].try_into().expect("ASDFASDFASDF");
        println!("TIME {}", bytes_to_u32(ts));
        let t = Token::from_base64(tok).expect("couldnt parse base64");
        t.verify(&public_key).expect("failed to verify");
    }
}
