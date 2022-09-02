mod nonce;
pub use nonce::Controller;

use anyhow::anyhow;
use anyhow::Result;
use base64::{decode_config, encode_config, URL_SAFE};
pub use secp256k1;
use secp256k1::ecdsa::{self, Signature};
use secp256k1::hashes::sha256::Hash as Sha256Hash;
use secp256k1::hashes::Hash;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
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
    encode_config(input, URL_SAFE)
}
pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let r = decode_config(input, URL_SAFE)?;
    Ok(r)
}
// 27 + 4 for compressed
const MAGIC_NUMBER: i32 = 31;

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

pub fn sign_message(message: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>> {
    let encmsg = lightning_hash(message)?;
    let secp_ctx = Secp256k1::signing_only();
    let sig = secp_ctx.sign_ecdsa_recoverable(&encmsg, &secret_key);
    let (rid, sig) = sig.serialize_compact();
    let mut fin = vec![(rid.to_i32() + MAGIC_NUMBER) as u8];
    fin.extend_from_slice(&sig[..]);
    Ok(fin)
}
pub fn verify_message(message: &[u8], sig: &[u8; 65], public_key: &PublicKey) -> Result<()> {
    let secp_ctx = Secp256k1::verification_only();
    let encmsg = lightning_hash(message)?;
    // remove the rid
    let s = Signature::from_compact(&sig[1..])?;
    secp_ctx.verify_ecdsa(&encmsg, &s, public_key)?;
    Ok(())
}
pub fn recover_pubkey(message: &[u8], sig: &[u8; 65]) -> Result<PublicKey> {
    if sig.len() < 65 {
        return Err(anyhow!("too short sig".to_string()));
    }
    let encmsg = lightning_hash(message)?;
    let secp = Secp256k1::verification_only();
    let id = ecdsa::RecoveryId::from_i32(sig[0] as i32 - MAGIC_NUMBER)?;
    let s = ecdsa::RecoverableSignature::from_compact(&sig[1..], id)?;
    Ok(secp.recover_ecdsa(&encmsg, &s)?)
}
pub fn lightning_hash(message: &[u8]) -> Result<Message> {
    let mut buffer = String::from("Lightning Signed Message:").into_bytes();
    buffer.extend(message);
    let hash1 = Sha256Hash::hash(&buffer[..]);
    let hash2 = Sha256Hash::hash(&hash1[..]);
    let encmsg = secp256k1::Message::from_slice(&hash2[..])?;
    Ok(encmsg)
}

#[cfg(test)]
mod tests {
    use crate::*;
    use secp256k1::hashes::sha256d::Hash as Sha256dHash;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn secret_key() -> SecretKey {
        SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order")
    }

    fn a_token() -> String {
        "YvM0wyAZBWdHaVsS4sqy-ub3X0JRx7zVTY9O6aL0q_CIV9zOKykO_grPE4DSelinHNX9pTFZ3wEoLhg5QT7EVZpOlj0x".to_string()
    }

    #[test]
    fn test_sign() {
        let secp = Secp256k1::new();
        let sk = secret_key();
        let public_key = PublicKey::from_secret_key(&secp, &sk);
        let input = vec![1, 2, 3];
        let hash = Sha256dHash::hash(&input);
        let message = Message::from_slice(&hash[..]).expect("encmsg failed");
        let sig = secp.sign_ecdsa(&message, &sk);
        assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());
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
        let res = t1.sign(&sk).expect("couldnt make token");
        let token = base64_encode(&res);
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
}
