use anyhow::anyhow;
use anyhow::Result;
use base64::{decode_config, encode_config, URL_SAFE};
use secp256k1::ecdsa::{self, Signature};
use secp256k1::hashes::sha256d::Hash as Sha256dHash;
use secp256k1::hashes::Hash;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use std::convert::TryInto;

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
    input.to_le_bytes()
}
pub fn bytes_to_u32(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

pub fn base64_encode(input: &Vec<u8>) -> String {
    encode_config(input, URL_SAFE)
}
pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let r = decode_config(input, URL_SAFE)?;
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
        if s.len() < 8 {
            return Err(anyhow!("too short slice".to_string()));
        }
        let bytes = base64_decode(s)?;
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
        let sig = self.sign_message(&ts, secret_key)?;
        println!("tts {:?}", ts);
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
        self.verify_message(&msg.to_vec(), &self.1.unwrap(), public_key)
    }
    /// Recover pubkey from signed token
    pub fn recover(&self) -> Result<PublicKey> {
        if let None = self.1 {
            return Err(anyhow!("no sig".to_string()));
        }
        let msg = u32_to_bytes(self.0);
        self.recover_pubkey(&msg.to_vec(), &self.1.unwrap())
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
        self.recover_pubkey(&msg.to_vec(), &self.1.unwrap())
    }
    fn sign_message(&self, message: &Vec<u8>, secret_key: &SecretKey) -> Result<Vec<u8>> {
        let encmsg = self.lightning_hash(message)?;
        let secp_ctx = Secp256k1::signing_only();
        let sig = secp_ctx.sign_ecdsa_recoverable(&encmsg, &secret_key);
        let (rid, sig) = sig.serialize_compact();
        let mut res = sig.to_vec();
        res.push(rid.to_i32() as u8);
        Ok(res)
    }
    fn verify_message(
        &self,
        message: &Vec<u8>,
        sig: &[u8; 65],
        public_key: &PublicKey,
    ) -> Result<()> {
        let secp_ctx = Secp256k1::verification_only();
        let encmsg = self.lightning_hash(message)?;
        // remove the rid
        let s = Signature::from_compact(&sig[..64])?;
        secp_ctx.verify_ecdsa(&encmsg, &s, public_key)?;
        Ok(())
    }
    fn recover_pubkey(&self, message: &Vec<u8>, sig: &[u8; 65]) -> Result<PublicKey> {
        if sig.len() < 65 {
            return Err(anyhow!("too short sig".to_string()));
        }
        let encmsg = self.lightning_hash(message)?;
        let secp = Secp256k1::verification_only();
        let id = ecdsa::RecoveryId::from_i32(sig[64] as i32)?;
        let s = ecdsa::RecoverableSignature::from_compact(&sig[..64], id)?;
        Ok(secp.recover_ecdsa(&encmsg, &s)?)
    }
    fn lightning_hash(&self, message: &Vec<u8>) -> Result<Message> {
        let mut buffer = String::from("Lightning Signed Message:").into_bytes();
        buffer.extend(message);
        let hash = Sha256dHash::hash(&buffer);
        let encmsg = secp256k1::Message::from_slice(&hash[..])?;
        Ok(encmsg)
    }
}

pub fn sign<T: secp256k1::Signing>(
    secp: &Secp256k1<T>,
    input: Vec<u8>,
    secret_key: &SecretKey,
) -> Signature {
    let message = hash_message(input);
    secp.sign_ecdsa(&message, &secret_key)
}

pub fn hash_message(input: Vec<u8>) -> Message {
    let hash = Sha256dHash::hash(&input);
    Message::from_slice(&hash[..]).expect("encmsg failed")
}

#[cfg(test)]
mod tests {
    use crate::*;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn secret_key() -> SecretKey {
        SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order")
    }

    fn premade_token() -> String {
        "7K3uYhxpP-qScsGcSXjBLsBMJ7rGf6mJd4ZPLbic80xmbyUFWpe4XtjbA3cFf08LTDH0ahd0UpOJFaZscFiptZQLaNIB".to_string()
    }

    #[test]
    fn test_sign() {
        let secp = Secp256k1::new();
        let sk = secret_key();
        let public_key = PublicKey::from_secret_key(&secp, &sk);
        let input = vec![1, 2, 3];
        let message = hash_message(input);
        let sig = sign(&secp, vec![1, 2, 3], &sk);
        assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());
    }

    #[test]
    fn test_token() {
        let sk = secret_key();
        let mut t = Token::new();
        let res = t.sign(&sk).expect("couldnt make token");
        // println!("{}", base64_encode(&res));
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &sk);
        let sig: [u8; 65] = res[4..].try_into().expect("wrong sig length");
        t.set_sig(sig);
        t.verify(&public_key).expect("couldnt verify");
        println!("token verified!");
    }

    #[test]
    fn test_decode() {
        let sk = secret_key();
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &sk);
        let t = Token::from_base64(&premade_token()).expect("couldnt parse base64");
        t.verify(&public_key).expect("failed to verify");
        println!("decoded token verified!");
    }

    #[test]
    fn test_recover() {
        let sk = secret_key();
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &sk);
        let t = Token::from_base64(&premade_token()).expect("couldnt parse base64");
        let pk2 = t.recover().expect("failed to verify");
        assert_eq!(public_key, pk2);
        println!("decoded token pubkey recovered!");
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
        println!("decoded token pubkey recovered!");
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
            panic!("should fail")
        }
    }
}
