use crate::{sign_message, verify_message};
use anyhow::anyhow;
use secp256k1::{PublicKey, SecretKey};
use std::convert::TryInto;

// u64 is the nonce. Each signature must have a higher nonce
pub struct Controller(SecretKey, PublicKey, u64);

const SIG_LEN: usize = 65;

impl Controller {
    pub fn new(sk: SecretKey, pk: PublicKey, nonce: u64) -> Self {
        Self(sk, pk, nonce)
    }
    pub fn nonce(&self) -> u64 {
        self.2
    }
    pub fn pubkey(&self) -> PublicKey {
        self.1
    }
    pub fn build_msg(&mut self, d: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.2 = self.2 + 1;
        Ok(build_msg(d, &self.0, self.2)?)
    }
    pub fn build_msg_with_nonce(&mut self, d: &[u8], nonce: u64) -> anyhow::Result<Vec<u8>> {
        Ok(build_msg(d, &self.0, nonce)?)
    }
    pub fn parse_msg(&mut self, input: &[u8]) -> anyhow::Result<Vec<u8>> {
        let res = parse_msg(input, &self.1, self.2)?;
        self.2 = self.2 + 1;
        Ok(res)
    }
    pub fn parse_msg_with_nonce(&mut self, input: &[u8], nonce: u64) -> anyhow::Result<Vec<u8>> {
        let res = parse_msg(input, &self.1, nonce)?;
        Ok(res)
    }
}

pub fn build_msg(input: &[u8], sk: &SecretKey, nonce: u64) -> anyhow::Result<Vec<u8>> {
    let mut d = input.to_vec();
    d.extend_from_slice(&nonce.to_be_bytes());
    let sig = sign_message(&d, sk)?;
    d.extend_from_slice(&sig);
    Ok(d)
}

pub fn parse_msg(input: &[u8], pk: &PublicKey, last_nonce: u64) -> anyhow::Result<Vec<u8>> {
    let msg_sig = input.split_at(input.len() - SIG_LEN);
    let sig: [u8; SIG_LEN] = msg_sig.1.try_into()?;
    let msg_nonce = msg_sig.0.split_at(msg_sig.0.len() - 8);
    let nonce_bytes: [u8; 8] = msg_nonce.1.try_into()?;
    let nonce = u64::from_be_bytes(nonce_bytes);
    if nonce <= last_nonce {
        println!("nonce {} last_mnone {}", nonce, last_nonce);
        return Err(anyhow!("bad nonce"));
    }
    let msg = msg_nonce.0;
    verify_message(msg_sig.0, &sig, pk)?;
    // increment nonce
    Ok(msg.to_vec())
}

#[cfg(test)]
mod tests {
    use crate::nonce::*;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn secret_key() -> SecretKey {
        SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order")
    }

    #[test]
    fn test_nonce() {
        let secp = Secp256k1::new();
        let sk = secret_key();
        let public_key = PublicKey::from_secret_key(&secp, &sk);
        let input = vec![1, 2, 3];
        let mut cont = Controller::new(sk, public_key, 0);
        let msg = cont.build_msg(&input).expect("couldnt sign");
        // 0 nonce, this is the first verification
        let parsed = cont.parse_msg_with_nonce(&msg, 0).expect("couldnt verify");
        assert_eq!(input, parsed, "unequal");
    }
}
