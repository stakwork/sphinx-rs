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
    pub fn build_msg(&mut self, mut d: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        self.2 = self.2 + 1;
        d.extend_from_slice(&self.2.to_be_bytes());
        let sig = sign_message(&d, &self.0)?;
        d.extend_from_slice(&sig);
        Ok(d)
    }
    pub fn parse_msg(&mut self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let msg_sig = input.split_at(input.len() - SIG_LEN);
        let sig: [u8; SIG_LEN] = msg_sig.1.try_into()?;
        let msg_nonce = msg_sig.0.split_at(msg_sig.0.len() - 8);
        let nonce_bytes: [u8; 8] = msg_nonce.1.try_into()?;
        let nonce = u64::from_be_bytes(nonce_bytes);
        if nonce < self.2 {
            return Err(anyhow!("bad nonce"));
        }
        let msg = msg_nonce.0;
        verify_message(msg_sig.0, &sig, &self.1)?;
        // increment nonce
        self.2 = self.2 + 1;
        Ok(msg.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
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
        let msg = cont.build_msg(input.clone()).expect("couldnt sign");
        let parsed = cont.parse_msg(msg).expect("couldnt verify");
        assert_eq!(input, parsed, "unequal");
    }
}
