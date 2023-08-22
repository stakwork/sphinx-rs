pub mod nonce;
pub mod token;

pub use secp256k1;

use anyhow::{anyhow, Error as AnyErr, Result};
use secp256k1::ecdsa::{self, Signature};
use secp256k1::hashes::sha256::Hash as Sha256Hash;
use secp256k1::hashes::Hash;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

// 27 + 4 for compressed
const MAGIC_NUMBER: i32 = 31;

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
    let s = Signature::from_compact(&sig[1..]).map_err(AnyErr::msg)?;
    secp_ctx
        .verify_ecdsa(&encmsg, &s, public_key)
        .map_err(AnyErr::msg)?;
    Ok(())
}

pub fn recover_pubkey(message: &[u8], sig: &[u8; 65]) -> Result<PublicKey> {
    if sig.len() < 65 {
        return Err(anyhow!("too short sig".to_string()));
    }
    let encmsg = lightning_hash(message).map_err(AnyErr::msg)?;
    let secp = Secp256k1::verification_only();
    let id = ecdsa::RecoveryId::from_i32(sig[0] as i32 - MAGIC_NUMBER).map_err(AnyErr::msg)?;
    let s = ecdsa::RecoverableSignature::from_compact(&sig[1..], id).map_err(AnyErr::msg)?;
    Ok(secp.recover_ecdsa(&encmsg, &s).map_err(AnyErr::msg)?)
}

pub fn lightning_hash(message: &[u8]) -> Result<Message> {
    let mut buffer = String::from("Lightning Signed Message:").into_bytes();
    buffer.extend(message);
    let hash1 = Sha256Hash::hash(&buffer[..]);
    let hash2 = Sha256Hash::hash(&hash1[..]);
    let encmsg = secp256k1::Message::from_slice(&hash2[..]).map_err(AnyErr::msg)?;
    Ok(encmsg)
}
