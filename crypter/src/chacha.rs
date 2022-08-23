use anyhow::Error;
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit, heapless::Vec},
    ChaCha20Poly1305, Nonce,
};

pub const KEY_LEN: usize = 32;
pub const MSG_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

pub const CIPHER_LEN: usize = MSG_LEN + TAG_LEN;
pub const PAYLOAD_LEN: usize = MSG_LEN + TAG_LEN + NONCE_LEN;

pub fn encrypt(
    plaintext: [u8; MSG_LEN],
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
) -> anyhow::Result<[u8; PAYLOAD_LEN]> {
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(&nonce);
    let mut ret: Vec<u8, PAYLOAD_LEN> = Vec::new();
    ret.extend_from_slice(&plaintext).unwrap();
    cipher.encrypt_in_place(&nonce, b"", &mut ret).or(Err(Error::msg("Failed to encrypt")))?;
    ret.extend_from_slice(&nonce).unwrap();
    let ret = ret.into_array().unwrap();
    Ok(ret)
}

pub fn decrypt(payload: [u8; PAYLOAD_LEN], key: [u8; KEY_LEN]) -> anyhow::Result<[u8; MSG_LEN]> {
    let nonce = Nonce::from_slice(&payload[CIPHER_LEN..]);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let mut buf: Vec<u8, CIPHER_LEN> = Vec::new();
    buf.extend_from_slice(&payload[..CIPHER_LEN]).unwrap();
    cipher.decrypt_in_place(&nonce, b"", &mut buf).or(Err(Error::msg("Failed to decrypt")))?;
    let ret = buf.into_array().unwrap();
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use crate::chacha::{decrypt, encrypt, KEY_LEN, MSG_LEN, NONCE_LEN};
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn test_chacha() -> anyhow::Result<()> {
        let key = [9; KEY_LEN];
        let plaintext = [1; MSG_LEN];
        let mut nonce = [0; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let cipher = encrypt(plaintext, key, nonce)?;
        let plain = decrypt(cipher, key)?;
        assert_eq!(plaintext, plain);
        Ok(())
    }
}
