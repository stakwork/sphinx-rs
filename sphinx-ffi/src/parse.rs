use crate::{Result, SphinxError};

use sphinx_crypter::chacha::{KEY_LEN, NONCE_LEN, PAYLOAD_LEN};
use sphinx_crypter::ecdh::PUBLIC_KEY_LEN;
use std::convert::TryInto;

pub(crate) fn parse_secret_string(sk: String) -> Result<[u8; KEY_LEN]> {
    if sk.len() != KEY_LEN * 2 {
        return Err(SphinxError::BadSecret);
    }
    let secret_key_bytes: Vec<u8> = match hex::decode(sk) {
        Ok(sk) => sk,
        Err(_) => return Err(SphinxError::BadSecret),
    };
    let secret_key: [u8; KEY_LEN] = match secret_key_bytes.try_into() {
        Ok(sk) => sk,
        Err(_) => return Err(SphinxError::BadSecret),
    };
    Ok(secret_key)
}

pub(crate) fn parse_public_key_string(pk: String) -> Result<[u8; PUBLIC_KEY_LEN]> {
    if pk.len() != PUBLIC_KEY_LEN * 2 {
        return Err(SphinxError::BadPubkey);
    }
    let pubkey_bytes: Vec<u8> = match hex::decode(pk) {
        Ok(pk) => pk,
        Err(_) => return Err(SphinxError::BadPubkey),
    };
    let pubkey: [u8; PUBLIC_KEY_LEN] = match pubkey_bytes.try_into() {
        Ok(pk) => pk,
        Err(_) => return Err(SphinxError::BadPubkey),
    };
    Ok(pubkey)
}

pub(crate) fn parse_nonce_string(n: String) -> Result<[u8; NONCE_LEN]> {
    if n.len() != NONCE_LEN * 2 {
        return Err(SphinxError::BadNonce);
    }
    let nonce_bytes: Vec<u8> = match hex::decode(n) {
        Ok(n) => n,
        Err(_) => return Err(SphinxError::BadNonce),
    };
    let nonce: [u8; NONCE_LEN] = match nonce_bytes.try_into() {
        Ok(n) => n,
        Err(_) => return Err(SphinxError::BadNonce),
    };
    Ok(nonce)
}

pub(crate) fn parse_cipher_string(c: String) -> Result<[u8; PAYLOAD_LEN]> {
    if c.len() != PAYLOAD_LEN * 2 {
        return Err(SphinxError::BadCiper);
    }
    let cipher_bytes: Vec<u8> = match hex::decode(c) {
        Ok(n) => n,
        Err(_) => return Err(SphinxError::BadCiper),
    };
    let cipher: [u8; PAYLOAD_LEN] = match cipher_bytes.try_into() {
        Ok(n) => n,
        Err(_) => return Err(SphinxError::BadCiper),
    };
    Ok(cipher)
}
