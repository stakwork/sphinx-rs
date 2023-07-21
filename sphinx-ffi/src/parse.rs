use crate::{Result, SphinxError};

use sphinx_crypter::chacha::{KEY_LEN, NONCE_LEN, PAYLOAD_LEN};
use sphinx_crypter::ecdh::PUBLIC_KEY_LEN;
use std::convert::TryInto;

pub(crate) fn parse_secret_string(sk: String) -> Result<[u8; KEY_LEN]> {
    if sk.len() != KEY_LEN * 2 {
        return Err(SphinxError::BadSecret {
            r: "bad key length".to_string(),
        });
    }
    let secret_key_bytes: Vec<u8> = hex::decode(sk).map_err(|e| SphinxError::BadSecret {
        r: format!("{:?}", e),
    })?;
    let secret_key: [u8; KEY_LEN] =
        secret_key_bytes
            .try_into()
            .map_err(|e| SphinxError::BadSecret {
                r: format!("{:?}", e),
            })?;
    Ok(secret_key)
}

pub(crate) fn parse_public_key_string(pk: String) -> Result<[u8; PUBLIC_KEY_LEN]> {
    if pk.len() != PUBLIC_KEY_LEN * 2 {
        return Err(SphinxError::BadPubkey {
            r: "bad pubkey length".to_string(),
        });
    }
    let pubkey_bytes: Vec<u8> = hex::decode(pk).map_err(|e| SphinxError::BadPubkey {
        r: format!("{:?}", e),
    })?;
    let pubkey: [u8; PUBLIC_KEY_LEN] =
        pubkey_bytes
            .try_into()
            .map_err(|e| SphinxError::BadPubkey {
                r: format!("{:?}", e),
            })?;
    Ok(pubkey)
}

pub(crate) fn parse_nonce_string(n: String) -> Result<[u8; NONCE_LEN]> {
    if n.len() != NONCE_LEN * 2 {
        return Err(SphinxError::BadNonce {
            r: "bad nonce length".to_string(),
        });
    }
    let nonce_bytes: Vec<u8> = hex::decode(n).map_err(|e| SphinxError::BadNonce {
        r: format!("{:?}", e),
    })?;
    let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().map_err(|e| SphinxError::BadNonce {
        r: format!("{:?}", e),
    })?;
    Ok(nonce)
}

pub(crate) fn parse_cipher_string(c: String) -> Result<[u8; PAYLOAD_LEN]> {
    if c.len() != PAYLOAD_LEN * 2 {
        return Err(SphinxError::BadCiper {
            r: format!("bad cipher length"),
        });
    }
    let cipher_bytes: Vec<u8> = hex::decode(c).map_err(|e| SphinxError::BadCiper {
        r: format!("{:?}", e),
    })?;
    let cipher: [u8; PAYLOAD_LEN] = cipher_bytes.try_into().map_err(|e| SphinxError::BadCiper {
        r: format!("{:?}", e),
    })?;
    Ok(cipher)
}
