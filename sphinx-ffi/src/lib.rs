mod auto;
mod control;
mod onion;
mod parse;
mod signer;

pub use control::*;

pub use signer::*;

pub use onion::*;

pub use auto::*;

use sphinx_crypter::chacha::{decrypt as chacha_decrypt, encrypt as chacha_encrypt};
use sphinx_crypter::ecdh::derive_shared_secret_from_slice;
use sphinx_crypter::secp256k1::{PublicKey, Secp256k1, SecretKey};
use sphinx_signer::{derive, lightning_signer::bitcoin::Network};
use std::str::FromStr;

#[cfg(not(feature = "wasm"))]
uniffi::include_scaffolding!("sphinxrs");

pub type Result<T> = std::result::Result<T, SphinxError>;

#[derive(Debug, thiserror::Error)]
pub enum SphinxError {
    #[error("Failed to derive public key: {r}")]
    DerivePublicKey { r: String },
    #[error("Failed to derive shared secret: {r}")]
    DeriveSharedSecret { r: String },
    #[error("Failed to encrypt: {r}")]
    Encrypt { r: String },
    #[error("Failed to decrypt: {r}")]
    Decrypt { r: String },
    #[error("Bad pubkey: {r}")]
    BadPubkey { r: String },
    #[error("Bad secret: {r}")]
    BadSecret { r: String },
    #[error("Bad nonce: {r}")]
    BadNonce { r: String },
    #[error("Bad cipher: {r}")]
    BadCiper { r: String },
    #[error("Invalid network: {r}")]
    InvalidNetwork { r: String },
    #[error("Bad Request: {r}")]
    BadRequest { r: String },
    #[error("Bad Response: {r}")]
    BadResponse { r: String },
    #[error("Bad Topic: {r}")]
    BadTopic { r: String },
    #[error("Bad Args: {r}")]
    BadArgs { r: String },
    #[error("Bad State: {r}")]
    BadState { r: String },
    #[error("Bad Velocity: {r}")]
    BadVelocity { r: String },
    #[error("Init Failed: {r}")]
    InitFailed { r: String },
    #[error("LSS Failed: {r}")]
    LssFailed { r: String },
    #[error("VLS Failed: {r}")]
    VlsFailed { r: String },
    #[error("Bad Child Index: {r}")]
    BadChildIndex { r: String },
    #[error("Bad Msg: {r}")]
    BadMsg { r: String },
    #[error("AddContactFailed: {r}")]
    AddContactFailed { r: String },
    #[error("GetContactFailed: {r}")]
    GetContactFailed { r: String },
    #[error("HandleFailed: {r}")]
    HandleFailed { r: String },
    #[error("FetchMsgsFailed: {r}")]
    FetchMsgsFailed { r: String },
    #[error("SendFailed: {r}")]
    SendFailed { r: String },
    #[error("SetNetworkFailed: {r}")]
    SetNetworkFailed { r: String },
    #[error("SetBlockheightFailed: {r}")]
    SetBlockheightFailed { r: String },
}

pub fn pubkey_from_secret_key(my_secret_key: String) -> Result<String> {
    let secret_key = parse::parse_secret_string(my_secret_key)?;
    let sk = SecretKey::from_slice(&secret_key[..]).map_err(|e| SphinxError::BadSecret {
        r: format!("{:?}", e),
    })?;
    let ctx = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&ctx, &sk).serialize();
    Ok(hex::encode(pk))
}

// their_pubkey: 33 bytes
// my_secret_key: 32 bytes
// return shared secret: 32 bytes
pub fn derive_shared_secret(their_pubkey: String, my_secret_key: String) -> Result<String> {
    let pubkey = parse::parse_public_key_string(their_pubkey)?;
    let secret_key = parse::parse_secret_string(my_secret_key)?;
    let secret = derive_shared_secret_from_slice(pubkey, secret_key).map_err(|e| {
        SphinxError::DeriveSharedSecret {
            r: format!("{:?}", e),
        }
    })?;
    Ok(hex::encode(secret))
}

// plaintext: 32 bytes
// secret: 32 bytes
// nonce: 12 bytes
// return ciphertext: 56 bytes
pub fn encrypt(plaintext: String, secret: String, nonce: String) -> Result<String> {
    let plain = parse::parse_secret_string(plaintext)?;
    let sec = parse::parse_secret_string(secret)?;
    let non = parse::parse_nonce_string(nonce)?;
    let cipher = chacha_encrypt(plain, sec, non).map_err(|e| SphinxError::Encrypt {
        r: format!("{:?}", e),
    })?;
    Ok(hex::encode(cipher))
}

// ciphertext: 56 bytes
// secret: 32 bytes
// return plaintext: 32 bytes
pub fn decrypt(ciphertext: String, secret: String) -> Result<String> {
    let cipher = parse::parse_cipher_string(ciphertext)?;
    let sec = parse::parse_secret_string(secret)?;
    let plain = chacha_decrypt(cipher, sec).map_err(|e| SphinxError::Decrypt {
        r: format!("{:?}", e),
    })?;
    Ok(hex::encode(plain))
}

pub struct Keys {
    pub secret: String,
    pub pubkey: String,
}

pub fn node_keys(net: String, seed: String) -> Result<Keys> {
    let seed = parse::parse_secret_string(seed)?;
    let network: Network = Network::from_str(&net).map_err(|e| SphinxError::InvalidNetwork {
        r: format!("{:?}", e),
    })?;
    let ks = derive::node_keys(&network, &seed[..]);
    Ok(Keys {
        secret: hex::encode(ks.1.secret_bytes()),
        pubkey: ks.0.to_string(),
    })
}

pub fn mnemonic_from_entropy(entropy: String) -> Result<String> {
    let entropy = parse::parse_entropy_string(entropy)?;
    let ret = derive::mnemonic_from_entropy(&entropy[..]).map_err(|e| SphinxError::BadSecret {
        r: format!("{:?}", e),
    })?;
    Ok(ret)
}

pub fn entropy_from_mnemonic(mnemonic: String) -> Result<String> {
    let m = derive::entropy_from_mnemonic(&mnemonic).map_err(|e| SphinxError::BadSecret {
        r: format!("{:?}", e),
    })?;
    Ok(hex::encode(m))
}

pub fn mnemonic_to_seed(mnemonic: String) -> Result<String> {
    let m = derive::mnemonic_to_seed(&mnemonic).map_err(|e| SphinxError::BadSecret {
        r: format!("{:?}", e),
    })?;
    Ok(hex::encode(m))
}

pub fn entropy_to_seed(entropy: String) -> Result<String> {
    let entropy = parse::parse_entropy_string(entropy)?;
    let m = derive::entropy_to_seed(&entropy[..]).map_err(|e| SphinxError::BadSecret {
        r: format!("{:?}", e),
    })?;
    Ok(hex::encode(m))
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_sphinx() -> Result<()> {
        let sk1 = "86c8977989592a97beb409bc27fde76e981ce3543499fd61743755b832e92a3e";
        let pk1 = "0362a684901b8d065fb034bc44ea972619a409aeafc2a698016a74f6eee1008aca";

        let sk2 = "21c2d41c7394b0a87dae89576bee2552aedb54a204cdcdbf5cdceb0b4c1c2a17";
        let pk2 = "027dd6297aff570a409fe05032b6e1dab39f309daa8c438a65c32e3d7b4722b7c3";

        // derive shared secrets
        let sec1 = derive_shared_secret(pk2.to_string(), sk1.to_string())?;
        let sec2 = derive_shared_secret(pk1.to_string(), sk2.to_string())?;
        assert_eq!(sec1, sec2);

        // encrypt plaintext with sec1
        let plaintext = "59ff446bec1d96dc7d1a69232cd69ca409e069294e983df7f1e3e5fb3c95c41c";
        let nonce = "0da01cc0c0a73ad3c0a73ad3";
        let cipher = encrypt(plaintext.to_string(), sec1, nonce.to_string())?;

        // decrypt with sec2
        let plain = decrypt(cipher, sec2)?;
        assert_eq!(plaintext, plain);

        println!("PLAINTEXT MATCHES!");
        Ok(())
    }

    #[test]
    fn test_derive_pubkey() -> Result<()> {
        let sk1 = "86c8977989592a97beb409bc27fde76e981ce3543499fd61743755b832e92a3e";
        let pk1 = "0362a684901b8d065fb034bc44ea972619a409aeafc2a698016a74f6eee1008aca";
        let pk = pubkey_from_secret_key(sk1.to_string())?;
        assert_eq!(pk, pk1);
        Ok(())
    }

    #[test]
    fn test_derive_keys() -> Result<()> {
        let seed = "86c8977989592a97beb409bc27fde76e981ce3543499fd61743755b832e92a3e";
        let keys = node_keys("regtest".to_string(), seed.to_string()).expect("fail");
        assert_eq!(
            keys.pubkey,
            "02debe869398af7e6ee6b7f25f464da65f50cdc26987a9ac6946b709bc69020472"
        );
        assert_eq!(
            keys.secret,
            "66a553b3498d7471709184a01b956e3ad837a29f73c277c90329fc08b7a969b3"
        );
        Ok(())
    }

    #[test]
    fn test_mnemonic_to_seed() -> Result<()> {
        let seed = mnemonic_to_seed("forget parent wage payment cotton excite venue into era crouch because twin bargain flash library fever raise chunk suit evil jar perfect almost supreme".to_string()).expect("fail");
        let vector = "df585d7edbf9863e42efc1ef00b1d10d9c6bb7b3ffea272a48430e8a3e4b600b";
        assert_eq!(seed, vector);
        Ok(())
    }
}
