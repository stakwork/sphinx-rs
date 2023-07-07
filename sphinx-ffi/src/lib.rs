mod control;
mod parse;
mod signer;

pub use control::*;
pub use signer::*;

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
    #[error("Failed to derive public key")]
    DerivePublicKey,
    #[error("Failed to derive shared secret")]
    DeriveSharedSecret,
    #[error("Failed to encrypt")]
    Encrypt,
    #[error("Failed to decrypt")]
    Decrypt,
    #[error("Bad pubkey")]
    BadPubkey,
    #[error("Bad secret")]
    BadSecret,
    #[error("Bad nonce")]
    BadNonce,
    #[error("Bad cipher")]
    BadCiper,
    #[error("Invalid network")]
    InvalidNetwork,
    #[error("Bad Request")]
    BadRequest,
    #[error("Bad Response")]
    BadResponse,
    #[error("Bad Args")]
    BadArgs,
    #[error("Init Failed")]
    InitFailed,
    #[error("LSS Failed")]
    LssFailed,
    #[error("VLS Failed")]
    VlsFailed,
}

pub fn pubkey_from_secret_key(my_secret_key: String) -> Result<String> {
    let secret_key = parse::parse_secret_string(my_secret_key)?;
    let sk = SecretKey::from_slice(&secret_key[..]).map_err(|_| SphinxError::BadSecret)?;
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
    let secret = derive_shared_secret_from_slice(pubkey, secret_key)
        .map_err(|_| SphinxError::DeriveSharedSecret)?;
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
    let cipher = chacha_encrypt(plain, sec, non).map_err(|_| SphinxError::Encrypt)?;
    Ok(hex::encode(cipher))
}

// ciphertext: 56 bytes
// secret: 32 bytes
// return plaintext: 32 bytes
pub fn decrypt(ciphertext: String, secret: String) -> Result<String> {
    let cipher = parse::parse_cipher_string(ciphertext)?;
    let sec = parse::parse_secret_string(secret)?;
    let plain = chacha_decrypt(cipher, sec).map_err(|_| SphinxError::Decrypt)?;
    Ok(hex::encode(plain))
}

pub struct Keys {
    pub secret: String,
    pub pubkey: String,
}

pub fn node_keys(net: String, seed: String) -> Result<Keys> {
    let seed = parse::parse_secret_string(seed)?;
    let network: Network = Network::from_str(&net).map_err(|_| SphinxError::InvalidNetwork)?;
    let ks = derive::node_keys(&network, &seed[..]);
    Ok(Keys {
        secret: hex::encode(ks.1.secret_bytes()),
        pubkey: ks.0.to_string(),
    })
}

pub fn mnemonic_from_entropy(seed: String) -> Result<String> {
    let seed = parse::parse_secret_string(seed)?;
    Ok(derive::mnemonic_from_entropy(&seed[..]).map_err(|_| SphinxError::BadSecret)?)
}

pub fn entropy_from_mnemonic(mnemonic: String) -> Result<String> {
    let m = derive::entropy_from_mnemonic(&mnemonic).map_err(|_| SphinxError::BadSecret)?;
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
}
