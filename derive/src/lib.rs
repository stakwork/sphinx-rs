use bitcoin::hashes::sha256::Hash as BitcoinSha256;
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::Network;

pub const ENTROPY_LEN: usize = 16;

/// derive a secret from another secret using HKDF-SHA256
pub fn hkdf_sha256(secret: &[u8], info: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    hkdf_extract_expand(salt, secret, info, &mut result);
    result
}

fn hkdf_extract_expand(salt: &[u8], secret: &[u8], info: &[u8], output: &mut [u8]) {
    let mut hmac = HmacEngine::<BitcoinSha256>::new(salt);
    hmac.input(secret);
    let prk = Hmac::from_engine(hmac).to_byte_array();

    let mut t = [0; 32];
    let mut n: u8 = 0;

    for chunk in output.chunks_mut(32) {
        let mut hmac = HmacEngine::<BitcoinSha256>::new(&prk[..]);
        n = n.checked_add(1).expect("HKDF size limit exceeded.");
        if n != 1 {
            hmac.input(&t);
        }
        hmac.input(&info);
        hmac.input(&[n]);
        t = Hmac::from_engine(hmac).to_byte_array();
        chunk.copy_from_slice(&t);
    }
}

/// CLN compatible node key derivation
pub fn node_keys(network: &Network, seed: &[u8]) -> (PublicKey, SecretKey) {
    let _ = network; // CLN native derivation doesn't use network for node keys
    let secp_ctx = Secp256k1::new();
    let node_private_bytes = hkdf_sha256(seed, "nodeid".as_bytes(), &[]);
    let node_secret_key = SecretKey::from_slice(&node_private_bytes).unwrap();
    let node_id = PublicKey::from_secret_key(&secp_ctx, &node_secret_key);
    (node_id, node_secret_key)
}

pub fn mnemonic_from_entropy(entropy: &[u8]) -> anyhow::Result<String> {
    let mn = bip39::Mnemonic::from_entropy(entropy)
        .map_err(|e| anyhow::anyhow!("Mnemonic::from_entropy failed {:?}", e))?;
    let mut ret = Vec::new();
    mn.word_iter().for_each(|w| ret.push(w.to_string()));
    Ok(ret.join(" "))
}

pub fn entropy_from_mnemonic(mn: &str) -> anyhow::Result<Vec<u8>> {
    let mn = bip39::Mnemonic::parse_normalized(mn)
        .map_err(|e| anyhow::anyhow!("Mnemonic::parse_normalized failed {:?}", e))?;
    match mn.word_count() {
        12 => (),
        len => {
            return Err(anyhow::anyhow!(
                "Mnemonic is length {}, should be 12 words long.",
                len
            ))
        }
    }
    let (array, len) = mn.to_entropy_array();
    if len != 16 {
        return Err(anyhow::anyhow!("Should never happen, 12 words didn't convert to 16 bytes of entropy. Please try again."));
    }
    Ok(array[..len].to_vec())
}

pub fn mnemonic_to_seed(mn: &str) -> anyhow::Result<Vec<u8>> {
    let mn = bip39::Mnemonic::parse_normalized(mn)
        .map_err(|e| anyhow::anyhow!("Mnemonic::parse_normalized failed {:?}", e))?;
    match mn.word_count() {
        12 => (),
        len => {
            return Err(anyhow::anyhow!(
                "Mnemonic is length {}, should be 12 words long.",
                len
            ))
        }
    }
    // BIP39 seed is 64 bytes. Do like CLN does, chop off the last 32 bytes.
    let e = mn.to_seed_normalized("")[..32].to_vec();
    Ok(e)
}

pub fn entropy_to_seed(entropy: &[u8]) -> anyhow::Result<Vec<u8>> {
    match entropy.len() {
        16 => (),
        len => {
            return Err(anyhow::anyhow!(
                "Entropy is length {}, should be 16 bytes.",
                len
            ))
        }
    }
    let mn = bip39::Mnemonic::from_entropy(entropy)
        .map_err(|e| anyhow::anyhow!("Mnemonic::from_entropy failed {:?}", e))?;
    if mn.word_count() != 12 {
        return Err(anyhow::anyhow!("Should never happen, 16 bytes of entropy didn't convert to 12 words. Please try again."));
    }
    // Do like CLN does, chop off the last 32 bytes
    let e = mn.to_seed_normalized("")[..32].to_vec();
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entropy() -> [u8; 16] {
        [1; 16]
    }

    fn seed() -> [u8; 32] {
        [1; 32]
    }

    #[test]
    fn test_mnemonic() {
        let entropy = entropy();
        let mn = mnemonic_from_entropy(&entropy).expect("nope");
        assert_eq!(
            mn,
            "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor adjust"
        );
        let en = entropy_from_mnemonic(&mn).expect("fail");
        assert_eq!(en, entropy);
    }

    #[test]
    fn test_mnemonic_to_seed() {
        let seed = mnemonic_to_seed(
            "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor adjust",
        )
        .expect("fail");
        let vector = [
            2, 89, 45, 66, 60, 78, 124, 109, 24, 148, 119, 19, 180, 127, 121, 87, 201, 241, 221,
            208, 161, 150, 214, 73, 215, 119, 205, 145, 70, 156, 15, 179,
        ];
        assert_eq!(seed, vector);
    }

    #[test]
    fn test_derive() {
        let net = Network::Regtest;
        let ks = node_keys(&net, &seed());
        let hexpk = ks.0.to_string();
        assert_eq!(
            hexpk,
            "026f61d7ee82f937f9697f4f3e44bfaaa25849cc4f526b3a57326130eba6346002"
        );
    }
}
