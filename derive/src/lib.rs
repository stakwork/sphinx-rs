use bitcoin::bip32::{ChildNumber, ExtendedPrivKey};
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

/// Twelve BIP39 words, the only length a Sphinx account has.
fn twelve_words(mn: &str) -> anyhow::Result<bip39::Mnemonic> {
    let mn = bip39::Mnemonic::parse_normalized(mn)
        .map_err(|e| anyhow::anyhow!("Mnemonic::parse_normalized failed {:?}", e))?;
    match mn.word_count() {
        12 => Ok(mn),
        len => Err(anyhow::anyhow!(
            "Mnemonic is length {}, should be 12 words long.",
            len
        )),
    }
}

pub fn entropy_from_mnemonic(mn: &str) -> anyhow::Result<Vec<u8>> {
    let mn = twelve_words(mn)?;
    let (array, len) = mn.to_entropy_array();
    if len != 16 {
        return Err(anyhow::anyhow!("Should never happen, 12 words didn't convert to 16 bytes of entropy. Please try again."));
    }
    Ok(array[..len].to_vec())
}

pub fn mnemonic_to_seed(mn: &str) -> anyhow::Result<Vec<u8>> {
    // BIP39 seed is 64 bytes. Do like CLN does, chop off the last 32 bytes.
    let e = mnemonic_to_bip39_seed(mn)?[..32].to_vec();
    Ok(e)
}

/// The whole 64-byte BIP39 seed of twelve words (empty passphrase): what a
/// standard BIP39 wallet makes its BIP32 master from. `mnemonic_to_seed`
/// keeps only its first 32 bytes (the Sphinx seed, CLN's hsm_secret), and
/// the other 32 can't be had back from those, so anything that must match
/// another wallet holding the same words (LUD-05) starts here.
pub fn mnemonic_to_bip39_seed(mn: &str) -> anyhow::Result<[u8; 64]> {
    Ok(twelve_words(mn)?.to_seed_normalized(""))
}

/// LUD-05 (LNURL-auth) `hashingKey`: the private key at m/138'/0.
pub fn lud05_hashing_key(master: &ExtendedPrivKey) -> anyhow::Result<SecretKey> {
    let secp = Secp256k1::signing_only();
    let path = [
        ChildNumber::from_hardened_idx(138)?,
        ChildNumber::from_normal_idx(0)?,
    ];
    Ok(master.derive_priv(&secp, &path)?.private_key)
}

/// LUD-05's path suffix for a domain: the first 16 bytes of
/// HMAC-SHA256(hashingKey, domain) as four big-endian u32.
pub fn lud05_path_suffix(hashing_key: &SecretKey, domain: &str) -> [u32; 4] {
    let mut hmac = HmacEngine::<BitcoinSha256>::new(&hashing_key.secret_bytes());
    hmac.input(domain.as_bytes());
    let material = Hmac::from_engine(hmac).to_byte_array();
    let mut suffix = [0u32; 4];
    for (i, n) in suffix.iter_mut().enumerate() {
        let mut be = [0u8; 4];
        be.copy_from_slice(&material[i * 4..i * 4 + 4]);
        *n = u32::from_be_bytes(be);
    }
    suffix
}

/// LUD-05's `linkingKey` for a domain: m/138'/a/b/c/d of the standard BIP32
/// master of the 64-byte BIP39 seed, where a/b/c/d is `lud05_path_suffix`.
/// Each index is a raw u32, so one of 2^31 or more is a hardened step, as
/// in the spec's reference code. `domain` is used as given: the bare host.
pub fn lud05_linking_key(bip39_seed: &[u8; 64], domain: &str) -> anyhow::Result<SecretKey> {
    if domain.is_empty() {
        return Err(anyhow::anyhow!("LUD-05 needs a domain"));
    }
    let secp = Secp256k1::signing_only();
    // the network only names the xprv's version bytes; the keys are the same
    let master = ExtendedPrivKey::new_master(Network::Bitcoin, bip39_seed)?;
    let hashing_key = lud05_hashing_key(&master)?;
    let mut path = vec![ChildNumber::from_hardened_idx(138)?];
    path.extend(
        lud05_path_suffix(&hashing_key, domain)
            .iter()
            .map(|n| ChildNumber::from(*n)),
    );
    Ok(master.derive_priv(&secp, &path)?.private_key)
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

    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn tohex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn test_mnemonic_to_bip39_seed() {
        // the standard BIP39 seed of these words, empty passphrase
        let seed = mnemonic_to_bip39_seed(ABANDON).expect("fail");
        assert_eq!(
            tohex(&seed),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
        // the Sphinx seed is its first half
        assert_eq!(
            mnemonic_to_seed(ABANDON).expect("fail"),
            seed[..32].to_vec()
        );
        // and its BIP32 master is the one every BIP39 wallet has for these words
        let master = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).expect("master");
        assert_eq!(
            master.to_string(),
            "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
        );
        assert!(mnemonic_to_bip39_seed("abandon abandon about").is_err());
    }

    #[test]
    fn test_lud05_spec_vector() {
        // LUD-05's test vector (lnurl/luds 05.md)
        let hashing_key = SecretKey::from_slice(&unhex(
            "7d417a6a5e9a6a4a879aeaba11a11838764c8fa2b959c242d43dea682b3e409b",
        ))
        .unwrap();
        assert_eq!(
            lud05_path_suffix(&hashing_key, "site.com"),
            [1588488367, 2659270754, 38110259, 4136336762]
        );
    }

    #[test]
    fn test_lud05_linking_key() {
        // vectors from an independent implementation (@noble/curves +
        // @noble/hashes BIP39/BIP32), which also reproduces the spec vector
        // and the seed and master above
        let seed = mnemonic_to_bip39_seed(ABANDON).expect("fail");
        let master = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).expect("master");
        let hashing_key = lud05_hashing_key(&master).expect("hashing key");
        assert_eq!(
            tohex(&hashing_key.secret_bytes()),
            "21bb08e5349e42d874770a935abb4ac5c986c34a59d87c2a1cf4afb426c98c37"
        );
        let secp = Secp256k1::new();
        for (domain, suffix, secret, pubkey) in [
            (
                "site.com",
                [3640730404, 1920417683, 1560216870, 2516166035],
                "0a2ab7357ca824220a4e80eb5201499340a750b098c1a81f376ff2062ffe690e",
                "027da5d64331f61260eb8e2b356403446555f525bc7dc35b991ec1447e4f58991f",
            ),
            (
                "app.example.com",
                [3168507378, 3008999557, 2422805726, 2133500784],
                "7670060aeb6f0b819ec6e22093437894e0a17f0dd5bd81480df6de7e0b14799a",
                "0278e4feeddc78fae0a8d5d1b5d40c4d56ffa88ac42d13e8e3b2ac480e2b85b243",
            ),
        ] {
            assert_eq!(lud05_path_suffix(&hashing_key, domain), suffix);
            let key = lud05_linking_key(&seed, domain).expect("linking key");
            assert_eq!(tohex(&key.secret_bytes()), secret);
            assert_eq!(PublicKey::from_secret_key(&secp, &key).to_string(), pubkey);
        }
    }

    #[test]
    fn test_lud05_domains() {
        let seed = mnemonic_to_bip39_seed(ABANDON).expect("fail");
        let a = lud05_linking_key(&seed, "site.com").unwrap();
        assert_eq!(a, lud05_linking_key(&seed, "site.com").unwrap());
        assert_ne!(a, lud05_linking_key(&seed, "other.com").unwrap());
        assert_ne!(a, lud05_linking_key(&seed, "x.site.com").unwrap());
        // another person's words, another key for the same domain
        let other = mnemonic_to_bip39_seed(
            "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor adjust",
        )
        .unwrap();
        assert_ne!(a, lud05_linking_key(&other, "site.com").unwrap());
        assert!(lud05_linking_key(&seed, "").is_err());
    }
}
