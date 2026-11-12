use crate::{Result, SphinxError};
use sphinx::bip32::XKey;
use sphinx::{make_signer, MyKeysManager, Network, PublicKey, Secp256k1, SecretKey};
use std::convert::TryInto;
use std::str::FromStr;

pub fn sha_256(msg: Vec<u8>) -> String {
    hex::encode(sphinx::sha_256(&msg))
}

pub fn xpub_from_seed(seed: String, time: String, net: String) -> Result<String> {
    let km = make_keys_manager(&seed, Some(-1), &time, &net)?;
    let xpub = km.root_xpub();
    Ok(xpub.to_string())
}

pub fn root_sign_ms(seed: String, time: String, net: String) -> Result<String> {
    let km = make_keys_manager(&seed, Some(-1), &time, &net)?;
    let sig = sphinx::sig::sign_message(time.as_bytes(), &km.get_node_secret()).map_err(|_| {
        SphinxError::BadCiper {
            r: "sign failed".to_string(),
        }
    })?;
    Ok(hex::encode(sig))
}

pub fn sign_ms(seed: String, idx: u64, time: String, network: String) -> Result<String> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let sig = sphinx::sig::sign_message(time.as_bytes(), &km.get_node_secret()).map_err(|_| {
        SphinxError::BadCiper {
            r: "sign failed".to_string(),
        }
    })?;
    Ok(hex::encode(sig))
}

pub fn sign_bytes(
    seed: String,
    idx: u64,
    time: String,
    network: String,
    msg: Vec<u8>,
) -> Result<String> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let sig = sphinx::sig::sign_message(&msg[..], &km.get_node_secret()).map_err(|_| {
        SphinxError::BadCiper {
            r: "sign failed".to_string(),
        }
    })?;
    Ok(hex::encode(sig))
}

pub fn sign_base64(
    seed: String,
    idx: u64,
    time: String,
    network: String,
    msg64: String,
) -> Result<String> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let msg = sphinx::base64::base64_decode(&msg64).map_err(|_| SphinxError::BadCiper {
        r: "bad base64".to_string(),
    })?;
    let sig = sphinx::sig::sign_message(&msg, &km.get_node_secret()).map_err(|_| {
        SphinxError::BadCiper {
            r: "sign failed".to_string(),
        }
    })?;
    Ok(sphinx::base64::base64_encode(&sig))
}

pub fn pubkey_from_seed(seed: String, idx: u64, time: String, network: String) -> Result<String> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let pubkey = km.get_node_pubkey();
    Ok(hex::encode(pubkey.serialize()))
}

/// A message signed with a LUD-05 linking key, and that key.
pub struct Lud05Sig {
    /// The linking key's compressed pubkey (33 bytes), hex.
    pub pubkey: String,
    /// The signature in `sign_bytes`' format: a Lightning signed message
    /// (`sphinx::sig::sign_message`), 65 bytes (recovery byte + compact
    /// signature), hex.
    pub sig: String,
}

/// Signs `msg` with the person's LUD-05 (LNURL-auth) linking key for
/// `domain`: the key any BIP39 wallet holding the same twelve words derives
/// for that domain, m/138'/a/b/c/d of the standard BIP32 master, where
/// a/b/c/d are the first 16 bytes of HMAC-SHA256(key at m/138'/0, domain).
///
/// `bip39_seed` is the whole 64-byte BIP39 seed, hex, from
/// `mnemonic_to_bip39_seed`. The 32-byte Sphinx seed the other signing
/// functions take can't reach that master: it is only the BIP39 seed's
/// first half.
///
/// `domain` is the bare host, as LUD-05 defines it: no scheme, port, path,
/// or trailing dot. It is used as given. Strut passes its visitor
/// challenge's `host`, which is already lowercase with no port.
///
/// The signature is in exactly `sign_bytes`' format, so a verifier of
/// `sign_bytes`' signatures checks this one too.
pub fn sign_bytes_lud05(bip39_seed: String, domain: String, msg: Vec<u8>) -> Result<Lud05Sig> {
    let secret = lud05_secret(&bip39_seed, &domain)?;
    let sig = sphinx::sig::sign_message(&msg[..], &secret).map_err(|_| SphinxError::BadCiper {
        r: "sign failed".to_string(),
    })?;
    Ok(Lud05Sig {
        pubkey: lud05_pubkey_hex(&secret),
        sig: hex::encode(sig),
    })
}

/// The compressed pubkey (hex) of the LUD-05 linking key `sign_bytes_lud05`
/// signs with for `domain`.
pub fn lud05_pubkey(bip39_seed: String, domain: String) -> Result<String> {
    Ok(lud05_pubkey_hex(&lud05_secret(&bip39_seed, &domain)?))
}

fn lud05_secret(bip39_seed: &str, domain: &str) -> Result<SecretKey> {
    let seed = parse_bip39_seed(bip39_seed)?;
    let key =
        sphinx_derive::lud05_linking_key(&seed, domain).map_err(|e| SphinxError::BadArgs {
            r: format!("{:?}", e),
        })?;
    SecretKey::from_slice(&key.secret_bytes()).map_err(|e| SphinxError::BadSecret {
        r: format!("{:?}", e),
    })
}

fn lud05_pubkey_hex(secret: &SecretKey) -> String {
    let pubkey = PublicKey::from_secret_key(&Secp256k1::signing_only(), secret);
    hex::encode(pubkey.serialize())
}

fn create_onion_inner(km: &MyKeysManager, hops: String, payload: Vec<u8>) -> Result<Vec<u8>> {
    let hops = parse_hops(&hops)?;
    let (_, data) = run_create_onion_bytes(&km, hops, &payload)?;
    Ok(data)
}

pub fn create_onion(
    seed: String,
    idx: u64,
    time: String,
    network: String,
    hops: String,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let data = create_onion_inner(&km, hops, payload)?;
    Ok(data)
}

pub fn create_onion_msg(
    seed: String,
    idx: u64,
    time: String,
    network: String,
    hops: String,
    msg_json: String,
) -> Result<Vec<u8>> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let payload = sphinx::msg::create_sphinx_msg_from_json(&km, &msg_json, &time)
        .map_err(|e| SphinxError::BadMsg { r: e.to_string() })?;
    let data = create_onion_inner(&km, hops, payload)?;
    Ok(data)
}

pub fn peel_onion(
    seed: String,
    idx: u64,
    time: String,
    network: String,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    Ok(run_peel_onion_to_bytes(&km, &payload)?)
}

pub fn peel_onion_msg(
    seed: String,
    idx: u64,
    time: String,
    network: String,
    payload: Vec<u8>,
) -> Result<String> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let bytes = run_peel_received_onion_to_bytes(&km, &payload)?;
    let msg = sphinx::msg::parse_sphinx_msg_to_json(&bytes, None)
        .map_err(|e| SphinxError::BadMsg { r: e.to_string() })?;
    Ok(msg)
}

pub fn create_keysend_inner(
    km: &MyKeysManager,
    hops: String,
    msat: u64,
    rhash: String,
    payload: Vec<u8>,
    curr_height: u32,
    preimage: String,
) -> Result<Vec<u8>> {
    let hops = parse_hops(&hops)?;
    let ph = parse_hash(&rhash)?;
    let prmg = parse_preimage(&preimage)?;
    let data = run_create_keysend_bytes(km, hops, msat, ph, &payload, curr_height, prmg)?;
    Ok(data.to_vec())
}

pub fn create_keysend(
    seed: String,
    idx: u64,
    time: String,
    network: String,
    hops: String,
    msat: u64,
    rhash: String,
    payload: Vec<u8>,
    curr_height: u32,
    preimage: String,
) -> Result<Vec<u8>> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let data = create_keysend_inner(&km, hops, msat, rhash, payload, curr_height, preimage)?;
    Ok(data.to_vec())
}

pub fn create_keysend_msg(
    seed: String,
    idx: u64,
    time: String,
    network: String,
    hops: String,
    msat: u64,
    rhash: String,
    msg_json: String,
    curr_height: u32,
    preimage: String,
) -> Result<Vec<u8>> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let payload = sphinx::msg::create_sphinx_msg_from_json(&km, &msg_json, &time)
        .map_err(|e| SphinxError::BadMsg { r: e.to_string() })?;
    let data = create_keysend_inner(&km, hops, msat, rhash, payload, curr_height, preimage)?;
    Ok(data.to_vec())
}

pub fn peel_payment(
    seed: String,
    idx: u64,
    time: String,
    network: String,
    payload: Vec<u8>,
    rhash: String,
    cur_height: u32,
    cltv_expiry: u32,
) -> Result<Vec<u8>> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let payment_hash = parse_hash(&rhash)?;
    Ok(run_peel_payment_to_bytes(
        &km,
        &payload,
        payment_hash,
        cur_height,
        cltv_expiry,
    )?)
}

pub fn peel_payment_msg(
    seed: String,
    idx: u64,
    time: String,
    network: String,
    payload: Vec<u8>,
    rhash: String,
    cur_height: u32,
    cltv_expiry: u32,
) -> Result<String> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let payment_hash = parse_hash(&rhash)?;
    let (amt_opt, _preimage, bytes) =
        run_peel_received_payment_to_bytes(&km, &payload, payment_hash, cur_height, cltv_expiry)?;
    let msg = sphinx::msg::parse_sphinx_msg_to_json(&bytes, amt_opt)
        .map_err(|e| SphinxError::BadMsg { r: e.to_string() })?;
    Ok(msg)
}

pub fn idx_to_idx(idx: u64) -> Result<Option<i64>> {
    Ok(Some(idx.try_into().map_err(|_| {
        SphinxError::BadChildIndex {
            r: "infallible".to_string(),
        }
    })?))
}

pub fn make_keys_manager(
    seed: &str,
    idx: Option<i64>,
    time: &str,
    network: &str,
) -> Result<MyKeysManager> {
    let seed = parse_seed(seed)?;
    let ts = parse_u64(time)?;
    let net = Network::from_str(network).map_err(|_| SphinxError::BadArgs {
        r: "invalid network".to_string(),
    })?;
    let mkm = make_signer(&seed, idx, ts, net);
    Ok(mkm)
}

fn parse_u64(time: &str) -> Result<u64> {
    Ok(str::parse::<u64>(time).map_err(|e| SphinxError::BadArgs {
        r: format!("{:?}", e),
    })?)
}

fn parse_seed(s: &str) -> Result<[u8; 32]> {
    Ok(unhex(s)?.try_into().map_err(|e| SphinxError::BadSecret {
        r: format!("{:?}", e),
    })?)
}

fn parse_bip39_seed(s: &str) -> Result<[u8; 64]> {
    Ok(unhex(s)?.try_into().map_err(|e| SphinxError::BadSecret {
        r: format!("{:?}", e),
    })?)
}

fn parse_hash(s: &str) -> Result<[u8; 32]> {
    Ok(unhex(s)?.try_into().map_err(|e| SphinxError::BadSecret {
        r: format!("{:?}", e),
    })?)
}

fn parse_preimage(s: &str) -> Result<[u8; 32]> {
    Ok(unhex(s)?.try_into().map_err(|e| SphinxError::BadSecret {
        r: format!("{:?}", e),
    })?)
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(s).map_err(|e| SphinxError::BadArgs {
        r: format!("{:?}", e),
    })?)
}

fn parse_hops(hops: &str) -> Result<Vec<sphinx::Hop>> {
    Ok(
        sphinx::serde_json::from_str(hops).map_err(|e| SphinxError::BadArgs {
            r: format!("{:?}", e),
        })?,
    )
}

fn run_create_onion_bytes(
    km: &MyKeysManager,
    hops: Vec<sphinx::Hop>,
    pld: &[u8],
) -> Result<(PublicKey, Vec<u8>)> {
    Ok(
        sphinx::create_onion_bytes(km, hops, &pld).map_err(|e| SphinxError::Encrypt {
            r: format!("{:?}", e),
        })?,
    )
}

fn run_create_keysend_bytes(
    km: &MyKeysManager,
    hops: Vec<sphinx::Hop>,
    value: u64,
    rhash: [u8; 32],
    pld: &[u8],
    curr_height: u32,
    preimage: [u8; 32],
) -> Result<[u8; 1366]> {
    Ok(sphinx::create_keysend_bytes(
        km,
        &hops,
        value,
        rhash,
        Some(pld.to_vec()),
        curr_height,
        preimage,
    )
    .map_err(|e| SphinxError::Encrypt {
        r: format!("{:?}", e),
    })?)
}

fn run_peel_onion_to_bytes(km: &MyKeysManager, pld: &[u8]) -> Result<Vec<u8>> {
    Ok(
        sphinx::peel_onion_to_bytes(km, pld).map_err(|e| SphinxError::Decrypt {
            r: format!("{:?}", e),
        })?,
    )
}

fn run_peel_received_onion_to_bytes(km: &MyKeysManager, pld: &[u8]) -> Result<Vec<u8>> {
    Ok(
        sphinx::peel_received_onion(km, pld).map_err(|e| SphinxError::Decrypt {
            r: format!("{:?}", e),
        })?,
    )
}

fn run_peel_payment_to_bytes(
    km: &MyKeysManager,
    pld: &[u8],
    rhash: [u8; 32],
    cur_height: u32,
    cltv_expiry: u32,
) -> Result<Vec<u8>> {
    Ok(
        sphinx::peel_payment_onion_to_bytes(km, pld, rhash, cur_height, cltv_expiry).map_err(
            |e| SphinxError::Decrypt {
                r: format!("{:?}", e),
            },
        )?,
    )
}

fn run_peel_received_payment_to_bytes(
    km: &MyKeysManager,
    pld: &[u8],
    rhash: [u8; 32],
    cur_height: u32,
    cltv_expiry: u32,
) -> Result<(Option<u64>, Option<String>, Vec<u8>)> {
    Ok(
        sphinx::peel_received_payment(km, pld, rhash, cur_height, cltv_expiry).map_err(|e| {
            SphinxError::Decrypt {
                r: format!("{:?}", e),
            }
        })?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic_to_bip39_seed;

    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn bip39_seed() -> String {
        mnemonic_to_bip39_seed(ABANDON.to_string()).unwrap()
    }

    // what checks `sign_bytes`' output: the pubkey the signature recovers,
    // and the signature verified against it
    fn recover(msg: &[u8], sig_hex: &str) -> String {
        let sig: [u8; 65] = hex::decode(sig_hex).unwrap().try_into().unwrap();
        let pubkey = sphinx::sig::recover_pubkey(msg, &sig).unwrap();
        sphinx::sig::verify_message(msg, &sig, &pubkey).unwrap();
        hex::encode(pubkey.serialize())
    }

    #[test]
    fn test_sign_bytes_lud05_round_trip() -> Result<()> {
        let msg = b"strut visitor challenge".to_vec();
        let signed = sign_bytes_lud05(bip39_seed(), "site.com".to_string(), msg.clone())?;
        // the linking key LUD-05 gives these words for site.com (derive's vectors)
        assert_eq!(
            signed.pubkey,
            "027da5d64331f61260eb8e2b356403446555f525bc7dc35b991ec1447e4f58991f"
        );
        assert_eq!(
            lud05_pubkey(bip39_seed(), "site.com".to_string())?,
            signed.pubkey
        );
        assert_eq!(recover(&msg, &signed.sig), signed.pubkey);

        // sign_bytes' signature goes through the same check, to its own key
        let seed = crate::mnemonic_to_seed(ABANDON.to_string())?;
        let time = "1700000000000".to_string();
        let net = "regtest".to_string();
        let sig = sign_bytes(seed.clone(), 0, time.clone(), net.clone(), msg.clone())?;
        let account = pubkey_from_seed(seed, 0, time, net)?;
        assert_eq!(recover(&msg, &sig), account);
        assert_eq!(sig.len(), signed.sig.len());
        assert_ne!(account, signed.pubkey);
        Ok(())
    }

    #[test]
    fn test_lud05_domains() -> Result<()> {
        let site = lud05_pubkey(bip39_seed(), "site.com".to_string())?;
        assert_eq!(site, lud05_pubkey(bip39_seed(), "site.com".to_string())?);
        assert_eq!(
            lud05_pubkey(bip39_seed(), "app.example.com".to_string())?,
            "0278e4feeddc78fae0a8d5d1b5d40c4d56ffa88ac42d13e8e3b2ac480e2b85b243"
        );
        assert_ne!(site, lud05_pubkey(bip39_seed(), "other.com".to_string())?);
        Ok(())
    }

    #[test]
    fn test_lud05_bad_args() {
        // the 32-byte Sphinx seed is not a BIP39 seed
        let sphinx_seed = crate::mnemonic_to_seed(ABANDON.to_string()).unwrap();
        assert!(matches!(
            lud05_pubkey(sphinx_seed, "site.com".to_string()),
            Err(SphinxError::BadSecret { .. })
        ));
        assert!(matches!(
            sign_bytes_lud05(bip39_seed(), "".to_string(), b"m".to_vec()),
            Err(SphinxError::BadArgs { .. })
        ));
    }
}
