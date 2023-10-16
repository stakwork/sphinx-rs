use crate::{Result, SphinxError};
use sphinx::{KeysManager, PublicKey, Secp256k1};
use std::convert::TryInto;

pub fn sha_256(msg: Vec<u8>) -> String {
    hex::encode(sphinx::sha_256(&msg))
}

pub fn sign_ms(seed: String, time: String) -> Result<String> {
    let km = make_keys_manager(&seed, &time)?;
    let sig =
        sphinx::sig::sign_message(time.as_bytes(), &km.get_node_secret_key()).map_err(|_| {
            SphinxError::BadCiper {
                r: "sign failed".to_string(),
            }
        })?;
    Ok(hex::encode(sig))
}

pub fn create_onion(seed: String, time: String, hops: String, payload: Vec<u8>) -> Result<Vec<u8>> {
    let km = make_keys_manager(&seed, &time)?;
    let hops = parse_hops(&hops)?;
    let (_, data) = run_create_onion_bytes(&km, hops, &payload)?;
    Ok(data)
}

pub fn peel_onion(seed: String, time: String, payload: Vec<u8>) -> Result<Vec<u8>> {
    let km = make_keys_manager(&seed, &time)?;
    Ok(run_peel_onion_bytes(&km, &payload)?)
}

pub fn create_keysend(
    seed: String,
    time: String,
    hops: String,
    msat: u64,
    rhash: String,
    payload: Vec<u8>,
    curr_height: u32,
    preimage: String,
) -> Result<Vec<u8>> {
    let km = make_keys_manager(&seed, &time)?;
    let hops = parse_hops(&hops)?;
    let payment_hash = parse_hash(&rhash)?;
    let preimage = parse_preimage(&preimage)?;
    let data = run_create_keysend_bytes(
        &km,
        hops,
        msat,
        payment_hash,
        &payload,
        curr_height,
        preimage,
    )?;
    Ok(data.to_vec())
}

pub fn peel_payment(
    seed: String,
    time: String,
    payload: Vec<u8>,
    rhash: String,
) -> Result<Vec<u8>> {
    let km = make_keys_manager(&seed, &time)?;
    let payment_hash = parse_hash(&rhash)?;
    Ok(run_peel_payment_bytes(&km, &payload, payment_hash)?)
}

fn make_keys_manager(seed: &str, time: &str) -> Result<KeysManager> {
    let seed = parse_seed(seed)?;
    let ts = parse_u64(time)?;
    let time = std::time::Duration::from_millis(ts);
    Ok(KeysManager::new(&seed, time.as_secs(), time.subsec_nanos()))
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
    km: &KeysManager,
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
    km: &KeysManager,
    hops: Vec<sphinx::Hop>,
    value: u64,
    rhash: [u8; 32],
    pld: &[u8],
    curr_height: u32,
    preimage: [u8; 32],
) -> Result<[u8; 1366]> {
    Ok(sphinx::create_keysend_bytes(
        km,
        hops,
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

fn run_peel_onion_bytes(km: &KeysManager, pld: &[u8]) -> Result<Vec<u8>> {
    Ok(
        sphinx::peel_onion_to_bytes(km, pld).map_err(|e| SphinxError::Decrypt {
            r: format!("{:?}", e),
        })?,
    )
}

fn run_peel_payment_bytes(km: &KeysManager, pld: &[u8], rhash: [u8; 32]) -> Result<Vec<u8>> {
    Ok(
        sphinx::peel_payment_onion_to_bytes(km, pld, rhash).map_err(|e| SphinxError::Decrypt {
            r: format!("{:?}", e),
        })?,
    )
}
