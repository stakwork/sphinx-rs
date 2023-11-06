use crate::{Result, SphinxError};
use sphinx::bip32::XKey;
use sphinx::{make_signer, MyKeysManager, Network, PublicKey};
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

pub fn sign_ms(seed: String, idx: u32, time: String, network: String) -> Result<String> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let sig = sphinx::sig::sign_message(time.as_bytes(), &km.get_node_secret()).map_err(|_| {
        SphinxError::BadCiper {
            r: "sign failed".to_string(),
        }
    })?;
    Ok(hex::encode(sig))
}

pub fn pubkey_from_seed(seed: String, idx: u32, time: String, network: String) -> Result<String> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let pubkey = km.get_node_pubkey();
    Ok(hex::encode(pubkey.serialize()))
}

pub fn create_onion(
    seed: String,
    idx: u32,
    time: String,
    network: String,
    hops: String,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let hops = parse_hops(&hops)?;
    let (_, data) = run_create_onion_bytes(&km, hops, &payload)?;
    Ok(data)
}

pub fn create_onion_msg(
    seed: String,
    idx: u32,
    time: String,
    network: String,
    hops: String,
    msg_json: String,
) -> Result<Vec<u8>> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let hops = parse_hops(&hops)?;
    let payload = sphinx::msg::create_sphinx_msg_from_json(&km, &msg_json)
        .map_err(|e| SphinxError::BadMsg { r: e.to_string() })?;
    let (_, data) = run_create_onion_bytes(&km, hops, &payload)?;
    Ok(data)
}

pub fn peel_onion(
    seed: String,
    idx: u32,
    time: String,
    network: String,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    Ok(run_peel_onion_bytes(&km, &payload)?)
}

pub fn peel_onion_msg(
    seed: String,
    idx: u32,
    time: String,
    network: String,
    payload: Vec<u8>,
) -> Result<String> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let bytes = run_peel_onion_bytes(&km, &payload)?;
    let msg = sphinx::msg::parse_sphinx_msg_to_json(&bytes, None)
        .map_err(|e| SphinxError::BadMsg { r: e.to_string() })?;
    Ok(msg)
}

pub fn create_keysend(
    seed: String,
    idx: u32,
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
    idx: u32,
    time: String,
    network: String,
    payload: Vec<u8>,
    rhash: String,
) -> Result<Vec<u8>> {
    let idx = idx_to_idx(idx)?;
    let km = make_keys_manager(&seed, idx, &time, &network)?;
    let payment_hash = parse_hash(&rhash)?;
    Ok(run_peel_payment_bytes(&km, &payload, payment_hash)?)
}

fn idx_to_idx(idx: u32) -> Result<Option<isize>> {
    Ok(Some(idx.try_into().map_err(|_| {
        SphinxError::BadChildIndex {
            r: "infallible".to_string(),
        }
    })?))
}

fn make_keys_manager(
    seed: &str,
    idx: Option<isize>,
    time: &str,
    network: &str,
) -> Result<MyKeysManager> {
    let seed = parse_seed(seed)?;
    let ts = parse_u64(time)?;
    let net = Network::from_str(network).map_err(|_| SphinxError::BadArgs {
        r: "invalid network".to_string(),
    })?;
    let mut mkm = make_signer(&seed, idx, ts, net);
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

fn run_peel_onion_bytes(km: &MyKeysManager, pld: &[u8]) -> Result<Vec<u8>> {
    Ok(
        sphinx::peel_onion_to_bytes(km, pld).map_err(|e| SphinxError::Decrypt {
            r: format!("{:?}", e),
        })?,
    )
}

fn run_peel_payment_bytes(km: &MyKeysManager, pld: &[u8], rhash: [u8; 32]) -> Result<Vec<u8>> {
    Ok(
        sphinx::peel_payment_onion_to_bytes(km, pld, rhash).map_err(|e| SphinxError::Decrypt {
            r: format!("{:?}", e),
        })?,
    )
}
