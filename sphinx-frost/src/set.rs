use rand_chacha::ChaCha20Rng;
use schnorr_fun::{frost, nonce, Message};
use sha2::Sha256;
use std::{collections::HashMap, hash::Hash};

/*
vls

let bolt12_secret = master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(9735).unwrap())
get_bolt12_pubkey
sign_bolt12
Message::SignBolt12

could we intercept hose msgs
could we provider our own bolt12 keypair?
and sign as federation
*/

pub struct Federation {
    pub set: Set,
    pub shares: HashMap<String, Shares>,
    // session_id: { pubkey: nonce }
    pub sessions: HashMap<String, HashMap<String, Vec<u8>>>,
}

pub struct Frost {
    // for building the federations
    // server stores partial federations for joining
    federations: HashMap<String, Federation>,
    // for the actual Frost state
    sets: HashMap<String, frost::Frost<Sha256, nonce::Deterministic<Sha256>>>,
}

pub struct Set {
    pub id: String,
    pub pubkeys: Vec<String>,
    pub threshold: u16,
}
pub struct Shares {
    pub id: String,
    pub shares: u8,
    pub pop: u8,
}

pub struct Sign {
    pub id: String,
    pub session_id: String,
    pub msg: String,
}

pub struct Nonce {
    pub id: String,
    pub session_id: String,
    pub nonce: String,
}

pub enum FrostMsg {
    Register(Set),
    Shares(Shares),
    Nonce(Nonce),
    Signed(Vec<u8>),
}
pub enum FrostResponse {
    Set(Set),
    Shares(Shares),
    Sign(Sign),
    Nonce(Nonce),
}

impl Frost {
    pub fn new() -> Self {
        let mut sets = HashMap::new();
        sets.insert(
            format!("test"),
            frost::new_with_deterministic_nonces::<Sha256>(),
        );
        Self {
            sets,
            federations: HashMap::new(),
        }
    }
    // the clients handle msgs from server
    pub fn handle(&mut self, msg: FrostResponse) -> Option<FrostMsg> {
        match msg {
            FrostResponse::Set(set) => {
                // if the received set is complete, add it to sets
                //   - new_keygen
                //   - create_shares
                None
            }
            FrostResponse::Shares(shares) => {
                // add them to shares until complete
                //   - finish_keygen
                None
            }
            FrostResponse::Sign(sign) => {
                // gen nonce
                Some(FrostMsg::Nonce(Nonce {
                    id: String::from(""),
                    session_id: String::from(""),
                    nonce: String::from(""),
                }))
            }
            FrostResponse::Nonce(nonce) => {
                // add nonces until reached threshold
                //   - start_sign_session
                //   - sign
                Some(FrostMsg::Signed(Vec::new()))
            }
        }
    }
    // aggregator logic
    pub fn serve(&mut self, msg: FrostMsg) -> Option<FrostResponse> {
        match msg {
            FrostMsg::Register(set) => {
                // add set to federations (key by hash w sorted pubkeys)

                // return the partial set of registered people
                // or the full thing if complete!
                Some(FrostResponse::Set(set))
            }
            FrostMsg::Shares(s) => Some(FrostResponse::Shares(s)),
            FrostMsg::Nonce(nonce) => Some(FrostResponse::Nonce(nonce)),
            FrostMsg::Signed(nonce) => {
                // collect sigs and see
                //   - verify_signature_share
                //   - combine_signature_shares
                None
            }
        }
    }
}

// cargo test --package sphinx-frost -- --nocapture
#[cfg(test)]
mod tests {
    use crate::set::*;

    #[test]
    fn test_set() {
        let server = Frost::new();
        let client1 = Frost::new();
        let client2 = Frost::new();
        let client3 = Frost::new();
    }
}
