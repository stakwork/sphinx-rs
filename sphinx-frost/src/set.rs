
use schnorr_fun::{frost, nonce};
use sha2::Sha256;
use std::{collections::HashMap};

pub struct Frost {
    // for building the federations
    federations: HashMap<Id, Federation>,
    // the actual Frost state
    sets: HashMap<Id, frost::Frost<Sha256, nonce::Deterministic<Sha256>>>,
}

// random unique id
pub type Id = String;
pub type PubkeyHex = String;
pub type SessionId = String;

pub struct Federation {
    pub set: Set,
    pub shares: HashMap<PubkeyHex, Shares>,
    pub sessions: HashMap<SessionId, HashMap<PubkeyHex, Vec<u8>>>,
}

impl Federation {
    pub fn new(set: Set) -> Self {
        Self {
            set,
            shares: HashMap::new(),
            sessions: HashMap::new(),
        }
    }
}

pub struct Set {
    pub pubkeys: Vec<PubkeyHex>,
    pub threshold: u16,
    pub n: u16,
}
pub struct Shares {
    pub shares: u8,
    pub pop: u8,
}
pub struct Sign {
    pub session_id: String,
    pub msg: String,
}
pub struct Nonce {
    pub session_id: String,
    pub nonce: String,
}

pub enum FrostMsg {
    Register((Id, Set)),
    Shares((Id, Shares)),
    Nonce((Id, Nonce)),
    Signed((Id, Vec<u8>)),
}
pub enum FrostResponse {
    Set((Id, Set)),
    Shares((Id, Shares)),
    Sign((Id, Sign)),
    Nonce((Id, Nonce)),
}

impl Frost {
    pub fn new() -> Self {
        let sets = HashMap::new();
        // sets.insert(
        //     format!("test"),
        //     frost::new_with_deterministic_nonces::<Sha256>(),
        // );
        Self {
            sets,
            federations: HashMap::new(),
        }
    }
    // the clients handle responses from server
    pub fn handle(&mut self, msg: FrostResponse) -> Option<FrostMsg> {
        match msg {
            FrostResponse::Set((_id, _set)) => {
                // if the received set is complete, add it to sets
                //   - new_keygen
                //   - create_shares
                None
            }
            FrostResponse::Shares((_id, _shares)) => {
                // add them to shares until complete
                //   - finish_keygen
                None
            }
            FrostResponse::Sign((_id, _sign)) => {
                // gen nonce
                Some(FrostMsg::Nonce((
                    "test".to_string(),
                    Nonce {
                        session_id: hex_secret_32(),
                        nonce: String::from(""),
                    },
                )))
            }
            FrostResponse::Nonce((id, _nonce)) => {
                // add nonces until reached threshold
                //   - start_sign_session
                //   - sign
                Some(FrostMsg::Signed((id, Vec::new())))
            }
        }
    }
    // aggregator logic
    pub fn serve(&mut self, msg: FrostMsg) -> Option<FrostResponse> {
        match msg {
            FrostMsg::Register((id, set)) => {
                // register only takes zero (init) or one pubkey
                if set.pubkeys.len() > 1 {
                    return None;
                }
                match self.federations.get_mut(&id) {
                    Some(fed) => {
                        // just joining
                        if set.pubkeys.len() != 1 {
                            return Some(FrostResponse::Set((id, set)));
                        }
                        // too late, federation has already formed
                        if fed.set.pubkeys.len() as u16 == fed.set.n {
                            return Some(FrostResponse::Set((id, set)));
                        }
                        fed.set.pubkeys.push(set.pubkeys[0].clone());
                        Some(FrostResponse::Set((id, set)))
                    }
                    None => {
                        // invalid
                        if set.threshold > set.n {
                            return None;
                        }
                        // empty set for sharing threshold and n only
                        self.federations.insert(
                            id.clone(),
                            Federation::new(Set {
                                threshold: set.threshold,
                                n: set.n,
                                pubkeys: Vec::new(),
                            }),
                        );
                        Some(FrostResponse::Set((id, set)))
                    }
                }
            }
            FrostMsg::Shares((id, s)) => Some(FrostResponse::Shares((id, s))),
            FrostMsg::Nonce((id, nonce)) => Some(FrostResponse::Nonce((id, nonce))),
            FrostMsg::Signed((_id, _sig)) => {
                // collect sigs and see
                //   - verify_signature_share
                //   - combine_signature_shares
                None
            }
        }
    }
}

pub fn hex_secret_32() -> String {
    use rand::{RngCore};
    let mut store_key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut store_key_bytes);
    hex::encode(store_key_bytes)
}

// cargo test --package sphinx-frost -- --nocapture
#[cfg(test)]
mod tests {
    use crate::set::*;
    pub use crossbeam::channel as chan;
    use std::thread::spawn;

    struct Client {
        frost: Frost,
        msg_tx: chan::Sender<FrostMsg>,
        res_rx: chan::Receiver<FrostResponse>,
    }
    impl Client {
        pub fn new(msg_tx: chan::Sender<FrostMsg>, res_rx: chan::Receiver<FrostResponse>) -> Self {
            Self {
                frost: Frost::new(),
                msg_tx,
                res_rx,
            }
        }
        pub fn send(&mut self, msg: FrostMsg) {
            self.msg_tx.send(msg).unwrap();
        }
        pub fn start(&mut self) {
            while let Ok(res) = self.res_rx.recv() {
                let _ = self.frost.handle(res);
            }
        }
    }
    struct Server {
        frost: Frost,
        res_tx: chan::Sender<FrostResponse>,
        msg_rx: chan::Receiver<FrostMsg>,
    }
    impl Server {
        pub fn new(res_tx: chan::Sender<FrostResponse>, msg_rx: chan::Receiver<FrostMsg>) -> Self {
            Self {
                frost: Frost::new(),
                msg_rx,
                res_tx,
            }
        }
        pub fn send(&mut self, res: FrostResponse) {
            self.res_tx.send(res).unwrap();
        }
        pub fn listen(&mut self) {
            while let Ok(msg) = self.msg_rx.recv() {
                let _ = self.frost.serve(msg);
            }
        }
    }

    #[test]
    fn test_set() {
        let (msg_tx, msg_rx) = chan::unbounded::<FrostMsg>();
        let (res_tx, res_rx) = chan::unbounded::<FrostResponse>();

        let mut server = Server::new(res_tx, msg_rx);
        let mut client1 = Client::new(msg_tx.clone(), res_rx.clone());
        let mut client2 = Client::new(msg_tx.clone(), res_rx.clone());
        let mut client3 = Client::new(msg_tx, res_rx);

        spawn(move || client1.start());
        spawn(move || client2.start());
        spawn(move || client3.start());

        spawn(move || server.listen());

        // let id = String::from("text");
        // client1.send(FrostMsg::Register((id, Set{
        //     pubkeys: Vec::new(),
        //     threshold: 2,
        //     n: 3
        // })))
    }
}
