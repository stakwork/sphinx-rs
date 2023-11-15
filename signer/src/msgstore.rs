use fsdb::{Bucket, Fsdb};
use lightning_signer::persist::Error;
use lightning_signer::SendSync;
use vls_protocol_signer::lightning_signer;

pub struct MsgStore {
    prev_msgs: Bucket<Vec<u8>>,
}

impl SendSync for MsgStore {}

impl MsgStore {
    pub fn new(dir: &str, maxsize: Option<usize>) -> Self {
        let db = Fsdb::new(dir).expect("could not create db");
        Self {
            prev_msgs: db.bucket("prevs", maxsize).expect("fail prevs"),
        }
    }
}

impl MsgStore {
    pub fn set_prevs(&self, prev_vls: &[u8], prev_lss: &[u8]) {
        let _ = self.prev_msgs.put_raw("prev_vls", prev_vls);
        let _ = self.prev_msgs.put_raw("prev_lss", prev_lss);
    }
    pub fn remove_prevs(&self) {
        let _ = self.prev_msgs.remove("prev_vls");
        let _ = self.prev_msgs.remove("prev_lss");
    }
    pub fn read_prevs(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let prev_vls = match self.prev_msgs.get_raw("prev_vls") {
            Ok(pv) => pv,
            Err(_) => {
                return Err(Error::NotFound("Failed to get prev_vls".to_string()));
            }
        };
        let prev_lss = match self.prev_msgs.get_raw("prev_lss") {
            Ok(pl) => pl,
            Err(_) => {
                return Err(Error::NotFound("Failed to get prev_lss".to_string()));
            }
        };
        Ok((prev_vls, prev_lss))
    }
}
