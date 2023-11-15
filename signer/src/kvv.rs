use fsdb::{AnyBucket, Bucket, Fsdb};
use lightning_signer::persist::{Error, SignerId};
use lightning_signer::SendSync;
use log::error;
use std::collections::BTreeMap;
use std::convert::TryInto;
pub use vls_persist::kvv::{cloud::CloudKVVStore, KVVPersister, KVVStore, KVV};
use vls_protocol_signer::lightning_signer;
extern crate alloc;
use std::cmp::Ordering;
use std::sync::Mutex;

/// A key-version-value store backed by fsdb
pub struct FsKVVStore {
    db: AnyBucket<Vec<u8>>,
    meta: Bucket<Vec<u8>>,
    signer_id: [u8; 16],
    versions: Mutex<BTreeMap<String, u64>>,
}

/// An iterator over a KVVStore range
pub struct Iter(alloc::vec::IntoIter<KVV>);

impl Iterator for Iter {
    type Item = KVV;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl SendSync for FsKVVStore {}

impl FsKVVStore {
    pub fn new(path: &str, signer_id: [u8; 16], maxsize: Option<usize>) -> KVVPersister<Self> {
        let db = Fsdb::new(path).expect("could not create db");
        let bucket = db
            .any_bucket::<Vec<u8>>(maxsize)
            .expect("could not create bucket");

        // seed the initial versions store
        let mut versions = BTreeMap::new();
        let fulllist = bucket.list_all().expect("could not list bucket");
        for path in fulllist {
            match bucket.get_raw(&path) {
                Ok(item) => {
                    let (version, _) = Self::decode_vv(&item);
                    versions.insert(path, version);
                }
                Err(e) => log::error!("failed to seed version {:?}", e),
            }
        }

        let meta = db
            .bucket::<Vec<u8>>("meta", None)
            .expect("could not create bucket");
        KVVPersister(Self {
            db: bucket,
            meta,
            signer_id,
            versions: Mutex::new(versions),
        })
    }
    fn decode_vv(vv: &[u8]) -> (u64, Vec<u8>) {
        let version = u64::from_be_bytes(vv[..8].try_into().unwrap());
        let value = vv[8..].to_vec();
        (version, value)
    }
    fn encode_vv(version: u64, value: &[u8]) -> Vec<u8> {
        let mut vv = Vec::with_capacity(value.len() + 8);
        vv.extend_from_slice(&version.to_be_bytes());
        vv.extend_from_slice(value);
        vv
    }
    fn check_version(
        &self,
        key: &str,
        version: u64,
        prev: u64,
        value: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let vv = Self::encode_vv(version, value);
        match version.cmp(&prev) {
            Ordering::Less => {
                error!("version mismatch for {}: {} < {}", key, version, prev);
                // version cannot go backwards
                Err(Error::VersionMismatch)
            }
            Ordering::Equal => {
                // if same version, value must not have changed
                if let Ok(existing) = self.db.get_raw(key) {
                    if existing != vv {
                        error!("value mismatch for {}: {}", key, version);
                        return Err(Error::VersionMismatch);
                    }
                }
                Ok(vv)
            }
            Ordering::Greater => Ok(vv),
        }
    }
}

impl KVVStore for FsKVVStore {
    type Iter = Iter;

    fn signer_id(&self) -> SignerId {
        self.signer_id
    }

    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), Error> {
        let v = self
            .versions
            .lock()
            .unwrap()
            .get(key)
            .map(|v| v + 1)
            .unwrap_or(0);
        self.put_with_version(key, v, value)
    }

    fn put_with_version(&self, key: &str, version: u64, value: Vec<u8>) -> Result<(), Error> {
        let mut vers = self.versions.lock().unwrap();
        let vv = match vers.get(key) {
            Some(prev) => self.check_version(key, version, *prev, &value)?,
            None => Self::encode_vv(version, &value),
        };
        vers.insert(key.to_string(), version);
        self.db
            .put_raw(key, &vv)
            .map_err(|_| Error::Internal("could not put".to_string()))?;
        Ok(())
    }
    fn put_batch(&self, kvvs: Vec<KVV>) -> Result<(), Error> {
        let mut found_version_mismatch = false;
        let mut staged_vvs: Vec<(String, u64, Vec<u8>)> = Vec::new();

        let mut vers = self.versions.lock().unwrap();
        for kvv in kvvs.into_iter() {
            let key = kvv.0.clone();
            let ver = kvv.1 .0;
            let val = &kvv.1 .1;
            match vers.get(&key) {
                Some(prev) => match self.check_version(&key, ver, *prev, val) {
                    Ok(vv) => staged_vvs.push((key.clone(), ver, vv)),
                    Err(_) => found_version_mismatch = true,
                },
                None => {
                    let vv = Self::encode_vv(ver, val);
                    staged_vvs.push((key.clone(), ver, vv));
                }
            }
        }
        if found_version_mismatch {
            // abort the transaction
            return Err(Error::VersionMismatch);
        } else {
            for vv in staged_vvs {
                self.db
                    .put_raw(&vv.0, &vv.2)
                    .map_err(|_| Error::Internal("could not put".to_string()))?;
                vers.insert(vv.0, vv.1);
            }
        }
        Ok(())
    }
    fn get(&self, key: &str) -> Result<Option<(u64, Vec<u8>)>, Error> {
        if let Ok(vv) = self.db.get_raw(key) {
            let (version, value) = Self::decode_vv(&vv);
            Ok(Some((version, value)))
        } else {
            Ok(None)
        }
    }
    fn get_version(&self, key: &str) -> Result<Option<u64>, Error> {
        Ok(self.versions.lock().unwrap().get(key).copied())
    }
    fn get_prefix(&self, prefix: &str) -> Result<Self::Iter, Error> {
        let items = self
            .db
            .list(prefix)
            .map_err(|_| Error::Internal("could not list".to_string()))?;
        let mut result = Vec::new();
        for item in items {
            let sep = if prefix.ends_with('/') {
                "".to_string()
            } else {
                "/".to_string()
            };
            let key = format!("{}{}{}", prefix, sep, item);
            let vv = self
                .db
                .get_raw(&key)
                .map_err(|_| Error::Internal("could not get".to_string()))?;
            let (version, value) = Self::decode_vv(&vv);
            result.push(KVV(key, (version, value)));
        }
        Ok(Iter(result.into_iter()))
    }
    fn delete(&self, key: &str) -> Result<(), Error> {
        self.db
            .remove(key)
            .map_err(|_| Error::Internal("could not remove".to_string()))
    }
    fn clear_database(&self) -> Result<(), Error> {
        self.db
            .clear()
            .map_err(|_| Error::Internal("could not clear".to_string()))
    }
}

impl FsKVVStore {
    pub fn get_raw(&self, key: &str) -> Result<Vec<u8>, Error> {
        self.meta
            .get_raw(key)
            .map_err(|_| Error::Internal("failed get_raw".to_string()))
    }
    pub fn set_raw(&self, key: &str, data: &[u8]) -> Result<(), Error> {
        self.meta
            .put_raw(key, data)
            .map_err(|_| Error::Internal("failed put_raw".to_string()))
    }
    pub fn delete_raw(&self, key: &str) -> Result<(), Error> {
        self.meta
            .remove(key)
            .map_err(|_| Error::Internal("failed remove".to_string()))
    }
}
