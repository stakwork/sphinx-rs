use fsdb::{AnyBucket, Fsdb};
use lightning_signer::persist::Error;
use lightning_signer::SendSync;
use log::error;
use std::collections::BTreeMap;
use std::convert::TryInto;
pub use vls_persist::kvv::{cloud::CloudKVVStore, KVVPersister, KVVStore, KVV};
use vls_protocol_signer::lightning_signer;
extern crate alloc;

/// A key-version-value store backed by redb
pub struct FsKVVStore {
    db: AnyBucket<Vec<u8>>,
    // keep track of current versions for each key, so we can efficiently enforce versioning.
    // we don't expect many keys, so this is OK for low-resource environments.
    versions: BTreeMap<String, u64>,
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
    pub fn new(path: &str, maxsize: Option<usize>) -> KVVPersister<Self> {
        let db = Fsdb::new(path).expect("could not create db");
        let bucket = db
            .any_bucket::<Vec<u8>>(maxsize)
            .expect("could not create bucket");

        // seed the initial versions store
        let mut versions = BTreeMap::new();
        let fulllist = bucket.list_all().expect("could not list bucket");
        for path in fulllist {
            match bucket.get(&path) {
                Ok(item) => {
                    let (version, _) = Self::decode_vv(&item);
                    versions.insert(path, version);
                }
                Err(e) => log::error!("failed to seed version {:?}", e),
            }
        }

        KVVPersister(Self {
            db: bucket,
            versions,
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
    fn check_version(&self, key: &str, version: u64, value: &[u8]) -> Result<Vec<u8>, Error> {
        let vv = Self::encode_vv(version, value);
        if let Some(v) = self.versions.get(key) {
            if version < *v {
                error!("version mismatch for {}: {} < {}", key, version, v);
                // version cannot go backwards
                return Err(Error::VersionMismatch);
            } else if version == *v {
                // if same version, value must not have changed
                if let Ok(existing) = self.db.get(key) {
                    if existing != vv {
                        error!("value mismatch for {}: {}", key, version);
                        return Err(Error::VersionMismatch);
                    }
                }
                return Ok(vv);
            }
        }
        Ok(vv)
    }
}

impl KVVStore for FsKVVStore {
    type Iter = Iter;

    fn put(&self, key: &str, value: &[u8]) -> Result<(), Error> {
        let version = self.versions.get(key).map(|v| v + 1).unwrap_or(0);
        self.put_with_version(key, version, value)
    }

    fn put_with_version(&self, key: &str, version: u64, value: &[u8]) -> Result<(), Error> {
        let vv = self.check_version(key, version, value)?;
        self.db
            .put(key, &vv)
            .map_err(|_| Error::Internal("could not put".to_string()))?;
        Ok(())
    }
    fn put_batch(&self, kvvs: &[&KVV]) -> Result<(), Error> {
        let mut found_version_mismatch = false;
        let mut staged_vvs: Vec<(String, Vec<u8>)> = Vec::new();
        for kvv in kvvs.into_iter() {
            match self.check_version(&kvv.0, kvv.1 .0, &kvv.1 .1) {
                Ok(vv) => staged_vvs.push((kvv.0.clone(), vv)),
                Err(_) => found_version_mismatch = true,
            }
        }
        if found_version_mismatch {
            // abort the transaction
            return Err(Error::VersionMismatch);
        } else {
            for vv in staged_vvs {
                self.db
                    .put(&vv.0, &vv.1)
                    .map_err(|_| Error::Internal("could not put".to_string()))?;
            }
        }
        Ok(())
    }
    fn get(&self, key: &str) -> Result<Option<(u64, Vec<u8>)>, Error> {
        if let Ok(vv) = self.db.get(key) {
            let (version, value) = Self::decode_vv(&vv);
            Ok(Some((version, value)))
        } else {
            Ok(None)
        }
    }
    fn get_version(&self, key: &str) -> Result<Option<u64>, Error> {
        Ok(self.versions.get(key).copied())
    }
    fn get_prefix(&self, prefix: &str) -> Result<Self::Iter, Error> {
        let items = self
            .db
            .list(prefix)
            .map_err(|_| Error::Internal("could not list".to_string()))?;
        let mut result = Vec::new();
        for item in items {
            let key = format!("{}/{}", prefix, item);
            let vv = self
                .db
                .get(&key)
                .map_err(|_| Error::Internal("could not get".to_string()))?;
            let (version, value) = Self::decode_vv(&vv);
            result.push(KVV(key, (version, value)));
        }
        Ok(Iter(result.into_iter()))
    }
    fn delete(&self, key: &str) -> Result<(), Error> {
        Ok(self
            .db
            .remove(key)
            .map_err(|_| Error::Internal("could not remove".to_string()))?)
    }
    fn clear_database(&self) -> Result<(), Error> {
        Ok(self
            .db
            .clear()
            .map_err(|_| Error::Internal("could not clear".to_string()))?)
    }
}
