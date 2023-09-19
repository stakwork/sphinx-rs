use anyhow::Result;
use fsdb::{Bucket, Fsdb};
use sphinx_signer::sphinx_glyph::control::{Config, ControlPersist, Policy, Velocity};

pub struct ControlPersister {
    nonce: Bucket<[u8; 8]>,
    config: Bucket<Config>,
    seed: Bucket<[u8; 32]>,
    id: Bucket<[u8; 16]>,
    policy: Bucket<Policy>,
    velocity: Bucket<Velocity>,
}

impl ControlPersister {
    pub fn new(dir: &str) -> Self {
        let db = Fsdb::new(dir).expect("could not create db");
        Self {
            nonce: db.bucket("nonce", None).expect("fail nonce db"),
            config: db.bucket("config", None).expect("fail config db"),
            seed: db.bucket("seed", None).expect("fail seed db"),
            id: db.bucket("id", None).expect("fail id db"),
            policy: db.bucket("policy", None).expect("fail policy db"),
            velocity: db.bucket("velocity", None).expect("fail velocity db"),
        }
    }
}

impl ControlPersist for ControlPersister {
    fn read_nonce(&self) -> Result<u64> {
        let r = self.nonce.get("nonce")?;
        Ok(u64::from_be_bytes(r))
    }
    fn set_nonce(&mut self, nonce: u64) -> Result<()> {
        Ok(self.nonce.put("nonce", &nonce.to_be_bytes())?)
    }
    fn read_config(&self) -> Result<Config> {
        Ok(self.config.get("config")?)
    }
    fn write_config(&mut self, conf: Config) -> Result<()> {
        Ok(self.config.put("config", &conf)?)
    }
    fn remove_config(&mut self) -> Result<()> {
        Ok(self.config.remove("config")?)
    }
    fn read_seed(&self) -> Result<[u8; 32]> {
        Ok(self.seed.get("seed")?)
    }
    fn write_seed(&mut self, s: [u8; 32]) -> Result<()> {
        Ok(self.seed.put("seed", &s)?)
    }
    fn remove_seed(&mut self) -> Result<()> {
        Ok(self.seed.remove("seed")?)
    }
    fn read_id(&self) -> Result<[u8; 16]> {
        Ok(self.id.get("id")?)
    }
    fn write_id(&mut self, id: [u8; 16]) -> Result<()> {
        Ok(self.id.put("id", &id)?)
    }
    fn read_policy(&self) -> Result<Policy> {
        Ok(self.policy.get("policy")?)
    }
    fn write_policy(&mut self, pol: Policy) -> Result<()> {
        Ok(self.policy.put("policy", &pol)?)
    }
    fn remove_policy(&mut self) -> Result<()> {
        Ok(self.policy.remove("policy")?)
    }
    fn read_velocity(&self) -> Result<Velocity> {
        Ok(self.velocity.get("velocity")?)
    }
    fn write_velocity(&mut self, v: Velocity) -> Result<()> {
        Ok(self.velocity.put("velocity", &v)?)
    }
}
