use crate::persist::ThreadMemoPersister;
use crate::root::builder_inner;
use anyhow::Result;
use lightning_signer::bitcoin::Network;
use lightning_signer::prelude::SendSync;
use lightning_signer::util::clock::Clock;
use sphinx_glyph::types::{Policy, Velocity};
use std::sync::Arc;
use std::time::Duration;
use vls_protocol_signer::lightning_signer;

// fully create a VLS node run the command on it
// returning muts to be stored in phone persistence

pub fn run_vls(
    seed: [u8; 32],
    network: Network,
    policy: Policy,
    velocity: Option<Velocity>,
    allowlist: Vec<String>,
    timestamp: Duration,
) -> Result<()> {
    let persister = Arc::new(ThreadMemoPersister {});
    // FIXME load up persister with all state
    let clock = Arc::new(NowClock::new(timestamp));
    let (_rhb, _approver) =
        builder_inner(seed, network, policy, velocity, allowlist, persister, clock)?;
    Ok(())
}

pub struct NowClock(Duration);

impl SendSync for NowClock {}

impl Clock for NowClock {
    fn now(&self) -> Duration {
        self.0
    }
}

impl NowClock {
    pub fn new(now: Duration) -> Self {
        NowClock(now)
    }
}
