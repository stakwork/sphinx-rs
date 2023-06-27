use crate::policy::policy_interval;
use sphinx_glyph::types;
use types::{Policy, Velocity};

use lightning_signer::util::clock::Clock;
use lightning_signer::util::velocity::{VelocityControl, VelocityControlSpec};
use std::sync::Arc;
use vls_protocol_signer::approver::{NegativeApprover, VelocityApprover};
use vls_protocol_signer::lightning_signer;

pub type SphinxApprover = VelocityApprover<NegativeApprover>;

pub fn approver_control(
    initial_policy: Policy,
    initial_velocity: Option<Velocity>,
) -> VelocityControl {
    let spec = VelocityControlSpec {
        limit_msat: initial_policy.msat_per_interval,
        interval_type: policy_interval(initial_policy.interval),
    };
    match initial_velocity {
        Some(v) => VelocityControl::load_from_state(spec, v),
        None => VelocityControl::new(spec),
    }
}

pub fn create_approver(
    clock: Arc<dyn Clock>,
    initial_policy: Policy,
    initial_velocity: Option<Velocity>,
) -> SphinxApprover {
    let delegate = NegativeApprover();
    let control = approver_control(initial_policy, initial_velocity);
    VelocityApprover::new(clock.clone(), control, delegate)
}
