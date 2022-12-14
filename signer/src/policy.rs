use sphinx_glyph::types::{Interval, Policy};

use lightning_signer::policy::filter::PolicyFilter;
use lightning_signer::policy::simple_validator::{
    make_simple_policy, SimplePolicy, SimpleValidatorFactory,
};
use lightning_signer::util::velocity::{VelocityControlIntervalType, VelocityControlSpec};
use sphinx_glyph::control::{ControlMessage, ControlResponse};
use std::sync::Arc;
use vls_protocol_signer::handler::{Handler, RootHandler};
use vls_protocol_signer::lightning_signer;
use vls_protocol_signer::lightning_signer::bitcoin::Network;

pub fn update_controls(
    rh: &RootHandler,
    network: Network,
    msg: ControlMessage,
    mut res: ControlResponse,
) -> ControlResponse {
    match msg {
        ControlMessage::UpdatePolicy(new_policy) => {
            if let Err(e) = set_policy(rh, network, new_policy) {
                log::error!("set policy failed {:?}", e);
                res = ControlResponse::Error(format!("set policy failed {:?}", e))
            }
        }
        ControlMessage::UpdateAllowlist(al) => {
            if let Err(e) = set_allowlist(rh, &al) {
                log::error!("set allowlist failed {:?}", e);
                res = ControlResponse::Error(format!("set allowlist failed {:?}", e))
            }
        }
        ControlMessage::QueryAllowlist => match get_allowlist(rh) {
            Ok(al) => res = ControlResponse::AllowlistCurrent(al),
            Err(e) => {
                log::error!("read allowlist failed {:?}", e);
                res = ControlResponse::Error(format!("read allowlist failed {:?}", e))
            }
        },
        _ => (),
    }
    res
}

pub fn set_allowlist(root_handler: &RootHandler, allowlist: &Vec<String>) -> anyhow::Result<()> {
    if let Err(e) = root_handler.node().set_allowlist(allowlist) {
        return Err(anyhow::anyhow!("error setting allowlist {:?}", e));
    }
    Ok(())
}

pub fn get_allowlist(root_handler: &RootHandler) -> anyhow::Result<Vec<String>> {
    match root_handler.node().allowlist() {
        Ok(al) => Ok(al),
        Err(e) => Err(anyhow::anyhow!("error setting allowlist {:?}", e)),
    }
}

pub fn set_policy(root_handler: &RootHandler, network: Network, po: Policy) -> anyhow::Result<()> {
    let policy = make_policy(network, &po);
    let validator_factory = Arc::new(SimpleValidatorFactory::new_with_policy(policy));
    root_handler.node().set_validator_factory(validator_factory);
    Ok(())
}

pub fn make_policy(network: Network, po: &Policy) -> SimplePolicy {
    let mut p = make_simple_policy(network);
    p.max_htlc_value_sat = po.htlc_limit;
    p.filter = PolicyFilter::new_permissive();
    let velocity_spec = VelocityControlSpec {
        limit: po.sat_limit,
        interval_type: policy_interval(po.interval),
    };
    p.global_velocity_control = velocity_spec;
    p
}

fn policy_interval(int: Interval) -> VelocityControlIntervalType {
    match int {
        Interval::Hourly => VelocityControlIntervalType::Hourly,
        Interval::Daily => VelocityControlIntervalType::Daily,
    }
}
