use sphinx_glyph::types::{Interval, Policy};

use lightning_signer::persist::Mutations;
use lightning_signer::policy::filter::PolicyFilter;
use lightning_signer::policy::simple_validator::{
    make_simple_policy, SimplePolicy, SimpleValidatorFactory,
};
use lightning_signer::util::velocity::VelocityControlIntervalType;
use sphinx_glyph::control::{ControlMessage, ControlResponse};
use std::sync::Arc;
use vls_protocol_signer::handler::{Handler, RootHandler};
use vls_protocol_signer::lightning_signer;
use vls_protocol_signer::lightning_signer::bitcoin::Network;

use crate::root::SphinxApprover;

pub fn update_controls(
    rh: &RootHandler,
    network: Network,
    msg: ControlMessage,
    mut res: ControlResponse,
    approver: &SphinxApprover,
) -> (ControlResponse, Option<Mutations>) {
    let mut muts = None;
    match msg {
        ControlMessage::UpdatePolicy(new_policy) => {
            if let Err(e) = set_policy(rh, network, new_policy) {
                log::error!("set policy failed {:?}", e);
                res = ControlResponse::Error(format!("set policy failed {:?}", e))
            }
        }
        ControlMessage::UpdateAllowlist(al) => match set_allowlist(rh, &al) {
            Ok(muts_) => {
                muts = Some(muts_);
            }
            Err(e) => {
                log::error!("set allowlist failed {:?}", e);
                res = ControlResponse::Error(format!("set allowlist failed {:?}", e))
            }
        },
        ControlMessage::QueryAllowlist => match get_allowlist(rh) {
            Ok(al) => res = ControlResponse::AllowlistCurrent(al),
            Err(e) => {
                log::error!("read allowlist failed {:?}", e);
                res = ControlResponse::Error(format!("read allowlist failed {:?}", e))
            }
        },
        _ => (),
    }
    (res, muts)
}

pub fn set_allowlist(
    root_handler: &RootHandler,
    allowlist: &Vec<String>,
) -> anyhow::Result<Mutations> {
    let muts = root_handler
        .with_persist(|node| Ok(node.set_allowlist(allowlist)?))
        .map_err(|e| anyhow::anyhow!("error setting allowlist {:?}", e))?;
    Ok(muts)
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

pub fn make_policy(network: Network, _po: &Policy) -> SimplePolicy {
    let mut p = make_simple_policy(network);
    // let mut p = make_simple_policy(network);
    // p.max_htlc_value_sat = po.htlc_limit_msat;
    p.filter = PolicyFilter::new_permissive();
    // FIXME for prod use a nempty filter
    p
}

pub fn policy_interval(int: Interval) -> VelocityControlIntervalType {
    match int {
        Interval::Hourly => VelocityControlIntervalType::Hourly,
        Interval::Daily => VelocityControlIntervalType::Daily,
    }
}
