use sphinx_glyph::types::Policy;

use lightning_signer::persist::Mutations;
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::Arc;
use sphinx_glyph::control::{All, ControlMessage, ControlResponse};
use vls_protocol_signer::handler::{Handler, RootHandler};
use vls_protocol_signer::lightning_signer;
use vls_protocol_signer::lightning_signer::bitcoin::Network;

use crate::approver::{approver_control, SphinxApprover};

pub fn update_controls(
    rh: &RootHandler,
    msg: ControlMessage,
    mut res: ControlResponse,
    approver: &SphinxApprover,
) -> (ControlResponse, Option<Mutations>) {
    let mut muts = None;
    match msg {
        ControlMessage::UpdatePolicy(new_policy) => {
            if let Err(e) = set_approver_policy(approver, new_policy) {
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
        ControlMessage::QueryAll => match get_allowlist(rh) {
            Ok(al) => {
                if let ControlResponse::AllCurrent(ac) = res {
                    res = ControlResponse::AllCurrent(All {
                        policy: ac.policy,
                        velocity: ac.velocity,
                        allowlist: al,
                    })
                } else {
                    res = ControlResponse::Error("wrong ControlResponse type".to_string())
                }
            }
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
    allowlist: &[String],
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
    let policy = crate::root::make_policy(network, &po);
    let validator_factory = Arc::new(SimpleValidatorFactory::new_with_policy(policy));
    root_handler.node().set_validator_factory(validator_factory);
    Ok(())
}

pub fn set_approver_policy(approver: &SphinxApprover, po: Policy) -> anyhow::Result<()> {
    let app_control = approver_control(po, None);
    approver.set_control(app_control);
    Ok(())
}
