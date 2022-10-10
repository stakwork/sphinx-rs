use crate::types::{ControlMessage, ControlResponse};
use sphinx_auther::{nonce, secp256k1::SecretKey};

pub fn build_control_msg(
    msg: ControlMessage,
    nonce: u64,
    secret: &SecretKey,
) -> anyhow::Result<Vec<u8>> {
    let data = rmp_serde::to_vec(&msg)?;
    let ret = nonce::build_msg(&data, secret, nonce)?;
    Ok(ret)
}

pub fn parse_control_response(input: &[u8]) -> anyhow::Result<ControlResponse> {
    Ok(rmp_serde::from_slice(input)?)
}

pub fn parse_control_response_to_json(input: &[u8]) -> anyhow::Result<String> {
    let res: ControlResponse = rmp_serde::from_slice(input)?;
    Ok(serde_json::to_string(&res)?)
}

pub fn control_msg_from_json(msg: &[u8]) -> anyhow::Result<ControlMessage> {
    let data: ControlMessage = serde_json::from_slice(msg)?;
    Ok(data)
}

// cargo test controller::tests::test_ctrl_json -- --exact
mod tests {

    #[test]
    fn test_ctrl_json() {
        use crate::controller::control_msg_from_json;

        let msg = "{}";
        let res = control_msg_from_json(msg.as_bytes());
        if let Ok(_) = res {
            panic!("should have failed");
        }

        let msg = "{\"type\":\"Nonce\"}";
        control_msg_from_json(msg.as_bytes()).expect("Nonce failed");

        let msg = "{\"type\":\"UpdatePolicy\", \"content\":{\"sat_limit\":0, \"interval\":\"hourly\", \"htlc_limit\":10}}";
        control_msg_from_json(msg.as_bytes()).expect("Nonce failed");
    }
}
