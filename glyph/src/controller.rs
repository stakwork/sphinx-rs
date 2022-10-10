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

pub fn control_msg_from_json(
    msg: &[u8],
    nonce: u64,
    secret: &SecretKey,
) -> anyhow::Result<Vec<u8>> {
    let data: ControlMessage = serde_json::from_slice(msg)?;
    let ret = build_control_msg(data, nonce, secret)?;
    Ok(ret)
}

// cargo test controller::tests::test_ctrl_json -- --exact
mod tests {

    #[test]
    fn test_ctrl_json() {
        use crate::controller::control_msg_from_json;
        use sphinx_auther::secp256k1::SecretKey;

        let sk = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let msg = "{}";
        let res = control_msg_from_json(msg.as_bytes(), 0, &sk);
        if let Ok(_) = res {
            panic!("should have failed");
        }

        let msg = "{\"type\":\"Nonce\"}";
        control_msg_from_json(msg.as_bytes(), 0, &sk).expect("Nonce failed");

        let msg = "{\"type\":\"UpdatePolicy\", \"content\":{\"sat_limit\":0, \"interval\":\"hourly\", \"htlc_limit\":10}}";
        control_msg_from_json(msg.as_bytes(), 0, &sk).expect("Nonce failed");
    }
}
