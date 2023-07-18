use crate::types::*;
use anyhow::{anyhow, Result};
use rmp_utils as rmp;
pub use rmp_utils::{ByteBuf, Bytes};

pub fn serialize_controlmessage(buff: &mut ByteBuf, object: &ControlMessage) -> Result<()> {
    match object {
        ControlMessage::Nonce => rmp::serialize_variant(buff, "Nonce")?,
        ControlMessage::ResetWifi => rmp::serialize_variant(buff, "ResetWifi")?,
        ControlMessage::ResetKeys => rmp::serialize_variant(buff, "ResetKeys")?,
        ControlMessage::ResetAll => rmp::serialize_variant(buff, "ResetAll")?,
        ControlMessage::QueryPolicy => rmp::serialize_variant(buff, "QueryPolicy")?,
        ControlMessage::UpdatePolicy(policy) => {
            rmp::serialize_map_len(buff, 1)?;
            serialize_policy(buff, Some("UpdatePolicy"), policy)?;
        }
        ControlMessage::QueryAllowlist => rmp::serialize_variant(buff, "QueryAllowlist")?,
        ControlMessage::UpdateAllowlist(list) => {
            rmp::serialize_map_len(buff, 1)?;
            rmp::serialize_string_vec(buff, Some("UpdateAllowlist"), list)?;
        }
        ControlMessage::QueryVelocity => rmp::serialize_variant(buff, "QueryVelocity")?,
        ControlMessage::Ota(ota_params) => {
            rmp::serialize_map_len(buff, 1)?;
            serialize_otaparams(buff, Some("Ota"), ota_params)?;
        }
        ControlMessage::QueryAll => rmp::serialize_variant(buff, "QueryAll")?,
    }
    Ok(())
}

pub fn deserialize_controlmessage(bytes: &mut Bytes) -> Result<ControlMessage> {
    let peek = rmp::peek_byte(bytes)?;
    if peek == 0x81 {
        rmp::deserialize_map_len(bytes, 1)?;
    }
    let variant = rmp::deserialize_variant(bytes)?;
    let en = match variant.as_str() {
        "Nonce" => ControlMessage::Nonce,
        "ResetWifi" => ControlMessage::ResetWifi,
        "ResetKeys" => ControlMessage::ResetKeys,
        "ResetAll" => ControlMessage::ResetAll,
        "QueryPolicy" => ControlMessage::QueryPolicy,
        "UpdatePolicy" => {
            let policy = deserialize_policy(bytes, None)?;
            ControlMessage::UpdatePolicy(policy)
        }
        "QueryAllowlist" => ControlMessage::QueryAllowlist,
        "UpdateAllowlist" => {
            let list = rmp::deserialize_string_vec(bytes, None)?;
            ControlMessage::UpdateAllowlist(list)
        }
        "QueryVelocity" => ControlMessage::QueryVelocity,
        "Ota" => {
            let params = deserialize_otaparams(bytes)?;
            ControlMessage::Ota(params)
        }
        "QueryAll" => ControlMessage::QueryAll,
        _ => panic!("could not deserialize controlmessage"),
    };
    Ok(en)
}

#[test]
fn test_controlmessage_serde() {
    for test in [
        ControlMessage::Nonce,
        ControlMessage::ResetWifi,
        ControlMessage::ResetKeys,
        ControlMessage::ResetAll,
        ControlMessage::QueryPolicy,
        ControlMessage::UpdatePolicy(Policy {
            msat_per_interval: u64::MAX,
            interval: Interval::Hourly,
            htlc_limit_msat: u64::MAX,
        }),
        ControlMessage::QueryAllowlist,
        ControlMessage::UpdateAllowlist(vec![
            "alice".to_string(),
            "bob".to_string(),
            "carol".to_string(),
        ]),
        ControlMessage::QueryVelocity,
        ControlMessage::Ota(OtaParams {
            version: u64::MAX,
            url: "https://www.sphinx.chat/signer/ota".to_string(),
        }),
        ControlMessage::QueryAll,
    ] {
        //serialize
        let mut buff = ByteBuf::new();
        let reference = rmp_serde::to_vec_named(&test).unwrap();
        serialize_controlmessage(&mut buff, &test).unwrap();
        assert!(reference == *buff.as_vec());

        // deserialize with rmp-serde
        let result: ControlMessage = rmp_serde::from_slice(buff.as_slice()).unwrap();
        assert!(test == result);

        // deserialize with rmp
        let mut bytes = Bytes::new(buff.as_slice());
        let object = deserialize_controlmessage(&mut bytes).unwrap();
        assert!(test == object);
    }
}

fn serialize_all(buff: &mut ByteBuf, field_name: Option<&str>, object: &All) -> Result<()> {
    rmp::serialize_field_name(buff, field_name)?;
    rmp::serialize_map_len(buff, 3u32)?;
    serialize_policy(buff, Some("policy"), &object.policy)?;
    rmp::serialize_string_vec(buff, Some("allowlist"), &object.allowlist)?;
    serialize_velocity(buff, Some("velocity"), object.velocity.as_ref())?;
    Ok(())
}

fn deserialize_all(bytes: &mut Bytes, field_name: Option<&str>) -> Result<All> {
    rmp::deserialize_field_name(bytes, field_name)?;
    rmp::deserialize_map_len(bytes, 3)?;
    let policy = deserialize_policy(bytes, Some("policy"))?;
    let allowlist = rmp::deserialize_string_vec(bytes, Some("allowlist"))?;
    let velocity = deserialize_velocity(bytes, Some("velocity"))?;
    Ok(All {
        policy,
        allowlist,
        velocity,
    })
}

#[test]
fn test_all_serde() {
    for test in [
        All {
            policy: Policy {
                msat_per_interval: u64::MAX,
                interval: Interval::Hourly,
                htlc_limit_msat: u64::MAX,
            },
            allowlist: vec!["alice".to_string(), "bob".to_string(), "carol".to_string()],
            velocity: None,
        },
        All {
            policy: Policy {
                msat_per_interval: u64::MAX,
                interval: Interval::Daily,
                htlc_limit_msat: u64::MAX,
            },
            allowlist: vec!["daniel".to_string(), "eve".to_string(), "frank".to_string()],
            velocity: Some((u64::MAX, vec![u64::MAX, u64::MAX, u64::MAX, u64::MAX])),
        },
    ] {
        //serialize
        let mut buff = ByteBuf::new();
        let reference = rmp_serde::to_vec_named(&test).unwrap();
        serialize_all(&mut buff, None, &test).unwrap();
        assert!(reference == *buff.as_vec());

        // deserialize with rmp-serde
        let result: All = rmp_serde::from_slice(buff.as_slice()).unwrap();
        assert!(test == result);

        // deserialize with rmp
        let mut bytes = Bytes::new(buff.as_slice());
        let object = deserialize_all(&mut bytes, None).unwrap();
        assert!(test == object);
    }
}

pub fn serialize_controlresponse(buff: &mut ByteBuf, object: &ControlResponse) -> Result<()> {
    match object {
        ControlResponse::Nonce(u) => {
            rmp::serialize_map_len(buff, 1u32)?;
            rmp::serialize_uint(buff, Some("Nonce"), *u)?;
        }
        ControlResponse::ResetWifi => rmp::serialize_variant(buff, "ResetWifi")?,
        ControlResponse::ResetKeys => rmp::serialize_variant(buff, "ResetKeys")?,
        ControlResponse::ResetAll => rmp::serialize_variant(buff, "ResetAll")?,
        ControlResponse::PolicyCurrent(policy) => {
            rmp::serialize_map_len(buff, 1u32)?;
            serialize_policy(buff, Some("PolicyCurrent"), policy)?;
        }
        ControlResponse::PolicyUpdated(policy) => {
            rmp::serialize_map_len(buff, 1u32)?;
            serialize_policy(buff, Some("PolicyUpdated"), policy)?;
        }
        ControlResponse::AllowlistCurrent(list) => {
            rmp::serialize_map_len(buff, 1u32)?;
            rmp::serialize_string_vec(buff, Some("AllowlistCurrent"), list)?;
        }
        ControlResponse::AllowlistUpdated(list) => {
            rmp::serialize_map_len(buff, 1u32)?;
            rmp::serialize_string_vec(buff, Some("AllowlistUpdated"), list)?;
        }
        ControlResponse::VelocityCurrent(velocity) => {
            rmp::serialize_map_len(buff, 1u32)?;
            serialize_velocity(buff, Some("VelocityCurrent"), velocity.as_ref())?;
        }
        ControlResponse::OtaConfirm(ota_params) => {
            rmp::serialize_map_len(buff, 1u32)?;
            serialize_otaparams(buff, Some("OtaConfirm"), ota_params)?;
        }
        ControlResponse::AllCurrent(all) => {
            rmp::serialize_map_len(buff, 1u32)?;
            serialize_all(buff, Some("AllCurrent"), all)?;
        }
        ControlResponse::Error(error) => {
            rmp::serialize_map_len(buff, 1u32)?;
            rmp::serialize_string(buff, Some("Error"), error)?;
        }
    }
    Ok(())
}

pub fn deserialize_controlresponse(bytes: &mut Bytes) -> Result<ControlResponse> {
    let peek = rmp::peek_byte(bytes)?;
    if peek == 0x81 {
        rmp::deserialize_map_len(bytes, 1)?;
    }
    let variant = rmp::deserialize_variant(bytes)?;
    let en = match variant.as_str() {
        "Nonce" => {
            let u = rmp::deserialize_uint(bytes, None)?;
            ControlResponse::Nonce(u)
        }
        "ResetWifi" => ControlResponse::ResetWifi,
        "ResetKeys" => ControlResponse::ResetKeys,
        "ResetAll" => ControlResponse::ResetAll,
        "PolicyCurrent" => {
            let policy = deserialize_policy(bytes, None)?;
            ControlResponse::PolicyCurrent(policy)
        }
        "PolicyUpdated" => {
            let policy = deserialize_policy(bytes, None)?;
            ControlResponse::PolicyUpdated(policy)
        }
        "AllowlistCurrent" => {
            let list = rmp::deserialize_string_vec(bytes, None)?;
            ControlResponse::AllowlistCurrent(list)
        }
        "AllowlistUpdated" => {
            let list = rmp::deserialize_string_vec(bytes, None)?;
            ControlResponse::AllowlistUpdated(list)
        }
        "VelocityCurrent" => {
            let velocity = deserialize_velocity(bytes, None)?;
            ControlResponse::VelocityCurrent(velocity)
        }
        "OtaConfirm" => {
            let params = deserialize_otaparams(bytes)?;
            ControlResponse::OtaConfirm(params)
        }
        "AllCurrent" => {
            let all = deserialize_all(bytes, None)?;
            ControlResponse::AllCurrent(all)
        }
        "Error" => {
            let error = rmp::deserialize_string(bytes, None)?;
            ControlResponse::Error(error)
        }
        _ => panic!("could not deserialize controlresponse"),
    };
    Ok(en)
}

#[test]
fn test_controlresponse_serde() {
    for test in [
        ControlResponse::Nonce(u64::MAX),
        ControlResponse::ResetWifi,
        ControlResponse::ResetKeys,
        ControlResponse::ResetAll,
        ControlResponse::PolicyCurrent(Policy {
            msat_per_interval: u64::MAX,
            interval: Interval::Hourly,
            htlc_limit_msat: u64::MAX,
        }),
        ControlResponse::PolicyUpdated(Policy {
            msat_per_interval: u64::MAX,
            interval: Interval::Daily,
            htlc_limit_msat: u64::MAX,
        }),
        ControlResponse::AllowlistCurrent(vec![
            "alice".to_string(),
            "bob".to_string(),
            "carol".to_string(),
        ]),
        ControlResponse::AllowlistUpdated(vec![
            "daniel".to_string(),
            "eve".to_string(),
            "frank".to_string(),
        ]),
        ControlResponse::VelocityCurrent(Some((
            u64::MAX,
            vec![u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX],
        ))),
        ControlResponse::VelocityCurrent(None),
        ControlResponse::OtaConfirm(OtaParams {
            version: u64::MAX,
            url: "https://www.sphinx.chat/signer/ota".to_string(),
        }),
        ControlResponse::AllCurrent(All {
            policy: Policy {
                msat_per_interval: u64::MAX,
                interval: Interval::Hourly,
                htlc_limit_msat: u64::MAX,
            },
            allowlist: vec!["alice".to_string(), "bob".to_string(), "carol".to_string()],
            velocity: None,
        }),
        ControlResponse::AllCurrent(All {
            policy: Policy {
                msat_per_interval: u64::MAX,
                interval: Interval::Daily,
                htlc_limit_msat: u64::MAX,
            },
            allowlist: vec!["daniel".to_string(), "eve".to_string(), "frank".to_string()],
            velocity: Some((u64::MAX, vec![u64::MAX, u64::MAX, u64::MAX, u64::MAX])),
        }),
        ControlResponse::Error("I am your father".to_string()),
    ] {
        //serialize
        let mut buff = ByteBuf::new();
        let reference = rmp_serde::to_vec_named(&test).unwrap();
        serialize_controlresponse(&mut buff, &test).unwrap();
        assert!(reference == *buff.as_vec());

        // deserialize with rmp-serde
        let result: ControlResponse = rmp_serde::from_slice(buff.as_slice()).unwrap();
        assert!(test == result);

        // deserialize with rmp
        let mut bytes = Bytes::new(buff.as_slice());
        let object = deserialize_controlresponse(&mut bytes).unwrap();
        assert!(test == object);
    }
}

pub fn serialize_config(buff: &mut ByteBuf, object: &Config) -> Result<()> {
    rmp::serialize_map_len(buff, 4u32)?;
    rmp::serialize_string(buff, Some("broker"), &object.broker)?;
    rmp::serialize_string(buff, Some("ssid"), &object.ssid)?;
    rmp::serialize_string(buff, Some("pass"), &object.pass)?;
    rmp::serialize_string(buff, Some("network"), &object.network)?;
    Ok(())
}

pub fn deserialize_config(bytes: &mut Bytes) -> Result<Config> {
    rmp::deserialize_map_len(bytes, 4)?;
    let broker = rmp::deserialize_string(bytes, Some("broker"))?;
    let ssid = rmp::deserialize_string(bytes, Some("ssid"))?;
    let pass = rmp::deserialize_string(bytes, Some("pass"))?;
    let network = rmp::deserialize_string(bytes, Some("network"))?;
    Ok(Config {
        broker,
        ssid,
        pass,
        network,
    })
}

#[test]
fn test_config_serde() {
    let test: Config = Config {
        broker: "alice".to_string(),
        ssid: "bob".to_string(),
        pass: "carol".to_string(),
        network: "daniel".to_string(),
    };

    //serialize
    let mut buff = ByteBuf::new();
    let reference = rmp_serde::to_vec_named(&test).unwrap();
    serialize_config(&mut buff, &test).unwrap();
    assert!(reference == *buff.as_vec());

    // deserialize with rmp-serde
    let result: Config = rmp_serde::from_slice(buff.as_slice()).unwrap();
    assert!(test == result);

    // deserialize with rmp
    let mut bytes = Bytes::new(buff.as_slice());
    let object = deserialize_config(&mut bytes).unwrap();
    assert!(test == object);
}

pub fn serialize_velocity(
    buff: &mut ByteBuf,
    field_name: Option<&str>,
    object: Option<&Velocity>,
) -> Result<()> {
    match object {
        None => {
            rmp::serialize_none(buff, field_name)?;
        }
        Some(object) => {
            rmp::serialize_field_name(buff, field_name)?;
            rmp::serialize_array_len(buff, 2u32)?;
            rmp::serialize_uint(buff, None, object.0)?;
            rmp::serialize_array_len(buff, object.1.len() as u32)?;
            for e in &object.1 {
                rmp::serialize_uint(buff, None, *e)?;
            }
        }
    }
    Ok(())
}

pub fn deserialize_velocity(
    bytes: &mut Bytes,
    field_name: Option<&str>,
) -> Result<Option<Velocity>> {
    rmp::deserialize_field_name(bytes, field_name)?;
    let peek = rmp::peek_byte(bytes)?;
    if peek == rmp::null_marker_byte() {
        return Ok(None);
    }
    let length = rmp::deserialize_array_len(bytes)?;
    if length != 2 {
        return Err(anyhow!("deserialize_velocity: unexpected array length"));
    }
    let x = rmp::deserialize_uint(bytes, None)?;
    let length = rmp::deserialize_array_len(bytes)?;
    let mut y: Vec<u64> = Vec::with_capacity(length as usize);
    for _ in 0..length {
        let e = rmp::deserialize_uint(bytes, None)?;
        y.push(e);
    }
    Ok(Some((x, y)))
}

#[test]
fn test_velocity_serde() {
    let test: Velocity = (u64::MAX, vec![u64::MAX, u64::MAX, u64::MAX, u64::MAX]);

    //serialize
    let mut buff = ByteBuf::new();
    let reference = rmp_serde::to_vec_named(&test).unwrap();
    serialize_velocity(&mut buff, None, Some(&test)).unwrap();
    assert!(reference == *buff.as_vec());

    // deserialize with rmp-serde
    let result: Velocity = rmp_serde::from_slice(buff.as_slice()).unwrap();
    assert!(test == result);

    // deserialize with rmp
    let mut bytes = Bytes::new(buff.as_slice());
    let object = deserialize_velocity(&mut bytes, None).unwrap().unwrap();
    assert!(test == object);
}

pub fn serialize_policy(
    buff: &mut ByteBuf,
    field_name: Option<&str>,
    object: &Policy,
) -> Result<()> {
    rmp::serialize_field_name(buff, field_name)?;
    rmp::serialize_map_len(buff, 3u32)?;
    rmp::serialize_uint(buff, Some("msat_per_interval"), object.msat_per_interval)?;
    serialize_interval(buff, Some("interval"), &object.interval)?;
    rmp::serialize_uint(buff, Some("htlc_limit_msat"), object.htlc_limit_msat)?;
    Ok(())
}

pub fn deserialize_policy(bytes: &mut Bytes, field_name: Option<&str>) -> Result<Policy> {
    rmp::deserialize_field_name(bytes, field_name)?;
    rmp::deserialize_map_len(bytes, 3)?;
    let msat_per_interval = rmp::deserialize_uint(bytes, Some("msat_per_interval"))?;
    let interval = deserialize_interval(bytes, Some("interval"))?;
    let htlc_limit_msat = rmp::deserialize_uint(bytes, Some("htlc_limit_msat"))?;
    Ok(Policy {
        msat_per_interval,
        interval,
        htlc_limit_msat,
    })
}

#[test]
fn test_policy_serde() {
    let test = Policy {
        msat_per_interval: u64::MAX,
        interval: Interval::Hourly,
        htlc_limit_msat: u64::MAX,
    };

    //serialize
    let mut buff = ByteBuf::new();
    let reference = rmp_serde::to_vec_named(&test).unwrap();
    serialize_policy(&mut buff, None, &test).unwrap();
    assert!(reference == *buff.as_vec());

    // deserialize with rmp-serde
    let result: Policy = rmp_serde::from_slice(buff.as_slice()).unwrap();
    assert!(test == result);

    // deserialize with rmp
    let mut bytes = Bytes::new(buff.as_slice());
    let object = deserialize_policy(&mut bytes, None).unwrap();
    assert!(test == object);

    let test = Policy {
        msat_per_interval: u64::MAX,
        interval: Interval::Daily,
        htlc_limit_msat: u64::MAX,
    };

    //serialize
    let mut buff = ByteBuf::new();
    let reference = rmp_serde::to_vec_named(&test).unwrap();
    serialize_policy(&mut buff, None, &test).unwrap();
    assert!(reference == *buff.as_vec());

    // deserialize with rmp-serde
    let result: Policy = rmp_serde::from_slice(buff.as_slice()).unwrap();
    assert!(test == result);

    // deserialize with rmp
    let mut bytes = Bytes::new(buff.as_slice());
    let object = deserialize_policy(&mut bytes, None).unwrap();
    assert!(test == object);
}

fn serialize_interval(
    buff: &mut ByteBuf,
    field_name: Option<&str>,
    object: &Interval,
) -> Result<()> {
    rmp::serialize_field_name(buff, field_name)?;
    match object {
        Interval::Hourly => rmp::serialize_variant(buff, "hourly")?,
        Interval::Daily => rmp::serialize_variant(buff, "daily")?,
    };
    Ok(())
}

fn deserialize_interval(bytes: &mut Bytes, field_name: Option<&str>) -> Result<Interval> {
    rmp::deserialize_field_name(bytes, field_name)?;
    let variant = rmp::deserialize_variant(bytes)?;
    let en = match variant.as_str() {
        "hourly" => Interval::Hourly,
        "daily" => Interval::Daily,
        m => panic!("wrong: {}", m),
    };
    Ok(en)
}

#[test]
fn test_interval_serde() {
    for test in [Interval::Hourly, Interval::Daily] {
        //serialize
        let mut buff = ByteBuf::new();
        let reference = rmp_serde::to_vec_named(&test).unwrap();
        serialize_interval(&mut buff, None, &test).unwrap();
        assert!(reference == *buff.as_vec());

        // deserialize with rmp-serde
        let result: Interval = rmp_serde::from_slice(buff.as_slice()).unwrap();
        assert!(test == result);

        // deserialize with rmp
        let mut bytes = Bytes::new(buff.as_slice());
        let object = deserialize_interval(&mut bytes, None).unwrap();
        assert!(test == object);
    }
}

fn serialize_otaparams(
    buff: &mut ByteBuf,
    field_name: Option<&str>,
    object: &OtaParams,
) -> Result<()> {
    rmp::serialize_field_name(buff, field_name)?;
    rmp::serialize_map_len(buff, 2u32)?;
    rmp::serialize_uint(buff, Some("version"), object.version)?;
    rmp::serialize_string(buff, Some("url"), &object.url)?;
    Ok(())
}

fn deserialize_otaparams(bytes: &mut Bytes) -> Result<OtaParams> {
    rmp::deserialize_map_len(bytes, 2)?;
    let version = rmp::deserialize_uint(bytes, Some("version"))?;
    let url = rmp::deserialize_string(bytes, Some("url"))?;
    Ok(OtaParams { version, url })
}

#[test]
fn test_otaparams_serde() {
    let test = OtaParams {
        version: u64::MAX,
        url: "https://www.sphinx.chat/signer/ota".to_string(),
    };

    //serialize
    let mut buff = ByteBuf::new();
    let reference = rmp_serde::to_vec_named(&test).unwrap();
    serialize_otaparams(&mut buff, None, &test).unwrap();
    assert!(reference == *buff.as_vec());

    // deserialize with rmp-serde
    let result: OtaParams = rmp_serde::from_slice(buff.as_slice()).unwrap();
    assert!(test == result);

    // deserialize with rmp
    let mut bytes = Bytes::new(buff.as_slice());
    let object = deserialize_otaparams(&mut bytes).unwrap();
    assert!(test == object);
}

pub fn serialize_wifiparams(buff: &mut ByteBuf, object: &WifiParams) -> Result<()> {
    rmp::serialize_map_len(buff, 2u32)?;
    rmp::serialize_string(buff, Some("ssid"), &object.ssid)?;
    rmp::serialize_string(buff, Some("password"), &object.password)?;
    Ok(())
}

pub fn deserialize_wifiparams(bytes: &mut Bytes) -> Result<WifiParams> {
    rmp::deserialize_map_len(bytes, 2)?;
    let ssid = rmp::deserialize_string(bytes, Some("ssid"))?;
    let password = rmp::deserialize_string(bytes, Some("password"))?;
    Ok(WifiParams { ssid, password })
}

#[test]
fn test_wifiparams_serde() {
    let test = WifiParams {
        ssid: "hello world".to_string(),
        password: "foobar".to_string(),
    };

    //serialize
    let mut buff = ByteBuf::new();
    let reference = rmp_serde::to_vec_named(&test).unwrap();
    serialize_wifiparams(&mut buff, &test).unwrap();
    assert!(reference == *buff.as_vec());

    // deserialize with rmp-serde
    let result: WifiParams = rmp_serde::from_slice(buff.as_slice()).unwrap();
    assert!(test == result);

    // deserialize with rmp
    let mut bytes = Bytes::new(buff.as_slice());
    let object = deserialize_wifiparams(&mut bytes).unwrap();
    assert!(test == object);
}
