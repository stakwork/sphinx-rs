use crate::{Result, SphinxError};
use sphinx::bindings;
use sphinx::serde_json;

pub struct RunReturn {
    pub topic_0: Option<String>,
    pub payload_0: Option<Vec<u8>>,
    pub topic_1: Option<String>,
    pub payload_1: Option<Vec<u8>>,
    pub topic_2: Option<String>,
    pub payload_2: Option<Vec<u8>>,
    pub state_mp: Option<Vec<u8>>,
    pub msg: Option<String>,
    pub msg_uuid: Option<String>,
    pub msg_index: Option<String>,
    pub msg_sender: Option<String>,
    pub new_balance: Option<u64>,
    pub my_contact_info: Option<String>,
    pub sent_status: Option<String>,
    pub settled_status: Option<String>,
    pub error: Option<String>,
}

pub fn set_network(net: String) -> Result<RunReturn> {
    Ok(bindings::set_network(&net)
        .map_err(|e| SphinxError::SetNetworkFailed { r: e.to_string() })?
        .into())
}

pub fn set_blockheight(bh: u32) -> Result<RunReturn> {
    Ok(bindings::set_blockheight(bh)
        .map_err(|e| SphinxError::SetBlockheightFailed { r: e.to_string() })?
        .into())
}

pub fn add_contact(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    to_pubkey: String,
    route_hint: String,
    my_alias: String,
    my_img: String,
    amt_msat: u64,
) -> Result<RunReturn> {
    Ok(bindings::add_contact(
        &seed,
        &unique_time,
        &full_state,
        &to_pubkey,
        &route_hint,
        &my_alias,
        &my_img_opt(&my_img),
        amt_msat,
    )
    .map_err(|e| SphinxError::AddContactFailed { r: e.to_string() })?
    .into())
}

pub fn get_contact(full_state: Vec<u8>, contact_pubkey: String) -> Result<String> {
    let c = bindings::get_contact(&full_state, &contact_pubkey).map_err(|_| {
        SphinxError::GetContactFailed {
            r: format!("get_contact failed for pubkey: {}", &contact_pubkey),
        }
    })?;
    let json = serde_json::to_string(&c).map_err(|_| SphinxError::GetContactFailed {
        r: format!("get_contact serialization failed"),
    })?;
    Ok(json)
}

pub fn list_contacts(full_state: Vec<u8>) -> Result<String> {
    let cs = bindings::list_contacts(&full_state).map_err(|_| SphinxError::GetContactFailed {
        r: format!("list_contacts failed"),
    })?;
    let json = serde_json::to_string(&cs).map_err(|_| SphinxError::GetContactFailed {
        r: format!("list_contacts serialization failed"),
    })?;
    Ok(json)
}

pub fn get_subscription_topic(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
) -> Result<String> {
    Ok(
        bindings::get_subscription_topic(&seed, &unique_time, &full_state)
            .map_err(|e| SphinxError::HandleFailed { r: e.to_string() })?,
    )
}

pub fn initial_setup(seed: String, unique_time: String, full_state: Vec<u8>) -> Result<RunReturn> {
    Ok(bindings::initial_setup(&seed, &unique_time, &full_state)
        .map_err(|e| SphinxError::HandleFailed { r: e.to_string() })?
        .into())
}

pub fn fetch_msgs(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    last_msg_idx: u64,
    limit: Option<u32>,
) -> Result<RunReturn> {
    Ok(
        bindings::fetch_msgs(&seed, &unique_time, &full_state, last_msg_idx, limit)
            .map_err(|e| SphinxError::FetchMsgsFailed { r: e.to_string() })?
            .into(),
    )
}

pub fn handle(
    topic: String,
    payload: Vec<u8>,
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    my_alias: String,
    my_img: String,
) -> Result<RunReturn> {
    Ok(bindings::handle(
        &topic,
        &payload,
        &seed,
        &unique_time,
        &full_state,
        &my_alias,
        &my_img_opt(&my_img),
    )
    .map_err(|e| SphinxError::HandleFailed { r: e.to_string() })?
    .into())
}

pub fn send(
    seed: String,
    unique_time: String,
    to: String,
    msg_type: u8,
    msg_json: String,
    full_state: Vec<u8>,
    my_alias: String,
    my_img: String,
    amt_msat: u64,
) -> Result<RunReturn> {
    Ok(bindings::send(
        &seed,
        &unique_time,
        &to,
        msg_type,
        &msg_json,
        &full_state,
        &my_alias,
        &my_img_opt(&my_img),
        amt_msat,
    )
    .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
    .into())
}

fn my_img_opt(my_img: &str) -> Option<&str> {
    match my_img {
        "" => None,
        _ => Some(my_img),
    }
}

impl From<bindings::RunReturn> for RunReturn {
    fn from(rr: bindings::RunReturn) -> Self {
        RunReturn {
            topic_0: rr.topic_0,
            payload_0: rr.payload_0,
            topic_1: rr.topic_1,
            payload_1: rr.payload_1,
            topic_2: rr.topic_2,
            payload_2: rr.payload_2,
            state_mp: rr.state_mp,
            msg: rr.msg,
            msg_uuid: rr.msg_uuid,
            msg_index: rr.msg_index,
            msg_sender: rr.msg_sender,
            new_balance: rr.new_balance,
            my_contact_info: rr.my_contact_info,
            sent_status: rr.sent_status,
            settled_status: rr.settled_status,
            error: rr.error,
        }
    }
}
