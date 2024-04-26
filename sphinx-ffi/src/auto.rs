use crate::{Result, SphinxError};
use sphinx::bindings;
use sphinx::serde_json;

pub struct Msg {
    pub r#type: Option<u8>,
    pub message: Option<String>,
    pub sender: Option<String>,
    pub uuid: Option<String>,
    pub tag: Option<String>,
    pub index: Option<String>,
    pub msat: Option<u64>,
    pub timestamp: Option<u64>,
    pub sent_to: Option<String>,
    pub from_me: Option<bool>,
}

pub struct RunReturn {
    pub msgs: Vec<Msg>,
    pub msgs_total: Option<u64>,
    pub msgs_counts: Option<String>,
    pub topics: Vec<String>,
    pub payloads: Vec<Vec<u8>>,
    pub state_mp: Option<Vec<u8>>,
    pub state_to_delete: Vec<String>,
    pub new_balance: Option<u64>,
    pub my_contact_info: Option<String>,
    pub sent_status: Option<String>,
    pub settled_status: Option<String>,
    pub error: Option<String>,
    pub new_tribe: Option<String>,
    pub tribe_members: Option<String>,
    pub new_invite: Option<String>,
    pub inviter_contact_info: Option<String>,
    pub inviter_alias: Option<String>,
    pub initial_tribe: Option<String>,
    pub lsp_host: Option<String>,
    pub invoice: Option<String>,
    pub route: Option<String>,
    pub node: Option<String>,
    pub last_read: Option<String>,
    pub mute_levels: Option<String>,
    pub payments: Option<String>,
    pub payments_total: Option<u64>,
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

pub fn get_default_tribe_server(full_state: Vec<u8>) -> Result<String> {
    let ns = bindings::get_default_tribe_server(&full_state)
        .map_err(|e| SphinxError::ParseStateFailed { r: e.to_string() })?;
    Ok(ns.to_string())
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
    invite_code: Option<String>,
    their_alias: Option<String>,
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
        invite_code.as_deref(),
        &their_alias.as_deref(),
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

pub fn contact_pubkey_by_child_index(full_state: Vec<u8>, child_idx: u64) -> Result<String> {
    Ok(
        bindings::contact_pubkey_by_child_index(&full_state, child_idx).map_err(|e| {
            SphinxError::GetContactFailed {
                r: format!("contact_pubkey_by_child_index failed: {:?}", e),
            }
        })?,
    )
}

pub fn contact_pubkey_by_encrypted_child(
    seed: String,
    full_state: Vec<u8>,
    child_idx: u64,
) -> Result<String> {
    Ok(
        bindings::contact_pubkey_by_encrypted_child(&seed, &full_state, child_idx).map_err(
            |e| SphinxError::GetContactFailed {
                r: format!("contact_pubkey_by_encrypted_child failed: {:?}", e),
            },
        )?,
    )
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

pub fn get_tribe_management_topic(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
) -> Result<String> {
    Ok(
        bindings::get_tribe_management_topic(&seed, &unique_time, &full_state)
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
    is_tribe: bool,
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
        is_tribe,
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

pub fn make_media_token(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    host: String,
    muid: String,
    to: String,
    exp: u32,
) -> Result<String> {
    Ok(
        bindings::make_media_token(&seed, &unique_time, &full_state, &host, &muid, &to, exp)
            .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
            .into(),
    )
}

pub fn make_media_token_with_meta(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    host: String,
    muid: String,
    to: String,
    exp: u32,
    meta: String,
) -> Result<String> {
    Ok(bindings::make_media_token_with_meta(
        &seed,
        &unique_time,
        &full_state,
        &host,
        &muid,
        &to,
        exp,
        &meta,
    )
    .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
    .into())
}

pub fn make_media_token_with_price(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    host: String,
    muid: String,
    to: String,
    exp: u32,
    price: u64,
) -> Result<String> {
    Ok(bindings::make_media_token_with_price(
        &seed,
        &unique_time,
        &full_state,
        &host,
        &muid,
        &to,
        exp,
        price,
    )
    .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
    .into())
}

pub fn make_invoice(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    amt_msat: u64,
    description: String,
) -> Result<RunReturn> {
    Ok(
        bindings::make_invoice(&seed, &unique_time, &full_state, amt_msat, &description)
            .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
            .into(),
    )
}

pub fn pay_invoice(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    bolt11: String,
    overpay_msat: Option<u64>,
) -> Result<RunReturn> {
    Ok(bindings::pay_invoice(
        &seed,
        &unique_time,
        &full_state,
        &bolt11,
        overpay_msat,
        None,
    )
    .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
    .into())
}

pub fn pay_contact_invoice(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    bolt11: String,
    my_alias: String,
    my_img: String,
    is_tribe: bool,
) -> Result<RunReturn> {
    Ok(bindings::pay_contact_invoice(
        &seed,
        &unique_time,
        &full_state,
        &bolt11,
        &my_alias,
        &my_img_opt(&my_img),
        is_tribe,
    )
    .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
    .into())
}

pub fn payment_hash_from_invoice(bolt11: String) -> Result<String> {
    Ok(bindings::payment_hash_from_invoice(&bolt11)
        .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?)
}

pub fn parse_invoice(bolt11: String) -> Result<String> {
    Ok(bindings::parse_invoice(&bolt11)
        .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?)
}

pub fn create_tribe(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    tribe_server_pubkey: String,
    tribe_json: String,
) -> Result<RunReturn> {
    Ok(bindings::create_tribe(
        &seed,
        &unique_time,
        &full_state,
        &tribe_server_pubkey,
        &tribe_json,
    )
    .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
    .into())
}

pub fn join_tribe(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    tribe_pubkey: String,
    tribe_route_hint: String,
    alias: String,
    amt_msat: u64,
    is_private: bool,
) -> Result<RunReturn> {
    Ok(bindings::join_tribe(
        &seed,
        &unique_time,
        &full_state,
        &tribe_pubkey,
        &tribe_route_hint,
        &alias,
        amt_msat,
        is_private,
    )
    .map_err(|e| SphinxError::HandleFailed { r: e.to_string() })?
    .into())
}

pub fn list_tribe_members(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    tribe_server_pubkey: String,
    tribe_pubkey: String,
) -> Result<RunReturn> {
    Ok(bindings::list_tribe_members(
        &seed,
        &unique_time,
        &full_state,
        &tribe_server_pubkey,
        &tribe_pubkey,
    )
    .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
    .into())
}

pub fn make_invite(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    host: String,
    amt_msat: u64,
    my_alias: String,
    tribe_host: Option<String>,
    tribe_pubkey: Option<String>,
) -> Result<RunReturn> {
    Ok(bindings::make_invite(
        &seed,
        &unique_time,
        &full_state,
        &host,
        amt_msat,
        &my_alias,
        tribe_host.as_deref(),
        tribe_pubkey.as_deref(),
    )
    .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
    .into())
}

pub fn process_invite(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    invite_qr: String,
) -> Result<RunReturn> {
    Ok(
        bindings::process_invite(&seed, &unique_time, &full_state, &invite_qr)
            .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
            .into(),
    )
}

pub fn code_from_invite(invite_qr: String) -> Result<String> {
    Ok(bindings::code_from_invite(&invite_qr)
        .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?)
}

pub fn read(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    pubkey: String,
    msg_idx: u64,
) -> Result<RunReturn> {
    Ok(
        bindings::read(&seed, &unique_time, &full_state, &pubkey, msg_idx)
            .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
            .into(),
    )
}

pub fn get_reads(seed: String, unique_time: String, full_state: Vec<u8>) -> Result<RunReturn> {
    Ok(bindings::get_reads(&seed, &unique_time, &full_state)
        .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
        .into())
}

pub fn mute(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    pubkey: String,
    mute_level: u8,
) -> Result<RunReturn> {
    Ok(
        bindings::mute(&seed, &unique_time, &full_state, &pubkey, mute_level)
            .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
            .into(),
    )
}

pub fn get_mutes(seed: String, unique_time: String, full_state: Vec<u8>) -> Result<RunReturn> {
    Ok(bindings::get_mutes(&seed, &unique_time, &full_state)
        .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
        .into())
}

pub fn set_push_token(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    push_token: String,
) -> Result<RunReturn> {
    Ok(
        bindings::set_push_token(&seed, &unique_time, &full_state, &push_token)
            .map_err(|e| SphinxError::SendFailed { r: e.to_string() })?
            .into(),
    )
}

pub fn get_msgs_counts(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
) -> Result<RunReturn> {
    Ok(bindings::get_msgs_counts(&seed, &unique_time, &full_state)
        .map_err(|e| SphinxError::FetchMsgsFailed { r: e.to_string() })?
        .into())
}

pub fn fetch_msgs_batch(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    last_msg_idx: u64,
    limit: Option<u32>,
    reverse: Option<bool>,
) -> Result<RunReturn> {
    Ok(bindings::fetch_msgs_batch(
        &seed,
        &unique_time,
        &full_state,
        last_msg_idx,
        limit,
        reverse,
    )
    .map_err(|e| SphinxError::FetchMsgsFailed { r: e.to_string() })?
    .into())
}

pub fn fetch_msgs_batch_okkey(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    last_msg_idx: u64,
    limit: Option<u32>,
    reverse: Option<bool>,
) -> Result<RunReturn> {
    Ok(bindings::fetch_msgs_batch_okkey(
        &seed,
        &unique_time,
        &full_state,
        last_msg_idx,
        limit,
        reverse,
    )
    .map_err(|e| SphinxError::FetchMsgsFailed { r: e.to_string() })?
    .into())
}

pub fn fetch_first_msgs_per_key(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    last_msg_idx: u64,
    limit: Option<u32>,
    reverse: Option<bool>,
) -> Result<RunReturn> {
    Ok(bindings::fetch_first_msgs_per_key(
        &seed,
        &unique_time,
        &full_state,
        last_msg_idx,
        limit,
        reverse,
    )
    .map_err(|e| SphinxError::FetchMsgsFailed { r: e.to_string() })?
    .into())
}

pub fn fetch_payments(
    seed: String,
    unique_time: String,
    full_state: Vec<u8>,
    since: Option<u64>,
    limit: Option<u32>,
    scid: Option<u64>,
    remote_only: Option<bool>,
    min_msat: Option<u64>,
    reverse: Option<bool>,
) -> Result<RunReturn> {
    Ok(bindings::fetch_payments(
        &seed,
        &unique_time,
        &full_state,
        since,
        limit,
        scid,
        remote_only,
        min_msat,
        reverse,
    )
    .map_err(|e| SphinxError::FetchMsgsFailed { r: e.to_string() })?
    .into())
}

impl From<bindings::Msg> for Msg {
    fn from(rr: bindings::Msg) -> Self {
        Msg {
            r#type: rr.r#type,
            message: rr.message,
            sender: rr.sender,
            uuid: rr.uuid,
            tag: rr.tag,
            index: rr.index,
            msat: rr.msat,
            timestamp: rr.timestamp,
            sent_to: rr.sent_to,
            from_me: rr.from_me,
        }
    }
}

impl From<bindings::RunReturn> for RunReturn {
    fn from(rr: bindings::RunReturn) -> Self {
        RunReturn {
            msgs: rr.msgs.into_iter().map(|m| m.into()).collect(),
            msgs_total: rr.msgs_total,
            msgs_counts: rr.msgs_counts,
            topics: rr.topics,
            payloads: rr.payloads,
            state_mp: rr.state_mp,
            state_to_delete: rr.state_to_delete,
            new_balance: rr.new_balance,
            my_contact_info: rr.my_contact_info,
            sent_status: rr.sent_status,
            settled_status: rr.settled_status,
            error: rr.error,
            new_tribe: rr.new_tribe,
            tribe_members: rr.tribe_members,
            new_invite: rr.new_invite,
            inviter_contact_info: rr.inviter_contact_info,
            inviter_alias: rr.inviter_alias,
            initial_tribe: rr.initial_tribe,
            lsp_host: rr.lsp_host,
            invoice: rr.invoice,
            route: rr.route,
            node: rr.node,
            last_read: rr.last_read,
            mute_levels: rr.mute_levels,
            payments: rr.payments,
            payments_total: rr.payments_total,
        }
    }
}
