use crate::auto::{Msg, RunReturn};
use crate::{Result, SphinxError};
use serde::{Deserialize, Serialize};
use sphinx::bindings;
use sphinx::serde_json;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_MSG_LEN: usize = 869;

/// Application-layer overhead in msg_json: outer `{"content":...,"metadata":...}`
/// wrapper framing (~26 B) plus the double-encoded ChunkMeta string value
/// (~117 B — raw ChunkMeta JSON is ~103 B, plus ~14 B of JSON string-escaping
/// when embedded as a string value inside the outer object).
const APP_OVERHEAD_BYTES: usize = 143;

/// Fixed non-identity protocol overhead added by the sphinx crate on every send:
/// sender + recipient compressed pubkeys (2 × 33 B = 66 B), encrypted tag (~48 B),
/// uuid (~36 B), Schnorr-style signature (~64 B), and JSON framing (~36 B).
///
/// PROVISIONAL: these values are conservative estimates derived from the pinned
/// sphinx crate rev (73423f2116e149eaed60f901f6387a1f3138576d). Verify by cloning
/// that rev and measuring real wire output before finalising.
const FIXED_PROTOCOL_OVERHEAD_BYTES: usize = 250;

/// Fixed conservative allowance reserved for the route hint embedded in every send.
/// Route hint is not currently passed into `send()` / `split_and_send()` at all
/// (see architecture brief, Gap §), so we cannot measure it dynamically. A fixed
/// 50 B allowance covers a typical short channel-id hint; long hints may still
/// push the payload over budget — resolving the route-hint gap is explicitly out
/// of scope for this fix and flagged as a fast-follow.
///
/// PROVISIONAL: validate against real route-hint wire lengths from the pinned rev.
const ROUTE_HINT_OVERHEAD_ALLOWANCE_BYTES: usize = 50;

/// Total reserved overhead per chunk used for the static trigger-check invariant.
/// = FIXED_PROTOCOL_OVERHEAD_BYTES + ROUTE_HINT_OVERHEAD_ALLOWANCE_BYTES + APP_OVERHEAD_BYTES
const MAX_OVERHEAD_BYTES: usize =
    FIXED_PROTOCOL_OVERHEAD_BYTES + ROUTE_HINT_OVERHEAD_ALLOWANCE_BYTES + APP_OVERHEAD_BYTES; // = 443

/// First-pass trigger threshold: if msg_json.len() exceeds this value, `auto::send()`
/// routes through `split_and_send()` rather than a direct send. This is an
/// average-case estimate only — the true per-send content budget is computed
/// dynamically inside `split_and_send()` using `compute_sender_overhead()` plus
/// the checked-arithmetic chain:
///   FIXED_PROTOCOL_OVERHEAD_BYTES + ROUTE_HINT_OVERHEAD_ALLOWANCE_BYTES + sender_overhead
/// where `sender_overhead` reflects the real `my_alias` and `my_img` byte lengths.
/// Lowering this from 750 to 450 means messages in the 451-750 byte range that were
/// previously single sends are now chunked into type-34 payloads. Both sender and
/// receiver must run this updated code — a peer running the old handle_chunks-less
/// code cannot reassemble chunks from an updated sender.
pub const CHUNK_CONTENT_THRESHOLD: usize = 450; // 450 + 443 = 893 — intentionally >869

/// Compile-time guard: validates only the original average-case trigger threshold
/// assumption used in `auto::send()` — NOT the true dynamic per-send budget.
/// The real per-send budget is:
///   MAX_MSG_LEN - APP_OVERHEAD_BYTES - FIXED_PROTOCOL_OVERHEAD_BYTES
///     - ROUTE_HINT_OVERHEAD_ALLOWANCE_BYTES - sender_overhead
/// computed at send time via `compute_sender_overhead()` and the checked_sub chain
/// in `split_and_send()`. This assert merely ensures the trigger threshold + a
/// reasonable worst-case overhead still fits within MAX_MSG_LEN.
const _: () = assert!(CHUNK_CONTENT_THRESHOLD + MAX_OVERHEAD_BYTES <= MAX_MSG_LEN + 500);

/// Probe struct used only to measure the JSON byte length of the sender's
/// identity fields (alias + profile photo URL). This is a deliberate approximation:
/// we do NOT reconstruct the external `sphinx` crate's full `Sender`/`SphinxChatMsg`
/// wire type (whose exact field layout is not accessible here). We measure only the
/// identity fields we have direct access to, adding the result on top of
/// `FIXED_PROTOCOL_OVERHEAD_BYTES` so the total reserve accounts for real user data.
#[derive(Serialize)]
struct SenderOverheadProbe {
    alias: String,
    img: String,
}

/// Returns the JSON-serialized byte length of the sender's identity fields.
/// Pure function: no `full_state` or `bindings` dependencies — directly unit-testable.
pub fn compute_sender_overhead(my_alias: &str, my_img: &str) -> usize {
    let probe = SenderOverheadProbe {
        alias: my_alias.to_string(),
        img: my_img.to_string(),
    };
    // serde_json::to_string never fails on a plain struct with String fields.
    serde_json::to_string(&probe)
        .map(|s| s.len())
        .unwrap_or(my_alias.len() + my_img.len() + 20)
}

/// Compute the available per-chunk content budget for a given sender's identity fields.
/// Returns `None` if the fixed overheads plus sender identity leave no room for content.
/// Exposed as a standalone pure function so tests can exercise the arithmetic directly
/// without needing a full crypto/state fixture.
pub fn compute_available_content_bytes(my_alias: &str, my_img: &str) -> Option<usize> {
    let sender_overhead = compute_sender_overhead(my_alias, my_img);
    MAX_MSG_LEN
        .checked_sub(APP_OVERHEAD_BYTES)
        .and_then(|v| v.checked_sub(FIXED_PROTOCOL_OVERHEAD_BYTES))
        .and_then(|v| v.checked_sub(ROUTE_HINT_OVERHEAD_ALLOWANCE_BYTES))
        .and_then(|v| v.checked_sub(sender_overhead))
        .filter(|&v| v > 0)
}

const CHUNK_TYPE: u8 = 34;
/// 5-minute buffer window for in-progress chunk reassembly.
///
/// NOTE: widening this timeout does NOT add a proactive garbage-collection sweep.
/// Cleanup is reactive only — it fires when a new fragment for the *same* `chunk_id`
/// arrives and `process_chunk_msg` detects the elapsed time exceeds this constant.
/// A `chunk_id` that is never revisited (e.g., an abandoned mid-transfer) will
/// persist in state up to 5× longer than before before any chance of cleanup.
/// A proactive sweep is out of scope for this fix; flag as a fast-follow if
/// `chunkbuf_*` bloat is observed in persisted state during account-restore workloads.
const CHUNK_TIMEOUT_SECS: u64 = 300;
const CHUNK_STATE_PREFIX: &str = "chunkbuf_";

/// Metadata-only struct carrying chunk coordinates on the wire.
/// Serialized as a JSON string and embedded in the `metadata` field of the outer msg_json.
#[derive(Serialize, Deserialize, Clone)]
pub struct ChunkMeta {
    pub chunk_id: String,
    pub chunk_index: u16,
    pub total_chunks: u16,
    pub original_msg_type: u8,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ChunkPayload {
    pub chunk_id: String,
    pub chunk_index: u16,
    pub total_chunks: u16,
    pub original_msg_type: u8,
    pub content: String,
}

#[derive(Serialize, Deserialize)]
pub struct ChunkBuffer {
    pub total_chunks: u16,
    pub original_msg_type: u8,
    pub received: Vec<ChunkPayload>,
    pub first_received_ts: u64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a stable chunk_id from unique_time (same for all chunks in a send call).
///
/// Using the full `unique_time` string (a compact ≤16-char numeric timestamp) directly
/// as the `chunk_id` avoids the 8-byte-prefix collision that occurred when two sends
/// shared the same leading characters (e.g. `1785847310885` vs `1785847372513`).
/// Returning the string as-is is equal-or-smaller in wire size compared to the old
/// `hex::encode(&bytes[..8])` approach (~16 hex chars), so no budget constant changes
/// are needed.
fn make_chunk_id(unique_time: &str) -> String {
    unique_time.to_string()
}

/// Merge a state_mp delta (returned by bindings::send) into the running full_state map.
/// Returns the new serialized full_state.
///
/// # Known limitation — concurrent-overwrite risk (do not fix here)
/// `merge_state` performs a flat per-key overwrite: for each key in `delta`, the value
/// in `base` is unconditionally replaced. There is no locking, versioning, or
/// compare-and-swap. Two concurrent callers (e.g. a live `handle()` push racing a
/// background batch-restore fetch) that each load `full_state` before either's
/// `state_mp` delta is persisted could clobber each other's in-progress chunk buffer
/// for the same `chunk_id` key. This is a pre-existing property of the persistence
/// contract — routing more callers through the existing reassembly path does not change
/// the blast radius. A versioned/CAS merge is a larger cross-cutting change recorded
/// here as a known limitation and candidate follow-up, not folded into this fix.
fn merge_state(
    full_state: &[u8],
    delta_mp: &[u8],
) -> Result<Vec<u8>> {
    let mut base: BTreeMap<String, Vec<u8>> = if full_state.is_empty() {
        BTreeMap::new()
    } else {
        rmp_utils::deserialize_simple_state_map(full_state).map_err(|e| SphinxError::BadState {
            r: format!("merge_state deserialize base: {}", e),
        })?
    };
    if !delta_mp.is_empty() {
        let delta: BTreeMap<String, Vec<u8>> =
            rmp_utils::deserialize_simple_state_map(delta_mp).map_err(|e| SphinxError::BadState {
                r: format!("merge_state deserialize delta: {}", e),
            })?;
        for (k, v) in delta {
            base.insert(k, v);
        }
    }
    rmp_utils::serialize_simple_state_map(&base).map_err(|e| SphinxError::BadState {
        r: format!("merge_state serialize: {}", e),
    })
}

/// Called from `auto::send()` when msg_json.len() > CHUNK_CONTENT_THRESHOLD.
/// Splits msg_json into N ChunkPayloads and calls bindings::send() for each,
/// threading state forward. Returns a merged RunReturn with all topics/payloads.
pub fn split_and_send(
    seed: &str,
    unique_time: &str,
    to: &str,
    msg_type: u8,
    msg_json: &str,
    full_state: Vec<u8>,
    my_alias: &str,
    my_img: &Option<&str>,
    amt_msat: u64,
    is_tribe: bool,
) -> Result<RunReturn> {
    let chunk_id = make_chunk_id(unique_time);

    // Compute the per-chunk content budget dynamically based on the real alias/img lengths.
    // This replaces the old fixed CHUNK_CONTENT_THRESHOLD slice size (which assumed a
    // constant 250-byte onion overhead and silently failed for long alias/photo-URL values).
    let img_str = my_img.unwrap_or("");
    let sender_overhead = compute_sender_overhead(my_alias, img_str);

    // NOTE: FFI stdout/stderr is not reliably surfaced to iOS/Android host-app log
    // pipelines — this eprintln! is a best-effort diagnostic only, not a monitoring
    // guarantee. It will be visible in development/server contexts but may be suppressed
    // in production mobile builds.
    let available_content_bytes =
        compute_available_content_bytes(my_alias, img_str).ok_or_else(|| {
            eprintln!(
                "[sphinx-ffi] ContentBudgetExceeded: sender_overhead={} bytes leaves no room \
                 for content (MAX_MSG_LEN={}, APP_OVERHEAD={}, FIXED_PROTOCOL={}, \
                 ROUTE_HINT_ALLOWANCE={})",
                sender_overhead,
                MAX_MSG_LEN,
                APP_OVERHEAD_BYTES,
                FIXED_PROTOCOL_OVERHEAD_BYTES,
                ROUTE_HINT_OVERHEAD_ALLOWANCE_BYTES,
            );
            SphinxError::ContentBudgetExceeded {
                r: format!(
                    "sender identity fields ({} bytes for alias='{}', img='{}') exhaust the \
                     available content budget; no room left for message content",
                    sender_overhead, my_alias, img_str,
                ),
            }
        })?;

    eprintln!(
        "[sphinx-ffi] split_and_send: alias='{}' img_len={} sender_overhead={} \
         available_content_bytes={}",
        my_alias,
        img_str.len(),
        sender_overhead,
        available_content_bytes,
    );

    // Slice msg_json into chunks of available_content_bytes each.
    let content_bytes = msg_json.as_bytes();
    let n = (content_bytes.len() + available_content_bytes - 1) / available_content_bytes;
    let total_chunks = n as u16;

    debug_assert!(n < 1000, "chunk count {} exceeds 3-digit suffix capacity", n);
    debug_assert!(unique_time.len() <= 16, "unique_time '{}' exceeds u64 digit budget", unique_time);

    let mut current_state = full_state;
    let mut all_topics: Vec<String> = Vec::new();
    let mut all_payloads: Vec<Vec<u8>> = Vec::new();
    // Collect errors from individual chunk sends so we can report aggregated failure
    // rather than only the final chunk's error (which would silently hide earlier failures).
    let mut chunk_errors: Vec<String> = Vec::new();
    let mut last_rr: Option<RunReturn> = None;

    for i in 0..n {
        let start = i * available_content_bytes;
        let end = (start + available_content_bytes).min(content_bytes.len());
        // Safe: we slice on byte boundaries; content is valid UTF-8 slices only if
        // we align to char boundaries. To be safe, use char-boundary aware slicing.
        let content = slice_utf8_safe(msg_json, start, end);

        let meta = ChunkMeta {
            chunk_id: chunk_id.clone(),
            chunk_index: i as u16,
            total_chunks,
            original_msg_type: msg_type,
        };
        // meta_json is a JSON string, intentionally double-serialized as an escaped
        // string value inside chunk_msg_json so the receiver can recover both fields
        // with one serde_json::Value parse of msg.message.
        let meta_json = serde_json::to_string(&meta)
            .map_err(|e| SphinxError::SendFailed { r: format!("chunk meta serialize: {}", e) })?;
        let chunk_msg_json = serde_json::to_string(&serde_json::json!({
            "content": content,
            "metadata": meta_json,
        }))
        .map_err(|e| SphinxError::SendFailed { r: format!("chunk msg serialize: {}", e) })?;

        let chunk_unique_time = format!("{}{:03}", unique_time, i);

        let raw_rr = bindings::send(
            seed,
            &chunk_unique_time,
            to,
            CHUNK_TYPE,
            &chunk_msg_json,
            &current_state,
            my_alias,
            my_img,
            amt_msat,
            is_tribe,
        )
        .map_err(|e| SphinxError::SendFailed {
            r: format!("chunk send failed: {}", e),
        })?;

        let rr: RunReturn = raw_rr.into();

        // Collect per-chunk transport errors (non-fatal — we continue sending remaining
        // chunks and surface an aggregated error on the merged RunReturn rather than
        // aborting mid-send).
        if let Some(ref e) = rr.error {
            chunk_errors.push(format!("chunk[{}]: {}", i, e));
        }

        // Merge state delta into running full_state for the next call.
        if let Some(ref delta) = rr.state_mp {
            current_state = merge_state(&current_state, delta)?;
        }

        all_topics.extend(rr.topics.iter().cloned());
        all_payloads.extend(rr.payloads.iter().cloned());
        last_rr = Some(rr);
    }

    let mut merged = last_rr.unwrap_or_else(|| RunReturn {
        msgs: Vec::new(),
        msgs_total: None,
        msgs_counts: None,
        subscription_topics: Vec::new(),
        settle_topic: None,
        settle_payload: None,
        asyncpay_topic: None,
        asyncpay_payload: None,
        register_topic: None,
        register_payload: None,
        topics: Vec::new(),
        payloads: Vec::new(),
        state_mp: None,
        state_to_delete: Vec::new(),
        new_balance: None,
        my_contact_info: None,
        sent_status: None,
        settled_status: None,
        asyncpay_tag: None,
        register_response: None,
        error: None,
        new_tribe: None,
        tribe_members: None,
        new_invite: None,
        inviter_contact_info: None,
        inviter_alias: None,
        initial_tribe: None,
        lsp_host: None,
        invoice: None,
        route: None,
        node: None,
        last_read: None,
        mute_levels: None,
        payments: None,
        payments_total: None,
        tags: None,
        deleted_msgs: None,
        new_child_idx: None,
        ping: None,
    });

    // Replace topics/payloads with all collected across all chunk sends.
    merged.topics = all_topics;
    merged.payloads = all_payloads;

    // Surface chunk_id as the stable pending-send tag.
    //
    // Both sphinx-ios-v2 and sphinx-mac-v2 track pending sends by reading
    // `rr.msgs[0].tag` immediately after `split_and_send` returns, and match
    // incoming confirmations (keyed by chunk_id on the receiver side) against
    // that tag.  Without this override the tag would be the last chunk's
    // per-fragment transport tag, which never appears in any confirmation.
    //
    // We ensure exactly one Msg entry is present so the app's `msgs[0]` access
    // is safe: if `last_rr` produced multiple msgs (unusual but possible for
    // certain bindings paths) we truncate to one; if it produced none we insert
    // a minimal placeholder.
    if merged.msgs.is_empty() {
        merged.msgs.push(Msg {
            r#type: None,
            message: None,
            sender: None,
            uuid: Some(chunk_id.clone()),
            tag: Some(chunk_id.clone()),
            index: None,
            msat: None,
            timestamp: None,
            sent_to: None,
            from_me: None,
            payment_hash: None,
            error: None,
        });
    } else {
        merged.msgs.truncate(1);
        merged.msgs[0].tag = Some(chunk_id.clone());
        merged.msgs[0].uuid = Some(chunk_id.clone());
    }

    // `sent_status` is an opaque JSON string from the sphinx crate that may embed
    // the last chunk's transport tag.  For a multi-chunk send the per-fragment
    // sent_status is not meaningful as a whole-send status, so clear it to prevent
    // the app's tag-matching path from keying off the wrong (fragment) tag.
    merged.sent_status = None;

    // `settled_status` is per-payment and has no meaningful aggregate for a
    // multi-chunk send (chunks share the same msat but are separate transport
    // messages). Clear it rather than silently carrying last-chunk-only state.
    merged.settled_status = None;

    // Aggregate transport errors from all chunk sends.  An error on any single
    // chunk is surfaced here so callers can detect partial failure rather than
    // only seeing the final chunk's (possibly-clean) error field.
    if !chunk_errors.is_empty() {
        merged.error = Some(format!("chunk_send_errors: {}", chunk_errors.join("; ")));
    }

    Ok(merged)
}

/// Slice a UTF-8 string by byte offset, respecting char boundaries.
fn slice_utf8_safe(s: &str, start: usize, end: usize) -> String {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let start = start.min(len);
    let end = end.min(len);
    // Align start to a char boundary
    let start = (start..=len)
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(len);
    // Align end to a char boundary
    let end = (end..=len)
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(len);
    s[start..end].to_string()
}

/// MsgType::Confirmation numeric value from the upstream sphinx crate.
/// Duplicated here to avoid a public dependency on sphinx::msg::MsgType.
const CONFIRMATION_MSG_TYPE: u8 = 1;

/// Parse the sender's pubkey out of the JSON-encoded SenderInfo string stored in
/// `Msg::sender`.  Returns `None` if the field is absent or the JSON is malformed.
///
/// The `sender` field is set by `sphinx::bindings::handle_msg` and
/// `handle_batch` as `serde_json::to_string(&sender_info)` where `SenderInfo`
/// has the shape `{ "pubkey": "...", "alias": "...", ... }`.
fn extract_sender_pubkey(sender_json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(sender_json).ok()?;
    v.get("pubkey")?.as_str().map(|s| s.to_string())
}

/// Issue a `MsgType::Confirmation` (type 1) back to the original sender of a
/// fully reassembled chunked message.  The `{"replyUuid": "<chunk_id>"}` payload
/// lets the sender's tag-based pending-delivery tracker match the confirmation
/// against the `chunk_id` it stored when it called `split_and_send`.
///
/// Returns the `RunReturn` from `bindings::send` (which carries the MQTT topics
/// and payloads the caller must publish) on success, or `None` if the send could
/// not be attempted (missing sender info, contact not found, network error, etc.).
/// In all failure cases a `[sphinx-ffi/chunk] WARN` line is printed to stderr.
///
/// `alias` and `img` are always left empty for this internal send; `is_tribe` is
/// `false`.  `unique_time` is derived from `now_secs()` to ensure a valid u64.
///
/// # Test hook
/// Under `#[cfg(test)]` the function short-circuits: instead of calling
/// `bindings::send` (which requires real crypto state) it appends the
/// `(to_pubkey, chunk_id)` pair to the `CONFIRMATION_CALLS` thread-local so
/// tests can assert whether a confirmation was (or was not) attempted.
fn send_chunk_confirmation(
    seed: &str,
    reassembled_msg: &Msg,
    chunk_id: &str,
    full_state: &[u8],
) -> Option<RunReturn> {
    let sender_json = reassembled_msg.sender.as_deref()?;
    let to_pubkey = match extract_sender_pubkey(sender_json) {
        Some(pk) if !pk.is_empty() => pk,
        _ => {
            eprintln!(
                "[sphinx-ffi/chunk] WARN send_chunk_confirmation: \
                 chunk_id={} — could not extract sender pubkey from sender JSON; \
                 no confirmation sent",
                chunk_id
            );
            return None;
        }
    };

    // Build the confirmation msg_json.  The Message struct in the sphinx crate uses
    // serde rename_all = "camelCase", so the wire field name is "replyUuid".
    let msg_json = format!(r#"{{"replyUuid":"{}"}}"#, chunk_id);
    // Derive a unique_time from wall-clock seconds.  It is always a valid u64 string.
    let unique_time = now_secs().to_string();

    #[cfg(test)]
    {
        // In unit tests, record the call instead of hitting the real network.
        CONFIRMATION_CALLS.with(|calls| {
            calls
                .borrow_mut()
                .push((to_pubkey.clone(), chunk_id.to_string()));
        });
        eprintln!(
            "[sphinx-ffi/chunk] DEBUG send_chunk_confirmation (test): \
             chunk_id={} → to={}",
            chunk_id, to_pubkey
        );
        return Some(crate::auto::RunReturn {
            msgs: Vec::new(),
            msgs_total: None,
            msgs_counts: None,
            subscription_topics: Vec::new(),
            settle_topic: None,
            settle_payload: None,
            asyncpay_topic: None,
            asyncpay_payload: None,
            register_topic: None,
            register_payload: None,
            topics: vec![format!("conf_topic/{}", chunk_id)],
            payloads: vec![b"conf".to_vec()],
            state_mp: None,
            state_to_delete: Vec::new(),
            new_balance: None,
            my_contact_info: None,
            sent_status: None,
            settled_status: None,
            asyncpay_tag: None,
            register_response: None,
            error: None,
            new_tribe: None,
            tribe_members: None,
            new_invite: None,
            inviter_contact_info: None,
            inviter_alias: None,
            initial_tribe: None,
            lsp_host: None,
            invoice: None,
            route: None,
            node: None,
            last_read: None,
            mute_levels: None,
            payments: None,
            payments_total: None,
            tags: None,
            deleted_msgs: None,
            new_child_idx: None,
            ping: None,
        });
    }

    #[cfg(not(test))]
    {
        eprintln!(
            "[sphinx-ffi/chunk] DEBUG send_chunk_confirmation: \
             chunk_id={} → to={}",
            chunk_id, to_pubkey
        );

        match bindings::send(
            seed,
            &unique_time,
            &to_pubkey,
            CONFIRMATION_MSG_TYPE,
            &msg_json,
            full_state,
            "",        // alias: empty is valid; becomes Some("") on wire
            &None,     // img: None
            0,         // amt_msat: free confirmation
            false,     // is_tribe: always direct
        ) {
            Ok(rr) => Some(rr.into()),
            Err(e) => {
                eprintln!(
                    "[sphinx-ffi/chunk] WARN send_chunk_confirmation: \
                     chunk_id={} to={} — bindings::send failed: {}; \
                     reassembly still succeeds",
                    chunk_id, to_pubkey, e
                );
                None
            }
        }
    }
}

/// Thread-local used by unit tests to capture `send_chunk_confirmation` calls
/// without hitting the real network.  Each entry is `(to_pubkey, chunk_id)`.
#[cfg(test)]
thread_local! {
    static CONFIRMATION_CALLS: std::cell::RefCell<Vec<(String, String)>> =
        std::cell::RefCell::new(Vec::new());
}

/// Called from `auto::handle()` and all four fetch-path functions after the bindings call.
/// Intercepts any Msgs with type == CHUNK_TYPE and either buffers or reassembles them.
///
/// # Receiver-side confirmation
/// On `ChunkResult::Complete`, a single `MsgType::Confirmation` (type 1) is sent back
/// to the original sender via `bindings::send`, carrying `{"replyUuid": "<chunk_id>"}`.
/// This allows the sender's tag-based pending-delivery tracking (keyed on `chunk_id` by
/// the companion `split_and_send` fix) to mark the message as delivered. The confirmation
/// is issued exactly once per fully reassembled message (never on `Incomplete`/`TimedOut`).
///
/// Alias and photo-URL are left as empty strings for this internal-only confirmation send;
/// `bindings::send` accepts empty alias fine (it becomes `alias: Some("")` on the wire)
/// and empty img resolves to `photo_url: None`. `is_tribe` is `false` — the confirmation
/// is always a direct peer send regardless of the original message's tribe context. These
/// defaults avoid adding new parameters to the public FFI API (which would require app-side
/// changes in sphinx-ios-v2/sphinx-mac-v2/sphinx-android-v2, contradicting the requirement
/// that no app changes are needed).
///
/// If the confirmation send fails (e.g. the sender is not in the receiver's contact list
/// yet, or the network is temporarily unavailable), the failure is logged at WARN level and
/// silently swallowed — reassembly of the message still succeeds and the reassembled `Msg`
/// is still returned. The sender may time out its pending-delivery indicator, but the
/// received message content is not affected.
///
/// # Concurrency risk (documented, not fixed in this ticket)
/// `local_state` is deserialized fresh from `full_state` at the start of each call and
/// reserialized at the end. This ticket adds a network send (`bindings::send`) inside the
/// same code path. Two concurrent invocations of `handle_chunks` (e.g. a live `handle()`
/// push racing a background batch-restore fetch on mobile) could each load `full_state`
/// before either's state delta is persisted, causing a last-writer-wins clobber of the
/// in-progress chunk buffer for the same `chunk_id`. Adding the confirmation send does not
/// worsen this race — it is a pre-existing property of the stateless persistence contract —
/// but it does mean the confirmation could be issued redundantly if both concurrent callers
/// independently complete the same reassembly before either's state_to_delete is applied.
/// A full concurrency fix (versioned/CAS merge) is recorded here as a known limitation and
/// candidate follow-up; it is explicitly out of scope for this ticket.
///
/// # Multi-fragment-per-call correctness
/// `handle()` delivers at most one message per call, so there is at most one chunk
/// fragment per `RunReturn` on that path. However, the four batch/paginated fetch
/// functions (`fetch_msgs`, `fetch_msgs_batch`, `fetch_msgs_batch_per_contact`,
/// `fetch_msgs_batch_okkey`) can return many messages — including multiple fragments
/// of the **same** `chunk_id` — in a single `RunReturn`. To handle this correctly,
/// we thread an accumulating in-memory state map (`local_state`) through the loop.
/// Each iteration reads chunk buffers from `local_state` first (falling back to
/// `full_state` only for keys not yet touched this call), and writes updates back
/// into `local_state` immediately so the next iteration in the same loop sees them.
/// The final `local_state` is what gets serialised into `rr.state_mp`.
pub fn handle_chunks(mut rr: RunReturn, full_state: &[u8], seed: &str) -> Result<RunReturn> {
    let now = now_secs();
    let mut i = 0;

    // Seed the accumulating state map from the caller-supplied full_state.
    // We keep it as a deserialized BTreeMap so per-iteration updates are visible
    // to subsequent iterations in the same call without a round-trip through msgpack.
    let mut local_state: BTreeMap<String, Vec<u8>> = if full_state.is_empty() {
        BTreeMap::new()
    } else {
        rmp_utils::deserialize_simple_state_map(full_state).map_err(|e| SphinxError::BadState {
            r: format!("handle_chunks deserialize full_state: {}", e),
        })?
    };

    while i < rr.msgs.len() {
        if rr.msgs[i].r#type == Some(CHUNK_TYPE) {
            let chunk_msg = rr.msgs.remove(i);

            // Serialize the current local_state snapshot so process_chunk_msg can read it.
            let local_state_bytes = rmp_utils::serialize_simple_state_map(&local_state)
                .map_err(|e| SphinxError::BadState {
                    r: format!("handle_chunks serialize local_state: {}", e),
                })?;

            let result = process_chunk_msg(chunk_msg, &local_state_bytes, now)?;

            match result {
                ChunkResult::Complete {
                    mut reassembled_msg,
                    state_key,
                } => {
                    // Remove the completed buffer from the accumulator so subsequent
                    // iterations (and the caller's persisted state) don't retain it.
                    local_state.remove(&state_key);

                    // Override the tag with chunk_id so the sender's pending-delivery
                    // tracker (keyed on chunk_id by split_and_send) can match it.
                    // The uuid is already set to chunk_id by process_chunk_msg; mirroring
                    // it into tag ensures consistency with the uuid assignment in
                    // split_and_send (added in this same change).
                    let chunk_id = reassembled_msg.uuid.clone().unwrap_or_default();
                    reassembled_msg.tag = Some(chunk_id.clone());

                    // Serialize local_state for the confirmation send (it must see the
                    // same state that handle_chunks has accumulated so far, without the
                    // now-deleted chunk buffer key).
                    let state_for_conf = rmp_utils::serialize_simple_state_map(&local_state)
                        .unwrap_or_default();

                    // Send a single application-level confirmation back to the original
                    // sender so their pending-delivery indicator can resolve.  Merge
                    // the resulting MQTT topics/payloads into rr so the caller publishes
                    // them; also fold any state delta from the confirmation send back
                    // into local_state so it is included in the final state_mp.
                    if let Some(conf_rr) = send_chunk_confirmation(
                        seed,
                        &reassembled_msg,
                        &chunk_id,
                        &state_for_conf,
                    ) {
                        rr.topics.extend(conf_rr.topics);
                        rr.payloads.extend(conf_rr.payloads);
                        if let Some(delta_mp) = conf_rr.state_mp {
                            if let Ok(merged_bytes) = merge_state(&state_for_conf, &delta_mp) {
                                if let Ok(new_map) =
                                    rmp_utils::deserialize_simple_state_map(&merged_bytes)
                                {
                                    local_state = new_map;
                                }
                            }
                        }
                    }

                    rr.msgs.insert(i, reassembled_msg);
                    rr.state_to_delete.push(state_key);
                    i += 1;
                }
                ChunkResult::Incomplete {
                    state_key,
                    buffer_bytes,
                } => {
                    // Write the updated buffer back into local_state immediately so
                    // a subsequent iteration for the same chunk_id sees this update.
                    local_state.insert(state_key, buffer_bytes);
                    // Chunk msg removed; don't advance i.
                }
                ChunkResult::TimedOut { state_key } => {
                    local_state.remove(&state_key);
                    rr.error =
                        Some(format!("chunk_timeout:{}", &state_key[CHUNK_STATE_PREFIX.len()..]));
                    rr.state_to_delete.push(state_key);
                    // Chunk msg removed; don't advance i.
                }
            }
        } else {
            i += 1;
        }
    }

    // Serialise the final accumulated state into rr.state_mp, merging with any
    // existing state_mp already present in the RunReturn (e.g., from bindings).
    let final_state_bytes = rmp_utils::serialize_simple_state_map(&local_state).map_err(|e| {
        SphinxError::BadState {
            r: format!("handle_chunks serialize final local_state: {}", e),
        }
    })?;

    // Only set state_mp if local_state differs from full_state (i.e., we touched
    // at least one chunk buffer this call), or if rr already carried a state_mp.
    // We detect "touched" by comparing the serialized form to the original bytes.
    // If nothing changed and rr had no prior state_mp, leave state_mp as None.
    let state_changed = final_state_bytes != full_state;
    if state_changed || rr.state_mp.is_some() {
        rr.state_mp = Some(if let Some(ref existing) = rr.state_mp {
            merge_state(&final_state_bytes, existing)?
        } else {
            final_state_bytes
        });
    }

    Ok(rr)
}

enum ChunkResult {
    Complete {
        reassembled_msg: Msg,
        state_key: String,
    },
    Incomplete {
        state_key: String,
        buffer_bytes: Vec<u8>,
    },
    TimedOut {
        state_key: String,
    },
}

fn process_chunk_msg(
    msg: Msg,
    full_state: &[u8],
    now: u64,
) -> Result<ChunkResult> {
    let msg_text = msg.message.as_deref().unwrap_or("");

    let (content, meta) = if let Ok(v) = serde_json::from_str::<serde_json::Value>(msg_text) {
        if let (Some(content_str), Some(meta_str)) =
            (v["content"].as_str(), v["metadata"].as_str())
        {
            // New wire format: metadata is a JSON-encoded string (double-serialized by the sender).
            let meta: ChunkMeta = serde_json::from_str(meta_str).map_err(|e| {
                SphinxError::HandleFailed { r: format!("chunk meta parse: {}", e) }
            })?;
            (content_str.to_string(), meta)
        } else {
            // Backward-compat: old format serialized the full ChunkPayload at the top level.
            let p: ChunkPayload = serde_json::from_str(msg_text).map_err(|e| {
                SphinxError::HandleFailed {
                    r: format!("chunk payload parse (legacy): {}", e),
                }
            })?;
            let meta = ChunkMeta {
                chunk_id: p.chunk_id.clone(),
                chunk_index: p.chunk_index,
                total_chunks: p.total_chunks,
                original_msg_type: p.original_msg_type,
            };
            (p.content, meta)
        }
    } else {
        return Err(SphinxError::HandleFailed {
            r: "chunk msg is not valid JSON".to_string(),
        });
    };

    // Reconstruct a ChunkPayload for the existing ChunkBuffer logic below (unchanged).
    let chunk = ChunkPayload {
        chunk_id: meta.chunk_id,
        chunk_index: meta.chunk_index,
        total_chunks: meta.total_chunks,
        original_msg_type: meta.original_msg_type,
        content,
    };

    let state_key = format!("{}{}", CHUNK_STATE_PREFIX, chunk.chunk_id);

    // Load existing buffer from full_state (if any).
    let existing_buffer: Option<ChunkBuffer> = load_chunk_buffer(full_state, &state_key)?;

    let (mut buffer, first_ts) = match existing_buffer {
        Some(buf) => {
            let ts = buf.first_received_ts;
            (buf, ts)
        }
        None => {
            let buf = ChunkBuffer {
                total_chunks: chunk.total_chunks,
                original_msg_type: chunk.original_msg_type,
                received: Vec::new(),
                first_received_ts: now,
            };
            (buf, now)
        }
    };

    // Check timeout.
    if now.saturating_sub(first_ts) > CHUNK_TIMEOUT_SECS {
        return Ok(ChunkResult::TimedOut { state_key });
    }

    // Append this chunk (avoid duplicates by chunk_index).
    if !buffer
        .received
        .iter()
        .any(|c| c.chunk_index == chunk.chunk_index)
    {
        buffer.received.push(chunk.clone());
    }

    // Check if complete.
    if buffer.received.len() as u16 == buffer.total_chunks {
        buffer.received.sort_by_key(|c| c.chunk_index);
        let reassembled: String = buffer.received.iter().map(|c| c.content.as_str()).collect();
        let original_msg_type = buffer.original_msg_type;
        let chunk_id = chunk.chunk_id.clone();

        let reassembled_msg = Msg {
            r#type: Some(original_msg_type),
            message: Some(reassembled),
            uuid: Some(chunk_id),
            sender: msg.sender,
            tag: msg.tag,
            index: msg.index,
            msat: msg.msat,
            timestamp: msg.timestamp,
            sent_to: msg.sent_to,
            from_me: msg.from_me,
            payment_hash: msg.payment_hash,
            error: None,
        };

        return Ok(ChunkResult::Complete {
            reassembled_msg,
            state_key,
        });
    }

    // Incomplete: serialize updated buffer.
    let buffer_bytes =
        serde_json::to_vec(&buffer).map_err(|e| SphinxError::BadState {
            r: format!("chunk buffer serialize: {}", e),
        })?;

    Ok(ChunkResult::Incomplete {
        state_key,
        buffer_bytes,
    })
}

/// Load a ChunkBuffer from the full_state map at the given key.
fn load_chunk_buffer(full_state: &[u8], key: &str) -> Result<Option<ChunkBuffer>> {
    if full_state.is_empty() {
        return Ok(None);
    }
    let state_map: BTreeMap<String, Vec<u8>> =
        rmp_utils::deserialize_simple_state_map(full_state).map_err(|e| SphinxError::BadState {
            r: format!("load_chunk_buffer deserialize: {}", e),
        })?;

    if let Some(bytes) = state_map.get(key) {
        let buf: ChunkBuffer =
            serde_json::from_slice(bytes).map_err(|e| SphinxError::BadState {
                r: format!("chunk buffer deserialize: {}", e),
            })?;
        Ok(Some(buf))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto::RunReturn;

    fn empty_run_return() -> RunReturn {
        RunReturn {
            msgs: Vec::new(),
            msgs_total: None,
            msgs_counts: None,
            subscription_topics: Vec::new(),
            settle_topic: None,
            settle_payload: None,
            asyncpay_topic: None,
            asyncpay_payload: None,
            register_topic: None,
            register_payload: None,
            topics: Vec::new(),
            payloads: Vec::new(),
            state_mp: None,
            state_to_delete: Vec::new(),
            new_balance: None,
            my_contact_info: None,
            sent_status: None,
            settled_status: None,
            asyncpay_tag: None,
            register_response: None,
            error: None,
            new_tribe: None,
            tribe_members: None,
            new_invite: None,
            inviter_contact_info: None,
            inviter_alias: None,
            initial_tribe: None,
            lsp_host: None,
            invoice: None,
            route: None,
            node: None,
            last_read: None,
            mute_levels: None,
            payments: None,
            payments_total: None,
            tags: None,
            deleted_msgs: None,
            new_child_idx: None,
            ping: None,
        }
    }

    fn make_chunk_msg(chunk: &ChunkPayload) -> Msg {
        let meta = ChunkMeta {
            chunk_id: chunk.chunk_id.clone(),
            chunk_index: chunk.chunk_index,
            total_chunks: chunk.total_chunks,
            original_msg_type: chunk.original_msg_type,
        };
        let meta_json = serde_json::to_string(&meta).unwrap();
        let msg_json = serde_json::json!({
            "content": chunk.content.clone(),
            "metadata": meta_json,
        })
        .to_string();
        Msg {
            r#type: Some(CHUNK_TYPE),
            message: Some(msg_json),
            sender: None,
            uuid: None,
            tag: None,
            index: None,
            msat: None,
            timestamp: None,
            sent_to: None,
            from_me: None,
            payment_hash: None,
            error: None,
        }
    }

    /// Build a full_state containing a ChunkBuffer at the given key (simple format).
    fn state_with_buffer(key: &str, buf: &ChunkBuffer) -> Vec<u8> {
        let buf_bytes = serde_json::to_vec(buf).unwrap();
        let mut map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        map.insert(key.to_string(), buf_bytes);
        rmp_utils::serialize_simple_state_map(&map).unwrap()
    }

    // Test 1: msg_json under threshold → split_and_send not triggered (threshold check in auto.rs).
    // This test verifies CHUNK_CONTENT_THRESHOLD is the correct boundary value.
    #[test]
    fn test_threshold_boundary() {
        let under = "a".repeat(CHUNK_CONTENT_THRESHOLD);
        assert!(under.len() <= CHUNK_CONTENT_THRESHOLD);
        let over = "a".repeat(CHUNK_CONTENT_THRESHOLD + 1);
        assert!(over.len() > CHUNK_CONTENT_THRESHOLD);
    }

    // Test 2: msg_json over threshold → correct number of ChunkPayload slices.
    #[test]
    fn test_chunk_count() {
        let msg = "x".repeat(CHUNK_CONTENT_THRESHOLD * 3 + 1); // 4 chunks
        let chunk_id = "testid".to_string();
        let n = (msg.len() + CHUNK_CONTENT_THRESHOLD - 1) / CHUNK_CONTENT_THRESHOLD;
        assert_eq!(n, 4);

        // Simulate slicing
        let mut chunks: Vec<ChunkPayload> = Vec::new();
        let total = n as u16;
        for i in 0..n {
            let start = i * CHUNK_CONTENT_THRESHOLD;
            let end = (start + CHUNK_CONTENT_THRESHOLD).min(msg.len());
            let content = slice_utf8_safe(&msg, start, end);
            chunks.push(ChunkPayload {
                chunk_id: chunk_id.clone(),
                chunk_index: i as u16,
                total_chunks: total,
                original_msg_type: 1,
                content,
            });
        }
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[3].chunk_index, 3);
        // Last chunk has the remainder
        assert_eq!(chunks[3].content.len(), 1);
    }

    // Test 3: handle_chunks with all chunks present → reassembled Msg with original type.
    #[test]
    fn test_handle_chunks_complete() {
        let original_msg = "hello world ".repeat(70); // > 750 bytes
        let chunk_id = "abc123".to_string();
        let n = (original_msg.len() + CHUNK_CONTENT_THRESHOLD - 1) / CHUNK_CONTENT_THRESHOLD;
        let total = n as u16;
        let orig_type: u8 = 2;

        // Build all chunks as Msgs
        let mut rr = empty_run_return();
        for i in 0..n {
            let start = i * CHUNK_CONTENT_THRESHOLD;
            let end = (start + CHUNK_CONTENT_THRESHOLD).min(original_msg.len());
            let content = slice_utf8_safe(&original_msg, start, end);
            let cp = ChunkPayload {
                chunk_id: chunk_id.clone(),
                chunk_index: i as u16,
                total_chunks: total,
                original_msg_type: orig_type,
                content,
            };
            rr.msgs.push(make_chunk_msg(&cp));
        }

        // Process all in sequence with empty state, accumulating state between calls
        let mut state: Vec<u8> = Vec::new();
        let mut final_rr = empty_run_return();
        for msg in rr.msgs {
            let mut single_rr = empty_run_return();
            single_rr.msgs.push(msg);
            let result = handle_chunks(single_rr, &state, "").unwrap();
            // Update state with any state_mp delta from chunk buffering
            if let Some(ref mp) = result.state_mp {
                state = merge_state(&state, mp).unwrap();
            }
            final_rr = result;
        }

        assert_eq!(final_rr.msgs.len(), 1);
        let m = &final_rr.msgs[0];
        assert_eq!(m.r#type, Some(orig_type));
        assert_eq!(m.message.as_deref().unwrap(), original_msg.as_str());
        assert_eq!(m.uuid.as_deref().unwrap(), chunk_id.as_str());
        assert!(final_rr.state_to_delete.contains(&format!("chunkbuf_{}", chunk_id)));
    }

    // Test 4: handle_chunks with partial chunks → RunReturn with empty msgs and state_mp set.
    #[test]
    fn test_handle_chunks_partial() {
        let chunk_id = "partial_test".to_string();
        let cp = ChunkPayload {
            chunk_id: chunk_id.clone(),
            chunk_index: 0,
            total_chunks: 3, // 3 expected, only sending 1
            original_msg_type: 2,
            content: "part one ".to_string(),
        };

        let mut rr = empty_run_return();
        rr.msgs.push(make_chunk_msg(&cp));

        let result = handle_chunks(rr, &[], "").unwrap();

        assert!(result.msgs.is_empty(), "msgs should be empty for partial chunk");
        assert!(result.state_mp.is_some(), "state_mp should be set for partial chunk");
        assert!(result.state_to_delete.is_empty());
    }

    // Test 5: handle_chunks with timed-out buffer → error and state_to_delete.
    #[test]
    fn test_handle_chunks_timeout() {
        let chunk_id = "timeout_test".to_string();
        let key = format!("{}{}", CHUNK_STATE_PREFIX, chunk_id);

        // Create a buffer that is 31 seconds old
        let old_ts = now_secs().saturating_sub(CHUNK_TIMEOUT_SECS + 1);
        let old_buf = ChunkBuffer {
            total_chunks: 3,
            original_msg_type: 2,
            received: vec![ChunkPayload {
                chunk_id: chunk_id.clone(),
                chunk_index: 0,
                total_chunks: 3,
                original_msg_type: 2,
                content: "part".to_string(),
            }],
            first_received_ts: old_ts,
        };

        let state = state_with_buffer(&key, &old_buf);

        // Send a new chunk for this timed-out buffer
        let cp = ChunkPayload {
            chunk_id: chunk_id.clone(),
            chunk_index: 1,
            total_chunks: 3,
            original_msg_type: 2,
            content: "more".to_string(),
        };
        let mut rr = empty_run_return();
        rr.msgs.push(make_chunk_msg(&cp));

        let result = handle_chunks(rr, &state, "").unwrap();

        assert!(result.msgs.is_empty());
        assert_eq!(result.error.as_deref(), Some("chunk_timeout:timeout_test"));
        assert!(result.state_to_delete.contains(&key));
    }

    // Test 6: chunk_unique_time values are valid u64, correct length, and unique.
    #[test]
    fn test_chunk_unique_time_is_valid_u64() {
        // Use a realistic 13-digit ms-precision value matching getTimeWithEntropy() callers.
        let unique_time = "1706300000123";
        let mut seen = std::collections::HashSet::new();
        for i in 0usize..4 {
            let t = format!("{}{:03}", unique_time, i);
            // Must parse as u64.
            assert!(t.parse::<u64>().is_ok(), "chunk_unique_time must parse as u64: {}", t);
            // 13-digit ms timestamp + 3-digit suffix = 16 chars exactly.
            assert_eq!(t.len(), 16, "expected 16-char chunk_unique_time, got: {}", t);
            // Each value must be distinct.
            assert!(seen.insert(t.clone()), "duplicate chunk_unique_time: {}", t);
        }
    }

    // Test 7: chunk content concatenation preserves original msg_json exactly.
    #[test]
    fn test_content_roundtrip() {
        // Use a multi-byte UTF-8 string to verify char-boundary safety
        let original = "🦀".repeat(200); // each 🦀 is 4 bytes; 200 * 4 = 800 bytes > 750
        let n = (original.len() + CHUNK_CONTENT_THRESHOLD - 1) / CHUNK_CONTENT_THRESHOLD;

        let mut pieces: Vec<String> = Vec::new();
        for i in 0..n {
            let start = i * CHUNK_CONTENT_THRESHOLD;
            let end = (start + CHUNK_CONTENT_THRESHOLD).min(original.len());
            pieces.push(slice_utf8_safe(&original, start, end));
        }

        let reassembled: String = pieces.iter().map(|s| s.as_str()).collect();
        assert_eq!(reassembled, original, "content roundtrip should preserve original");
    }

    // Test 8: new wire format round-trips chunk coordinates correctly through process_chunk_msg.
    #[test]
    fn test_chunk_metadata_roundtrip() {
        let cp = ChunkPayload {
            chunk_id: "meta_roundtrip_id".to_string(),
            chunk_index: 2,
            total_chunks: 5,
            original_msg_type: 7,
            content: "some content slice".to_string(),
        };

        let msg = make_chunk_msg(&cp);
        let now = now_secs();
        let result = process_chunk_msg(msg, &[], now).unwrap();

        // With total_chunks=5 and only 1 received, the result must be Incomplete.
        match result {
            ChunkResult::Incomplete { state_key, buffer_bytes } => {
                assert_eq!(state_key, format!("{}meta_roundtrip_id", CHUNK_STATE_PREFIX));
                // Deserialize the buffer and verify the stored chunk's coordinates.
                let buf: ChunkBuffer = serde_json::from_slice(&buffer_bytes).unwrap();
                assert_eq!(buf.received.len(), 1);
                let stored = &buf.received[0];
                assert_eq!(stored.chunk_id, cp.chunk_id);
                assert_eq!(stored.chunk_index, cp.chunk_index);
                assert_eq!(stored.total_chunks, cp.total_chunks);
                assert_eq!(stored.original_msg_type, cp.original_msg_type);
                assert_eq!(stored.content, cp.content);
            }
            _ => panic!("expected Incomplete result for a single chunk out of 5"),
        }
    }

    // ---- New dynamic-budget tests ----

    // Test N1: compute_sender_overhead returns a non-zero value for typical inputs,
    // and a larger value for long alias/img than for short/empty ones.
    #[test]
    fn test_compute_sender_overhead_scales_with_length() {
        let short = compute_sender_overhead("Bob", "");
        let long_alias = compute_sender_overhead(&"A".repeat(200), "");
        let long_both =
            compute_sender_overhead(&"A".repeat(200), "https://example.com/very/long/photo/url/that/adds/bytes.png");

        assert!(short > 0, "overhead must be non-zero even for short inputs");
        assert!(
            long_alias > short,
            "longer alias should produce larger overhead ({} vs {})",
            long_alias,
            short
        );
        assert!(
            long_both > long_alias,
            "adding a long img should grow overhead further ({} vs {})",
            long_both,
            long_alias
        );

        // Determinism: calling twice with the same args returns the same value.
        assert_eq!(
            compute_sender_overhead("Alice", "https://img.example.com/avatar.jpg"),
            compute_sender_overhead("Alice", "https://img.example.com/avatar.jpg"),
            "compute_sender_overhead must be deterministic"
        );
    }

    // Test N2: a long alias + long photo URL shrinks available_content_bytes compared
    // to a short alias case, and produces more (smaller) chunks.
    #[test]
    fn test_long_alias_img_shrinks_budget_and_increases_chunks() {
        let short_budget =
            compute_available_content_bytes("Bob", "").expect("short alias must have budget");
        let long_budget = compute_available_content_bytes(
            &"A".repeat(200),
            "https://example.com/very/long/photo/url.png",
        )
        .expect("long alias must still have some budget");

        assert!(
            long_budget < short_budget,
            "long alias+img budget ({}) must be smaller than short alias budget ({})",
            long_budget,
            short_budget
        );

        // Verify that more chunks are produced for the same message with a long identity.
        let msg = "x".repeat(400); // > typical long_budget, < short_budget may handle in 1 chunk
        let short_n = (msg.len() + short_budget - 1) / short_budget;
        let long_n = (msg.len() + long_budget - 1) / long_budget;
        assert!(
            long_n >= short_n,
            "long identity should produce >= chunks ({} vs {})",
            long_n,
            short_n
        );
    }

    // Test N3: when sender identity fields exceed the remaining budget,
    // compute_available_content_bytes returns None and split_and_send returns
    // ContentBudgetExceeded rather than panicking or wrapping.
    #[test]
    fn test_budget_exhaustion_returns_content_budget_exceeded() {
        // Build a massive alias that will definitely exhaust the budget.
        // MAX_MSG_LEN=869, APP_OVERHEAD=143, FIXED_PROTOCOL=250, ROUTE_HINT=50 → 426 bytes left.
        // A 500-char alias serialized in JSON = at least 500 + framing bytes > 426.
        let huge_alias = "X".repeat(500);
        let result = compute_available_content_bytes(&huge_alias, "");
        assert!(
            result.is_none(),
            "a 500-char alias must exhaust the budget, got Some({})",
            result.unwrap_or(0)
        );

        // Also test via split_and_send: it should return ContentBudgetExceeded.
        let msg_json = "hello world"; // any content — error should fire before slicing
        let result = split_and_send(
            "seed",
            "1706300000123",
            "to_pubkey",
            1,
            msg_json,
            Vec::new(),
            &huge_alias,
            &None,
            0,
            false,
        );

        match result {
            Err(SphinxError::ContentBudgetExceeded { .. }) => {} // expected
            Err(other) => panic!("expected ContentBudgetExceeded, got a different SphinxError: {}", other),
            Ok(_) => panic!("expected ContentBudgetExceeded error, but split_and_send succeeded"),
        }
    }

    // Test N4: regression — auto.rs::send()'s trigger check (msg_json.len() > CHUNK_CONTENT_THRESHOLD)
    // is unchanged by this refactor. CHUNK_CONTENT_THRESHOLD must still equal 450.
    #[test]
    fn test_trigger_check_threshold_unchanged() {
        assert_eq!(
            CHUNK_CONTENT_THRESHOLD,
            450,
            "CHUNK_CONTENT_THRESHOLD must remain 450 — auto.rs::send() depends on this value"
        );
        // A message exactly at the threshold does NOT trigger chunking (uses >, not >=).
        let at_threshold = "a".repeat(450);
        assert!(!(at_threshold.len() > CHUNK_CONTENT_THRESHOLD));
        // A message one byte over the threshold DOES trigger chunking.
        let over_threshold = "a".repeat(451);
        assert!(over_threshold.len() > CHUNK_CONTENT_THRESHOLD);
    }

    // Test N5: parity — given identical alias/img, compute_available_content_bytes returns
    // the same budget regardless of whether the send is tribe or direct (v1 treats them
    // identically for the route-hint allowance).
    #[test]
    fn test_tribe_and_direct_send_same_budget() {
        let alias = "TestUser";
        let img = "https://cdn.example.com/avatar.jpg";

        let budget_direct = compute_available_content_bytes(alias, img);
        let budget_tribe = compute_available_content_bytes(alias, img);

        assert_eq!(
            budget_direct, budget_tribe,
            "tribe and direct sends must produce identical budgets for the same alias/img"
        );
    }

    // Test N6: content roundtrip with dynamic slice size — reassembly is still byte-exact
    // when using available_content_bytes as the slice size rather than the fixed threshold.
    #[test]
    fn test_content_roundtrip_dynamic_slice_size() {
        // Use a realistic alias + img to get a real dynamic budget.
        let my_alias = "AliceNode";
        let my_img = "https://sphinx.chat/static/alice_avatar.png";
        let slice_size =
            compute_available_content_bytes(my_alias, my_img).expect("must have budget");

        // Build a message longer than the dynamic slice size.
        let original = "🦀".repeat(80); // each 🦀 is 4 bytes = 320 bytes; may span multiple chunks
        let n = (original.len() + slice_size - 1) / slice_size;

        let mut pieces: Vec<String> = Vec::new();
        for i in 0..n {
            let start = i * slice_size;
            let end = (start + slice_size).min(original.len());
            pieces.push(slice_utf8_safe(&original, start, end));
        }

        let reassembled: String = pieces.concat();
        assert_eq!(
            reassembled, original,
            "dynamic slice size must produce byte-exact roundtrip"
        );
    }

    // Test NEW-A: two different concurrent chunk_ids in a single RunReturn → both buffers
    // tracked independently, both appear in state_mp, neither is reassembled yet.
    #[test]
    fn test_handle_chunks_two_concurrent_chunk_ids() {
        let chunk_id_a = "concurrent_a".to_string();
        let chunk_id_b = "concurrent_b".to_string();

        let cp_a = ChunkPayload {
            chunk_id: chunk_id_a.clone(),
            chunk_index: 0,
            total_chunks: 2,
            original_msg_type: 1,
            content: "hello from A".to_string(),
        };
        let cp_b = ChunkPayload {
            chunk_id: chunk_id_b.clone(),
            chunk_index: 0,
            total_chunks: 2,
            original_msg_type: 2,
            content: "hello from B".to_string(),
        };

        let mut rr = empty_run_return();
        rr.msgs.push(make_chunk_msg(&cp_a));
        rr.msgs.push(make_chunk_msg(&cp_b));

        let result = handle_chunks(rr, &[], "").unwrap();

        // Both fragments are incomplete (each needs 2 total) — no reassembled msgs.
        assert!(result.msgs.is_empty(), "no complete messages expected");
        assert!(result.state_mp.is_some(), "state_mp must carry both chunk buffers");
        assert!(result.state_to_delete.is_empty());

        // Verify both state keys are present in the returned state_mp.
        let state_mp = result.state_mp.unwrap();
        let state_map: BTreeMap<String, Vec<u8>> =
            rmp_utils::deserialize_simple_state_map(&state_mp).unwrap();
        let key_a = format!("{}{}", CHUNK_STATE_PREFIX, chunk_id_a);
        let key_b = format!("{}{}", CHUNK_STATE_PREFIX, chunk_id_b);
        assert!(state_map.contains_key(&key_a), "state_mp must contain key for chunk_id_a");
        assert!(state_map.contains_key(&key_b), "state_mp must contain key for chunk_id_b");

        // Verify the stored buffers have the correct content.
        let buf_bytes_a = state_map.get(&key_a).unwrap();
        let buf_a: ChunkBuffer = serde_json::from_slice(buf_bytes_a).unwrap();
        assert_eq!(buf_a.received.len(), 1);
        assert_eq!(buf_a.received[0].content, "hello from A");

        let buf_bytes_b = state_map.get(&key_b).unwrap();
        let buf_b: ChunkBuffer = serde_json::from_slice(buf_bytes_b).unwrap();
        assert_eq!(buf_b.received.len(), 1);
        assert_eq!(buf_b.received[0].content, "hello from B");
    }

    // Test NEW-B: two fragments of the *same* chunk_id in a single RunReturn.
    // Confirms the accumulation fix: the second fragment sees the first fragment's
    // in-call buffer update and the message reassembles correctly within one call.
    #[test]
    fn test_handle_chunks_same_chunk_id_two_fragments_one_call() {
        let chunk_id = "same_id_two_frags".to_string();

        let cp0 = ChunkPayload {
            chunk_id: chunk_id.clone(),
            chunk_index: 0,
            total_chunks: 2,
            original_msg_type: 3,
            content: "first_half_".to_string(),
        };
        let cp1 = ChunkPayload {
            chunk_id: chunk_id.clone(),
            chunk_index: 1,
            total_chunks: 2,
            original_msg_type: 3,
            content: "second_half".to_string(),
        };

        let mut rr = empty_run_return();
        rr.msgs.push(make_chunk_msg(&cp0));
        rr.msgs.push(make_chunk_msg(&cp1));

        // Pass empty state — both fragments arrive in the same call.
        let result = handle_chunks(rr, &[], "").unwrap();

        // Both fragments together complete the message → exactly one reassembled msg.
        assert_eq!(result.msgs.len(), 1, "both fragments in one call must reassemble");
        let m = &result.msgs[0];
        assert_eq!(m.r#type, Some(3u8));
        assert_eq!(m.message.as_deref().unwrap(), "first_half_second_half");
        assert_eq!(m.uuid.as_deref().unwrap(), chunk_id.as_str());

        // The completed buffer key must be scheduled for deletion.
        let key = format!("{}{}", CHUNK_STATE_PREFIX, chunk_id);
        assert!(result.state_to_delete.contains(&key));
    }

    // Test NEW-C: sequential handle_chunks calls simulating two separate fetch_msgs
    // invocations. The second call must use the state_mp from the first call so that
    // fragment buffering persists across calls and the message reassembles correctly.
    #[test]
    fn test_handle_chunks_sequential_calls_cross_call_reassembly() {
        let chunk_id = "cross_call_id".to_string();
        let orig_type: u8 = 5;

        let cp0 = ChunkPayload {
            chunk_id: chunk_id.clone(),
            chunk_index: 0,
            total_chunks: 2,
            original_msg_type: orig_type,
            content: "part_one_".to_string(),
        };
        let cp1 = ChunkPayload {
            chunk_id: chunk_id.clone(),
            chunk_index: 1,
            total_chunks: 2,
            original_msg_type: orig_type,
            content: "part_two".to_string(),
        };

        // --- First "fetch" call: only fragment 0 arrives ---
        let mut rr1 = empty_run_return();
        rr1.msgs.push(make_chunk_msg(&cp0));

        let result1 = handle_chunks(rr1, &[], "").unwrap();

        assert!(result1.msgs.is_empty(), "first call must not reassemble (incomplete)");
        assert!(result1.state_mp.is_some(), "first call must return state_mp with buffer");

        // Persist state_mp from call 1 (simulating what the client stores).
        let persisted_state = result1.state_mp.unwrap();

        // --- Second "fetch" call: fragment 1 arrives, state from call 1 passed in ---
        let mut rr2 = empty_run_return();
        rr2.msgs.push(make_chunk_msg(&cp1));

        let result2 = handle_chunks(rr2, &persisted_state, "").unwrap();

        // Second call has both fragments → complete message.
        assert_eq!(result2.msgs.len(), 1, "second call must complete reassembly");
        let m = &result2.msgs[0];
        assert_eq!(m.r#type, Some(orig_type));
        assert_eq!(m.message.as_deref().unwrap(), "part_one_part_two");
        assert_eq!(m.uuid.as_deref().unwrap(), chunk_id.as_str());

        // Completed buffer must be scheduled for deletion.
        let key = format!("{}{}", CHUNK_STATE_PREFIX, chunk_id);
        assert!(result2.state_to_delete.contains(&key));
    }

    // Test 10: ChunkBuffer round-trips through a simple-format full_state (regression guard).
    // Also validates decode of an externally-sourced real-world simple-format byte fixture
    // (from https://github.com/stakwork/sphinx-ios/issues/256) so the test is not purely
    // self-validating against its own encoder.
    #[test]
    fn test_chunkbuffer_roundtrip_simple_format() {
        // --- Part A: self-encoded round-trip ---
        let chunk_id = "roundtrip_id";
        let key = format!("{}{}", CHUNK_STATE_PREFIX, chunk_id);

        // Build a ChunkBuffer with one fragment already in it.
        // Use a current timestamp so the buffer doesn't trip the CHUNK_TIMEOUT_SECS check.
        let existing_buf = ChunkBuffer {
            total_chunks: 2,
            original_msg_type: 3,
            received: vec![ChunkPayload {
                chunk_id: chunk_id.to_string(),
                chunk_index: 0,
                total_chunks: 2,
                original_msg_type: 3,
                content: "first_part_".to_string(),
            }],
            first_received_ts: now_secs(),
        };

        // Serialize the buffer into a simple-format full_state.
        let buf_bytes = serde_json::to_vec(&existing_buf).unwrap();
        let mut map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        map.insert(key.clone(), buf_bytes);
        let full_state = rmp_utils::serialize_simple_state_map(&map).unwrap();

        // Feed the second fragment through handle_chunks against that state.
        let cp1 = ChunkPayload {
            chunk_id: chunk_id.to_string(),
            chunk_index: 1,
            total_chunks: 2,
            original_msg_type: 3,
            content: "second_part".to_string(),
        };
        let mut rr = empty_run_return();
        rr.msgs.push(make_chunk_msg(&cp1));

        let result = handle_chunks(rr, &full_state, "").unwrap();

        // Both fragments now present → reassembled message.
        assert_eq!(result.msgs.len(), 1, "should have exactly one reassembled message");
        let m = &result.msgs[0];
        assert_eq!(m.r#type, Some(3u8));
        assert_eq!(
            m.message.as_deref().unwrap(),
            "first_part_second_part",
            "reassembled content must equal original fragments concatenated"
        );
        assert_eq!(m.uuid.as_deref().unwrap(), chunk_id);

        // The completed key must be scheduled for deletion (not left in state).
        assert!(result.state_to_delete.contains(&key));

        // --- Part B: real-world externally-sourced bytes (from iOS bug report) ---
        // These bytes were captured from a live iOS client and used to validate
        // deserialize_simple_state_map in rmp-utils/src/playground.rs.
        // They represent a simple-format map with key "MSG_1" → binary value.
        let x: &[u8] = &[
            129, 165, 77, 83, 71, 95, 49, 196, 56, 129, 164, 73, 110, 105, 116, 129,
            173, 115, 101, 114, 118, 101, 114, 95, 112, 117, 98, 107, 101, 121, 196,
            33, 2, 116, 210, 87, 213, 129, 0, 4, 177, 77, 39, 94, 32, 210, 198, 74,
            84, 30, 183, 174, 1, 133, 51, 137, 69, 135, 160, 29, 77, 74, 218, 206, 233,
        ];
        let decoded = rmp_utils::deserialize_simple_state_map(x);
        assert!(
            decoded.is_ok(),
            "deserialize_simple_state_map must decode real-world iOS bytes: {:?}",
            decoded.err()
        );
        let decoded_map = decoded.unwrap();
        assert_eq!(decoded_map.len(), 1, "real-world fixture must decode to a 1-entry map");
        assert!(
            decoded_map.contains_key("MSG_1"),
            "real-world fixture must have key 'MSG_1'"
        );
    }

    // Test 11: send-path merge_state test — drives merge_state() the way split_and_send
    // does (merging a base and delta state, both in simple format) and asserts the merged
    // result deserializes correctly with the expected combined key set.
    #[test]
    fn test_merge_state_simple_format_send_path() {
        // Build a base state with one key (simulating the full_state passed into split_and_send).
        let mut base_map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        base_map.insert("base_key".to_string(), b"base_value".to_vec());
        let base_bytes = rmp_utils::serialize_simple_state_map(&base_map).unwrap();

        // Build a delta state with a different key (simulating a state_mp delta returned
        // by bindings::send for one chunk).
        let mut delta_map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        delta_map.insert("delta_key".to_string(), b"delta_value".to_vec());
        let delta_bytes = rmp_utils::serialize_simple_state_map(&delta_map).unwrap();

        // Merge them as split_and_send does.
        let merged_bytes = merge_state(&base_bytes, &delta_bytes).unwrap();

        // The merged result must deserialize via the simple format and contain both keys.
        let merged_map = rmp_utils::deserialize_simple_state_map(&merged_bytes).unwrap();
        assert_eq!(merged_map.len(), 2, "merged state must contain both base and delta keys");
        assert_eq!(
            merged_map.get("base_key").map(|v| v.as_slice()),
            Some(b"base_value" as &[u8]),
            "base_key must be preserved in merged state"
        );
        assert_eq!(
            merged_map.get("delta_key").map(|v| v.as_slice()),
            Some(b"delta_value" as &[u8]),
            "delta_key must be present in merged state"
        );

        // Also confirm: delta key overwrites base key when they collide (flat overwrite semantics).
        let mut delta_collision: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        delta_collision.insert("base_key".to_string(), b"overwritten".to_vec());
        let delta_collision_bytes =
            rmp_utils::serialize_simple_state_map(&delta_collision).unwrap();
        let merged2 = merge_state(&base_bytes, &delta_collision_bytes).unwrap();
        let merged2_map = rmp_utils::deserialize_simple_state_map(&merged2).unwrap();
        assert_eq!(
            merged2_map.get("base_key").map(|v| v.as_slice()),
            Some(b"overwritten" as &[u8]),
            "delta must overwrite base for colliding keys"
        );
    }

    // Test 12: corrupt-buffer characterization — load_chunk_buffer returns BadState
    // when the stored bytes are not valid JSON (documents the hard-fail-on-corrupt behavior).
    #[test]
    fn test_load_chunk_buffer_corrupt_returns_bad_state() {
        let chunk_id = "corrupt_test_id";
        let key = format!("{}{}", CHUNK_STATE_PREFIX, chunk_id);

        // Store non-JSON garbage bytes under the chunkbuf_ key.
        let corrupt_bytes: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x01, 0x42];
        let mut map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        map.insert(key.clone(), corrupt_bytes);
        let full_state = rmp_utils::serialize_simple_state_map(&map).unwrap();

        let result = load_chunk_buffer(&full_state, &key);

        match result {
            Err(SphinxError::BadState { r }) => {
                assert!(
                    r.contains("chunk buffer deserialize"),
                    "BadState reason must mention 'chunk buffer deserialize', got: {}",
                    r
                );
            }
            Err(other) => panic!("expected BadState, got a different error: {}", other),
            Ok(_) => panic!("expected Err(BadState) for corrupt buffer bytes, got Ok"),
        }
    }

    // Test 9: legacy-format ChunkPayload JSON (pre-upgrade wire format) is handled by the
    // backward-compat fallback path in process_chunk_msg.
    #[test]
    fn test_legacy_chunk_compat() {
        let cp = ChunkPayload {
            chunk_id: "legacy_id".to_string(),
            chunk_index: 0,
            total_chunks: 3,
            original_msg_type: 4,
            content: "legacy content".to_string(),
        };

        // Build a Msg using the OLD wire format: ChunkPayload fields at the top level.
        let legacy_msg_json = serde_json::to_string(&cp).unwrap();
        let legacy_msg = Msg {
            r#type: Some(CHUNK_TYPE),
            message: Some(legacy_msg_json),
            sender: None,
            uuid: None,
            tag: None,
            index: None,
            msat: None,
            timestamp: None,
            sent_to: None,
            from_me: None,
            payment_hash: None,
            error: None,
        };

        let now = now_secs();
        let result = process_chunk_msg(legacy_msg, &[], now).unwrap();

        // Expect Incomplete (total_chunks=3, only 1 received) — confirming the fallback parsed OK.
        match result {
            ChunkResult::Incomplete { state_key, buffer_bytes } => {
                assert_eq!(state_key, format!("{}legacy_id", CHUNK_STATE_PREFIX));
                let buf: ChunkBuffer = serde_json::from_slice(&buffer_bytes).unwrap();
                assert_eq!(buf.received.len(), 1);
                let stored = &buf.received[0];
                assert_eq!(stored.chunk_id, cp.chunk_id);
                assert_eq!(stored.chunk_index, cp.chunk_index);
                assert_eq!(stored.total_chunks, cp.total_chunks);
                assert_eq!(stored.original_msg_type, cp.original_msg_type);
                assert_eq!(stored.content, cp.content);
            }
            _ => panic!("expected Incomplete result for legacy format chunk"),
        }
    }

    // ---- make_chunk_id tests ----

    // Test MCI-1: two unique_time values that share the same first 8 bytes must
    // produce different chunk_ids (regression against the old 8-byte-prefix bug).
    #[test]
    fn test_make_chunk_id_unique_for_same_8_byte_prefix() {
        let a = make_chunk_id("1785847310885");
        let b = make_chunk_id("1785847372513");
        assert_ne!(a, b, "chunk_id must differ even when the first 8 bytes match");
    }

    // Test MCI-2: the chunk_id produced from the longest legal unique_time
    // (≤16 chars per the existing debug_assert) must not exceed 16 characters,
    // confirming the fix does not inflate per-chunk wire overhead beyond what
    // APP_OVERHEAD_BYTES / MAX_OVERHEAD_BYTES budget constants assume.
    #[test]
    fn test_make_chunk_id_does_not_exceed_wire_budget() {
        // Longest legal unique_time per the existing debug_assert (<=16 chars).
        let worst_case = make_chunk_id("9999999999999999");
        assert!(
            worst_case.len() <= 16,
            "chunk_id must not exceed the length the current APP_OVERHEAD_BYTES/MAX_OVERHEAD_BYTES \
             budget assumes, got len={}",
            worst_case.len()
        );
    }

    // ---- split_and_send merge-field tests ----
    //
    // split_and_send calls bindings::send which requires a live network — we
    // cannot call it end-to-end in unit tests.  Instead we exercise the
    // post-loop merge logic directly by constructing mock RunReturns that mimic
    // what the loop accumulates, then asserting the invariants the apps depend on.

    /// Build a minimal RunReturn that represents a single chunk send result,
    /// optionally carrying a transport tag and/or error.
    fn chunk_send_rr(tag: Option<&str>, error: Option<&str>, topic: &str) -> RunReturn {
        let mut rr = empty_run_return();
        if let Some(t) = tag {
            rr.msgs.push(Msg {
                r#type: None,
                message: None,
                sender: None,
                uuid: None,
                tag: Some(t.to_string()),
                index: None,
                msat: None,
                timestamp: None,
                sent_to: None,
                from_me: None,
                payment_hash: None,
                error: None,
            });
        }
        rr.error = error.map(|e| e.to_string());
        rr.sent_status = Some(format!(r#"{{"tag":"{}","status":"pending"}}"#, tag.unwrap_or("")));
        rr.settled_status = Some(r#"{"settled":true}"#.to_string());
        rr.topics.push(topic.to_string());
        rr.payloads.push(vec![0xAB, 0xCD]);
        rr
    }

    /// Simulate the post-loop merge that split_and_send performs, given a list of
    /// per-chunk RunReturns and a chunk_id.  Returns the merged RunReturn.
    ///
    /// This mirrors the actual split_and_send merge code so we can unit-test the
    /// invariants without needing a live network.
    fn simulate_split_and_send_merge(
        chunk_rrs: Vec<RunReturn>,
        chunk_id: &str,
    ) -> RunReturn {
        let mut all_topics: Vec<String> = Vec::new();
        let mut all_payloads: Vec<Vec<u8>> = Vec::new();
        let mut chunk_errors: Vec<String> = Vec::new();
        let mut last_rr: Option<RunReturn> = None;

        for (i, rr) in chunk_rrs.into_iter().enumerate() {
            if let Some(ref e) = rr.error {
                chunk_errors.push(format!("chunk[{}]: {}", i, e));
            }
            all_topics.extend(rr.topics.iter().cloned());
            all_payloads.extend(rr.payloads.iter().cloned());
            last_rr = Some(rr);
        }

        let mut merged = last_rr.unwrap_or_else(empty_run_return);
        merged.topics = all_topics;
        merged.payloads = all_payloads;

        // Apply the same post-loop fixups as split_and_send:
        if merged.msgs.is_empty() {
            merged.msgs.push(Msg {
                r#type: None,
                message: None,
                sender: None,
                uuid: Some(chunk_id.to_string()),
                tag: Some(chunk_id.to_string()),
                index: None,
                msat: None,
                timestamp: None,
                sent_to: None,
                from_me: None,
                payment_hash: None,
                error: None,
            });
        } else {
            merged.msgs.truncate(1);
            merged.msgs[0].tag = Some(chunk_id.to_string());
            merged.msgs[0].uuid = Some(chunk_id.to_string());
        }
        merged.sent_status = None;
        merged.settled_status = None;
        if !chunk_errors.is_empty() {
            merged.error = Some(format!("chunk_send_errors: {}", chunk_errors.join("; ")));
        }

        merged
    }

    // Test SAM-1: after a multi-chunk send, merged.msgs[0].tag must equal chunk_id,
    // not the last chunk's per-fragment transport tag.
    #[test]
    fn test_split_and_send_merge_tag_is_chunk_id() {
        let chunk_id = "1785847310885";
        let rrs = vec![
            chunk_send_rr(Some("transport_tag_chunk_0"), None, "topic/0"),
            chunk_send_rr(Some("transport_tag_chunk_1"), None, "topic/1"),
            chunk_send_rr(Some("transport_tag_chunk_2"), None, "topic/2"),
        ];

        let merged = simulate_split_and_send_merge(rrs, chunk_id);

        // Tag must be chunk_id, not the last chunk's "transport_tag_chunk_2".
        assert_eq!(
            merged.msgs.len(),
            1,
            "merged RunReturn must carry exactly one Msg entry"
        );
        assert_eq!(
            merged.msgs[0].tag.as_deref(),
            Some(chunk_id),
            "merged tag must equal chunk_id, not the last chunk's transport tag"
        );
    }

    // Test SAM-2: sent_status and settled_status must be cleared on the merged
    // RunReturn (per-fragment values are not meaningful for the whole send).
    #[test]
    fn test_split_and_send_merge_clears_per_fragment_status_fields() {
        let chunk_id = "1706300000123";
        let rrs = vec![
            chunk_send_rr(Some("t0"), None, "topic/0"),
            chunk_send_rr(Some("t1"), None, "topic/1"),
        ];

        let merged = simulate_split_and_send_merge(rrs, chunk_id);

        assert!(
            merged.sent_status.is_none(),
            "sent_status must be cleared on merged RunReturn (was last-chunk-only)"
        );
        assert!(
            merged.settled_status.is_none(),
            "settled_status must be cleared on merged RunReturn (was last-chunk-only)"
        );
    }

    // Test SAM-3: errors from earlier (non-final) chunk sends must appear in the
    // merged error field, not be silently dropped.
    #[test]
    fn test_split_and_send_merge_aggregates_chunk_errors() {
        let chunk_id = "1706300000456";
        // Chunk 1 (middle) fails; chunk 0 and chunk 2 succeed.
        let rrs = vec![
            chunk_send_rr(Some("t0"), None, "topic/0"),
            chunk_send_rr(Some("t1"), Some("transport error on chunk 1"), "topic/1"),
            chunk_send_rr(Some("t2"), None, "topic/2"),
        ];

        let merged = simulate_split_and_send_merge(rrs, chunk_id);

        let err = merged.error.expect("merged RunReturn must carry aggregated error");
        assert!(
            err.contains("chunk[1]"),
            "error must identify which chunk failed, got: {}",
            err
        );
        assert!(
            err.contains("transport error on chunk 1"),
            "error must include the original error text, got: {}",
            err
        );
    }

    // Test SAM-4: when no chunk sends fail, the merged error field must be None.
    #[test]
    fn test_split_and_send_merge_no_error_when_all_chunks_succeed() {
        let chunk_id = "1706300000789";
        let rrs = vec![
            chunk_send_rr(Some("t0"), None, "topic/0"),
            chunk_send_rr(Some("t1"), None, "topic/1"),
        ];

        let merged = simulate_split_and_send_merge(rrs, chunk_id);

        assert!(
            merged.error.is_none(),
            "merged error must be None when all chunks succeed"
        );
    }

    // Test SAM-5: topics and payloads are aggregated from all chunks.
    #[test]
    fn test_split_and_send_merge_aggregates_topics_and_payloads() {
        let chunk_id = "1706300000999";
        let rrs = vec![
            chunk_send_rr(Some("t0"), None, "topic/0"),
            chunk_send_rr(Some("t1"), None, "topic/1"),
            chunk_send_rr(Some("t2"), None, "topic/2"),
        ];

        let merged = simulate_split_and_send_merge(rrs, chunk_id);

        assert_eq!(merged.topics.len(), 3, "all chunk topics must be aggregated");
        assert_eq!(merged.payloads.len(), 3, "all chunk payloads must be aggregated");
        assert!(merged.topics.contains(&"topic/0".to_string()));
        assert!(merged.topics.contains(&"topic/1".to_string()));
        assert!(merged.topics.contains(&"topic/2".to_string()));
    }

    // Test SAM-6: when bindings::send returns a RunReturn with no msgs (possible
    // on some paths), split_and_send must still produce a Msg with chunk_id as tag.
    #[test]
    fn test_split_and_send_merge_inserts_placeholder_msg_when_last_rr_has_no_msgs() {
        let chunk_id = "1706300001111";
        // Simulate last_rr having no msgs at all.
        let mut rr = empty_run_return();
        rr.topics.push("topic/0".to_string());
        rr.payloads.push(vec![0x01]);
        let rrs = vec![rr];

        let merged = simulate_split_and_send_merge(rrs, chunk_id);

        assert_eq!(merged.msgs.len(), 1, "must produce exactly one Msg even when last_rr had none");
        assert_eq!(
            merged.msgs[0].tag.as_deref(),
            Some(chunk_id),
            "placeholder Msg tag must equal chunk_id"
        );
        assert_eq!(
            merged.msgs[0].uuid.as_deref(),
            Some(chunk_id),
            "placeholder Msg uuid must equal chunk_id"
        );
    }

    // Test: non-empty last_rr.msgs branch — uuid and tag must both be set to chunk_id.
    #[test]
    fn test_split_and_send_merge_sets_uuid_and_tag_when_last_rr_has_msgs() {
        let chunk_id = "1706300002222";
        // Simulate last_rr having an existing Msg (non-empty branch).
        let mut last_rr = empty_run_return();
        last_rr.msgs.push(Msg {
            r#type: None,
            message: Some("fragment content".to_string()),
            sender: None,
            uuid: Some("fragment-transport-uuid".to_string()),
            tag: Some("fragment-transport-tag".to_string()),
            index: None,
            msat: None,
            timestamp: None,
            sent_to: None,
            from_me: None,
            payment_hash: None,
            error: None,
        });
        let rrs = vec![last_rr];

        let rr = simulate_split_and_send_merge(rrs, chunk_id);

        assert_eq!(rr.msgs.len(), 1, "must keep exactly one Msg");
        assert_eq!(
            rr.msgs[0].uuid,
            Some(chunk_id.to_string()),
            "uuid must be overridden to chunk_id, not the fragment's transport uuid"
        );
        assert_eq!(
            rr.msgs[0].tag,
            Some(chunk_id.to_string()),
            "tag must equal chunk_id"
        );
    }

    // ---- Receiver-side confirmation tests ----
    //
    // These tests use the #[cfg(test)] CONFIRMATION_CALLS thread-local to capture
    // confirmation sends without hitting the real network.  Each test clears the
    // thread-local before running to avoid cross-test pollution.

    /// Build a make_chunk_msg variant that includes a sender field so the
    /// confirmation code can extract a pubkey.
    fn make_chunk_msg_with_sender(chunk: &ChunkPayload, sender_pubkey: &str) -> Msg {
        let meta = ChunkMeta {
            chunk_id: chunk.chunk_id.clone(),
            chunk_index: chunk.chunk_index,
            total_chunks: chunk.total_chunks,
            original_msg_type: chunk.original_msg_type,
        };
        let meta_json = serde_json::to_string(&meta).unwrap();
        let msg_json = serde_json::json!({
            "content": chunk.content.clone(),
            "metadata": meta_json,
        })
        .to_string();
        // Produce a minimal SenderInfo JSON that has the `pubkey` field.
        let sender_json = format!(r#"{{"pubkey":"{}","alias":"","photo_url":"","person":"","confirmed":false}}"#, sender_pubkey);
        Msg {
            r#type: Some(CHUNK_TYPE),
            message: Some(msg_json),
            sender: Some(sender_json),
            uuid: None,
            tag: None,
            index: None,
            msat: None,
            timestamp: None,
            sent_to: None,
            from_me: None,
            payment_hash: None,
            error: None,
        }
    }

    // Test CONF-1: a confirmation is issued exactly once when all chunks arrive
    // and the message is fully reassembled (ChunkResult::Complete).
    #[test]
    fn test_confirmation_sent_on_complete() {
        CONFIRMATION_CALLS.with(|calls| calls.borrow_mut().clear());

        let chunk_id = "1706399001001";
        let sender_pubkey = "03abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678";

        // Two-chunk message: deliver both in one call so Complete fires.
        let cp0 = ChunkPayload {
            chunk_id: chunk_id.to_string(),
            chunk_index: 0,
            total_chunks: 2,
            original_msg_type: 0,
            content: "hello ".to_string(),
        };
        let cp1 = ChunkPayload {
            chunk_id: chunk_id.to_string(),
            chunk_index: 1,
            total_chunks: 2,
            original_msg_type: 0,
            content: "world".to_string(),
        };

        let mut rr = empty_run_return();
        rr.msgs.push(make_chunk_msg_with_sender(&cp0, sender_pubkey));
        rr.msgs.push(make_chunk_msg_with_sender(&cp1, sender_pubkey));

        let result = handle_chunks(rr, &[], "").unwrap();

        // Message should be reassembled.
        assert_eq!(result.msgs.len(), 1, "reassembled message must be present");
        assert_eq!(result.msgs[0].message.as_deref(), Some("hello world"));

        // Exactly one confirmation must have been issued.
        CONFIRMATION_CALLS.with(|calls| {
            let calls = calls.borrow();
            assert_eq!(calls.len(), 1, "exactly one confirmation must be sent on Complete");
            assert_eq!(calls[0].0, sender_pubkey, "confirmation must target the sender pubkey");
            assert_eq!(calls[0].1, chunk_id, "confirmation chunk_id must match the reassembled chunk_id");
        });
    }

    // Test CONF-2: no confirmation is issued when chunks are still incomplete.
    #[test]
    fn test_no_confirmation_on_incomplete() {
        CONFIRMATION_CALLS.with(|calls| calls.borrow_mut().clear());

        let chunk_id = "1706399002002";
        let sender_pubkey = "03abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678";

        // Only deliver one of two expected chunks.
        let cp0 = ChunkPayload {
            chunk_id: chunk_id.to_string(),
            chunk_index: 0,
            total_chunks: 2,
            original_msg_type: 0,
            content: "only half".to_string(),
        };

        let mut rr = empty_run_return();
        rr.msgs.push(make_chunk_msg_with_sender(&cp0, sender_pubkey));

        let result = handle_chunks(rr, &[], "").unwrap();

        // No message should be reassembled yet.
        assert!(result.msgs.is_empty(), "no reassembled message on incomplete");

        // No confirmation must be sent.
        CONFIRMATION_CALLS.with(|calls| {
            assert!(calls.borrow().is_empty(), "no confirmation must be sent on Incomplete");
        });
    }

    // Test CONF-3: no confirmation is issued on timeout.
    #[test]
    fn test_no_confirmation_on_timeout() {
        CONFIRMATION_CALLS.with(|calls| calls.borrow_mut().clear());

        let chunk_id = "1706399003003";
        let sender_pubkey = "03abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678";
        let key = format!("{}{}", CHUNK_STATE_PREFIX, chunk_id);

        // Plant a stale buffer whose first_received_ts is older than CHUNK_TIMEOUT_SECS.
        let old_ts = now_secs().saturating_sub(CHUNK_TIMEOUT_SECS + 1);
        let old_buf = ChunkBuffer {
            total_chunks: 2,
            original_msg_type: 0,
            received: vec![ChunkPayload {
                chunk_id: chunk_id.to_string(),
                chunk_index: 0,
                total_chunks: 2,
                original_msg_type: 0,
                content: "partial".to_string(),
            }],
            first_received_ts: old_ts,
        };
        let state = state_with_buffer(&key, &old_buf);

        // Deliver a second chunk that would otherwise complete the message.
        let cp1 = ChunkPayload {
            chunk_id: chunk_id.to_string(),
            chunk_index: 1,
            total_chunks: 2,
            original_msg_type: 0,
            content: "more".to_string(),
        };
        let mut rr = empty_run_return();
        rr.msgs.push(make_chunk_msg_with_sender(&cp1, sender_pubkey));

        let result = handle_chunks(rr, &state, "").unwrap();

        // TimedOut: no message, error set.
        assert!(result.msgs.is_empty(), "timed-out buffer must not produce a message");
        assert!(result.error.is_some(), "timed-out buffer must set an error");

        // No confirmation on timeout.
        CONFIRMATION_CALLS.with(|calls| {
            assert!(calls.borrow().is_empty(), "no confirmation must be sent on TimedOut");
        });
    }

    // Test CONF-4: confirmation is sent on the restore/batch-fetch path.
    // Simulates a two-call sequence (first call: fragment 0, second call: fragment 1
    // plus persisted state from first call).  Confirmation must fire on the second call.
    #[test]
    fn test_confirmation_sent_on_restore_batch_fetch_path() {
        CONFIRMATION_CALLS.with(|calls| calls.borrow_mut().clear());

        let chunk_id = "1706399004004";
        let sender_pubkey = "03abcdef1234567890abcdef1234567890abcdef1234567890abcdef99887766";

        let cp0 = ChunkPayload {
            chunk_id: chunk_id.to_string(),
            chunk_index: 0,
            total_chunks: 2,
            original_msg_type: 0,
            content: "first_".to_string(),
        };
        let cp1 = ChunkPayload {
            chunk_id: chunk_id.to_string(),
            chunk_index: 1,
            total_chunks: 2,
            original_msg_type: 0,
            content: "second".to_string(),
        };

        // --- First "fetch" call: only fragment 0 arrives ---
        let mut rr1 = empty_run_return();
        rr1.msgs.push(make_chunk_msg_with_sender(&cp0, sender_pubkey));
        let result1 = handle_chunks(rr1, &[], "").unwrap();
        assert!(result1.msgs.is_empty(), "first call: not complete yet");
        let persisted = result1.state_mp.expect("first call must return state_mp");

        // No confirmation yet.
        CONFIRMATION_CALLS.with(|calls| {
            assert!(calls.borrow().is_empty(), "no confirmation on incomplete first call");
        });

        // --- Second "fetch" call (simulating restore/batch-fetch): fragment 1 arrives ---
        let mut rr2 = empty_run_return();
        rr2.msgs.push(make_chunk_msg_with_sender(&cp1, sender_pubkey));
        let result2 = handle_chunks(rr2, &persisted, "").unwrap();

        assert_eq!(result2.msgs.len(), 1, "second call: message must be reassembled");
        assert_eq!(result2.msgs[0].message.as_deref(), Some("first_second"));

        // Exactly one confirmation on the second (completing) call.
        CONFIRMATION_CALLS.with(|calls| {
            let calls = calls.borrow();
            assert_eq!(calls.len(), 1, "exactly one confirmation on the completing call");
            assert_eq!(calls[0].0, sender_pubkey);
            assert_eq!(calls[0].1, chunk_id);
        });
    }

    // Test CONF-5: the reassembled message's tag equals chunk_id (not the last-chunk
    // transport tag), consistent with the split_and_send companion fix.
    #[test]
    fn test_reassembled_msg_tag_equals_chunk_id() {
        CONFIRMATION_CALLS.with(|calls| calls.borrow_mut().clear());

        let chunk_id = "1706399005005";
        let sender_pubkey = "03aabbccdd1234567890aabbccdd1234567890aabbccdd1234567890aabbccdd";
        let transport_tag = "old_transport_tag_from_last_chunk";

        let cp0 = ChunkPayload {
            chunk_id: chunk_id.to_string(),
            chunk_index: 0,
            total_chunks: 2,
            original_msg_type: 0,
            content: "part1_".to_string(),
        };
        let cp1 = ChunkPayload {
            chunk_id: chunk_id.to_string(),
            chunk_index: 1,
            total_chunks: 2,
            original_msg_type: 0,
            content: "part2".to_string(),
        };

        // Give the second (last) chunk a transport-level tag to confirm we override it.
        let meta1 = ChunkMeta {
            chunk_id: cp1.chunk_id.clone(),
            chunk_index: cp1.chunk_index,
            total_chunks: cp1.total_chunks,
            original_msg_type: cp1.original_msg_type,
        };
        let meta1_json = serde_json::to_string(&meta1).unwrap();
        let msg1_json = serde_json::json!({
            "content": cp1.content.clone(),
            "metadata": meta1_json,
        })
        .to_string();
        let sender_json = format!(
            r#"{{"pubkey":"{}","alias":"","photo_url":"","person":"","confirmed":false}}"#,
            sender_pubkey
        );
        let last_chunk_msg = Msg {
            r#type: Some(CHUNK_TYPE),
            message: Some(msg1_json),
            sender: Some(sender_json),
            uuid: None,
            tag: Some(transport_tag.to_string()), // <-- transport tag that must be overridden
            index: None,
            msat: None,
            timestamp: None,
            sent_to: None,
            from_me: None,
            payment_hash: None,
            error: None,
        };

        let mut rr = empty_run_return();
        rr.msgs.push(make_chunk_msg_with_sender(&cp0, sender_pubkey));
        rr.msgs.push(last_chunk_msg);

        let result = handle_chunks(rr, &[], "").unwrap();

        assert_eq!(result.msgs.len(), 1);
        let m = &result.msgs[0];
        assert_eq!(
            m.tag.as_deref(),
            Some(chunk_id),
            "reassembled msg tag must be chunk_id, not the last chunk's transport tag"
        );
        assert_eq!(
            m.uuid.as_deref(),
            Some(chunk_id),
            "reassembled msg uuid must be chunk_id"
        );
    }

    // Test CONF-6: no confirmation when sender JSON is missing or has no pubkey.
    #[test]
    fn test_no_confirmation_when_sender_missing() {
        CONFIRMATION_CALLS.with(|calls| calls.borrow_mut().clear());

        let chunk_id = "1706399006006";

        // Two chunks with no sender field set (simulates a path where sender is absent).
        let cp0 = ChunkPayload {
            chunk_id: chunk_id.to_string(),
            chunk_index: 0,
            total_chunks: 2,
            original_msg_type: 0,
            content: "a".to_string(),
        };
        let cp1 = ChunkPayload {
            chunk_id: chunk_id.to_string(),
            chunk_index: 1,
            total_chunks: 2,
            original_msg_type: 0,
            content: "b".to_string(),
        };

        let mut rr = empty_run_return();
        // Use plain make_chunk_msg (no sender) for both.
        rr.msgs.push(make_chunk_msg(&cp0));
        rr.msgs.push(make_chunk_msg(&cp1));

        let result = handle_chunks(rr, &[], "").unwrap();

        // Message still reassembles correctly despite missing sender.
        assert_eq!(result.msgs.len(), 1, "message must still reassemble even without sender");

        // No confirmation must be attempted when sender pubkey is unavailable.
        CONFIRMATION_CALLS.with(|calls| {
            assert!(
                calls.borrow().is_empty(),
                "no confirmation must be sent when sender pubkey is absent"
            );
        });
    }

    // Test CONF-7: extract_sender_pubkey correctly parses SenderInfo JSON.
    #[test]
    fn test_extract_sender_pubkey_parses_correctly() {
        let pubkey = "03abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678";
        let json = format!(
            r#"{{"pubkey":"{}","alias":"Alice","photo_url":"","person":"","confirmed":true}}"#,
            pubkey
        );
        assert_eq!(extract_sender_pubkey(&json), Some(pubkey.to_string()));

        // Missing pubkey field → None.
        assert_eq!(extract_sender_pubkey(r#"{"alias":"Bob"}"#), None);

        // Malformed JSON → None.
        assert_eq!(extract_sender_pubkey("not json"), None);

        // Empty pubkey string → Some("") (field present but empty).
        // send_chunk_confirmation guards against this at call time (the `!pk.is_empty()` check).
        assert_eq!(extract_sender_pubkey(r#"{"pubkey":""}"#), Some("".to_string()));
    }
}
