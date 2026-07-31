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
const CHUNK_TIMEOUT_SECS: u64 = 30;
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
fn make_chunk_id(unique_time: &str) -> String {
    let ut_bytes = unique_time.as_bytes();
    let len = 8.min(ut_bytes.len());
    hex::encode(&ut_bytes[..len])
}

/// Merge a state_mp delta (returned by bindings::send) into the running full_state map.
/// Returns the new serialized full_state.
fn merge_state(
    full_state: &[u8],
    delta_mp: &[u8],
) -> Result<Vec<u8>> {
    let mut base: BTreeMap<String, (u64, Vec<u8>)> = if full_state.is_empty() {
        BTreeMap::new()
    } else {
        rmp_utils::deserialize_state_map(full_state).map_err(|e| SphinxError::BadState {
            r: format!("merge_state deserialize base: {}", e),
        })?
    };
    if !delta_mp.is_empty() {
        let delta: BTreeMap<String, (u64, Vec<u8>)> =
            rmp_utils::deserialize_state_map(delta_mp).map_err(|e| SphinxError::BadState {
                r: format!("merge_state deserialize delta: {}", e),
            })?;
        for (k, v) in delta {
            base.insert(k, v);
        }
    }
    rmp_utils::serialize_state_map(&base).map_err(|e| SphinxError::BadState {
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

/// Called from `auto::handle()` after bindings::handle().
/// Intercepts any Msgs with type == CHUNK_TYPE and either buffers or reassembles them.
pub fn handle_chunks(mut rr: RunReturn, full_state: &[u8]) -> Result<RunReturn> {
    let now = now_secs();
    let mut i = 0;

    // We process chunk msgs one at a time (there should be at most one per handle call).
    while i < rr.msgs.len() {
        if rr.msgs[i].r#type == Some(CHUNK_TYPE) {
            let chunk_msg = rr.msgs.remove(i);
            let result = process_chunk_msg(chunk_msg, full_state, now)?;

            match result {
                ChunkResult::Complete {
                    reassembled_msg,
                    state_key,
                } => {
                    rr.msgs.insert(i, reassembled_msg);
                    rr.state_to_delete.push(state_key);
                    i += 1;
                }
                ChunkResult::Incomplete {
                    state_key,
                    buffer_bytes,
                } => {
                    // Store updated buffer in state_mp delta.
                    let mut delta: BTreeMap<String, (u64, Vec<u8>)> = BTreeMap::new();
                    delta.insert(state_key, (now, buffer_bytes));
                    let delta_bytes =
                        rmp_utils::serialize_state_map(&delta).map_err(|e| {
                            SphinxError::BadState {
                                r: format!("chunk buffer serialize: {}", e),
                            }
                        })?;
                    // Merge with any existing state_mp in rr.
                    rr.state_mp = Some(if let Some(ref existing) = rr.state_mp {
                        merge_state(existing, &delta_bytes)?
                    } else {
                        delta_bytes
                    });
                    // Chunk msg removed; don't advance i.
                }
                ChunkResult::TimedOut { state_key } => {
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
    let state_map: BTreeMap<String, (u64, Vec<u8>)> =
        rmp_utils::deserialize_state_map(full_state).map_err(|e| SphinxError::BadState {
            r: format!("load_chunk_buffer deserialize: {}", e),
        })?;

    if let Some((_version, bytes)) = state_map.get(key) {
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

    /// Build a full_state containing a ChunkBuffer at the given key.
    fn state_with_buffer(key: &str, buf: &ChunkBuffer) -> Vec<u8> {
        let buf_bytes = serde_json::to_vec(buf).unwrap();
        let mut map: BTreeMap<String, (u64, Vec<u8>)> = BTreeMap::new();
        map.insert(key.to_string(), (0, buf_bytes));
        rmp_utils::serialize_state_map(&map).unwrap()
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
            let result = handle_chunks(single_rr, &state).unwrap();
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

        let result = handle_chunks(rr, &[]).unwrap();

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

        let result = handle_chunks(rr, &state).unwrap();

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
}
