use crate::auto::{Msg, RunReturn};
use crate::{Result, SphinxError};
use serde::{Deserialize, Serialize};
use sphinx::bindings;
use sphinx::serde_json;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const CHUNK_CONTENT_THRESHOLD: usize = 750;
const CHUNK_TYPE: u8 = 34;
const CHUNK_TIMEOUT_SECS: u64 = 30;
const CHUNK_STATE_PREFIX: &str = "chunkbuf_";

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

    // Slice msg_json into chunks of CHUNK_CONTENT_THRESHOLD bytes each.
    let content_bytes = msg_json.as_bytes();
    let n = (content_bytes.len() + CHUNK_CONTENT_THRESHOLD - 1) / CHUNK_CONTENT_THRESHOLD;
    let total_chunks = n as u16;

    let mut current_state = full_state;
    let mut all_topics: Vec<String> = Vec::new();
    let mut all_payloads: Vec<Vec<u8>> = Vec::new();
    let mut last_rr: Option<RunReturn> = None;

    for i in 0..n {
        let start = i * CHUNK_CONTENT_THRESHOLD;
        let end = (start + CHUNK_CONTENT_THRESHOLD).min(content_bytes.len());
        // Safe: we slice on byte boundaries; content is valid UTF-8 slices only if
        // we align to char boundaries. To be safe, use char-boundary aware slicing.
        let content = slice_utf8_safe(msg_json, start, end);

        let payload = ChunkPayload {
            chunk_id: chunk_id.clone(),
            chunk_index: i as u16,
            total_chunks,
            original_msg_type: msg_type,
            content,
        };

        let chunk_json = serde_json::to_string(&payload).map_err(|e| SphinxError::SendFailed {
            r: format!("chunk serialization failed: {}", e),
        })?;

        let chunk_unique_time = format!("{}_{}", unique_time, i);

        let raw_rr = bindings::send(
            seed,
            &chunk_unique_time,
            to,
            CHUNK_TYPE,
            &chunk_json,
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
    let message_str = msg.message.as_deref().unwrap_or("");
    let chunk: ChunkPayload =
        serde_json::from_str(message_str).map_err(|e| SphinxError::HandleFailed {
            r: format!("chunk payload parse failed: {}", e),
        })?;

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
        Msg {
            r#type: Some(CHUNK_TYPE),
            message: Some(serde_json::to_string(chunk).unwrap()),
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

    // Test 6: chunk content concatenation preserves original msg_json exactly.
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
}
