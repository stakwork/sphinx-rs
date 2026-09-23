use crate::{Result, SphinxError};
use serde::Deserialize;

/// Default mixer heartbeat interval (30s). Callers should re-evaluate
/// staleness on this cadence while MQTT stays connected.
pub const SERVER_STATUS_HEARTBEAT_INTERVAL_MS: u64 = 30_000;

/// Missed-interval threshold N = 3 (~90s) before a silent heartbeat
/// is treated as [`ServerHealth::Unknown`].
pub const SERVER_STATUS_MAX_MISSED_INTERVALS: u32 = 3;

/// Small allowance for clock skew between the payload's `ts` and local `now_ms`.
/// A payload timestamp up to this far in the future of the local clock is still
/// treated as valid (not `Unknown`) - normal NTP drift/network jitter between the
/// mixer's clock and the device's clock, not a sign of a bad/retained sample.
pub const SERVER_STATUS_CLOCK_SKEW_TOLERANCE_MS: u64 = 5_000;

/// MQTT topic for mixer server-health heartbeats.
///
/// Follows the same convention as the global retained `blockheight` topic in
/// `sphinx/src/topics.rs` (single global topic, not per-root). Update this
/// constant in one place if the mixer contract finalizes a different name.
const SERVER_STATUS_TOPIC: &str = "health";

const CODE_CLN_UNAVAILABLE: &str = "CLN_UNAVAILABLE";
const CODE_CLN_TIMEOUT: &str = "CLN_TIMEOUT";
const CODE_INSUFFICIENT_BALANCE: &str = "INSUFFICIENT_BALANCE";

/// Mixer status payload `{ cln_ok, degraded, reason, ts }`.
///
/// `ts` is milliseconds since epoch (same unit as `now_ms` / `last_seen_ms`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ServerStatus {
    pub cln_ok: bool,
    pub degraded: bool,
    #[serde(default)]
    pub reason: Option<String>,
    pub ts: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerHealth {
    Ok,
    Degraded,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MixerErrorCode {
    ClnUnavailable,
    ClnTimeout,
    InsufficientBalance,
    Unknown,
}

/// Parse a mixer status JSON payload.
///
/// Invalid / malformed JSON throws [`SphinxError`]. Callers map that error
/// to [`ServerHealth::Unknown`]; this function does not coerce to a health enum.
pub fn parse_server_status(payload: String) -> Result<ServerStatus> {
    serde_json::from_str(&payload).map_err(|e| SphinxError::BadMsg {
        r: format!("invalid server status JSON: {}", e),
    })
}

/// Evaluate current server health from the last parsed sample and local receipt time.
///
/// `last_seen_ms` is **local receipt time only** — never the payload `ts`.
/// Payload `ts` is a freshness gate so a stale retained last-good cannot flash Ok.
pub fn evaluate_server_health(
    last: Option<ServerStatus>,
    last_seen_ms: u64,
    now_ms: u64,
    interval_ms: u64,
    max_missed: u32,
) -> ServerHealth {
    let last = match last {
        Some(status) => status,
        None => return ServerHealth::Unknown,
    };

    let threshold_ms = interval_ms.saturating_mul(max_missed as u64);
    let local_age_ms = now_ms.saturating_sub(last_seen_ms);
    if local_age_ms > threshold_ms {
        return ServerHealth::Unknown;
    }

    // Payload `ts` is metadata / freshness only. Future or unusable timestamps,
    // and retained samples older than N intervals, must not extend Ok.
    if last.ts == 0 || last.ts > now_ms.saturating_add(SERVER_STATUS_CLOCK_SKEW_TOLERANCE_MS) {
        return ServerHealth::Unknown;
    }
    let payload_age_ms = now_ms.saturating_sub(last.ts);
    if payload_age_ms > threshold_ms {
        return ServerHealth::Unknown;
    }

    if last.degraded || !last.cln_ok {
        ServerHealth::Degraded
    } else {
        ServerHealth::Ok
    }
}

/// Parse a mixer Failed `code` from a JSON object (`{"code":"..."}`) or a bare string.
/// Unrecognized input maps to [`MixerErrorCode::Unknown`] and never throws.
pub fn parse_mixer_error_code(raw: String) -> MixerErrorCode {
    let trimmed = raw.trim();
    let code = match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(serde_json::Value::Object(map)) => map
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        Ok(serde_json::Value::String(s)) => s,
        _ => trimmed.to_string(),
    };
    match code.as_str() {
        CODE_CLN_UNAVAILABLE => MixerErrorCode::ClnUnavailable,
        CODE_CLN_TIMEOUT => MixerErrorCode::ClnTimeout,
        CODE_INSUFFICIENT_BALANCE => MixerErrorCode::InsufficientBalance,
        _ => MixerErrorCode::Unknown,
    }
}

/// Single global retained mixer status topic (same family as `blockheight`).
pub fn server_status_topic() -> String {
    SERVER_STATUS_TOPIC.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy(ts: u64) -> ServerStatus {
        ServerStatus {
            cln_ok: true,
            degraded: false,
            reason: None,
            ts,
        }
    }

    fn degraded_status(ts: u64, reason: &str) -> ServerStatus {
        ServerStatus {
            cln_ok: false,
            degraded: true,
            reason: Some(reason.to_string()),
            ts,
        }
    }

    #[test]
    fn parse_server_status_happy_path() {
        let payload = r#"{"cln_ok":true,"degraded":false,"reason":null,"ts":1700000000000}"#;
        let status = parse_server_status(payload.to_string()).expect("valid status");
        assert!(status.cln_ok);
        assert!(!status.degraded);
        assert_eq!(status.reason, None);
        assert_eq!(status.ts, 1_700_000_000_000);
    }

    #[test]
    fn parse_server_status_degraded_payload() {
        let payload =
            r#"{"cln_ok":false,"degraded":true,"reason":"cln disconnected","ts":1700000000000}"#;
        let status = parse_server_status(payload.to_string()).expect("valid degraded status");
        assert!(!status.cln_ok);
        assert!(status.degraded);
        assert_eq!(status.reason.as_deref(), Some("cln disconnected"));
        assert_eq!(status.ts, 1_700_000_000_000);
    }

    #[test]
    fn parse_server_status_malformed_json_throws() {
        assert!(parse_server_status("not json".to_string()).is_err());
        assert!(parse_server_status("".to_string()).is_err());
        assert!(parse_server_status("{".to_string()).is_err());
        assert!(parse_server_status(r#"{"cln_ok":true}"#.to_string()).is_err());
    }

    #[test]
    fn evaluate_fresh_healthy_sample_is_ok() {
        let now = 1_700_000_090_000;
        let ts = now;
        let health = evaluate_server_health(
            Some(healthy(ts)),
            now,
            now,
            SERVER_STATUS_HEARTBEAT_INTERVAL_MS,
            SERVER_STATUS_MAX_MISSED_INTERVALS,
        );
        assert_eq!(health, ServerHealth::Ok);
    }

    #[test]
    fn evaluate_degraded_when_cln_not_ok_or_degraded_flag() {
        let now = 1_700_000_090_000;
        let interval = SERVER_STATUS_HEARTBEAT_INTERVAL_MS;
        let n = SERVER_STATUS_MAX_MISSED_INTERVALS;

        let from_flags = evaluate_server_health(
            Some(degraded_status(now, "cln down")),
            now,
            now,
            interval,
            n,
        );
        assert_eq!(from_flags, ServerHealth::Degraded);

        let cln_only = ServerStatus {
            cln_ok: false,
            degraded: false,
            reason: None,
            ts: now,
        };
        assert_eq!(
            evaluate_server_health(Some(cln_only), now, now, interval, n),
            ServerHealth::Degraded
        );

        let degraded_only = ServerStatus {
            cln_ok: true,
            degraded: true,
            reason: Some("partial".into()),
            ts: now,
        };
        assert_eq!(
            evaluate_server_health(Some(degraded_only), now, now, interval, n),
            ServerHealth::Degraded
        );
    }

    #[test]
    fn evaluate_staleness_boundary_n_minus_one_vs_n() {
        let interval = SERVER_STATUS_HEARTBEAT_INTERVAL_MS;
        let n = SERVER_STATUS_MAX_MISSED_INTERVALS;
        let now = 1_700_000_090_000;
        let ts = now - interval; // payload still fresh

        // N-1 missed intervals: still trusts the last sample.
        let age_n_minus_1 = interval.saturating_mul((n - 1) as u64);
        let health_n_minus_1 = evaluate_server_health(
            Some(healthy(ts)),
            now - age_n_minus_1,
            now,
            interval,
            n,
        );
        assert_eq!(health_n_minus_1, ServerHealth::Ok);

        // Age strictly greater than interval * N → Unknown.
        let age_past_n = interval.saturating_mul(n as u64) + 1;
        let health_past_n = evaluate_server_health(
            Some(healthy(ts)),
            now - age_past_n,
            now,
            interval,
            n,
        );
        assert_eq!(health_past_n, ServerHealth::Unknown);

        // Degraded content is still trusted at N-1.
        let degraded_n_minus_1 = evaluate_server_health(
            Some(degraded_status(ts, "cln down")),
            now - age_n_minus_1,
            now,
            interval,
            n,
        );
        assert_eq!(degraded_n_minus_1, ServerHealth::Degraded);
    }

    #[test]
    fn evaluate_no_prior_sample_is_unknown() {
        let health = evaluate_server_health(
            None,
            0,
            1_700_000_090_000,
            SERVER_STATUS_HEARTBEAT_INTERVAL_MS,
            SERVER_STATUS_MAX_MISSED_INTERVALS,
        );
        assert_eq!(health, ServerHealth::Unknown);
    }

    #[test]
    fn evaluate_stale_retained_ts_on_first_receipt_is_unknown() {
        let interval = SERVER_STATUS_HEARTBEAT_INTERVAL_MS;
        let n = SERVER_STATUS_MAX_MISSED_INTERVALS;
        let now = 1_700_000_090_000;
        // Just received (local last_seen is now) but payload ts is far in the past.
        let stale_ts = now - (interval.saturating_mul(n as u64) + 1);
        let health = evaluate_server_health(Some(healthy(stale_ts)), now, now, interval, n);
        assert_eq!(health, ServerHealth::Unknown);
    }

    #[test]
    fn evaluate_future_ts_within_clock_skew_tolerance_is_ok() {
        let interval = SERVER_STATUS_HEARTBEAT_INTERVAL_MS;
        let n = SERVER_STATUS_MAX_MISSED_INTERVALS;
        let now = 1_700_000_090_000;

        // Slightly in the future: within tolerance, should not be Unknown.
        let just_future = evaluate_server_health(Some(healthy(now + 1)), now, now, interval, n);
        assert_eq!(just_future, ServerHealth::Ok);

        // Exactly at the tolerance boundary: still within tolerance.
        let at_boundary = evaluate_server_health(
            Some(healthy(now + SERVER_STATUS_CLOCK_SKEW_TOLERANCE_MS)),
            now,
            now,
            interval,
            n,
        );
        assert_eq!(at_boundary, ServerHealth::Ok);
    }

    #[test]
    fn evaluate_future_ts_beyond_clock_skew_tolerance_is_unknown() {
        let interval = SERVER_STATUS_HEARTBEAT_INTERVAL_MS;
        let n = SERVER_STATUS_MAX_MISSED_INTERVALS;
        let now = 1_700_000_090_000;

        let beyond_tolerance = evaluate_server_health(
            Some(healthy(now + SERVER_STATUS_CLOCK_SKEW_TOLERANCE_MS + 1)),
            now,
            now,
            interval,
            n,
        );
        assert_eq!(beyond_tolerance, ServerHealth::Unknown);
    }

    #[test]
    fn evaluate_unusable_zero_ts_is_unknown() {
        let interval = SERVER_STATUS_HEARTBEAT_INTERVAL_MS;
        let n = SERVER_STATUS_MAX_MISSED_INTERVALS;
        let now = 1_700_000_090_000;

        let unusable = evaluate_server_health(Some(healthy(0)), now, now, interval, n);
        assert_eq!(unusable, ServerHealth::Unknown);
    }

    #[test]
    fn evaluate_future_ts_beyond_tolerance_does_not_slip_through_staleness_window() {
        // Even though the payload age (now - ts) would look "fresh" under the
        // staleness window, a ts far enough in the future must still be rejected
        // as Unknown - the clock-skew tolerance is a bounded window, not an
        // unbounded allowance that could be exploited by a wildly-future ts.
        let interval = SERVER_STATUS_HEARTBEAT_INTERVAL_MS;
        let n = SERVER_STATUS_MAX_MISSED_INTERVALS;
        let now = 1_700_000_090_000;

        let far_future_ts = now + SERVER_STATUS_CLOCK_SKEW_TOLERANCE_MS + 1;
        let health = evaluate_server_health(Some(healthy(far_future_ts)), now, now, interval, n);
        assert_eq!(health, ServerHealth::Unknown);
    }

    #[test]
    fn evaluate_recovers_to_ok_after_degraded_or_unknown() {
        let interval = SERVER_STATUS_HEARTBEAT_INTERVAL_MS;
        let n = SERVER_STATUS_MAX_MISSED_INTERVALS;
        let t0 = 1_700_000_000_000;

        let degraded = evaluate_server_health(
            Some(degraded_status(t0, "cln down")),
            t0,
            t0,
            interval,
            n,
        );
        assert_eq!(degraded, ServerHealth::Degraded);

        let unknown = evaluate_server_health(
            Some(healthy(t0)),
            t0,
            t0 + interval.saturating_mul(n as u64) + 1,
            interval,
            n,
        );
        assert_eq!(unknown, ServerHealth::Unknown);

        let recovered_at = t0 + interval.saturating_mul(n as u64) + 2;
        let recovered = evaluate_server_health(
            Some(healthy(recovered_at)),
            recovered_at,
            recovered_at,
            interval,
            n,
        );
        assert_eq!(recovered, ServerHealth::Ok);
    }

    #[test]
    fn parse_mixer_error_code_known_from_json_and_bare_string() {
        let cases = [
            (CODE_CLN_UNAVAILABLE, MixerErrorCode::ClnUnavailable),
            (CODE_CLN_TIMEOUT, MixerErrorCode::ClnTimeout),
            (CODE_INSUFFICIENT_BALANCE, MixerErrorCode::InsufficientBalance),
        ];
        for (code, expected) in cases {
            assert_eq!(parse_mixer_error_code(code.to_string()), expected);
            let json = format!(r#"{{"code":"{}"}}"#, code);
            assert_eq!(parse_mixer_error_code(json), expected);
            let quoted = format!("\"{}\"", code);
            assert_eq!(parse_mixer_error_code(quoted), expected);
        }
    }

    #[test]
    fn parse_mixer_error_code_unrecognized_is_unknown() {
        assert_eq!(
            parse_mixer_error_code("UNKNOWN".to_string()),
            MixerErrorCode::Unknown
        );
        assert_eq!(
            parse_mixer_error_code(r#"{"code":"UNKNOWN"}"#.to_string()),
            MixerErrorCode::Unknown
        );
        assert_eq!(
            parse_mixer_error_code("not-a-code".to_string()),
            MixerErrorCode::Unknown
        );
        assert_eq!(
            parse_mixer_error_code("{".to_string()),
            MixerErrorCode::Unknown
        );
        assert_eq!(
            parse_mixer_error_code("".to_string()),
            MixerErrorCode::Unknown
        );
        assert_eq!(
            parse_mixer_error_code(r#"{"code":123}"#.to_string()),
            MixerErrorCode::Unknown
        );
    }

    #[test]
    fn server_status_topic_is_single_global_constant() {
        assert_eq!(server_status_topic(), "health");
        assert_eq!(SERVER_STATUS_MAX_MISSED_INTERVALS, 3);
        assert_eq!(SERVER_STATUS_HEARTBEAT_INTERVAL_MS, 30_000);
    }
}
