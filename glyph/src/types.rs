use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ControlMessage {
    Nonce,
    ResetWifi,
    ResetKeys,
    ResetAll,
    QueryPolicy,
    UpdatePolicy(Policy),
    QueryAllowlist,
    UpdateAllowlist(Vec<String>),
    Ota(OtaParams),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ControlResponse {
    Nonce(u64),
    ResetWifi,
    ResetKeys,
    ResetAll,
    PolicyCurrent(Policy),
    PolicyUpdated(Policy),
    AllowlistCurrent(Vec<String>),
    AllowlistUpdated(Vec<String>),
    OtaConfirm(OtaParams),
    Error(String),
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct Config {
    pub broker: String,
    pub ssid: String,
    pub pass: String,
    pub network: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Policy {
    pub sat_limit: u64,
    pub interval: Interval,
    pub htlc_limit: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            sat_limit: 1_000_000,
            interval: Interval::Daily,
            htlc_limit: 1_000_000,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum Interval {
    Hourly,
    Daily,
}

impl FromStr for Interval {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "daily" => Ok(Interval::Daily),
            "hourly" => Ok(Interval::Hourly),
            _ => Err("invalid interval".to_string()),
        }
    }
}
impl Interval {
    pub fn as_str(&self) -> &'static str {
        match self {
            Interval::Hourly => "hourly",
            Interval::Daily => "daily",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OtaParams {
    pub version: u64,
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WifiParams {
    pub ssid: String,
    pub password: String,
}
