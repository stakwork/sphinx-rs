use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ControlMessage {
    Nonce,
    ResetWifi,
    ResetKeys,
    ResetAll,
    QueryPolicy,
    UpdatePolicy(Policy),
    QueryAllowlist,
    UpdateAllowlist(Vec<String>),
    QueryVelocity,
    Ota(OtaParams),
    QueryAll,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct All {
    pub policy: Policy,
    pub allowlist: Vec<String>,
    pub velocity: Option<Velocity>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ControlResponse {
    Nonce(u64),
    ResetWifi,
    ResetKeys,
    ResetAll,
    PolicyCurrent(Policy),
    PolicyUpdated(Policy),
    AllowlistCurrent(Vec<String>),
    AllowlistUpdated(Vec<String>),
    VelocityCurrent(Option<Velocity>),
    OtaConfirm(OtaParams),
    AllCurrent(All),
    Error(String),
}

#[derive(Clone, Debug, Deserialize, Serialize, Default, PartialEq)]
pub struct Config {
    pub broker: String,
    pub ssid: String,
    pub pass: String,
    pub network: String,
}

pub type Velocity = (u64, Vec<u64>);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Policy {
    pub msat_per_interval: u64,
    pub interval: Interval,
    pub htlc_limit_msat: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            msat_per_interval: 21_000_000_000,
            interval: Interval::Daily,
            htlc_limit_msat: 1_000_000_000,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OtaParams {
    pub version: u64,
    pub url: String,
    // sha256 hash as integrity check of binary file
    pub sha256_hash: String,
    // A base64 encoded bitcoin::sign_message::MessageSignature on the sha256_hash string
    // Should satisfy bitcoin::sign_message::is_signed_by_address
    // Get the message hash from bitcoin::sign_message::signed_msg_hash
    pub message_sig: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct WifiParams {
    pub ssid: String,
    pub password: String,
}
