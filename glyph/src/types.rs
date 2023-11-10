use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::default::Default;
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
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct WifiParams {
    pub ssid: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum SignerType {
    ReceiveOnly,
    ReceiveSend,
}

impl SignerType {
    pub fn to_byte(&self) -> u8 {
        match self {
            SignerType::ReceiveOnly => 0x5a,
            SignerType::ReceiveSend => 0x8c,
        }
    }
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x5a => Ok(SignerType::ReceiveOnly),
            0x8c => Ok(SignerType::ReceiveSend),
            _ => Err(anyhow!("SignerType byte incorrect: {:x}", b)),
        }
    }
}

impl Default for SignerType {
    fn default() -> Self {
        SignerType::ReceiveSend
    }
}
