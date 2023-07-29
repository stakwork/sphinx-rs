use crate::Result;
use sphinx_ffi as cy;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(getter_with_clone)]
pub struct VlsResponse {
    pub topic: String,
    pub bytes: Vec<u8>,
    pub sequence: u16,
    pub cmd: String,
    pub state: Vec<u8>,
}

impl From<cy::VlsResponse> for VlsResponse {
    fn from(vr: cy::VlsResponse) -> Self {
        VlsResponse {
            topic: vr.topic,
            bytes: vr.bytes,
            sequence: vr.sequence,
            cmd: vr.cmd,
            state: vr.state,
        }
    }
}

#[wasm_bindgen]
pub fn run_init_1(args: &str, state: &[u8], msg1: &[u8], seq: Option<u16>) -> Result<VlsResponse> {
    Ok(cy::run_init_1(args.to_string(), state.to_vec(), msg1.to_vec(), seq)?.into())
}

#[wasm_bindgen]
pub fn run_init_2(args: &str, state: &[u8], msg2: &[u8], seq: Option<u16>) -> Result<VlsResponse> {
    Ok(cy::run_init_2(args.to_string(), state.to_vec(), msg2.to_vec(), seq)?.into())
}

#[wasm_bindgen]
pub fn run_vls(args: &str, state: &[u8], vls_msg: &[u8], seq: Option<u16>) -> Result<VlsResponse> {
    Ok(cy::run_vls(args.to_string(), state.to_vec(), vls_msg.to_vec(), seq)?.into())
}

#[wasm_bindgen]
pub fn run_lss(args: &str, state: &[u8], lss_msg: &[u8], seq: Option<u16>) -> Result<VlsResponse> {
    Ok(cy::run_lss(args.to_string(), state.to_vec(), lss_msg.to_vec(), seq)?.into())
}
