use crate::Result;
use sphinx_ffi as cy;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct VlsResponse {
    topic: String,
    vls_bytes: Option<Vec<u8>>,
    lss_bytes: Option<Vec<u8>>,
    sequence: u16,
    state: Option<Vec<u8>>,
}

impl From<cy::VlsResponse> for VlsResponse {
    fn from(vr: cy::VlsResponse) -> Self {
        VlsResponse {
            topic: vr.topic,
            vls_bytes: vr.vls_bytes,
            lss_bytes: vr.lss_bytes,
            sequence: vr.sequence,
            state: vr.state,
        }
    }
}

#[wasm_bindgen]
impl VlsResponse {
    #[wasm_bindgen(getter)]
    pub fn topic(&self) -> String {
        self.topic.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn vls_bytes(&self) -> Option<Vec<u8>> {
        self.vls_bytes.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn lss_bytes(&self) -> Option<Vec<u8>> {
        self.lss_bytes.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn sequence(&self) -> u16 {
        self.sequence
    }
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> Option<Vec<u8>> {
        self.state.clone()
    }
}

#[wasm_bindgen]
pub fn run_init_1(args: &str, state: &[u8], msg1: &[u8]) -> Result<VlsResponse> {
    Ok(cy::run_init_1(args.to_string(), state.to_vec(), msg1.to_vec())?.into())
}

#[wasm_bindgen]
pub fn run_init_2(args: &str, state: &[u8], msg1: &[u8], msg2: &[u8]) -> Result<VlsResponse> {
    Ok(cy::run_init_2(
        args.to_string(),
        state.to_vec(),
        msg1.to_vec(),
        msg2.to_vec(),
    )?
    .into())
}

#[wasm_bindgen]
pub fn run_vls(
    args: &str,
    state: &[u8],
    msg1: &[u8],
    msg2: &[u8],
    vls_msg: &[u8],
    expected_sequence: Option<u16>,
) -> Result<VlsResponse> {
    Ok(cy::run_vls(
        args.to_string(),
        state.to_vec(),
        msg1.to_vec(),
        msg2.to_vec(),
        vls_msg.to_vec(),
        expected_sequence,
    )?
    .into())
}

#[wasm_bindgen]
pub fn run_lss(
    args: &str,
    state: &[u8],
    msg1: &[u8],
    msg2: &[u8],
    lss_msg: &[u8],
    prev_vls: &[u8],
    prev_lss: &[u8],
) -> Result<VlsResponse> {
    Ok(cy::run_lss(
        args.to_string(),
        state.to_vec(),
        msg1.to_vec(),
        msg2.to_vec(),
        lss_msg.to_vec(),
        prev_vls.to_vec(),
        prev_lss.to_vec(),
    )?
    .into())
}
