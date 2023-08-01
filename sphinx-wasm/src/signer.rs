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
pub fn run(
    topic: &str,
    args: &str,
    state: &[u8],
    msg: &[u8],
    sequence: Option<u16>,
) -> Result<VlsResponse> {
    Ok(cy::run(
        topic.to_string(),
        args.to_string(),
        state.to_vec(),
        msg.to_vec(),
        sequence,
    )?
    .into())
}
