pub const VLS: &str = "vls";
pub const VLS_RES: &str = "vls-res";
pub const CONTROL: &str = "control";
pub const CONTROL_RES: &str = "control-res";
pub const PROXY: &str = "proxy";
pub const PROXY_RES: &str = "proxy-res";
pub const ERROR: &str = "error";
pub const INIT_1_MSG: &str = "init-1-msg";
pub const INIT_1_RES: &str = "init-1-res";
pub const INIT_2_MSG: &str = "init-2-msg";
pub const INIT_2_RES: &str = "init-2-res";
pub const LSS_MSG: &str = "lss-msg";
pub const LSS_RES: &str = "lss-res";
pub const LSS_CONFLICT: &str = "lss-conflict";
pub const LSS_CONFLICT_RES: &str = "lss-conflict-res";
pub const HELLO: &str = "hello";
pub const BYE: &str = "bye";

pub const BROKER_SUBS: &[&str] = &[
    ERROR,
    VLS_RES,
    CONTROL_RES,
    PROXY_RES,
    INIT_1_RES,
    INIT_2_RES,
    LSS_RES,
    LSS_CONFLICT_RES,
];

pub const SIGNER_SUBS: &[&str] = &[
    VLS,
    CONTROL,
    PROXY,
    INIT_1_MSG,
    INIT_2_MSG,
    LSS_MSG,
    LSS_CONFLICT,
];
