use ring::pbkdf2::{derive, PBKDF2_HMAC_SHA256};
use std::num::NonZeroU32;

/// PBKDF2-HMAC-SHA256 (RFC 8018) producing exactly 32 bytes (a single block).
///
/// The PIN is used as its UTF-8 bytes. `salt` and `iterations` are entirely the
/// caller's responsibility. This is a pure speed path: iOS uses
/// `CCKeyDerivationPBKDF`, while Android currently loops `Mac.doFinal` 2.5M times.
///
/// `iterations == 0` is not valid PBKDF2; instead of panicking this returns an
/// empty `Vec`. That is not a valid key, so a caller using it as an AES-256 key
/// fails loudly rather than silently getting a weak/zero key.
///
/// The PIN bytes are overwritten after use.
pub fn pbkdf2_hmac_sha256(pin: String, salt: Vec<u8>, iterations: u32) -> Vec<u8> {
    let mut pin_bytes = pin.into_bytes();
    let out = match NonZeroU32::new(iterations) {
        Some(n) => {
            let mut out = [0u8; 32];
            derive(PBKDF2_HMAC_SHA256, n, &salt, &pin_bytes, &mut out);
            out.to_vec()
        }
        None => Vec::new(),
    };
    pin_bytes.fill(0);
    std::hint::black_box(&pin_bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pin: &str, salt: &[u8], it: u32) -> String {
        hex::encode(pbkdf2_hmac_sha256(pin.to_string(), salt.to_vec(), it))
    }

    #[test]
    fn vectors() {
        assert_eq!(
            h("password", b"salt", 1),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        assert_eq!(
            h("password", b"salt", 2),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
        assert_eq!(
            h("password", b"salt", 4096),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
        assert_eq!(
            h(
                "passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096
            ),
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1"
        );
        assert_eq!(
            h("", b"salt", 1),
            "f135c27993baf98773c5cdb40a5706ce6a345cde61b000a67858650cd6a324d7"
        );
    }

    #[test]
    fn zero_iterations_empty() {
        assert!(pbkdf2_hmac_sha256("pin".into(), vec![1, 2], 0).is_empty());
    }

    #[test]
    fn non_ascii_pin_utf8() {
        assert_eq!(
            h("pässwörd🔑", b"salt", 1000),
            "7dd40c3963d6e90c9277d13fdf4d8471851c26cbe551e1e5f77f4f8d8bc55831"
        );
    }

    #[test]
    fn real_params_timed() {
        let salt: Vec<u8> = (0u8..16).collect();
        let t = std::time::Instant::now();
        let out = pbkdf2_hmac_sha256("123456".into(), salt, 2_500_000);
        println!("real-params pbkdf2 took {:?}", t.elapsed());
        assert_eq!(
            hex::encode(out),
            "389afc0ec9eca1c0a363f4dac50a6162137c70e40f45559ac134f23c110b5b04"
        );
    }
}
