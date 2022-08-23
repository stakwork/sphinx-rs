pub mod chacha;
pub mod ecdh;

pub use secp256k1;

#[cfg(test)]
mod tests {
    use crate::chacha::{decrypt, encrypt, MSG_LEN, NONCE_LEN};
    use crate::ecdh::derive_shared_secret_from_slice;
    use secp256k1::rand::{rngs::OsRng, thread_rng, RngCore};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    #[test]
    fn test_crypter() -> anyhow::Result<()> {
        // two keypairs
        let s = Secp256k1::new();
        let (sk1, pk1) = s.generate_keypair(&mut thread_rng());
        let (sk2, pk2) = s.generate_keypair(&mut thread_rng());

        // derive shared secrets
        let sec1 = derive_shared_secret_from_slice(pk2.serialize(), sk1.secret_bytes())?;
        let sec2 = derive_shared_secret_from_slice(pk1.serialize(), sk2.secret_bytes())?;
        assert_eq!(sec1, sec2);

        // encrypt plaintext with sec1
        let plaintext = [1; MSG_LEN];
        let mut nonce = [0; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let cipher = encrypt(plaintext, sec1, nonce)?;

        // decrypt with sec2
        let plain = decrypt(cipher, sec2)?;
        assert_eq!(plaintext, plain);

        println!("PLAINTEXT MATCHES!");
        Ok(())
    }

    #[test]
    fn test_compat() -> anyhow::Result<()> {
        let s1 = [
            132, 142, 219, 93, 168, 139, 216, 88, 110, 157, 216, 144, 186, 37, 237, 55, 44, 202,
            21, 206, 139, 14, 133, 224, 147, 153, 0, 50, 226, 91, 236, 159,
        ];
        let sk1 = SecretKey::from_slice(&s1).expect("sk1 failed");
        let s2 = [
            250, 196, 10, 147, 43, 209, 110, 45, 163, 232, 151, 113, 227, 126, 12, 162, 5, 240,
            244, 167, 74, 8, 53, 94, 71, 158, 225, 4, 171, 43, 114, 107,
        ];
        let sk2 = SecretKey::from_slice(&s2).expect("sk2 failed");
        let s = Secp256k1::new();
        let pk2 = PublicKey::from_secret_key(&s, &sk2);

        // derive shared secrets
        let sec1 = derive_shared_secret_from_slice(pk2.serialize(), sk1.secret_bytes())?;
        assert_eq!(
            sec1,
            [
                119, 150, 199, 76, 170, 182, 81, 95, 167, 57, 243, 252, 70, 106, 137, 116, 38, 107,
                27, 123, 199, 179, 96, 109, 8, 53, 77, 77, 57, 213, 2, 121
            ]
        );
        Ok(())
    }
}
