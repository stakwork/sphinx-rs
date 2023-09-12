use vls_protocol_signer::lightning_signer::{
    bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey},
    bitcoin::Network,
    signer::derive::{key_derive, KeyDerivationStyle},
};

pub fn node_keys(network: &Network, seed: &[u8]) -> (PublicKey, SecretKey) {
    let style = KeyDerivationStyle::Native;
    let deriver = key_derive(style, network.clone());
    let ctx = Secp256k1::new();
    deriver.node_keys(seed, &ctx)
}

pub fn mnemonic_from_entropy(entropy: &[u8]) -> anyhow::Result<String> {
    let mn = bip39::Mnemonic::from_entropy(entropy)
        .map_err(|e| anyhow::anyhow!("Mnemonic::from_entropy failed {:?}", e))?;
    let mut ret = Vec::new();
    mn.word_iter().for_each(|w| ret.push(w.to_string()));
    Ok(ret.join(" "))
}

pub fn entropy_from_mnemonic(mn: &str) -> anyhow::Result<Vec<u8>> {
    let mn = bip39::Mnemonic::parse_normalized(mn)
        .map_err(|e| anyhow::anyhow!("Mnemonic::parse_normalized failed {:?}", e))?;
    let mut e = mn.to_entropy_array().0.to_vec();
    e.remove(32);
    Ok(e)
}

pub fn mnemonic_to_seed(mn: &str) -> anyhow::Result<Vec<u8>> {
    let mn = bip39::Mnemonic::parse_normalized(mn)
        .map_err(|e| anyhow::anyhow!("Mnemonic::parse_normalized failed {:?}", e))?;
    // Do like CLN does, chop off the last 32 bytes
    let e = mn.to_seed_normalized("")[..32].to_vec();
    Ok(e)
}

#[cfg(test)]
mod tests {
    use crate::derive::*;

    fn entropy() -> [u8; 32] {
        [1; 32]
    }

    fn seed() -> [u8; 32] {
        [1; 32]
    }

    #[test]
    fn test_mnemonic() {
        let entropy = entropy();
        let mn = mnemonic_from_entropy(&entropy).expect("nope");
        assert_eq!(mn, "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice comic");
        let en = entropy_from_mnemonic(&mn).expect("fail");
        assert_eq!(&en[..], &entropy);
    }

    #[test]
    fn test_mnemonic_to_seed() {
        let seed = mnemonic_to_seed("forget parent wage payment cotton excite venue into era crouch because twin bargain flash library fever raise chunk suit evil jar perfect almost supreme").expect("fail");
        let vector = [0xdf, 0x58, 0x5d, 0x7e, 0xdb, 0xf9, 0x86, 0x3e, 0x42, 0xef, 0xc1, 0xef, 0x00, 0xb1, 0xd1, 0x0d, 0x9c, 0x6b, 0xb7, 0xb3, 0xff, 0xea, 0x27, 0x2a, 0x48, 0x43, 0x0e, 0x8a, 0x3e, 0x4b, 0x60, 0x0b];
        assert_eq!(seed, vector);
    }

    #[test]
    fn test_derive() {
        use vls_protocol_signer::lightning_signer::bitcoin::Network;
        let net = Network::Regtest;
        let ks = node_keys(&net, &seed());
        // let pk = ks.0.serialize();
        let hexpk = ks.0.to_string();
        assert_eq!(
            hexpk,
            "026f61d7ee82f937f9697f4f3e44bfaaa25849cc4f526b3a57326130eba6346002"
        );
    }
}
