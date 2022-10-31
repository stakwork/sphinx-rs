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
    let mn = bip39::Mnemonic::from_entropy(entropy)?;
    let mut ret = Vec::new();
    mn.word_iter().for_each(|w| ret.push(w.to_string()));
    Ok(ret.join(" "))
}

pub fn entropy_from_mnemonic(mn: &str) -> anyhow::Result<Vec<u8>> {
    let mn = bip39::Mnemonic::parse_normalized(mn)?;
    Ok(mn.to_entropy())
}

#[cfg(test)]
mod tests {
    use crate::derive::*;

    fn seed() -> [u8; 32] {
        [1; 32]
    }

    #[test]
    fn test_mnemonic() {
        let entropy = seed();
        let mn = mnemonic_from_entropy(&entropy).expect("nope");
        assert_eq!(mn, "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice comic");
        let en = entropy_from_mnemonic(&mn).expect("fail");
        assert_eq!(&en[..], &entropy);
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
