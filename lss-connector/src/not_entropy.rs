use lightning_signer::lightning::sign::EntropySource;
use vls_protocol_signer::lightning_signer;

pub struct NotEntropy([u8; 32]);

impl NotEntropy {
    pub fn new(a: [u8; 32]) -> Self {
        Self(a)
    }
}

impl EntropySource for NotEntropy {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.0
    }
}
