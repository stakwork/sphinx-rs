# docs

**`pubkey_from_secret_key(secret_key: String)`**
- secret_key: 32-byte hex 
- returns a 33-byte public key

**`derive_shared_secret(their_pubkey: String, my_secret_key: String)`**
- their_pubkey: 33-byte hex 
- my_secret_key: 32-byte hex 
- returns a 32-byte secret

**`encrypt(plaintext: String, secret: String, nonce: String)`**
- plaintext: 32-byte hex
- secret: 32-byte hex
- nonce: 12-byte hex
- returns 60-byte ciphertext

**`decrypt(ciphertext: String, secret: String)`**
- ciphertext: 60-byte hex
- secret: 32-byte hex
- returns 32-byte plaintext

**`node_keys(net: String, seed: String)`**
- net: "regtest", "signet", "testnet", or "bitcoin"
- seed: 32-byte hex
- return Keys{secret: String, pubkey: String}

**`mnemonic_from_entropy(seed: String)`**
- seed: 32-byte hex
- returns a 24-word mnemonic

**`entropy_from_mnemonic(mnemonic: String)`**
- mnemonic: 24 words separated by spaces
- return a 32-byte hex seed

### control messages

Each Control message must be signed by the private key (derived from seed). Each control message must have a higher nonce than the previous one. 

**`get_nonce_request(secret: String, nonce: u64)`**

**`get_nonce_response(inp: String)`**

**`reset_wifi_request(secret: String, nonce: u64)`**

**`reset_wifi_response(inp: String)`**

**`reset_keys_request(secret: String, nonce: u64)`**

**`reset_keys_response(inp: String)`**

**`reset_all_request(secret: String, nonce: u64)`**

**`reset_all_response(inp: String)`**

**`get_policy_request(secret: String, nonce: u64)`**

**`get_policy_response(inp: String)`**

**`update_policy_request(secret: String, nonce: u64, policy: Policy)`**
- Policy{sat_limit: u64, interval: String, htlc_limit: u64}
- interval must be "hourly" or "daily"

**`update_policy_response(inp: String)`**

**`get_allowlist_request(secret: String, nonce: u64)`**

**`get_allowlist_response(inp: String)`**

**`update_allowlist_request(secret: String, nonce: u64, al: Vec<String>)`**

**`update_allowlist_response(inp: String)`**

**`ota_request(secret: String, nonce: u64, version: u64, url: String)`**

**`ota_response(inp: String)`**

# build

uniffi-bindgen --version

should match the uniffi version in Cargo.toml

### build the C ffi

uniffi-bindgen scaffolding src/sphinxrs.udl

### kotlin

rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android arm-linux-androideabi

./build-kotlin.sh

### swift

rustup target add aarch64-apple-ios x86_64-apple-ios

armv7-apple-ios
armv7s-apple-ios
i386-apple-ios

./build-swift.sh
