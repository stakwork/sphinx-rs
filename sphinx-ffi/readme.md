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

**`build_request`**

**`parse_response`**

### kotlin

rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android arm-linux-androideabi

./build-kotlin.sh

### swift

rustup target add aarch64-apple-ios x86_64-apple-ios

armv7-apple-ios
armv7s-apple-ios
i386-apple-ios

./build-swift.sh
