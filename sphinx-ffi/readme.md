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

**`build_request(json: String, secret: String, nonce: Number)`**

- json: JSON string of the [ControlMessage](https://github.com/stakwork/sphinx-rs/blob/master/glyph/src/types.rs#L7) enum. An object (dictionary) with one key, which is the enum name. The value is the value inside the enum, or `null`. Example: `{Nonce:null}` or `{UpdatePolicy:{msat_per_interval:0,interval:"daily",htlc_limit_msat:0}}`
- secret: the secret key returned from `node_keys`
- nonce: A number that you need to persist. For every request it needs to be greater than the last request.
- return the bytes (hex string) to send to the signer

**`parse_response(res: String)`**

- res: a hex string returned from the signer after sending the `build_request`.
- return a JSON string so you can easily see what's inside

### signer

The signer API requires the phone to persist the results of each call, in order to add them to the next call.

The `args` are a JSON string of arguments that are needed for every call:

```rs
pub struct Args {
    seed: [u8; 32], // entropy
    network: Network, // "bitcoin" or "regtest"
    policy: Policy,
    velocity: Option<Velocity>,
    allowlist: Vec<String>,
    timestamp: Duration,
    lss_nonce: [u8; 32], // random nonce
}
```

**`run_init_1(args: String, state: Bytes, msg1: Bytes)`**

**`run_init_2(args: String, state: Bytes, msg1: Bytes, msg2: Bytes)`**

**`run_vls(args: String, state: Bytes, msg1: Bytes, msg2: Bytes, vls_msg: Bytes)`**

**`run_lss(args: String, state: Bytes, msg1: Bytes, msg2: Bytes, lss_msg: Bytes, previous_vls_msg: Bytes, previous_lss_msg: Bytes)`**

### kotlin

rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android arm-linux-androideabi

./build-kotlin.sh

### swift

rustup target add aarch64-apple-ios x86_64-apple-ios

armv7-apple-ios
armv7s-apple-ios
i386-apple-ios

./build-swift.sh
