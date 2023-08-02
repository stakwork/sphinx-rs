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

**`make_auth_token(now: number, secret: String)`**

- now: 10-digit UNIX timestamp
- secret: 32-byte hex
- return auth_token string

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

The `args` are a JSON string of arguments that are needed for every call.

The `state` is a Map of strings to bytes, that should be persisted after each `run_vls` call.

Each mobile signer call returns a `VlsResponse` object.

```ts
type Bytes = Uint8Array;

interface Policy {
  msat_per_interval: number;
  interval: Interval; // "daily" or "hourly"
  htlc_limit_msat: number;
}

interface Args {
  seed: Bytes; // 32 bytes
  network: string; // "bitcoin" or "regtest"
  policy: Policy;
  allowlist: string[]; // list of btc addresses
  timestamp: number; // unix ts in seconds (10 digits)
  lss_nonce: Bytes; // random 32 bytes
}

type State = { [k: string]: Bytes };

interface VlsResponse {
  topic: string;
  bytes: Bytes;
  sequence?: number;
  cmd: string; // the name of the last VLS command that was run
  state: Bytes; // Map of strings to bytes, serialized with msgpack
}
```

**`run(topic: String, args: String, state: Bytes, msg1: Bytes, sequence?: u16)`**

### mobile signer instructions

First, run an example sphinx-swarm with CLN + bitcoind

- `git clone https://github.com/stakwork/sphinx-swarm.git`
- `cd sphinx-swarm`
- `cargo run --bin cln`
- this will run CLN and bitcoind inside docker
- to shut them down you can run `./clear.sh`

**Implementation instructions:**

1. generate your seed: random 32 bytes
2. run `node_keys(network, seed)` to get your keys.
3. connect to the MQTT broker
   - host: `localhost`
   - port: `1883`
   - clientID: random string
   - username: keys.pubkey
   - password: `make_auth_token(timestamp, keys.secret)`
4. subscribe to topics:
   - `{CLIENT_ID}/vls`, `{CLIENT_ID}/init-1-msg`, `{CLIENT_ID}/init-2-msg`, `{CLIENT_ID}/lss-msg`
5. publish to `{CLIENT_ID}/hello` to let the broker know you are ready
6. make a "sequence" number (starting at null, not zero)
7. when a MQTT message is received:

- load up ALL your stored State into a Map (dictionary or object) and encode with msgpack.
- `run(topics, args, state, msg, sequence)`
- after each call, store ALL the returned State:
  - msgpack.decode(`response.state`)
  - store each key/value pair
- Then publish the `bytes` on the returned `topic`.
- if the topic was `vls-msg`, then set the stored "sequence" number to equal the `response.sequence` + 1
- if you get an "invalid sequence" error, that means another signer signed instead (if you are running multiple signers). So clear ALL your stored state, set "sequence" back to undefined, and publish to `{CLIENT_ID}/hello` again.

### kotlin

rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android arm-linux-androideabi

./build-kotlin.sh

### swift

rustup target add aarch64-apple-ios x86_64-apple-ios

armv7-apple-ios
armv7s-apple-ios
i386-apple-ios

./build-swift.sh
