### onion messages

**`create_onion(seed: String, time: String, hops: String, payload: Bytes)`**

- seed: 32-byte hex
- time: 13-digit timestamp (milliseconds). MUST be unique each time!
- hops: JSON string of hops (object with `pubkey` hex string)
- payload: message Bytes to encrypto for the final hop
- return encrypted onion Bytes

**`peel_onion(seed: String, time: String, payload Bytes)`**

- seed: 32-byte hex
- time: 13-digit timestamp (milliseconds)
- payload: encrypted onion (1401 bytes)
- returns decrypted content Bytes

### keysends

**`sha_256(msg: Bytes)`**

- msg: Bytes to hash
- returns hex-encoded hash string

**`create_keysend(seed: String, time: String, hops: String, msat: u64, rhash: String, payload: Bytes, curr_height: u32, preimage: String)`**

- seed: 32-byte hex
- time: 13-digit timestamp (milliseconds). MUST be unique each time!
- hops: JSON string of hops (see below)
- msat: value to send (in millisatoshi)
- rhash: hash of preimage (hex string)
- payload: message Bytes to encrypto for the final hop
- curr_height: current block height
- preimage: random 32-byte hex string
- returns encrypted onion Bytes

```ts
interface Hop {
  pubkey: string;
  short_channel_id: number;
  cltv_expiry_delta: number;
  fee_msat?: number; // the last hop doesn't need this
}
```

**`peel_keysend(seed: String, time: String, rhash: String)`**

- seed: 32-byte hex
- time: 13-digit timestamp (milliseconds)
- rhash: hex-encoded payment hash

# MQTT setup
