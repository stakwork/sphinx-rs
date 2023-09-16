# Sphinx VLS Signer

cargo run multi

### clear

rm -rf teststore
rm -rf vls_mqtt_data

# LSS setup notes

### lss

In `lightning-storage-server` (in the VLS repo)

`cargo build --bin lssd --no-default-features --features crypt`

Then `./target/debug/lssd`

That starts a local `lssd` on port 55551

### swarm (CLN)

In `sphinx-swarm` repo: `git checkout feat/lss`

`cargo run --bin cln` will spin up bitcoind and 2 CLN nodes. One of them expects a signer

To change the broker docker image, its in images/cln.rs

### vls-mqtt

make a .env at the root of the `sphinx-rs` repo with:

```
SEED=56b289899f2871f77260a0ec8f1c2f1006b7ae4a74be4bb472a97945e416b191
NETWORK=regtest
BROKER=127.0.0.1:1883
ROCKET_ADDRESS=0.0.0.0
ROCKET_PORT=8008
```

`cargo run`

This will spin up a local software signer and connect it to the `cln_1.sphinx` CLN node running in swarm
