# AGENTS.md

Short instructions for agents working in `sphinx-ffi`.

## Adding / changing an FFI function

When a binding signature in the upstream `sphinx` crate changes (e.g. new arg added), update **all** of these:

1. `src/auto.rs` (or `src/signer.rs` / `src/control.rs` / `src/onion.rs` / `src/parse.rs`) — the Rust wrapper function.
2. `src/sphinxrs.udl` — the UniFFI interface definition. Use `?` suffix for `Option<T>` (e.g. `string? description`).

## Build / verify

```sh
cargo build --lib
```

Do not worry about errors in the `uniffi-bindgen` bin (pre-existing, unrelated).

The generated bindings (`src/sphinxrs.swift`, `src/uniffi/sphinxrs/sphinxrs.kt`, `src/sphinxrsFFI.h`) are regenerated via `./build-bindings.sh` — don't edit them by hand.
