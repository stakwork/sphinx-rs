### build

comment out the [lib] section in ../sphinx-ffi/Cargo.toml

AR=/usr/local/opt/llvm/bin/llvm-ar CC=/usr/local/opt/llvm/bin/clang wasm-pack build --target web

cp pkg/sphinx_wasm_bg.wasm demo/public/sphinx_wasm_bg.wasm

### dependencies

brew install llvm