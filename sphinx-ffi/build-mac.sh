echo "=> compiling swift mac bindings"
cargo run --features=uniffi/cli --bin uniffi-bindgen generate src/sphinxrs.udl --language swift

echo "=> creating swift mac bindings"
sed -i '' 's/module\ sphinxrsFFI/framework\ module\ sphinxrsFFI/' src/sphinxrsFFI.modulemap

echo "=> building x86_64-apple-darwin"
cross build --features=uniffi/cli --target=x86_64-apple-darwin --release
echo "=> building aarch64-apple-darwin"
cross build --features=uniffi/cli --target=aarch64-apple-darwin --release

echo "=> combining into a universal lib"
lipo -create target/x86_64-apple-darwin/release/libsphinxrs.a target/aarch64-apple-darwin/release/libsphinxrs.a -output target/universal-sphinxrs-mac.a

echo "=> done!"
