echo "=> compiling swift ios bindings"
cargo run --features=uniffi/cli --bin uniffi-bindgen generate src/sphinxrs.udl --language swift

echo "=> creating swift ios bindings"
sed -i '' 's/module\ sphinxrsFFI/framework\ module\ sphinxrsFFI/' src/sphinxrsFFI.modulemap

echo "=> building x86_64-apple-ios"
cross build --features=uniffi/cli --target=x86_64-apple-ios --release
echo "=> building aarch64-apple-ios"
cross build --features=uniffi/cli --target=aarch64-apple-ios --release

echo "=> combining into a universal lib"
lipo -create target/x86_64-apple-ios/release/libsphinxrs.a target/aarch64-apple-ios/release/libsphinxrs.a -output target/universal-sphinxrs.a

echo "=> done!"
