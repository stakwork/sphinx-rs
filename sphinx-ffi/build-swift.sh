echo "=> creating C FFI scaffolding"
uniffi-bindgen scaffolding src/sphinx.udl

echo "=> creating swift bindings"
uniffi-bindgen generate src/sphinx.udl --language swift

echo "=> creating swift bindings"
sed -i '' 's/module\ sphinxFFI/framework\ module\ sphinxFFI/' src/sphinxFFI.modulemap

echo "=> building x86_64-apple-ios"
cross build --target=x86_64-apple-ios --release
echo "=> building aarch64-apple-ios"
cross build --target=aarch64-apple-ios --release

echo "=> combining into a universal lib"
lipo -create target/x86_64-apple-ios/release/libsphinx.a target/aarch64-apple-ios/release/libsphinx.a -output target/universal-sphinx.a

echo "=> done!"
