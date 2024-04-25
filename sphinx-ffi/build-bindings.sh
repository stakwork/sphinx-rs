echo "=> creating swift bindings"
cargo run --features=uniffi/cli --bin uniffi-bindgen generate src/sphinxrs.udl --language swift

echo "=> creating swift bindings"
sed -i '' 's/module\ sphinxrsFFI/framework\ module\ sphinxrsFFI/' src/sphinxrsFFI.modulemap



echo "=> creating kotlin bindings"
cargo run --features=uniffi/cli --bin uniffi-bindgen generate src/sphinxrs.udl --language kotlin

echo "=> renaming uniffi_sphinxrs to sphinxrs"
sed -i '' 's/return "uniffi_sphinxrs"/return "sphinxrs"/' src/uniffi/sphinxrs/sphinxrs.kt
