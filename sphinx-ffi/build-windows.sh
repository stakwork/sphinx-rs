
echo "=> creating kotlin bindings"
cargo run --features=uniffi/cli --bin uniffi-bindgen generate src/sphinxrs.udl --language kotlin

echo "=> renaming uniffi_sphinxrs to sphinxrs"
sed -i '' 's/return "uniffi_sphinxrs"/return "sphinxrs"/' src/uniffi/sphinxrs/sphinxrs.kt

echo "=> building x86_64-pc-windows-gnu"
cross build --features=uniffi/cli --target x86_64-pc-windows-gnu --release
echo "=> building i686-pc-windows-gnu"
cross build --features=uniffi/cli --target i686-pc-windows-gnu --release

echo "=> renaming files"

mkdir -p target/windows
mkdir -p target/windows/x86_64
mkdir -p target/windows/i686

mv target/x86_64-pc-windows-gnu/release/sphinxrs.dll target/windows/x86_64/sphinxrs.dll
mv target/i686-pc-windows-gnu/release/sphinxrs.dll target/windows/i686/sphinxrs.dll

zip -r target/windows-libraries.zip target/windows

echo "=> done!"