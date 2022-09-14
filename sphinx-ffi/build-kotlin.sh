echo "=> creating C FFI scaffolding"
uniffi-bindgen scaffolding src/sphinx.udl

echo "=> creating kotlin bindings"
uniffi-bindgen generate src/sphinx.udl --language kotlin

echo "=> renaming uniffi_sphinx to sphinx"
sed -i '' 's/return "uniffi_sphinx"/return "sphinx"/' src/uniffi/sphinx/sphinx.kt

echo "=> building i686-linux-android"
cross build --target i686-linux-android --release
echo "=> building aarch64-linux-android"
cross build --target aarch64-linux-android --release
echo "=> building arm-linux-androideabi"
cross build --target arm-linux-androideabi --release
echo "=> building armv7-linux-androideabi"
cross build --target armv7-linux-androideabi --release
echo "=> building x86_64-linux-android"
cross build --target x86_64-linux-android --release

echo "=> renaming files"

mkdir -p target/out
mkdir -p target/out/x86
mkdir -p target/out/arm64-v8a
mkdir -p target/out/armeabi
mkdir -p target/out/armeabi-v7a
mkdir -p target/out/x86_64

mv target/i686-linux-android/release/libsphinx.so target/out/x86/libsphinx.so
mv target/aarch64-linux-android/release/libsphinx.so target/out/arm64-v8a/libsphinx.so
mv target/arm-linux-androideabi/release/libsphinx.so target/out/armeabi/libsphinx.so
mv target/armv7-linux-androideabi/release/libsphinx.so target/out/armeabi-v7a/libsphinx.so
mv target/x86_64-linux-android/release/libsphinx.so target/out/x86_64/libsphinx.so

zip -r target/kotlin-libraries.zip target/out

echo "=> done!"
