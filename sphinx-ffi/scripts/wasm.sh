mv build.rs build.rs-nope

sed -i '' 's/\[lib\]/# \[lib\]/' Cargo.toml

sed -i '' 's/name = "sphinxrs"/# name = "sphinxrs"/' Cargo.toml

sed -i '' 's/crate-type = \["staticlib", "cdylib"\]/# crate-type = \["staticlib", "cdylib"\]/' Cargo.toml


