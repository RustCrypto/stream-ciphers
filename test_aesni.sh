RUSTFLAGS="-C target-feature=+aes,+sse2,+ssse3" RUSTDOCFLAGS=$RUSTFLAGS cargo test --all --exclude chacha20 --exclude salsa20
