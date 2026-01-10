fn main() {
    if cfg!(feature = "serde") {
        println!(
            "cargo:warning=`serde` feature is enabled. Serializing CSPRNG states can leave unzeroizable copies of the seed in memory."
        );
    }
}
