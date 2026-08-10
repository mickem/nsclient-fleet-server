fn main() {
    // `main.rs` reads FLEET_BUILD_VERSION through `option_env!` so the release workflow can
    // compile the tag-derived version into the binary. Cargo does not know that a source
    // file depends on an environment variable, so without this the build would be
    // considered up to date after the value changed — and a cached target directory (CI
    // restores one) would keep handing out a binary that reports the previous version.
    println!("cargo:rerun-if-env-changed=FLEET_BUILD_VERSION");
}
