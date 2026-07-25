use std::env;
use std::path::PathBuf;

fn main() {
    // Generate C header from Rust code
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_file = PathBuf::from(&crate_dir).join("fmadio_ring_ffi.h");

    let config = cbindgen::Config::from_file("cbindgen.toml")
        .expect("Failed to read cbindgen.toml");

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Failed to generate bindings")
        .write_to_file(&output_file);

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/ring.rs");
    println!("cargo:rerun-if-changed=src/thread.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
