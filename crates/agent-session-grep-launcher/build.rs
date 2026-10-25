fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rustc-env=ASG_LAUNCHER_TARGET={}",
        std::env::var("TARGET").expect("Cargo supplies TARGET")
    );
}
