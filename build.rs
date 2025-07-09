pub fn main() {
    // recompile so new til/idb files are included to tests
    println!("cargo::rerun-if-changed=resources/idbs");
    println!("cargo::rerun-if-changed=resources/tils");
}
