//! On ELF targets, give the cdylib libcurl's SONAME (`libcurl.so.4`) and export
//! the `curl_*` symbols under the `CURL_OPENSSL_4` version node via a linker
//! version script, so an existing libcurl-linked binary can resolve against it.
//! Non-ELF targets (macOS/Windows) just produce the plain `libcurl` cdylib.

use std::env;
use std::path::Path;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    // Only emit cdylib link args; staticlib builds ignore them.
    let is_elf = !matches!(target_os.as_str(), "macos" | "ios" | "windows");
    if !is_elf {
        return;
    }

    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libcurl.so.4");

    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let map = Path::new(&manifest).join("libcurl.map");
    println!("cargo:rerun-if-changed={}", map.display());
    println!(
        "cargo:rustc-cdylib-link-arg=-Wl,--version-script={}",
        map.display()
    );
}
