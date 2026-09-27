//! Shared harness for the C smoke tests: find a C compiler and the built
//! drop-in library, compile a test program against `include/curl/curl.h`, and
//! run it with the loader pointed at the library.
//!
//! The library is located next to the running test binary (`target/<profile>/`,
//! whatever the target dir is), so the tests run under a plain
//! `cargo test --manifest-path curl-compat/Cargo.toml` — which builds the
//! cdylib alongside the test harness — on ELF and Mach-O alike.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// First working C compiler on `PATH`.
pub fn find_cc() -> Option<&'static str> {
    ["cc", "gcc", "clang"].into_iter().find(|cc| {
        Command::new(cc)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

/// File name of the shared drop-in on this platform.
fn shared_lib_name() -> &'static str {
    if cfg!(target_vendor = "apple") {
        "libcurl.dylib"
    } else {
        "libcurl.so"
    }
}

/// Directory holding the built shared library. `cargo test` builds the cdylib
/// into `<target>/<profile>/deps/` next to the test binary — prefer that copy:
/// the uplifted `<target>/<profile>/libcurl.*` is only refreshed by `cargo
/// build` and can be a stale older build that the loader would pick instead.
pub fn libdir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let deps_dir = exe.parent()?.to_path_buf();
    let profile_dir = deps_dir.parent()?.to_path_buf();
    [deps_dir, profile_dir]
        .into_iter()
        .find(|d| d.join(shared_lib_name()).exists())
}

/// Compile `src` (relative to the crate root) against the drop-in. Returns the
/// executable path, or `None` (after logging why) when the test must skip.
pub fn compile(src: &str, tag: &str) -> Option<(PathBuf, PathBuf)> {
    let Some(cc) = find_cc() else {
        eprintln!("skipping {tag}: no C compiler (cc/gcc/clang) found");
        return None;
    };
    let Some(libdir) = libdir() else {
        eprintln!("skipping {tag}: shared libcurl not built next to the test binary");
        return None;
    };
    // The ELF cdylib's SONAME is `libcurl.so.4`, so a linked program's NEEDED
    // entry is `libcurl.so.4`: provide that name next to the build output.
    if !cfg!(target_vendor = "apple") {
        let so4 = libdir.join("libcurl.so.4");
        if !so4.exists() {
            let _ = std::os::unix::fs::symlink(Path::new("libcurl.so"), &so4);
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let exe = std::env::temp_dir().join(format!("rsurl_curl_{tag}_{}", std::process::id()));
    // The test binary's target decides the C program's ABI: a 32-bit x86
    // build (the i686 CI lane, run on an x86-64 host) links a 32-bit libcurl.
    let arch_flags: &[&str] = if cfg!(target_arch = "x86") {
        &["-m32"]
    } else {
        &[]
    };
    let compile = Command::new(cc)
        .args(arch_flags)
        .arg(manifest.join(src))
        .arg("-I")
        .arg(manifest.join("include"))
        .arg("-L")
        .arg(&libdir)
        .arg("-lcurl")
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("failed to invoke C compiler");
    assert!(
        compile.status.success(),
        "compile of {src} failed:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    Some((exe, libdir))
}

/// Run a compiled test program with `args`, loader pointed at `libdir`, then
/// delete it.
pub fn run(exe: &Path, libdir: &Path, args: &[&str]) -> Output {
    let out = Command::new(exe)
        .args(args)
        .env("LD_LIBRARY_PATH", libdir)
        .env("DYLD_LIBRARY_PATH", libdir)
        .output()
        .expect("failed to run C test program");
    let _ = std::fs::remove_file(exe);
    out
}
