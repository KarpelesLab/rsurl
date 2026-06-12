//! Compile the C smoke program against the built `libcurl.{so,a}` drop-in and
//! run it. Skips gracefully if no C compiler is available or the shared library
//! has not been built yet (`cargo build -p curl-compat`).

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn find_cc() -> Option<&'static str> {
    ["cc", "gcc", "clang"].into_iter().find(|cc| {
        Command::new(cc)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

fn target_dir() -> PathBuf {
    if let Ok(d) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(d);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
}

fn libdir_with_so() -> Option<PathBuf> {
    let t = target_dir();
    for profile in ["debug", "release"] {
        let d = t.join(profile);
        if d.join("libcurl.so").exists() {
            return Some(d);
        }
    }
    None
}

#[test]
fn c_program_links_and_runs_against_libcurl() {
    let Some(cc) = find_cc() else {
        eprintln!("skipping c_smoke: no C compiler (cc/gcc/clang) found");
        return;
    };
    let Some(libdir) = libdir_with_so() else {
        eprintln!(
            "skipping c_smoke: libcurl.so not built — run `cargo build -p curl-compat` first"
        );
        return;
    };
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // The cdylib's SONAME is `libcurl.so.4`, so the linked program's NEEDED
    // entry is `libcurl.so.4`. Provide that name next to the build output.
    let so4 = libdir.join("libcurl.so.4");
    if !so4.exists() {
        let _ = std::os::unix::fs::symlink(Path::new("libcurl.so"), &so4);
    }

    let exe = std::env::temp_dir().join(format!("rsurl_curl_smoke_{}", std::process::id()));
    let compile = Command::new(cc)
        .arg(manifest.join("tests/smoke.c"))
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
        "compile failed:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let run = Command::new(&exe)
        .env("LD_LIBRARY_PATH", &libdir)
        .output()
        .expect("failed to run smoke binary");
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    let _ = std::fs::remove_file(&exe);

    assert!(
        run.status.success() && stdout.contains("SMOKE_OK"),
        "smoke run failed: status={:?}\nstdout={stdout:?}\nstderr={stderr:?}",
        run.status
    );
}
