//! Compile the C smoke program against the built `libcurl` drop-in and run it.
//! Skips gracefully if no C compiler is available or the shared library was
//! not built next to the test binary.

#![cfg(unix)]

mod support;

#[test]
fn c_program_links_and_runs_against_libcurl() {
    let Some((exe, libdir)) = support::compile("tests/smoke.c", "smoke") else {
        return;
    };
    let run = support::run(&exe, &libdir, &[]);
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success() && stdout.contains("SMOKE_OK"),
        "smoke run failed: status={:?}\nstdout={stdout:?}\nstderr={stderr:?}",
        run.status
    );
}
