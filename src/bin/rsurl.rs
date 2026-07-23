//! rsurl CLI entry point.
//!
//! The actual CLI lives in `src/cli.rs` (pulled in via `#[path]` below). It is
//! native-only: it uses the blocking API, the filesystem, and stdio, none of
//! which exist on `wasm32-unknown-unknown`. On wasm the binary compiles to an
//! empty `main` so the whole crate still builds for the browser — only the
//! library (`crate::aio`, fetch + WebSocket) is meaningful there.

#[cfg(not(target_arch = "wasm32"))]
#[path = "../cli.rs"]
mod cli;

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    cli::main()
}

#[cfg(target_arch = "wasm32")]
fn main() {}
