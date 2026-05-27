//! Minimal CLI for the first scaffold milestone:
//!     curlrs <url>
//!
//! Full curl-compatible argument parsing (-o, -i, -v, -X, -H, ...) lands in
//! the next milestone.

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let url = match args.iter().skip(1).find(|a| !a.starts_with('-')) {
        Some(u) => u,
        None => {
            eprintln!("usage: curlrs <url>");
            return ExitCode::from(2);
        }
    };

    match curlrs::get(url) {
        Ok(resp) => {
            if let Err(e) = std::io::stdout().write_all(&resp.body) {
                eprintln!("curlrs: write error: {e}");
                return ExitCode::from(23);
            }
            if (200..400).contains(&resp.status) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(22)
            }
        }
        Err(e) => {
            eprintln!("curlrs: {e}");
            ExitCode::from(1)
        }
    }
}
