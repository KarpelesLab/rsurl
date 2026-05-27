//! curlrs CLI — a (deliberately limited) curl-compatible front-end.
//!
//! Supported options at this milestone:
//!
//!     -o, --output <file>      write body to file instead of stdout
//!     -i, --include            include response headers in the output
//!     -I, --head               issue HEAD instead of GET
//!     -v, --verbose            print request/response headers to stderr
//!     -s, --silent             suppress error messages
//!     -X, --request <method>   override HTTP method
//!     -H, --header <line>      add a request header (repeatable)
//!     -d, --data <body>        send body and switch method to POST
//!     -A, --user-agent <ua>    set User-Agent
//!     -e, --referer <ref>      set Referer
//!         --http2              require HTTP/2 (ALPN h2); error if unavailable
//!         --http1.1            force HTTP/1.1 (alias: --http1)
//!     -h, --help               print help
//!     -V, --version            print version

use std::fs::File;
use std::io::{self, Write};
use std::process::ExitCode;

use curlrs::{HttpVersionPref, Request, Response, Url};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
struct Args {
    url: Option<String>,
    output: Option<String>,
    include_headers: bool,
    head: bool,
    verbose: bool,
    silent: bool,
    method: Option<String>,
    headers: Vec<(String, String)>,
    data: Option<String>,
    user_agent: Option<String>,
    referer: Option<String>,
    /// Most recent HTTP version flag (--http2, --http1.1) seen on the CLI.
    /// `None` means "Auto" — the library decides via ALPN. Last one wins,
    /// matching curl.
    http_version: Option<HttpVersionPref>,
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&raw) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("curlrs: {e}");
            eprintln!("try 'curlrs --help'");
            return ExitCode::from(2);
        }
    };

    let url = match args.url.as_deref() {
        Some(u) => u,
        None => {
            print_usage();
            return ExitCode::from(2);
        }
    };

    let parsed_url = match Url::parse(url) {
        Ok(u) => u,
        Err(e) => {
            if !args.silent {
                eprintln!("curlrs: {e}");
            }
            return ExitCode::from(3);
        }
    };

    // Non-HTTP schemes go through the generic transfer dispatcher; HTTP-only
    // options (-X, -H, -d, ...) are ignored for them in this milestone.
    if !matches!(parsed_url.scheme.as_str(), "http" | "https") {
        return run_transfer(url, &args);
    }

    let method = args.method.clone().unwrap_or_else(|| {
        if args.head {
            "HEAD".to_string()
        } else if args.data.is_some() {
            "POST".to_string()
        } else {
            "GET".to_string()
        }
    });

    let mut req = match Request::new(&method, url) {
        Ok(r) => r,
        Err(e) => {
            if !args.silent {
                eprintln!("curlrs: {e}");
            }
            return ExitCode::from(3);
        }
    };

    for (k, v) in &args.headers {
        req = req.header(k, v);
    }
    if let Some(ua) = &args.user_agent {
        req = req.header("User-Agent", ua);
    }
    if let Some(rf) = &args.referer {
        req = req.header("Referer", rf);
    }
    if let Some(body) = args.data.as_deref() {
        let body_bytes = body.as_bytes().to_vec();
        if !args
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            req = req.header("Content-Type", "application/x-www-form-urlencoded");
        }
        req = req.body(body_bytes);
    }
    match args.http_version {
        Some(HttpVersionPref::Http2Only) => req = req.http2_only(),
        Some(HttpVersionPref::Http11Only) => req = req.http11_only(),
        Some(HttpVersionPref::Auto) | None => {}
    }

    let send_result = if args.verbose {
        let mut err = io::stderr().lock();
        req.send_traced(&mut err)
    } else {
        req.send()
    };
    let resp = match send_result {
        Ok(r) => r,
        Err(e) => {
            if !args.silent {
                eprintln!("curlrs: {e}");
            }
            return ExitCode::from(7);
        }
    };

    let exit_for_status = if (200..400).contains(&resp.status) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(22)
    };

    if let Err(e) = write_output(&resp, &args) {
        if !args.silent {
            eprintln!("curlrs: write error: {e}");
        }
        return ExitCode::from(23);
    }

    exit_for_status
}

fn parse_args(raw: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = raw.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("curlrs {VERSION}");
                std::process::exit(0);
            }
            "-o" | "--output" => {
                a.output = Some(next_val(&mut it, arg)?);
            }
            "-i" | "--include" => a.include_headers = true,
            "-I" | "--head" => {
                a.head = true;
                a.include_headers = true;
            }
            "-v" | "--verbose" => a.verbose = true,
            "-s" | "--silent" => a.silent = true,
            "-X" | "--request" => a.method = Some(next_val(&mut it, arg)?),
            "-H" | "--header" => {
                let h = next_val(&mut it, arg)?;
                let (k, v) = h
                    .split_once(':')
                    .ok_or_else(|| format!("malformed header: {h:?}"))?;
                a.headers.push((k.trim().to_string(), v.trim().to_string()));
            }
            "-d" | "--data" | "--data-raw" => a.data = Some(next_val(&mut it, arg)?),
            "-A" | "--user-agent" => a.user_agent = Some(next_val(&mut it, arg)?),
            "-e" | "--referer" => a.referer = Some(next_val(&mut it, arg)?),
            "--http2" => a.http_version = Some(HttpVersionPref::Http2Only),
            // curl also accepts `--http1` as a shorthand for `--http1.1`.
            "--http1.1" | "--http1" => a.http_version = Some(HttpVersionPref::Http11Only),
            s if s.starts_with("--") => return Err(format!("unknown option: {s}")),
            s if s.starts_with('-') && s.len() > 1 => return Err(format!("unknown option: {s}")),
            _ => {
                if a.url.is_some() {
                    return Err(format!("multiple URLs are not supported yet: {arg}"));
                }
                a.url = Some(arg.clone());
            }
        }
    }
    Ok(a)
}

fn next_val(it: &mut std::slice::Iter<'_, String>, flag: &str) -> Result<String, String> {
    it.next()
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn run_transfer(url: &str, args: &Args) -> ExitCode {
    match curlrs::transfer(url) {
        Ok(bytes) => {
            let mut out: Box<dyn Write> = match &args.output {
                Some(path) if path != "-" => match File::create(path) {
                    Ok(f) => Box::new(f),
                    Err(e) => {
                        if !args.silent {
                            eprintln!("curlrs: open {path}: {e}");
                        }
                        return ExitCode::from(23);
                    }
                },
                _ => Box::new(io::stdout().lock()),
            };
            if let Err(e) = out.write_all(&bytes) {
                if !args.silent {
                    eprintln!("curlrs: write error: {e}");
                }
                return ExitCode::from(23);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            if !args.silent {
                eprintln!("curlrs: {e}");
            }
            ExitCode::from(7)
        }
    }
}

fn write_output(resp: &Response, args: &Args) -> io::Result<()> {
    let mut out: Box<dyn Write> = match &args.output {
        Some(path) if path != "-" => Box::new(File::create(path)?),
        _ => Box::new(io::stdout().lock()),
    };
    if args.include_headers {
        write!(out, "{} {} {}\r\n", resp.version, resp.status, resp.reason)?;
        for (k, v) in &resp.headers {
            write!(out, "{k}: {v}\r\n")?;
        }
        out.write_all(b"\r\n")?;
    }
    out.write_all(&resp.body)?;
    Ok(())
}

fn print_usage() {
    println!(
        "curlrs {VERSION} — a pure-Rust curl

Usage: curlrs [options] <url>

Options:
  -o, --output <file>      write body to file instead of stdout
  -i, --include            include response headers in the output
  -I, --head               issue HEAD instead of GET
  -v, --verbose            print request/response headers to stderr
  -s, --silent             suppress error messages
  -X, --request <method>   override HTTP method
  -H, --header <line>      add a request header (repeatable)
  -d, --data <body>        send body and switch method to POST
  -A, --user-agent <ua>    set User-Agent
  -e, --referer <ref>      set Referer
      --http2              require HTTP/2 (ALPN h2); error if unavailable
      --http1.1            force HTTP/1.1 (alias: --http1)
  -h, --help               print this help
  -V, --version            print version
"
    );
}
