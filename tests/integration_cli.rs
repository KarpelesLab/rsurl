//! End-to-end tests of `rsurl` command-line semantics that must match curl:
//! option parsing, output pairing, header forms, write-out, resume, exit codes.
//! Each test drives the real binary against the in-process test server.

mod common;

use std::io::Write;
use std::process::{Output, Stdio};
use std::time::Duration;

use common::{Request as SReq, Response as SResp, TestServer};

/// The `rsurl` binary under test, isolated from the developer's environment:
/// inherited `http_proxy`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY` would otherwise
/// route requests through an unrelated proxy and fail the test spuriously.
fn rsurl_cmd() -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_rsurl"));
    for var in [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

fn run(args: &[&str]) -> Output {
    rsurl_cmd()
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn rsurl")
}

fn run_with_stdin(args: &[&str], input: &[u8]) -> Output {
    let mut child = rsurl_cmd()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rsurl");
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().expect("wait rsurl")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("rsurl-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Echo the request headers back, one `name: value` line each (lower-cased
/// names), so a test can inspect exactly what went on the wire.
fn header_echo(req: SReq) -> SResp {
    let mut body = String::new();
    for (k, v) in &req.headers {
        body.push_str(&format!("{}: {}\n", k.to_ascii_lowercase(), v));
    }
    SResp::ok(body)
}

#[test]
fn outputs_pair_with_urls_positionally() {
    let server = TestServer::start(|req: SReq| SResp::ok(req.path.trim_start_matches('/')));
    let dir = temp_dir("pair");
    let (a, b) = (dir.join("a"), dir.join("b"));
    let out = run(&[
        "-s",
        "-o",
        a.to_str().unwrap(),
        &server.url("/one"),
        "-o",
        b.to_str().unwrap(),
        &server.url("/two"),
    ]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(std::fs::read_to_string(&a).unwrap(), "one");
    assert_eq!(std::fs::read_to_string(&b).unwrap(), "two");

    // A URL beyond the last -o goes to stdout, not into the earlier file.
    let c = dir.join("c");
    let out = run(&[
        "-s",
        "-o",
        c.to_str().unwrap(),
        &server.url("/first"),
        &server.url("/second"),
    ]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(std::fs::read_to_string(&c).unwrap(), "first");
    assert_eq!(stdout(&out), "second");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dump_header_dash_writes_headers_to_stdout() {
    let server = TestServer::start(|_req: SReq| SResp::ok("body").header("X-Probe", "yes"));
    let dir = temp_dir("dumphdr");
    let f = dir.join("out");
    let out = run(&["-s", "-D", "-", "-o", f.to_str().unwrap(), &server.url("/")]);
    assert!(out.status.success(), "{out:?}");
    let s = stdout(&out);
    assert!(s.starts_with("HTTP/1.1 200"), "{s:?}");
    assert!(s.contains("X-Probe: yes\r\n"), "{s:?}");
    assert!(
        !dir.join("-").exists(),
        "-D - must not create a file named '-'"
    );
    assert_eq!(std::fs::read_to_string(&f).unwrap(), "body");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn option_values_starting_with_dash_and_end_of_options() {
    let server = TestServer::start(|req: SReq| SResp::ok(req.body));
    // `-d -name=x`: the value is data, not a bundle of short options.
    let out = run(&["-s", "-d", "-name=x", &server.url("/")]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(stdout(&out), "-name=x");
    // `--` ends option parsing.
    let out = run(&["-s", "--", &server.url("/")]);
    assert!(out.status.success(), "{out:?}");
}

#[test]
fn header_remove_empty_and_override_forms() {
    let server = TestServer::start(header_echo);
    let url = server.url("/");

    // `-H "User-Agent: x"` replaces -A's value instead of adding a second one.
    let s = stdout(&run(&["-s", "-A", "foo", "-H", "User-Agent: bar", &url]));
    let uas: Vec<&str> = s.lines().filter(|l| l.starts_with("user-agent:")).collect();
    assert_eq!(uas, vec!["user-agent: bar"], "{s:?}");

    // `-H "User-Agent:"` removes the header; other defaults stay.
    let s = stdout(&run(&["-s", "-H", "User-Agent:", &url]));
    assert!(!s.contains("user-agent:"), "{s:?}");
    assert!(s.contains("accept: */*"), "{s:?}");

    // Removing a default must not drop -u credentials.
    let s = stdout(&run(&["-s", "-u", "a:b", "-H", "Accept:", &url]));
    assert!(!s.contains("accept:"), "{s:?}");
    assert!(s.contains("authorization: Basic YTpi"), "{s:?}");

    // `-H "X-Empty;"` sends the header with an empty value.
    let s = stdout(&run(&["-s", "-H", "X-Empty;", &url]));
    assert!(s.lines().any(|l| l.trim_end() == "x-empty:"), "{s:?}");
}

#[test]
fn write_out_reports_failures_and_final_url() {
    // Connection refused: curl still prints -w, with http_code 000.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let out = run(&[
        "-s",
        "-w",
        "%{http_code} %{exitcode}",
        &format!("http://127.0.0.1:{port}/"),
    ]);
    assert_eq!(out.status.code(), Some(7), "{out:?}");
    assert_eq!(stdout(&out), "000 7");

    // After -L, url_effective is the final URL.
    let server = TestServer::start(|req: SReq| {
        if req.path == "/start" {
            SResp::status(302).header("Location", "/landed")
        } else {
            SResp::ok("")
        }
    });
    let out = run(&["-s", "-L", "-w", "%{url_effective}", &server.url("/start")]);
    assert!(out.status.success(), "{out:?}");
    assert!(stdout(&out).ends_with("/landed"), "{:?}", stdout(&out));
}

#[test]
fn custom_method_survives_redirects() {
    let server = TestServer::start(|req: SReq| {
        if req.path == "/r" {
            SResp::status(302).header("Location", "/dest")
        } else {
            SResp::ok(req.method)
        }
    });
    // curl sends the -X method on every request, redirects included.
    let out = run(&["-s", "-L", "-X", "PUT", &server.url("/r")]);
    assert_eq!(stdout(&out), "PUT");
    // Without -X, a POST is still rewritten to GET on 302 (curl semantics).
    let out = run(&["-s", "-L", "-d", "x", &server.url("/r")]);
    assert_eq!(stdout(&out), "GET");
}

#[test]
fn stdin_inputs() {
    let server = TestServer::start(|req: SReq| {
        SResp::ok(format!(
            "{} {}",
            req.method,
            String::from_utf8_lossy(&req.body)
        ))
    });
    let url = server.url("/");
    let out = run_with_stdin(&["-s", "--data-binary", "@-", &url], b"from\nstdin");
    assert_eq!(stdout(&out), "POST from\nstdin");
    let out = run_with_stdin(&["-s", "-d", "@-", &url], b"a\r\nb");
    assert_eq!(
        stdout(&out),
        "POST ab",
        "-d @- strips newlines like -d @file"
    );
    let out = run_with_stdin(&["-s", "-T", "-", &url], b"upload");
    assert_eq!(stdout(&out), "PUT upload");
    // -K - reads the config from stdin.
    let cfg = format!("silent\nurl = \"{url}\"\n");
    let out = run_with_stdin(&["-K", "-"], cfg.as_bytes());
    assert!(out.status.success(), "{out:?}");
    assert_eq!(stdout(&out), "GET ");
}

#[test]
fn fractional_timeouts_and_url_query() {
    let server = TestServer::start(|req: SReq| SResp::ok(req.path));
    let out = run(&[
        "-s",
        "-m",
        "2.5",
        "--connect-timeout",
        "0.5",
        "--url-query",
        "a=b c",
        "--url-query",
        "+raw=%41",
        &server.url("/q?x=1"),
    ]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(stdout(&out), "/q?x=1&a=b+c&raw=%41");
}

#[test]
fn glob_errors_and_ipv6_literals() {
    // A reversed range is a malformed glob: exit 3, like curl.
    let out = run(&["-s", "http://127.0.0.1:1/[5-1]"]);
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    // A bracketed IPv6 literal is not a glob: it gets as far as connecting.
    let out = run(&["-s", "--connect-timeout", "2", "http://[::1]:1/"]);
    assert_ne!(out.status.code(), Some(3), "{out:?}");
}

#[test]
fn remote_time_stamps_the_file_actually_written() {
    let server = TestServer::start(|_req: SReq| {
        SResp::ok("x").header("Last-Modified", "Sun, 06 Nov 1994 08:49:37 GMT")
    });
    let dir = temp_dir("rtime");
    for extra in [&[][..], &["-f"][..]] {
        let name = format!("f{}", extra.len());
        let mut args = vec![
            "-s",
            "-R",
            "--output-dir",
            dir.to_str().unwrap(),
            "-o",
            &name,
        ];
        args.extend_from_slice(extra);
        let url = server.url("/");
        args.push(&url);
        let out = run(&args);
        assert!(out.status.success(), "{out:?}");
        let mtime = std::fs::metadata(dir.join(&name))
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        assert_eq!(mtime, Duration::from_secs(784_111_777), "{extra:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Serves "hello world", honouring `Range: bytes=N-` unless told otherwise.
fn range_server(mode: &'static str) -> TestServer {
    TestServer::start(move |req: SReq| {
        const FULL: &str = "hello world";
        let start = req
            .header("range")
            .and_then(|r| r.strip_prefix("bytes="))
            .and_then(|r| r.strip_suffix('-'))
            .and_then(|n| n.parse::<usize>().ok());
        match (mode, start) {
            ("ignore", _) | (_, None) => SResp::ok(FULL),
            (_, Some(n)) if n >= FULL.len() => {
                SResp::status(416).header("Content-Range", &format!("bytes */{}", FULL.len()))
            }
            (_, Some(n)) => SResp::status(206)
                .header(
                    "Content-Range",
                    &format!("bytes {n}-{}/{}", FULL.len() - 1, FULL.len()),
                )
                .body(&FULL[n..]),
        }
    })
}

#[test]
fn continue_at_resumes_http_downloads() {
    let dir = temp_dir("resume");
    let f = dir.join("file");
    let fs = f.to_str().unwrap();

    // -C - continues from the existing file's size.
    let server = range_server("honour");
    std::fs::write(&f, "hello ").unwrap();
    let out = run(&["-s", "-C", "-", "-o", fs, &server.url("/")]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(std::fs::read_to_string(&f).unwrap(), "hello world");

    // -C <N> uses the given offset.
    std::fs::write(&f, "hello ").unwrap();
    let out = run(&["-s", "-C", "6", "-o", fs, &server.url("/")]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(std::fs::read_to_string(&f).unwrap(), "hello world");

    // Already complete: 416 is success and the file is left alone.
    let out = run(&["-s", "-C", "-", "-o", fs, &server.url("/")]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(std::fs::read_to_string(&f).unwrap(), "hello world");

    // A server that ignores Range: curl's exit 33, file untouched.
    let ignoring = range_server("ignore");
    std::fs::write(&f, "hello ").unwrap();
    let out = run(&["-s", "-C", "-", "-o", fs, &ignoring.url("/")]);
    assert_eq!(out.status.code(), Some(33), "{out:?}");
    assert_eq!(std::fs::read_to_string(&f).unwrap(), "hello ");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn max_filesize_applies_when_streaming_to_stdout() {
    let server = TestServer::start(|_req: SReq| SResp::ok(vec![b'x'; 64 * 1024]));
    let out = run(&["-s", "--max-filesize", "1000", &server.url("/")]);
    assert_eq!(out.status.code(), Some(63), "{out:?}");
    assert!(out.stdout.len() <= 1000, "wrote {} bytes", out.stdout.len());
    // Under the cap, the body streams through intact.
    let out = run(&["-s", "--max-filesize", "100000", &server.url("/")]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout.len(), 64 * 1024);
}

#[test]
fn unreadable_tls_files_exit_with_curl_codes() {
    let out = run(&[
        "-s",
        "--cacert",
        "/nonexistent/ca.pem",
        "https://127.0.0.1:1/",
    ]);
    assert_eq!(out.status.code(), Some(77), "{out:?}");
    let out = run(&[
        "-s",
        "-E",
        "/nonexistent/client.pem",
        "https://127.0.0.1:1/",
    ]);
    assert_eq!(out.status.code(), Some(58), "{out:?}");
}

/// A one-connection POP3 server that answers `+OK` to everything, serves
/// message 1 on `RETR`, and records every command line it received.
fn pop3_mock() -> (u16, std::thread::JoinHandle<Vec<String>>) {
    use std::io::{BufRead, BufReader};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let mut w = sock.try_clone().unwrap();
        let mut r = BufReader::new(sock);
        let mut seen = Vec::new();
        w.write_all(b"+OK ready\r\n").unwrap();
        let mut line = String::new();
        while r.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
            let cmd = line.trim_end().to_string();
            line.clear();
            let reply: &[u8] = if cmd.starts_with("STLS") || cmd.starts_with("CAPA") {
                b"-ERR no\r\n"
            } else if cmd.starts_with("RETR") {
                b"+OK\r\nSubject: hi\r\n\r\nbody\r\n.\r\n"
            } else {
                b"+OK\r\n"
            };
            let quit = cmd == "QUIT";
            seen.push(cmd);
            let _ = w.write_all(reply);
            if quit {
                break;
            }
        }
        seen
    });
    (port, h)
}

/// curl applies `-u user:pass` to the login-based non-HTTP protocols, overriding
/// URL userinfo; special characters in the password survive intact.
#[test]
fn user_flag_applies_to_pop3_and_overrides_url_userinfo() {
    let (port, h) = pop3_mock();
    let out = run(&[
        "-s",
        "-u",
        "alice:p@ss:w%rd",
        &format!("pop3://bob:wrong@127.0.0.1:{port}/1"),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout(&out).contains("body"));
    let seen = h.join().unwrap();
    assert!(seen.contains(&"USER alice".to_string()), "{seen:?}");
    assert!(seen.contains(&"PASS p@ss:w%rd".to_string()), "{seen:?}");
}

/// Percent-encoded URL userinfo is decoded before login (`%40` → `@`).
#[test]
fn pop3_url_userinfo_is_percent_decoded() {
    let (port, h) = pop3_mock();
    let out = run(&[
        "-s",
        &format!("pop3://bob%40example.com:s%3Acret@127.0.0.1:{port}/1"),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let seen = h.join().unwrap();
    assert!(
        seen.contains(&"USER bob@example.com".to_string()),
        "{seen:?}"
    );
    assert!(seen.contains(&"PASS s:cret".to_string()), "{seen:?}");
}

/// `-T file tftp://[::1]:port/name` uploads over IPv6. The CLI used to call a
/// store path that always bound an IPv4 socket, so IPv6 servers (and `-x`
/// SOCKS5) were unreachable for uploads.
#[test]
fn tftp_upload_reaches_ipv6_server() {
    let Ok(server) = std::net::UdpSocket::bind("[::1]:0") else {
        eprintln!("skipping: no IPv6 loopback");
        return;
    };
    let port = server.local_addr().unwrap().port();
    server
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let h = std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        let (n, peer) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..2], &[0, 2], "expected WRQ");
        let name_end = buf[2..n].iter().position(|&b| b == 0).unwrap() + 2;
        let name = String::from_utf8_lossy(&buf[2..name_end]).into_owned();
        server.send_to(&[0, 4, 0, 0], peer).unwrap();
        let mut data = Vec::new();
        loop {
            let (n, _) = server.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..2], &[0, 3], "expected DATA");
            data.extend_from_slice(&buf[4..n]);
            server.send_to(&[0, 4, buf[2], buf[3]], peer).unwrap();
            if n - 4 < 512 {
                break;
            }
        }
        (name, data)
    });
    let dir = temp_dir("tftp6");
    let src = dir.join("up.txt");
    std::fs::write(&src, b"over ipv6").unwrap();
    let out = run(&[
        "-s",
        "-T",
        src.to_str().unwrap(),
        &format!("tftp://[::1]:{port}/remote.txt"),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (name, data) = h.join().unwrap();
    assert_eq!(name, "remote.txt");
    assert_eq!(data, b"over ipv6");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Per-hop NO_PROXY for SOCKS proxies
// ---------------------------------------------------------------------------

/// A minimal SOCKS5 (no-auth) proxy: records each requested `host:port` and
/// pipes the connection to it. Returns the proxy port and the target log.
fn start_socks5_mock() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        for sock in listener.incoming() {
            let Ok(mut c) = sock else { return };
            let log = log2.clone();
            std::thread::spawn(move || {
                let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
                let mut hdr = [0u8; 2];
                if c.read_exact(&mut hdr).is_err() {
                    return;
                }
                let mut methods = vec![0u8; hdr[1] as usize];
                c.read_exact(&mut methods).unwrap();
                c.write_all(&[5, 0]).unwrap();
                let mut req = [0u8; 4];
                c.read_exact(&mut req).unwrap();
                let host = match req[3] {
                    1 => {
                        let mut a = [0u8; 4];
                        c.read_exact(&mut a).unwrap();
                        std::net::Ipv4Addr::from(a).to_string()
                    }
                    3 => {
                        let mut l = [0u8; 1];
                        c.read_exact(&mut l).unwrap();
                        let mut n = vec![0u8; l[0] as usize];
                        c.read_exact(&mut n).unwrap();
                        String::from_utf8(n).unwrap()
                    }
                    _ => {
                        let mut a = [0u8; 16];
                        c.read_exact(&mut a).unwrap();
                        format!("[{}]", std::net::Ipv6Addr::from(a))
                    }
                };
                let mut p = [0u8; 2];
                c.read_exact(&mut p).unwrap();
                let tport = u16::from_be_bytes(p);
                log.lock().unwrap().push(format!("{host}:{tport}"));
                let Ok(up) = TcpStream::connect((host.trim_matches(['[', ']']), tport)) else {
                    let _ = c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
                    return;
                };
                c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                let _ = c.set_read_timeout(None);
                let (mut c2, mut up2) = (c.try_clone().unwrap(), up.try_clone().unwrap());
                let mut up = up;
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut c2, &mut up2);
                    let _ = up2.shutdown(std::net::Shutdown::Write);
                });
                let _ = std::io::copy(&mut up, &mut c);
                let _ = c.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    (port, log)
}

/// A redirect from a NO_PROXY host (`localhost`, dialed directly) to an
/// external one (`127.0.0.1`) must go through the SOCKS proxy. The connector
/// used to be chosen once from the first host, so the second hop went out
/// directly, bypassing a mandatory proxy.
#[test]
fn socks_noproxy_redirect_internal_to_external_uses_proxy() {
    let external = TestServer::start(|_| SResp::ok("external"));
    let ext_port = external.addr.port();
    let internal = TestServer::start(move |_| {
        SResp::status(302).header("Location", &format!("http://127.0.0.1:{ext_port}/final"))
    });
    let (sport, log) = start_socks5_mock();
    let out = run(&[
        "-s",
        "-L",
        "-x",
        &format!("socks5h://127.0.0.1:{sport}"),
        "--noproxy",
        "localhost",
        &format!("http://localhost:{}/start", internal.addr.port()),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"external");
    assert_eq!(
        *log.lock().unwrap(),
        vec![format!("127.0.0.1:{ext_port}")],
        "only the external hop may use the proxy"
    );
}

/// And the reverse: a proxied first hop redirecting to a NO_PROXY host must
/// reach that host directly, not through the proxy.
#[test]
fn socks_noproxy_redirect_external_to_internal_goes_direct() {
    let internal = TestServer::start(|_| SResp::ok("internal"));
    let int_port = internal.addr.port();
    let external = TestServer::start(move |_| {
        SResp::status(302).header("Location", &format!("http://localhost:{int_port}/final"))
    });
    let ext_port = external.addr.port();
    let (sport, log) = start_socks5_mock();
    let out = run(&[
        "-s",
        "-L",
        "-x",
        &format!("socks5h://127.0.0.1:{sport}"),
        "--noproxy",
        "localhost",
        &format!("http://127.0.0.1:{ext_port}/start"),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"internal");
    assert_eq!(
        *log.lock().unwrap(),
        vec![format!("127.0.0.1:{ext_port}")],
        "the NO_PROXY hop must not use the proxy"
    );
}

// ---------------------------------------------------------------------------
// --proxy-* TLS options (HTTPS proxy)
// ---------------------------------------------------------------------------

/// A mock `https://` proxy presenting a `localhost` certificate issued by a
/// private test CA (so it is untrusted by default). After `CONNECT` it serves
/// the tunnelled request itself: plain HTTP answers `via-proxy`, and a TLS
/// ClientHello gets a second (origin) TLS session with the same untrusted
/// certificate, answering `via-proxy-tls`.
#[cfg(feature = "rustls-tls")]
mod https_proxy {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::time::Duration;

    // Same test CA / `localhost` leaf as the crate's rustls unit tests.
    pub const CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBhzCCAS2gAwIBAgIUEJAJGguFhUu6Wi64F9FYb6oJ9bkwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNcnN1cmwtdGVzdC1jYTAgFw0yNjA2MjEyMzI2MjFaGA8yMTI2
MDUyODIzMjYyMVowGDEWMBQGA1UEAwwNcnN1cmwtdGVzdC1jYTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABGvezLhNMu/DJw3ClBkhcK571eQz/QctqGAf1whkMiXf
Sj46b9bBymWIV706DP/x2nXzSJgiXTv9rnTli35el0CjUzBRMB0GA1UdDgQWBBQU
AOFhWcYfxuM+R86kRFZWr/KATzAfBgNVHSMEGDAWgBQUAOFhWcYfxuM+R86kRFZW
r/KATzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIBWUfubWKWST
arQvZPn0jqXOwKG0x+xYs5UtcjVf3vOiAiEAlxoTAAh0nVLMrmTsnJXD131iPHz7
Uk3Wt1xw1blCE/8=
-----END CERTIFICATE-----
";

    const LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBuDCCAV2gAwIBAgIUcMudt8JBWAsDX8h+3CC46SiY14EwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNcnN1cmwtdGVzdC1jYTAgFw0yNjA2MjEyMzI2MjFaGA8yMTI2
MDUyODIzMjYyMVowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEuBVdUYNtZqpWDO9h4nw0HF9sTKT3R7p/WJYsNgIfeO4hi/AM
9x+n7MP1tYi6zPlfR6qG/ZbEJLFDzZShfHPc/KOBhjCBgzAUBgNVHREEDTALggls
b2NhbGhvc3QwCQYDVR0TBAIwADALBgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwHQYDVR0OBBYEFAAZvjmK2EXoiEDqFV3wFGMS8GBJMB8GA1UdIwQYMBaA
FBQA4WFZxh/G4z5HzqREVlav8oBPMAoGCCqGSM49BAMCA0kAMEYCIQCPQPF3G07F
EhDmMDPLFGbF/ZdfuDFfBN6Sjs3DuIgSXAIhAMGqymq6vFwXRbvrhbGljFfJQjtz
98VOQz3xfzdRnPC2
-----END CERTIFICATE-----
";

    const LEAF_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8mp/gpytQtzNMwlE
fXfhylHGgcKzHtmkPeil9MKfoSyhRANCAAS4FV1Rg21mqlYM72HifDQcX2xMpPdH
un9Yliw2Ah947iGL8Az3H6fsw/W1iLrM+V9Hqob9lsQksUPNlKF8c9z8
-----END PRIVATE KEY-----
";

    fn server_config() -> Arc<rustls::ServerConfig> {
        let certs = rustls_pemfile::certs(&mut LEAF_CERT_PEM.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut LEAF_KEY_PEM.as_bytes())
            .unwrap()
            .unwrap();
        Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap(),
        )
    }

    /// Read an HTTP head (up to the blank line) byte by byte.
    fn read_head<R: Read>(r: &mut R) -> Option<String> {
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match r.read(&mut b) {
                Ok(1) => head.push(b[0]),
                _ => return None,
            }
        }
        Some(String::from_utf8_lossy(&head).into_owned())
    }

    /// The tunnel after `CONNECT`, with one already-read byte pushed back.
    struct Prefixed<S> {
        first: Option<u8>,
        inner: S,
    }
    impl<S: Read> Read for Prefixed<S> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.first.take() {
                Some(b) if !buf.is_empty() => {
                    buf[0] = b;
                    Ok(1)
                }
                _ => self.inner.read(buf),
            }
        }
    }
    impl<S: Write> Write for Prefixed<S> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    fn respond<S: Write>(s: &mut S, body: &str) {
        let _ = write!(
            s,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = s.flush();
    }

    fn serve(sock: TcpStream, cfg: Arc<rustls::ServerConfig>) {
        let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
        let conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        // A client that rejects the proxy certificate aborts here.
        let Some(head) = read_head(&mut tls) else {
            return;
        };
        if !head.starts_with("CONNECT ") {
            return;
        }
        let _ = tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
        let _ = tls.flush();
        let mut first = [0u8; 1];
        if tls.read_exact(&mut first).is_err() {
            return;
        }
        let mut tunnel = Prefixed {
            first: Some(first[0]),
            inner: tls,
        };
        if first[0] == 0x16 {
            // TLS to the origin, inside the proxy's TLS session.
            let mut origin = rustls::ServerConnection::new(cfg).unwrap();
            let mut s = rustls::Stream::new(&mut origin, &mut tunnel);
            if read_head(&mut s).is_some() {
                respond(&mut s, "via-proxy-tls");
                s.conn.send_close_notify();
                let _ = s.flush();
            }
        } else if read_head(&mut tunnel).is_some() {
            respond(&mut tunnel, "via-proxy");
        }
        tunnel.inner.conn.send_close_notify();
        let _ = tunnel.inner.flush();
    }

    /// Start the mock proxy; returns its port.
    pub fn start() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = server_config();
        std::thread::spawn(move || {
            for sock in listener.incoming() {
                let Ok(sock) = sock else { return };
                let cfg = cfg.clone();
                std::thread::spawn(move || serve(sock, cfg));
            }
        });
        port
    }
}

#[cfg(feature = "rustls-tls")]
fn run_via_https_proxy(extra: &[&str], url: &str) -> Output {
    let port = https_proxy::start();
    let proxy = format!("https://localhost:{port}");
    let mut args = vec!["-s", "-x", &proxy];
    args.extend_from_slice(extra);
    args.push(url);
    run(&args)
}

/// The untrusted proxy certificate is rejected by default, and `-k` (which
/// only concerns the origin) must not relax proxy verification.
#[cfg(feature = "rustls-tls")]
#[test]
fn https_proxy_untrusted_cert_rejected_by_default_and_with_k() {
    for extra in [&[][..], &["-k"][..]] {
        let out = run_via_https_proxy(extra, "http://origin.test/");
        assert!(
            !out.status.success(),
            "{extra:?}: an untrusted https proxy must be rejected"
        );
        assert!(out.stdout.is_empty(), "{extra:?}");
    }
}

/// `--proxy-insecure` accepts the untrusted proxy; `--proxy-cacert` trusts it.
#[cfg(feature = "rustls-tls")]
#[test]
fn https_proxy_insecure_and_cacert_accept_proxy() {
    let out = run_via_https_proxy(&["--proxy-insecure"], "http://origin.test/");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"via-proxy");

    let dir = temp_dir("proxy-cacert");
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, https_proxy::CA_CERT_PEM).unwrap();
    let out = run_via_https_proxy(
        &["--proxy-cacert", ca.to_str().unwrap()],
        "http://origin.test/",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"via-proxy");

    // A wrong proxy pin fails even with --proxy-insecure.
    let out = run_via_https_proxy(
        &[
            "--proxy-insecure",
            "--proxy-pinnedpubkey",
            "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ],
        "http://origin.test/",
    );
    assert!(!out.status.success(), "a proxy pin mismatch must fail");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--proxy-insecure` must not relax *origin* verification: an https origin
/// with an untrusted certificate behind the proxy is still rejected, and is
/// accepted once the origin's own `--cacert` (or `-k`) trusts it.
#[cfg(feature = "rustls-tls")]
#[test]
fn https_proxy_insecure_keeps_origin_verification() {
    let out = run_via_https_proxy(&["--proxy-insecure"], "https://localhost/");
    assert!(
        !out.status.success(),
        "--proxy-insecure must not disable origin verification"
    );
    assert!(out.stdout.is_empty());

    let dir = temp_dir("proxy-origin-ca");
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, https_proxy::CA_CERT_PEM).unwrap();
    let out = run_via_https_proxy(
        &["--proxy-insecure", "--cacert", ca.to_str().unwrap()],
        "https://localhost/",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"via-proxy-tls");

    // Proxy and origin each trusted by their own flag.
    let out = run_via_https_proxy(
        &["--proxy-cacert", ca.to_str().unwrap(), "-k"],
        "https://localhost/",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"via-proxy-tls");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A missing `--proxy-cacert` file fails early with curl's exit code 77.
#[test]
fn proxy_cacert_missing_file_exits_77() {
    let out = run(&[
        "-s",
        "-x",
        "https://127.0.0.1:9",
        "--proxy-cacert",
        "/nonexistent/rsurl-proxy-ca.pem",
        "http://origin.test/",
    ]);
    assert_eq!(out.status.code(), Some(77));
}

/// `-m` is a whole-transfer deadline for non-HTTP schemes too: a DICT server
/// that trickles its banner one byte every 100 ms (so no single read ever
/// idles out) must still be cut off after ~1 s with curl's exit 28.
#[test]
fn max_time_bounds_a_trickling_non_http_transfer() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let Ok((mut s, _)) = listener.accept() else {
            return;
        };
        for _ in 0..100 {
            if s.write_all(b"2").is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    let start = std::time::Instant::now();
    let out = run(&["-s", "-m", "1", &format!("dict://127.0.0.1:{port}/d:word")]);
    let took = start.elapsed();
    assert_eq!(out.status.code(), Some(28), "{out:?}");
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_millis(2500),
        "took {took:?}"
    );
}
