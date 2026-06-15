# rsurl

[![CI](https://github.com/KarpelesLab/rsurl/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/rsurl/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/rsurl.svg)](https://crates.io/crates/rsurl)
[![Docs.rs](https://docs.rs/rsurl/badge.svg)](https://docs.rs/rsurl)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A pure-Rust implementation of curl, built on top of [purecrypto](https://crates.io/crates/purecrypto)
for TLS and [puressh](https://crates.io/crates/puressh) for SSH (SFTP/SCP) —
no OpenSSL, no system libcurl, no C dependencies. (The SSH stack pulls only
`libc`/`nix` on unix, which are pure-Rust FFI *bindings* — no compiled C, no
`*-sys`/cmake/bindgen in the default build.)

`rsurl` ships in three forms:

1. **Rust library** (`rsurl` crate) — a small, ergonomic HTTP client API for Rust projects.
2. **C library** (`librsurl.so` / `rsurl.h`) — a curl-compatible C ABI for non-Rust consumers.
3. **`rsurl` CLI** — a drop-in-ish replacement for the `curl` command line.

## Status

Early, in active development.

| Capability | Status | Notes |
|---|---|---|
| HTTP/1.1 (all methods) | working | Content-Length, chunked, read-to-EOF body modes |
| Connection reuse | working | process-wide keep-alive pool for HTTP/1.1 (plain & TLS) and HTTP/2 (post-handshake conns keyed on scheme/host/port, reused across requests) |
| Response compression | working | `gzip` / `deflate` / `x-gzip` / `zstd` / `br` / `compress` / `x-compress` (Unix `.Z` LZW) decoded transparently (always-on) |
| Cookies (`-b` / `-c`) | working | RFC 6265 jar; Netscape `cookies.txt` I/O, curl-compatible |
| Proxies (`-x`) | working | HTTP (absolute-form / `CONNECT`), HTTPS-to-proxy, and SOCKS4/4a/5/5h — including SOCKS5 UDP ASSOCIATE for HTTP/3 & TFTP. Basic/`Proxy-Authorization` + SOCKS5 user/pass auth, `--noproxy` / `*_PROXY` env vars. Honoured across every scheme, not just HTTP |
| Custom transport | working | implement `rsurl::net::Connector` (or `UdpProxy`) and pass it via `Client::connector` / `Request::connector` to supply your own sockets, pool, or test double |
| HTTPS via purecrypto | working | TLS 1.2/1.3, system roots, full cert verification |
| HTTP/2 (RFC 9113) | working* | ALPN h2, HPACK + Huffman decoder; connection- and stream-level flow control (WINDOW_UPDATE, INITIAL_WINDOW_SIZE deltas); process-wide connection pool reuses a warm conn across requests, advancing stream ids 1/3/5 (sequential reuse). True concurrent multiplexing — many in-flight streams on one connection, interleaved frame I/O, non-blocking body sends with no head-of-line stall, queueing at `SETTINGS_MAX_CONCURRENT_STREAMS`, per-stream RST + GOAWAY demux — is available as the `rsurl::send_multiplexed` library API (see below); the CLI still issues one request at a time |
| HTTP/3 over QUIC (RFC 9114) | working\*\* | reachable via `--http3` (try h3, fall back to HTTP/2/1.1 on a QUIC transport failure) and `--http3-only` (force h3, no fallback). QUIC + frame layer + QPACK static/dynamic tables and Huffman decoder; advertises a non-zero `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (blocked-streams 0), applies the peer's encoder-stream inserts and resolves dynamic / post-base field-line refs, acks sections on the decoder stream; the request encoder still emits literals only; honors `--cacert`/`-k` |
| FTP / FTPS (RFC 959, 4217) | working | RETR + LIST, STOR upload (`-T`) with REST resume (`-C`) or APPE append (`-a`), EPSV with PASV fallback, implicit FTPS |
| FILE (RFC 8089) | working | rejects non-local hosts |
| DICT (RFC 2229) | working | DEFINE, MATCH, SHOW DATABASES |
| GOPHER / GOPHERS (RFC 1436) | working | reads to EOF; item-type 7 search via `?<words>` (sends `selector\t<words>`) |
| IMAP / IMAPS (RFC 9051) | working | CAPABILITY probe, STARTTLS upgrade (RFC 2595), SASL AUTHENTICATE PLAIN/LOGIN with LOGIN-command fallback (honors LOGINDISABLED); LIST / SELECT+FETCH / UID FETCH BODY[] |
| LDAP / LDAPS (RFC 4511) | working | simple bind + search → LDIF; filter syntax: equality, presence, substring (`cn=foo*bar*`), extensible match (`cn:dn:caseIgnoreMatch:=foo`), and `& \| !` |
| MQTT / MQTTS (v3.1.1) | working | CONNECT; SUBSCRIBE + receive one PUBLISH (QoS 0); PUBLISH via `-d`/`-T` at QoS 0 (default, matches curl) or QoS 1 (PUBLISH→PUBACK) in the protocol layer |
| POP3 / POP3S (RFC 1939) | working | LIST or RETR, USER/PASS auth |
| RTSP (RFC 7826) | working | OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN via `-X` with CSeq + Session tracking (interleaved transport); RTP media reception not implemented |
| TFTP (RFC 1350) | working | read (RRQ) and write/upload (`-T`, WRQ) with timeout/retry, 256 MiB cap |
| SFTP (SSH) | working | download + upload (`-T`) over the SFTP subsystem (`open`/`read`/`write`/`close`); password (`-u`/userinfo) and public-key (`--key` or `~/.ssh/id_*`) auth; host-key verification via `~/.ssh/known_hosts` (TOFU: accept+persist unknown, reject changed; `-k` ⇒ accept-any). Via the pure-Rust `puressh` crate |
| SCP (SSH) | working | download + upload (`-T`) driving the remote `scp -f`/`scp -t` helper, bridged through a temp file; same auth + known_hosts TOFU as SFTP. Via `puressh` |
| WS / WSS (RFC 6455) | working | send + receive data frames, fragmented message reassembly, ping/pong/close handling; permessage-deflate (RFC 7692) negotiated in the upgrade — per-message inflate/deflate with RSV1, `client/server_no_context_takeover`, inflated-size cap against compression bombs |

\* HTTP/2 verified live against nghttp2.org and cloudflare.com from the implementation
worktree. Available via `--http2` (force) or auto-negotiated via ALPN.

### HTTP/2 concurrent multiplexing (`send_multiplexed`)

`rsurl::send_multiplexed(reqs: Vec<Request>, trace) -> Vec<Result<Response>>`
fans out a batch of requests to **one** `https://` origin concurrently over a
**single** HTTP/2 connection, returning one result per request in input order:

```rust
use rsurl::{Request, send_multiplexed};

let reqs = vec![
    Request::get("https://nghttp2.org/").unwrap(),
    Request::get("https://nghttp2.org/httpbin/get").unwrap(),
];
let results = send_multiplexed(reqs, &mut std::io::sink());
for r in results {
    println!("{}", r.unwrap().status);
}
```

How it works: the batch opens a stream per request up to the peer's
`SETTINGS_MAX_CONCURRENT_STREAMS` (queueing the rest), then drives all streams
from one frame loop. Request bodies are sent **non-blocking** — each pump pass
writes whatever the connection and per-stream send windows allow across every
stream, so a body that exhausts its window yields to the others and resumes when
a `WINDOW_UPDATE` arrives (no head-of-line blocking). Inbound frames are
demultiplexed to their stream by id; each request gets its own `Response`. A
single stream's `RST_STREAM` (or per-stream protocol error) fails only that
request while the others complete; a `GOAWAY` fails streams above the advertised
last-stream-id and lets the lower ones finish. The connection is returned to the
pool when still usable. Mixed-origin, non-`https`, or non-pool-eligible (`-k` /
`--cacert`) batches fall back to issuing each request sequentially, still
returning correct in-order results. The `-v` trace labels lines per stream
(`> [stream 3] GET …`, `< [stream 3] HTTP/2 200`) so interleaved output stays
readable.

The **CLI deliberately does not** auto-multiplex multiple URLs: it processes
URLs one at a time so the shared cookie jar, per-URL output ordering, and
per-URL exit codes stay exactly curl-compatible. Concurrent multiplexing is
exposed as the library API above rather than forced into the CLI loop.

\*\* HTTP/3 verified live end-to-end against `quic.nginx.org` and `www.google.com`
(QUIC handshake completed, request sent, real `HTTP/3 200` + headers + body
returned). Cloudflare's QUIC endpoints (`cloudflare-quic.com`,
`www.cloudflare.com`) currently fail at the QUIC packet-decode step
(`http3: feed: Decode`) against purecrypto's QUIC stack — under `--http3` this
triggers the documented fallback to HTTP/2; under `--http3-only` it is a hard
error. So h3 works against some major servers but is not yet universal.

System CA bundle paths searched, in order: `/etc/ssl/certs/ca-certificates.crt`,
`/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/cert.pem`, `/etc/ssl/ca-bundle.pem`,
`/etc/ca-certificates/extracted/tls-ca-bundle.pem`.

## Rust usage

```rust
let resp = rsurl::get("http://example.com")?;
println!("{} {}", resp.status, resp.reason);
println!("{}", String::from_utf8_lossy(&resp.body));
```

### Proxies and custom transport

A `Client` carries network config (proxy, timeouts, TLS/IDN) and applies it to
every scheme:

```rust
use rsurl::Client;

// Route everything — HTTP(S), FTP, IMAP, …, and HTTP/3 & TFTP over UDP — via SOCKS5.
let client = Client::new().proxy("socks5h://user:pass@127.0.0.1:1080")?;
let resp = client.get("https://example.com/")?;
let bytes = client.transfer("ftp://ftp.example.com/pub/file")?;
```

To supply your own sockets (a pre-opened connection, an in-process pipe, a
test double, an app-managed pool), implement `rsurl::net::Connector`:

```rust
use std::sync::Arc;
use std::time::Duration;
use rsurl::net::{Connector, NetStream};

#[derive(Debug)]
struct MyConnector;
impl Connector for MyConnector {
    fn connect(&self, host: &str, port: u16, _t: Option<Duration>)
        -> rsurl::Result<Box<dyn NetStream>> {
        Ok(Box::new(std::net::TcpStream::connect((host, port))?))
    }
}

let client = Client::new().connector(Arc::new(MyConnector));
// or per-request: rsurl::Request::get(url)?.connector(Arc::new(MyConnector)).send()?;
```

(Per-request HTTP also accepts a transport via `Request::connector` /
`Request::proxy`.)

## CLI usage

```sh
rsurl http://example.com
rsurl -o out.html -v http://example.com
rsurl https://example.com               # HTTPS via purecrypto
rsurl -L http://github.com              # follow redirects
rsurl -u alice:hunter2 http://api/...   # HTTP Basic auth
rsurl -k https://expired.badssl.com     # skip TLS verification (insecure!)
rsurl --cacert ./roots.pem https://...  # custom trust anchors
rsurl --max-time 5 -O http://e/foo.bin  # cap total time, save as foo.bin
rsurl -b cookies.txt -c cookies.txt http://api/...  # load + save jar
rsurl -b "sid=abc" http://api/...       # send one inline cookie
rsurl -x http://proxy:3128 http://x/    # plain HTTP via proxy (absolute-form)
rsurl -x http://proxy:3128 https://x/   # HTTPS via proxy CONNECT tunnel
rsurl -x socks5h://proxy:1080 https://x/   # SOCKS5 (proxy-side DNS)
rsurl -x socks5h://u:p@proxy:1080 ftp://x/ # SOCKS5 also covers non-HTTP schemes
rsurl --proxy-user u:p -x http://proxy:3128 https://x/   # Proxy-Authorization
rsurl --noproxy localhost,.internal -x http://proxy https://x/  # bypass list
rsurl -d a=1 -d b=2 http://api/         # urlencoded POST, multiple values
rsurl --data-binary @blob.bin http://api/   # send file bytes verbatim
rsurl --data-urlencode "q=hello world" http://api/   # encoded form value
rsurl -F "txt=hi" -F "file=@photo.jpg" http://api/   # multipart upload
rsurl --form-string "lit=@notafile" http://api/      # literal value, no @ magic
rsurl -T payload.json http://api/items/42            # PUT file as body
rsurl file:///etc/hostname              # local file
rsurl dict://dict.org/d:curl            # dictionary lookup
rsurl gopher://gopher.floodgap.com/     # gopher menu
rsurl ftp://ftp.example.com/pub/file    # FTP download
rsurl -u user sftp://host/path/file               # SFTP download (password auth)
rsurl --key ~/.ssh/id_ed25519 sftp://host/f       # SFTP download (public-key auth)
rsurl -T local.bin sftp://host/remote.bin         # SFTP upload (-T)
rsurl -u user scp://host/etc/motd                 # SCP download
rsurl --json '{"a":1}' https://api/               # POST JSON (+ JSON Accept)
rsurl --aws-sigv4 aws:amz:us-east-1:s3 -u K:S https://bucket.s3.amazonaws.com/o
rsurl -O --remove-on-error --no-clobber https://x/f.bin  # safe resumable-ish save
rsurl -Z -O https://x/[1-50].jpg                  # parallel globbed download
```

A man page is provided at `man/rsurl.1` (install to your `man1` directory); it
summarizes the most-used options. `rsurl --help` always lists the complete,
build-specific set.

SSH (`sftp://` / `scp://`) takes the user from the URL userinfo, else
`-u`, else `$USER`. Public-key auth uses `--key <file>` (curl's `--key`;
note `-i` stays bound to `--include` here) or, if absent, the existing
`~/.ssh/id_ed25519` / `id_ecdsa` / `id_rsa`. Host keys are verified
against `~/.ssh/known_hosts` with trust-on-first-use — an unknown host is
accepted and persisted, a *changed* host key is refused — and `-k`
downgrades to accept-any. Encrypted private keys reuse the `-u` password
as the passphrase (there is no interactive prompt in this one-shot CLI).

Supported curl-style flags include `-L`/`--location`, `--max-redirs`,
`-u`/`--user`, `-k`/`--insecure`, `--cacert`, `--no-idn`, `--max-time`,
`--connect-timeout`, `-O`/`--remote-name`, `-b`/`--cookie` /
`-c`/`--cookie-jar` for Netscape-format cookie I/O, and `-x`/`--proxy`
/ `--proxy-user` / `--noproxy` for HTTP proxying. Body flags cover
`-d`/`--data`, `--data-raw`, `--data-binary`, `--data-urlencode`,
`-F`/`--form` with the full curl-canonical `;type=`, `;filename=`,
`;headers=@file` modifier syntax, `--form-string` (literal value, no
`@`/`<`/`;` parsing), `--form-escape` (RFC 7578 §4.2 percent-encoding
for names and filenames), and `-T`/`--upload-file` for straight PUT
uploads. The usual env vars — `HTTPS_PROXY`, lowercase `http_proxy`
(for CGI safety), `ALL_PROXY`, `NO_PROXY` — are honoured when `-x` is
not given. Multiple URLs on one command line are processed
sequentially, with the cookie jar shared across them.

## C usage

```c
#include "rsurl.h"

RSURL *h = rsurl_easy_init();
rsurl_easy_setopt_str(h, RSURLOPT_URL, "http://example.com");
rsurl_easy_perform(h);

const uint8_t *body; size_t len;
rsurl_easy_response_body(h, &body, &len);
printf("%ld %.*s\n", rsurl_easy_response_status(h), (int)len, body);

rsurl_easy_cleanup(h);
```

Link with `-lrsurl`. Function names use a `rsurl_` prefix so the library
can coexist with libcurl in the same process.

## Build

```sh
cargo build --release
# Binary:       target/release/rsurl
# Rust rlib:    target/release/librsurl.rlib
# C cdylib:     target/release/librsurl.so
# C header:     include/rsurl.h
```

Minimum supported Rust version (MSRV): **1.95** (raised from 1.74 when the
`puressh`-backed SSH support landed; `puressh` requires 1.95).

### TLS backend

`rsurl` ships with two interchangeable TLS backends, selected at compile
time via Cargo features. The default is `purecrypto-tls`, which keeps the
"pure-Rust, zero C deps" promise; opt in to `rustls-tls` with
`cargo build --release --no-default-features --features rustls-tls` to use
rustls 0.23 + `ring` instead. The public API across `rsurl::tls` is
identical between backends, so consumer code does not change. HTTP/3
always uses purecrypto's TLS regardless of this feature, because the QUIC
stack it sits on is part of `purecrypto`.

### Internationalized domain names (IDN)

International hostnames are normalized to ASCII/punycode (UTS-46, e.g.
`müller.example` → `xn--mller-kva.example`) before DNS, the `Host:` header,
and TLS SNI — matching curl. This is the default `idn` feature, backed by the
first-party pure-Rust `intl` crate's `idna` module (no C, no transitive deps).
Turn it off per request with `--no-idn` (CLI), `Request::idn(false)` (library),
or `RSURLOPT_IDN = 0` (C FFI). To drop the capability and the `intl`
dependency/tables from the build entirely, compile without default features,
e.g. `cargo build --release --no-default-features --features purecrypto-tls`.

### Optional protocol stacks (SSH, BitTorrent)

The SSH transports (`sftp://` / `scp://`) and the BitTorrent client are each
behind a default-on Cargo feature — `ssh` and `bittorrent` respectively. An
HTTP-only consumer that doesn't want a full SSH client and BitTorrent stack
linked in can drop both:

```sh
cargo build --release --no-default-features --features purecrypto-tls,idn
```

Dropping `ssh` also stops the `puressh` dependency (and its `libc`/`nix`
bindings) from being compiled at all. With either feature off, the
corresponding URL schemes are rejected with `Error::UnsupportedScheme` (the CLI
prints `this build has no … support`).

## License

MIT — Copyright © 2026 Karpelès Lab Inc. See [LICENSE](LICENSE).
