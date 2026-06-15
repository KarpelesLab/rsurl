# rsurl

[![CI](https://github.com/KarpelesLab/rsurl/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/rsurl/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/rsurl.svg)](https://crates.io/crates/rsurl)
[![Docs.rs](https://docs.rs/rsurl/badge.svg)](https://docs.rs/rsurl)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A pure-Rust implementation of curl, built on [purecrypto](https://crates.io/crates/purecrypto)
for TLS — no OpenSSL, no system libcurl, no C dependencies. Optional first-party
pure-Rust stacks, on by default, add SSH ([puressh](https://crates.io/crates/puressh),
the `ssh` feature) and BitTorrent (the `bittorrent` feature); IDN host
normalization uses [intl](https://crates.io/crates/intl). An HTTP-only build
drops the lot with `--no-default-features`. Even with everything enabled the
only extra is `libc`/`nix` on unix — pure-Rust FFI *bindings*, no compiled C and
no `*-sys`/cmake/bindgen.

`rsurl` ships in three forms:

1. **Rust library** (`rsurl` crate) — a small, ergonomic HTTP client API for Rust projects.
2. **C library** (`librsurl.so` / `rsurl.h`) — a curl-compatible C ABI for non-Rust consumers.
3. **`rsurl` CLI** — a drop-in-ish replacement for the `curl` command line.

## Status

Functional across a broad protocol surface, in active development (APIs may
shift before 1.0). What works today:

- **HTTP/1.1** — all methods; Content-Length, chunked, and read-to-EOF bodies; a
  process-wide keep-alive connection pool (plain & TLS).
- **HTTP/2** and **HTTP/3 over QUIC** — see the dedicated sections below.
- **HTTPS** via purecrypto — TLS 1.2/1.3, system roots, full cert verification.
- **FTP/FTPS**, **FILE**, **DICT**, **GOPHER(S)**, **IMAP(S)**, **LDAP(S)**,
  **MQTT(S)**, **POP3(S)**, **RTSP**, **TFTP**, **WS/WSS** — uploads (`-T`),
  resume, STARTTLS, and the usual per-protocol verbs.
- **SSH** — SFTP and SCP download/upload, key + password auth, known_hosts TOFU
  (optional `ssh` feature).
- **BitTorrent** — `.torrent` / `magnet:`, trackers, DHT, peer wire, seeding,
  metadata inspection, selective / concatenated downloads (optional
  `bittorrent` feature).
- **Proxies** — HTTP `CONNECT`, HTTPS-to-proxy, SOCKS4/4a/5/5h (incl. SOCKS5 UDP
  for HTTP/3 & TFTP), honoured across every scheme; `--noproxy` / `*_PROXY`.
- **Custom transport** — supply your own sockets via `rsurl::net::Connector`.
- **Response compression** — `gzip`/`deflate`/`zstd`/`br`/`compress` decoded
  transparently by default, or `decompress(false)` for the raw wire bytes.
- **Cookies** — RFC 6265 jar with curl-compatible Netscape `cookies.txt` I/O.

Per-protocol detail lives in the [CLI examples](#cli-usage) below and on
[docs.rs](https://docs.rs/rsurl).

## HTTP/2

ALPN `h2`, HPACK + Huffman decoder; connection- and stream-level flow control
(WINDOW_UPDATE, INITIAL_WINDOW_SIZE deltas). A process-wide connection pool
reuses a warm conn across requests, advancing stream ids 1/3/5 (sequential
reuse). Available via `--http2` (force) or auto-negotiated over ALPN. Verified
live against nghttp2.org and cloudflare.com.

True concurrent multiplexing — many in-flight streams on one connection,
interleaved frame I/O, non-blocking body sends with no head-of-line stall,
queueing at `SETTINGS_MAX_CONCURRENT_STREAMS`, per-stream RST + GOAWAY demux —
is exposed as the `rsurl::send_multiplexed` library API (below); the CLI still
issues one request at a time.

### Concurrent multiplexing (`send_multiplexed`)

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

## HTTP/3 over QUIC (RFC 9114)

Reachable via `--http3` (try h3, fall back to HTTP/2/1.1 on a QUIC transport
failure) and `--http3-only` (force h3, no fallback). QUIC + frame layer + QPACK
static/dynamic tables and Huffman decoder; advertises a non-zero
`SETTINGS_QPACK_MAX_TABLE_CAPACITY` (blocked-streams 0), applies the peer's
encoder-stream inserts and resolves dynamic / post-base field-line refs, and
acks sections on the decoder stream; the request encoder still emits literals
only. Honors `--cacert` / `-k`. HTTP/3 always uses purecrypto's TLS (the QUIC
stack is bound to it), regardless of the selected TLS backend.

Verified live end-to-end against `quic.nginx.org` and `www.google.com` (QUIC
handshake completed, request sent, real `HTTP/3 200` + headers + body returned).
Cloudflare's QUIC endpoints (`cloudflare-quic.com`, `www.cloudflare.com`)
currently fail at the QUIC packet-decode step (`http3: feed: Decode`) against
purecrypto's QUIC stack — under `--http3` this triggers the documented fallback
to HTTP/2; under `--http3-only` it is a hard error. So h3 works against several
major servers but is not yet universal.

## Rust usage

```rust
let resp = rsurl::get("http://example.com")?;
println!("{} {}", resp.status, resp.reason);
println!("{}", String::from_utf8_lossy(&resp.body));
```

### Response body as a `Read` (raw / streaming)

Besides the buffered, transparently-decoded `Response::body`, a body can be
consumed as a `std::io::Read` — handy for handing it to a media/source driver
that wants a reader rather than a `Vec`:

```rust
use std::io::Read;
use rsurl::Request;

// Buffered + seekable: `into_reader()` is a `Read` + `Seek` cursor. Pair with
// `decompress(false)` to read the raw, undecoded wire bytes (Content-Encoding
// left intact) instead of the decoded plaintext.
let resp = Request::get("https://example.com/clip.bin")?
    .decompress(false)
    .send()?;
let mut reader = resp.into_reader(); // impl Read + Seek over the raw bytes

// Streaming: `send_reader()` hands back an `impl Read` over the undecoded body.
// On a direct HTTP/1.1 connection a Content-Length / close-delimited body streams
// straight off the socket (never fully buffered); the head is available up front.
let mut body = Request::get("https://example.com/big.bin")?.send_reader()?;
println!("status {}", body.status());
let mut buf = [0u8; 64 * 1024];
let n = body.read(&mut buf)?;
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

System CA bundle paths are searched, in order:
`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`,
`/etc/ssl/cert.pem`, `/etc/ssl/ca-bundle.pem`,
`/etc/ca-certificates/extracted/tls-ca-bundle.pem`.

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
