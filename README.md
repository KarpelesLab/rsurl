# rsurl

[![CI](https://github.com/KarpelesLab/rsurl/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/rsurl/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/rsurl.svg)](https://crates.io/crates/rsurl)
[![Docs.rs](https://docs.rs/rsurl/badge.svg)](https://docs.rs/rsurl)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A pure-Rust implementation of curl, built on top of [purecrypto](https://crates.io/crates/purecrypto)
for TLS — no OpenSSL, no system libcurl, no C dependencies.

`rsurl` ships in three forms:

1. **Rust library** (`rsurl` crate) — a small, ergonomic HTTP client API for Rust projects.
2. **C library** (`librsurl.so` / `rsurl.h`) — a curl-compatible C ABI for non-Rust consumers.
3. **`rsurl` CLI** — a drop-in-ish replacement for the `curl` command line.

## Status

Early, in active development.

| Capability | Status | Notes |
|---|---|---|
| HTTP/1.1 (all methods) | working | Content-Length, chunked, read-to-EOF body modes |
| Connection reuse | working | process-wide keep-alive pool for HTTP/1.1 (plain & TLS); HTTP/2 keeps its own pool |
| Response compression | working | `gzip` / `deflate` / `x-gzip` decoded transparently (always-on) |
| Cookies (`-b` / `-c`) | working | RFC 6265 jar; Netscape `cookies.txt` I/O, curl-compatible |
| HTTP proxy (`-x`) | working | absolute-form for plain HTTP, `CONNECT` tunnel for HTTPS, Basic auth, `--noproxy` / `*_PROXY` env vars |
| HTTPS via purecrypto | working | TLS 1.2/1.3, system roots, full cert verification |
| HTTP/2 (RFC 9113) | working* | ALPN h2, HPACK + Huffman decoder; connection- and stream-level flow control (WINDOW_UPDATE, INITIAL_WINDOW_SIZE deltas); one request per stream |
| HTTP/3 over QUIC (RFC 9114) | partial | QUIC + frame layer wired; QPACK Huffman decoder still TODO |
| FTP / FTPS (RFC 959, 4217) | working | RETR + LIST, STOR upload (`-T`) with REST resume (`-C`), EPSV with PASV fallback, implicit FTPS |
| FILE (RFC 8089) | working | rejects non-local hosts |
| DICT (RFC 2229) | working | DEFINE, MATCH, SHOW DATABASES |
| GOPHER / GOPHERS (RFC 1436) | working | reads to EOF, item-type 7 search deferred |
| IMAP / IMAPS (RFC 9051) | working | LOGIN + LIST / SELECT+FETCH / UID FETCH BODY[] |
| LDAP / LDAPS (RFC 4511) | working | simple bind + search → LDIF; subset of filter syntax |
| MQTT / MQTTS (v3.1.1) | working | CONNECT, SUBSCRIBE, receive one PUBLISH (QoS 0) |
| POP3 / POP3S (RFC 1939) | working | LIST or RETR, USER/PASS auth |
| RTSP (RFC 7826) | working | DESCRIBE only; SETUP/PLAY session flow deferred |
| TFTP (RFC 1350) | working | read (RRQ) and write/upload (`-T`, WRQ) with timeout/retry, 256 MiB cap |
| WS / WSS (RFC 6455) | working | send + receive data frames, fragmented message reassembly, ping/pong/close handling |

\* HTTP/2 verified live against nghttp2.org and cloudflare.com from the implementation
worktree. Available via `--http2` (force) or auto-negotiated via ALPN.

System CA bundle paths searched, in order: `/etc/ssl/certs/ca-certificates.crt`,
`/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/cert.pem`, `/etc/ssl/ca-bundle.pem`,
`/etc/ca-certificates/extracted/tls-ca-bundle.pem`.

## Rust usage

```rust
let resp = rsurl::get("http://example.com")?;
println!("{} {}", resp.status, resp.reason);
println!("{}", String::from_utf8_lossy(&resp.body));
```

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
```

Supported curl-style flags include `-L`/`--location`, `--max-redirs`,
`-u`/`--user`, `-k`/`--insecure`, `--cacert`, `--max-time`,
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

### TLS backend

`rsurl` ships with two interchangeable TLS backends, selected at compile
time via Cargo features. The default is `purecrypto-tls`, which keeps the
"pure-Rust, zero C deps" promise; opt in to `rustls-tls` with
`cargo build --release --no-default-features --features rustls-tls` to use
rustls 0.23 + `ring` instead. The public API across `rsurl::tls` is
identical between backends, so consumer code does not change. HTTP/3
always uses purecrypto's TLS regardless of this feature, because the QUIC
stack it sits on is part of `purecrypto`.

## License

MIT — Copyright © 2026 Karpelès Lab Inc. See [LICENSE](LICENSE).
