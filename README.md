# curlrs

A pure-Rust implementation of curl, built on top of [purecrypto](https://crates.io/crates/purecrypto)
for TLS — no OpenSSL, no system libcurl, no C dependencies.

`curlrs` ships in three forms:

1. **Rust library** (`curlrs` crate) — a small, ergonomic HTTP client API for Rust projects.
2. **C library** (`libcurlrs.so` / `curlrs.h`) — a curl-compatible C ABI for non-Rust consumers.
3. **`curlrs` CLI** — a drop-in-ish replacement for the `curl` command line.

## Status

Early, in active development.

| Capability | Status | Notes |
|---|---|---|
| HTTP/1.1 (all methods) | working | Content-Length, chunked, read-to-EOF body modes |
| HTTPS via purecrypto | working | TLS 1.2/1.3, system roots, full cert verification |
| HTTP/2 (RFC 9113) | working* | ALPN h2, HPACK + Huffman decoder; single request/conn, no flow control yet |
| HTTP/3 over QUIC (RFC 9114) | partial | QUIC + frame layer wired; QPACK Huffman decoder still TODO |
| FTP / FTPS (RFC 959, 4217) | working | RETR + LIST, EPSV with PASV fallback, implicit FTPS |
| FILE (RFC 8089) | working | rejects non-local hosts |
| DICT (RFC 2229) | working | DEFINE, MATCH, SHOW DATABASES |
| GOPHER / GOPHERS (RFC 1436) | working | reads to EOF, item-type 7 search deferred |
| IMAP / IMAPS (RFC 9051) | working | LOGIN + LIST / SELECT+FETCH / UID FETCH BODY[] |
| LDAP / LDAPS (RFC 4511) | working | simple bind + search → LDIF; subset of filter syntax |
| MQTT / MQTTS (v3.1.1) | working | CONNECT, SUBSCRIBE, receive one PUBLISH (QoS 0) |
| POP3 / POP3S (RFC 1939) | working | LIST or RETR, USER/PASS auth |
| RTSP (RFC 7826) | working | DESCRIBE only; SETUP/PLAY session flow deferred |
| TFTP (RFC 1350) | working | read side with timeout/retry, 256 MiB cap |
| WS / WSS (RFC 6455) | working | reads one data frame then closes |

\* HTTP/2 verified live against nghttp2.org and cloudflare.com from the implementation
worktree. Available via `--http2` (force) or auto-negotiated via ALPN.

System CA bundle paths searched, in order: `/etc/ssl/certs/ca-certificates.crt`,
`/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/cert.pem`, `/etc/ssl/ca-bundle.pem`,
`/etc/ca-certificates/extracted/tls-ca-bundle.pem`.

## Rust usage

```rust
let resp = curlrs::get("http://example.com")?;
println!("{} {}", resp.status, resp.reason);
println!("{}", String::from_utf8_lossy(&resp.body));
```

## CLI usage

```sh
curlrs http://example.com
curlrs -o out.html -v http://example.com
curlrs https://example.com               # HTTPS via purecrypto
curlrs file:///etc/hostname              # local file
curlrs dict://dict.org/d:curl            # dictionary lookup
curlrs gopher://gopher.floodgap.com/     # gopher menu
curlrs ftp://ftp.example.com/pub/file    # FTP download
```

## C usage

```c
#include "curlrs.h"

CURLRS *h = curlrs_easy_init();
curlrs_easy_setopt_str(h, CURLRSOPT_URL, "http://example.com");
curlrs_easy_perform(h);

const uint8_t *body; size_t len;
curlrs_easy_response_body(h, &body, &len);
printf("%ld %.*s\n", curlrs_easy_response_status(h), (int)len, body);

curlrs_easy_cleanup(h);
```

Link with `-lcurlrs`. Function names use a `curlrs_` prefix so the library
can coexist with libcurl in the same process.

## Build

```sh
cargo build --release
# Binary:       target/release/curlrs
# Rust rlib:    target/release/libcurlrs.rlib
# C cdylib:     target/release/libcurlrs.so
# C header:     include/curlrs.h
```

## License

MIT — Copyright © 2026 Karpelès Lab Inc. See [LICENSE](LICENSE).
