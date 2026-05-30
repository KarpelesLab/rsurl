# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.5](https://github.com/KarpelesLab/rsurl/compare/v0.0.4...v0.0.5) - 2026-05-30

### Other

- enforce inbound flow-control window, reject peer overrun (FLOW_CONTROL_ERROR)
- fail closed when an existing known_hosts file cannot be read (avoid silent TOFU accept-all)
- bound filter-parser recursion depth to prevent stack-overflow DoS
- cap packet remaining-length at 64 MiB to prevent pre-alloc memory exhaustion
- reject backslash and percent in reg-name host (parser-differential host confusion)
- bound status/header/chunk-size/trailer line reads to prevent server-driven OOM (DoS)
- fix three confirmed security bugs in Set-Cookie handling
- reject pre-TLS pipelined data before STARTTLS upgrade (CVE-2011-0411 class injection)
- bound attacker-controlled QPACK literal lengths with checked_add (fix slice-index panic / remote DoS)

## [0.0.4](https://github.com/KarpelesLab/rsurl/compare/v0.0.3...v0.0.4) - 2026-05-30

### Other

- concurrent stream multiplexing (send_multiplexed) over one connection
- wire --http3/--http3-only into dispatch (was unreachable)
- fix docs build and cross-platform FTP upload tests
- *(release-plz)* use RELEASE_PLZ_TOKEN so release PRs get CI and releases trigger binaries

## [0.0.3](https://github.com/KarpelesLab/rsurl/compare/v0.0.2...v0.0.3) - 2026-05-30

### Other

- add sftp:// and scp:// (download + upload) via puressh; bump MSRV to 1.95
- emit curl-style -v verbose trace (request/response/TLS/body)
- implement APPE append mode (-a/--append)
- implement extensibleMatch filters (RFC 4515 :=, dn, matchingRule)
- implement permessage-deflate (RFC 7692)
- implement QPACK dynamic table decoding (encoder-stream inserts + dynamic field-line refs)
- decode Content-Encoding: compress (LZW / .Z) via compcol
- implement PUBLISH (QoS 0/1) publisher side, wire -d/-T for mqtt://
- CAPABILITY, STARTTLS upgrade, and SASL AUTHENTICATE (PLAIN/LOGIN)
- process-wide connection pool — reuse h2 connections across requests
- correct HTTP/3 status (QPACK Huffman implemented; dynamic table is the remaining TODO)
- decode zstd and brotli (br) responses via compcol (pure-Rust)
- implement substring and presence filters (RFC 4515)
- implement item-type 7 search (selector\tquery)
- SETUP/PLAY/OPTIONS/TEARDOWN session flow with CSeq + Session tracking
- implement WRQ upload (write side), wire -T for tftp://
- implement STOR upload and REST resume, wire -T for ftp://
- bidirectional frames, fragmentation reassembly, ping/pong/close
- implement connection + stream flow control (WINDOW_UPDATE, INITIAL_WINDOW_SIZE)

## [0.0.2](https://github.com/KarpelesLab/rsurl/compare/v0.0.1...v0.0.2) - 2026-05-30

### Other

- Merge branch 'worktree-agent-a8eba2346aa84a9ee'
- Merge branch 'worktree-agent-a8a6c125f123e957a'
- Merge branch 'worktree-agent-a303cb1d088f59815'
- Merge branch 'worktree-agent-a37dd55d6037057b6'
- Merge branch 'worktree-agent-addf977f176bb0950'
- fill the curl-parity body-flag coverage gaps
- -F multipart, --form-string, --form-escape, -T upload
- --data-binary, --data-urlencode, --data-raw + repeatable -d
- swap flate2 for compcol (our pure-Rust codec collection)
- fix broken intra-doc link to `load_netscape`
- force blocking I/O on accepted sockets (Windows fix)
- Add HTTP/1.1 connection-reuse pool with stale-connection retry
- Add HTTP proxy support: -x/--proxy, --proxy-user, --noproxy
- Add cookie jar (-b / -c) compatible with curl's Netscape format
- Decode `Content-Encoding: gzip|deflate` responses transparently
- Add `rustls-tls` Cargo feature as an alternative TLS backend
- HPACK encoder Huffman + dynamic-table insertion (RFC 7541 §5.2, §6.2.1, §6.3)
- process-wide connection pool keyed on (scheme, host, port)
- stream multiplexing + per-stream state machine (RFC 9113 §5.1)
- CONTINUATION on encode + DATA fragmentation with flow-control gating
- implement connection + stream flow control (RFC 9113 §6.9)
- parse and apply peer SETTINGS (RFC 9113 §6.5)
- graceful TCP close in the integration test server
- Color MIT license badge blue
- Add CI / crates.io / docs.rs / MIT badges to README
- rustfmt cleanup of rsurl_easy_response_header signature
- Add staticlib to crate-type so cargo build produces librsurl.a

### Security

- cap HTTP/2 body and header-block growth, enforce header-list limits, thread h3 TLS opts
