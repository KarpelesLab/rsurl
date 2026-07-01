# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.5](https://github.com/KarpelesLab/rsurl/compare/rsurl-v0.1.4...rsurl-v0.1.5) - 2026-07-01

### Added

- *(tls)* use the embedded cacrt bundle as default trust; drop load_system_roots
- *(download)* unified fetch_to_file front door across schemes
- *(download)* support data: URIs in download()

### Fixed

- *(cli)* print a final progress line for library downloads

### Other

- *(download)* gate the front-door file:// case to unix
- *(download)* drop the HEAD probe; learn size from the first GET

## [0.1.4](https://github.com/KarpelesLab/rsurl/compare/rsurl-v0.1.3...rsurl-v0.1.4) - 2026-07-01

### Added

- *(http)* don't apply the in-memory body cap to streaming transfers
- *(download)* resumable, retrying HTTP downloads in the library
- *(ffi)* [**breaking**] gate the C ABI behind an off-by-default `ffi` feature

### Fixed

- *(websocket)* make WsShutdown::shutdown idempotent on an already-closed socket

### Other

- *(download)* unify segmented/parallel downloads into one engine

## [0.1.3](https://github.com/KarpelesLab/rsurl/compare/rsurl-v0.1.2...rsurl-v0.1.3) - 2026-06-28

### Added

- *(http)* route direct HTTPS HTTP/1.1 through the sans-IO core
- *(http)* route plaintext HTTP/1.1 through the sans-IO core
- *(pool)* connection pooling + keep-alive on the sans-IO core path
- *(proto/http1)* stream response bodies via Head/Body/End events
- *(http)* cutover P1 — HTTPS over the sans-IO core via the shared TlsClient
- *(http)* cutover P0 — blocking HTTP/1.1 transfer over the sans-IO core
- *(aio)* follow redirects and decompress response bodies
- *(http3)* handle response-stream framing edge cases and fix PTO loss recovery
- *(websocket)* add streaming send and idle keepalive
- *(http3)* replace hand-rolled QPACK with compcol::qpack
- *(aio)* support arbitrary method, body, and headers
- *(curl-compat)* support 32-bit (ILP32) targets

### Fixed

- *(tls)* don't load the system CA bundle when verification is off
- satisfy CI lint/doc gates across all feature combos
- *(curl-compat)* map Error::Cancelled to CURLE_ABORTED_BY_CALLBACK
- *(resume)* use checked size arithmetic in write_state end offset
- *(curl-compat)* use checked size arithmetic in c_alloc and curl_easy_escape
- *(cookie)* reject Set-Cookie Path= containing control bytes
- *(bittorrent)* reject Windows drive-letter/ADS/reserved path components
- *(bittorrent)* cap torrent piece length to prevent pre-allocation DoS
- *(bittorrent)* reject zero-length torrents carrying piece hashes
- *(file)* reject non-regular files to bound file:// reads
- *(websocket)* bound control-frame length before buffering payload
- *(rtsp)* compare Content-Length against cap as u64 before cast
- *(tls)* zeroize the transient decoded client-key DER (rustls backend)
- *(http3)* honor tls_verify_callback on the HTTP/3 path
- *(tls)* enforce --pinnedpubkey even when a verify callback is set

### Other

- *(multi)* make incremental_poll_and_running_count deterministic
- *(aio)* gracefully close the redirect test server to avoid Windows RST
- *(http)* gracefully close in-process test servers to avoid Windows RST
- *(http)* retire the legacy direct HTTP/1.1 engine (cutover P4)
- *(aio)* apply rustfmt to test bodies
- *(bittorrent)* document the full client, drop stale "Phase 1" note
- add 32-bit (i686) leg and build curl-compat in CI

## [0.1.2](https://github.com/KarpelesLab/rsurl/compare/rsurl-v0.1.1...rsurl-v0.1.2) - 2026-06-22

### Added

- *(aio)* public runtime-agnostic async HTTP client (P2 entry point)
- *(tls)* socket-free engine construction for the sans-IO stack (P2)
- *(proto)* purecrypto TlsEngine adapter + cross-backend handshake proof
- *(proto)* real rustls TlsEngine adapter + in-memory handshake proof
- *(proto)* sans-IO TLS as a layered Machine (Phase 1)
- *(io)* runtime-agnostic async driver + Tokio adapter (Phase 1)
- *(io)* sans-IO foundation + HTTP/1.1 core + blocking driver (Phase 1)

### Other

- *(deps)* update purecrypto 0.6.14 -> 0.6.17 (wire explicit TLS entropy)
- *(tls)* make connect-wiring test hermetic (fix Windows-rustls CI)

## [0.1.1](https://github.com/KarpelesLab/rsurl/compare/rsurl-v0.1.0...rsurl-v0.1.1) - 2026-06-21

### Added

- *(ssh)* adopt puressh 0.0.6 and complete the Rust 1.88 MSRV

### Fixed

- *(websocket)* make WsShutdown unblock a parked reader on Windows

### Other

- lower MSRV to Rust 1.88

## [0.1.0](https://github.com/KarpelesLab/rsurl/compare/rsurl-v0.0.11...rsurl-v0.1.0) - 2026-06-19

### Added

- *(websocket)* add WsShutdown to force-unblock a parked recv()

## [0.0.11](https://github.com/KarpelesLab/rsurl/compare/rsurl-v0.0.10...rsurl-v0.0.11) - 2026-06-15

### Added

- *(ffi)* add RSURLOPT_HTTP_CONTENT_DECODING to disable decompression

### Other

- WebSocket::split() into concurrent WsReader + WsWriter
- cover send_reader fallback+redirects, add http-only CI lane

## [0.0.10](https://github.com/KarpelesLab/rsurl/compare/rsurl-v0.0.9...rsurl-v0.0.10) - 2026-06-15

### Added

- add Read-returning raw body API (into_reader + send_reader)
- add `decompress(false)` to Request and Client
- gate SSH (puressh) behind a default-on `ssh` feature

### Other

- fix intro to reflect optional SSH/BitTorrent and the intl swap
- drop the status table; give HTTP/2 and HTTP/3 their own chapters
- refresh README for new APIs and maturity
- *(idn)* use the first-party `intl` crate instead of `idna`
- concurrent TLS connection + WsTransport (no API change yet)
- buffer inbound frames so a mid-frame read error can't desync

## [0.0.9](https://github.com/KarpelesLab/rsurl/compare/rsurl-v0.0.8...rsurl-v0.0.9) - 2026-06-14

### Other

- canonical forward-slash paths in metadata/selection (Windows)
- disable URL globbing for all torrent-routing flags (Windows)
- metadata inspection + selective/concatenated downloads

## [0.0.8](https://github.com/KarpelesLab/rsurl/compare/rsurl-v0.0.7...rsurl-v0.0.8) - 2026-06-14

### Other

- fix rustdoc private-intra-doc-link after making the module public
- HTTP/2 PRIORITY weights + runtime pool-size config
- TlsInfo + per-phase Timing on h2, h3, and pooled HTTPS
- timing, DNS/proxy resolvers, partitioning, WS subprotocols, priorities
- caller-owned cert-validation hook + handshake introspection
- SameSite/CHIPS surface + jar enumeration; opt-out redirect cookies
- streaming callbacks, cancellation, and strict header control

## [0.0.7](https://github.com/KarpelesLab/rsurl/compare/rsurl-v0.0.6...rsurl-v0.0.7) - 2026-06-14

### Other

- don't glob-expand local .torrent paths (fixes Windows CI)
- --recheck re-hashes on-disk data on resume
- resumable parallel download with -C - --parallel-segments
- resumable single-stream downloads with -C -
- resume downloads from saved piece state
- shared partial-file format for resumable downloads
- gitignore downloaded media in repo root
- endgame mode + detach workers so completion never blocks
- verbosity levels for torrent diagnostics
- per-peer diagnostics under -v
- bound block-request pipeline per piece
- probe peers concurrently for magnet metadata
- fix seeding on macOS/BSD/Windows (blocking accepted sockets)
- inbound seeding with --seed / --share-ratio
- DHT peer discovery (BEP 5)
- magnet metadata download (BEP 9 / BEP 10)
- concurrent swarm engine + CLI download
- phase 3 — peer wire protocol, picker, storage, verified download
- phase 2 — HTTP and UDP tracker clients
- phase 1 — bencode, .torrent metainfo, magnet (default feature)
- default --parallel-segments to 4 + live progress display
- add --parallel-segments for multi-connection single-file downloads
- fix broken intra-doc link in Response.final_url doc
- implement the multi interface on rsurl::Multi
- implement the easy interface
- optional libcurl-ABI drop-in crate (skeleton)
- add Response.final_url (effective URL after redirects)
- add a native concurrent multi-transfer driver (rsurl::Multi)
- add a command-line client (curl never built one)
- close lib feature gaps vs curl (control frames, raw mode, close code)
- drop intra-doc link to the private ctl field (rustdoc warning)
- document the persistent WebSocket entry point in the module header
- add persistent WebSocket client API
- honor --pinnedpubkey and SAN-required check over h3 (purecrypto#31)
- detect TLS truncation on the purecrypto backend (TLS-1, purecrypto#30)
- reject truncated EOF-delimited bodies over TLS (TLS-1)
- POP3 STLS (RFC 2595) + --ssl-reqd require-TLS enforcement
- add --ssl-reqd require-TLS mode for SMTP/IMAP
- honor --capath/--crlfile/--ciphers over h3; guard --pinnedpubkey
- fold effective dial target into HTTP/1.1 pool Key (HTTP1-5)
- TLS-4 reject SAN-less server leaf on the purecrypto backend
- TLS-5 zeroize client private-key material on drop
- reject forbidden header octets (H23-2)
- reject forbidden header octets (H23-1)
- validate UTF-8 on reassembled TEXT messages (websocket-utf8)
- fail closed on unknown algorithm; reject quoted-string breakout (AUTH-2/digest-algorithm)
- write jar 0600 owner-only, atomically (AUTH-1)
- validate SOCKS5 UDP relay source (NET-2)
- bound per-line read in LineReader::read_line (MAIL-2)
- bound per-line read in read_reply (MAIL-1)
- --crlfile honours all PEM CRL blocks, not just the first (TLS-3)
- make TlsOpts::default() verify certificates (TLS-2)
- fix four robustness bugs (HTTP1-1..HTTP1-4)
- terminate authority at first of / ? # (NET-1 authority confusion / SSRF)

## [0.0.6](https://github.com/KarpelesLab/rsurl/compare/v0.0.5...v0.0.6) - 2026-06-09

### Other

- Response ergonomics, no-trace send_multiplexed, pooling/timeout docs

## [0.0.5](https://github.com/KarpelesLab/rsurl/compare/v0.0.4...v0.0.5) - 2026-06-08

### Other

- wire purecrypto 0.6.5 fixes — --ciphers, encrypted ECDSA keys, faithful pinning
- wire --crlfile (CRL revocation) on the purecrypto backend; fix wording
- M2 client certs (mTLS), public-key pinning, and --capath (both backends)
- receive interleaved RTP/RTCP after PLAY (M10) — roadmap complete
- stream response bodies to a sink (completes M1)
- finalize status — functional curl parity complete under no-C invariant
- broaden the C ABI with ten common libcurl-shaped options (M11)
- active-mode FTP (-P/--ftp-port) + roadmap scope correction (M10)
- streaming decompression for single gzip/zstd/br downloads (rest of M1)
- stream all non-HTTP downloads to a file through the sink (rest of M1)
- --ftp-create-dirs + route FTP upload through the Client (M10)
- honor -w on FTP downloads (size_download, time_total, …)
- stream FTP/FTPS downloads to disk (rest of M1)
- accept --basic and --ftp-skip-pasv-ip as honest confirmations
- add man/rsurl.1 man page (M11) + README examples
- --disable-epsv (skip EPSV, use PASV directly) (M10)
- log --json/--remove-on-error/--no-clobber/-w extras/exit codes; mark NTLM out of scope
- --remove-on-error and --no-clobber for downloads (M5/M11)
- make CLI tests cross-platform (Windows CI green)
- --json shortcut (POST JSON body + JSON Accept) (M4)
- centralize transfer-error exit codes to match curl (M11)
- -w %header{Name} and %{ssl_verify_result} (M5)
- log SigV4, -y/-Y low-speed abort, -w phase timers, compat no-ops
- -w phase timers (%{time_connect,appconnect,pretransfer,starttransfer}) (M5)
- enforce -y/-Y low-speed abort + accept curl no-op flags (M5/M11)
- AWS SigV4 request signing (--aws-sigv4) (M3)
- roadmap progress — M1 streaming, M3 digest, M5 limits, M8 parallel
- -Z/--parallel concurrent transfers (M8)
- --oauth2-bearer and --data-ascii (M3/M4)
- HTTP Digest authentication (M3)
- streaming HTTP/1.1 downloads (M1) + enforce --limit-rate/-#/--max-filesize (M5)
- roadmap progress — SMTP/TELNET, TLS pins, connect-to, unix-socket
- minimal TELNET client (M9)
- SMTP/SMTPS sending (M9)
- roadmap progress log (network, Tiers A-C, M2/M4/M7 partials)
- --tlsv1.x / --tls-max version pinning (M2)
- --unix-socket via a UnixConnector (M6)
- --connect-to (M6) — override the dial target, keep Host/SNI
- --location-trusted and --post301/302/303 redirect controls (M4)
- URL globbing (M7) — {a,b} alternation, [1-100]/[a-z] ranges, -g, #N
- --retry-delay/--retry-max-time/--retry-connrefused/--retry-all-errors
- -z, -e ;auto, --output-dir, --fail-with-body, --proto[-default]
- getopt-style bundled short flags and attached values
- add curl feature-parity roadmap
- recognize -E/--limit-rate/-y/-Y/-# for compatibility (Tier C)
- -K/--config files and --next multi-operation (partial Tier C)
- Tier-B curl flags — netrc, -J, --retry, -4/-6, --resolve
- add Tier-A curl flags to close the -h gap
- route -x proxy through all schemes; no_proxy bypass; docs (phase 5)
- UDP transport + SOCKS5 UDP ASSOCIATE for HTTP/3 and TFTP (phase 4)
- Client/Session + thread connector through TCP protocols (phase 3)
- route requests through a pluggable Connector (phase 2)
- add pluggable Connector trait + built-in proxy connectors (phase 1)
- bump purecrypto to 0.6.1 and puressh to 0.0.4
- rustfmt the security-fix changes (cargo fmt --check)
- fix pre-existing doc link and clippy lint blocking master CI
- reject frame lengths exceeding usize (32-bit truncation in grease-frame path)
- add wall-clock deadline to handshake read (slowloris hold)
- make PEM root-bundle splitter skip malformed blocks instead of dropping the rest
- reject signed/non-digit chunk-size and Content-Length (RFC 9112 framing parity)
- don't re-ACK unvalidated source; add transfer deadline; fix TID comments
- reject data port 0 in PASV/EPSV parsers
- apply IP-literal scoping guard to cookies.txt load path
- document borrow-invalidation and thread-safety contracts; fix doc example symbol
- reject control bytes and over-long credentials in CONNECT
- bound total buffered response size (OOM DoS)
- fix panic on non-char-boundary split in status-line parsing (server DoS)
- sanitize/guard server bytes written to a TTY (ANSI escape injection)
- bound no-progress/control-frame floods (empty-DATA spin, SETTINGS/PING/Rapid-Reset DoS)
- re-validate host after UTS-46 to block authority-delimiter injection
- convert international (IDN) hostnames to punycode, on by default
- enforce Domain= eTLD scoping with the real PSL (psl2), kill supercookies
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
