# rsurl → curl feature-parity roadmap

The goal: a pure-Rust drop-in for the vast majority of real-world `curl`
invocations, keeping rsurl's defining constraints intact.

**Invariants (never traded away for parity):**

- **No C toolchain / no `*-sys` crates.** Pure-Rust deps only (purecrypto,
  puressh, compcol, psl2, idna). This rules out a few curl features as-is
  (OpenSSL `--engine`, GSSAPI/Kerberos, c-ares) — see *Out of scope / caveats*.
- **curl-compatible CLI and exit codes.** Flags, semantics, and exit codes
  match curl unless explicitly noted.
- **Security defaults stay strict.** Every new feature ships verified (full CI
  gate: build, `clippy -D warnings`, fmt, doc, both TLS backends, tests).

## Where we are today

Protocols: HTTP/1.1, HTTP/2, HTTP/3, FTP/FTPS, SFTP, SCP, IMAP(S), POP3(S),
MQTT(S), RTSP, TFTP, LDAP(S), gopher(s), dict, file, ws/wss. ~65 CLI flags,
cookies (RFC 6265 + Netscape I/O), transparent decompression, proxies
(HTTP/HTTPS/SOCKS4/4a/5/5h incl. SOCKS5-UDP), pluggable transport (`Connector`),
TLS 1.2/1.3 with full verification, a `Client`/`Request` library API.

**The single biggest limiter is buffered I/O:** request and response bodies are
materialized fully in memory. This blocks progress meters, rate limiting,
low-speed aborts, early `--max-filesize`, and large/▶infinite transfers. It is
the foundation that unlocks the most parity, so it is Milestone 1.

---

## Milestone 1 — Streaming I/O (foundation)

**Why first:** unlocks M5 (rate/speed/progress), early `--max-filesize`,
large-file and chunked-infinite downloads, streamed uploads, and lower memory.

- Introduce a streaming body sink/source: response bodies written to the output
  as they arrive; request bodies read from a reader. Thread through HTTP/1.1
  first, then HTTP/2 and HTTP/3, then the file-transfer protocols (FTP/SFTP/
  SCP/TFTP).
- Add a `Response` streaming variant (or a callback/`Read` handle) alongside the
  current buffered `body: Vec<u8>` (keep buffered as the default for the simple
  API).
- Wire phase/transfer metrics through this path (bytes so far, first-byte time).

**Delivers later:** progress bar, `--limit-rate`, `-y/-Y`, real `--max-filesize`
abort, `-C -` auto-resume, streamed `-T` uploads. **Effort: XL.**

## Milestone 2 — TLS completeness

Depends on small additions to `tls/*` (both purecrypto + rustls backends).

- **Client certificates** `-E/--cert`, `--cert-type`, `--key`, `--key-type`,
  `--pass` (purecrypto exposes `Identity`/`SigningKey`; needs PEM/DER key
  parsing across RSA/ECDSA/Ed25519 and plumbing through `TlsOpts`).
- **Version/cipher control** `--tlsv1.0/1.1/1.2/1.3`, `--tls-max`,
  `--ciphers`/`--tls13-ciphers`.
- **Pinning & revocation** `--pinnedpubkey`, `--cert-status` (OCSP staple),
  `--crlfile`, `--capath`.
- **Names/ALPN** `--connect-to`, explicit SNI override, `--false-start`,
  `--no-alpn`.

**Delivers:** mutual TLS, enterprise TLS knobs. **Effort: L.**

## Milestone 3 — Authentication completeness

Currently only HTTP Basic. Add the auth scheme negotiation layer.

- `--digest` (RFC 7616), `--ntlm`, `--negotiate` (SPNEGO — *caveat: pure-Rust
  Kerberos is the hard part; NTLM is feasible pure-Rust*), `--bearer`,
  `--aws-sigv4`, `--anyauth`, `--proxy-*` variants of each.
- `--netrc-optional`, per-scheme credential application (netrc for FTP/IMAP/…).

**Delivers:** the common enterprise/cloud auth flows. **Effort: L.**

## Milestone 4 — HTTP feature breadth

Mostly request/redirect/cache semantics; no streaming dependency.

- Conditional: `-z/--time-cond`, `--etag-save`, `--etag-compare`.
- State engines: `--alt-svc`, `--hsts`.
- Redirect control: `--post301/302/303`, `--proto`, `--proto-redir`,
  `--proto-default`, `--location-trusted`, `--max-filesize` (with M1).
- Request shaping: `-e` auto-referer (`;auto`), `--path-as-is`, `--raw`,
  `--ignore-content-length`, `--tr-encoding`, `--expect100-timeout`,
  `--request-target`, `-G` (done) edge cases, `--url-query`.
- HTTP/2/3 depth: `--http2-prior-knowledge`, server-push handling, HTTP/3
  dynamic-table *encoder* (we decode; we still send literals).

**Delivers:** the long tail of `-H`-adjacent HTTP behavior. **Effort: L.**

## Milestone 5 — Transfer control & UX (needs M1)

- **Progress**: `-#/--progress-bar` and the default progress meter (live).
- **Rate/speed**: `--limit-rate`, `-Y/--speed-limit`, `-y/--speed-time`.
- **Retry family**: `--retry-delay`, `--retry-max-time`, `--retry-connrefused`,
  `--retry-all-errors` (extend the existing `--retry`).
- **Resume**: `-C -` automatic resume (range/REST from existing file size).
- **Output**: full `-w/--write-out` variable set **with real phase timers**
  (`time_namelookup/connect/appconnect/pretransfer/starttransfer/total`,
  `speed_download`, `num_connects`, `ssl_verify_result`, `%{json}`, `%{header{}}`,
  `%{certs}`), `--output-dir`, `--remove-on-error`, `--create-dirs` (done),
  `-R` (done), `--fail-with-body`, `--fail-early`.
- **Tracing**: `--trace`, `--trace-ascii`, `--trace-time`, `--trace-ids`,
  `--stderr`, `--styled-output`.

**Delivers:** scripting/observability parity. **Effort: L (after M1).**

## Milestone 6 — Connection & DNS control

- Binding/locality: `--interface`, `--local-port`, `--unix-socket`,
  `--abstract-unix-socket`.
- TCP tuning: `--tcp-nodelay` (default on in curl), `--tcp-fastopen`,
  `--no-keepalive`, `--keepalive-time`.
- Address selection: Happy Eyeballs (`-4`/`-6` done; add dual-stack racing +
  `--happy-eyeballs-timeout-ms`), `--connect-to`, `--resolve` (done).
- DNS: custom servers/interface (`--dns-servers`, `--dns-interface`) — *caveat:
  needs a pure-Rust resolver; today we use the system resolver. Likely a
  pure-Rust DNS dependency or a built-in stub resolver.*

**Delivers:** placement/binding parity. **Effort: M–L.**

## Milestone 7 — URL handling & globbing

- **URL globbing**: `{a,b,c}` and `[1-100]`/`[a-z]`/`[001-100]` with `:step`,
  plus `--globoff (-g)`. Expands one URL into many transfers.
- `\#N` output-name references for globs (`-o "#1.html"`).
- `--path-as-is`, IDN edge cases, `--url` (done).

**Delivers:** curl's batch-URL ergonomics. **Effort: M.**

## Milestone 8 — Parallelism in the CLI

The library already has `send_multiplexed` (true HTTP/2 concurrency).

- `-Z/--parallel`, `--parallel-max`, `--parallel-immediate` driving multiple
  URLs/operations concurrently (across `--next` ops and globs).
- A shared progress meter for parallel transfers.

**Delivers:** `curl -Z` throughput. **Effort: M (after M1+M5).**

## Milestone 9 — New protocols

In rough value order:

- **SMTP / SMTPS** (`--mail-from`, `--mail-rcpt`, `-T` body, STARTTLS, SASL).
  High value; reuses the IMAP/POP3 SASL + STARTTLS machinery.
- **TELNET** (`-t/--telnet-option`). Small.
- **SMB / SMBS**. Large; pure-Rust SMB is a significant dependency/build.
- **RTMP family**. Large; niche. Likely lowest priority / possible *out of
  scope* depending on a pure-Rust impl.

**Effort: SMTP M, TELNET S, SMB XL, RTMP XL.**

## Milestone 10 — Protocol depth & polish

- FTP: active mode (`-P/--ftp-port`), `--ftp-method`, `--ftp-create-dirs`,
  `--ftp-pret`, `--ftp-ssl-ccc`, MLSD listings, `--disable-epsv/eprt`.
- IMAP/POP3/SMTP: more URL verbs, `--login-options`, UID ranges, APOP.
- RTSP: RTP media reception (`--interleaved`), `--rtsp-request` aliases.
- WebSocket: `--ws` ping interval, close-code surfacing.
- LDAP: paged results, modify/add (read-only today).
- Combined short flags (`-sS`, `-fL`) — small, high compatibility value;
  **good early win, can land before M1.**

**Effort: mixed S–L.**

## Milestone 11 — Compatibility & ecosystem polish

- Exit-code parity sweep (curl's full table), error-message wording.
- `--help category`, generated man page, `--manual`, `-q/--disable` (.curlrc),
  shell completions.
- `libcurl`-shaped C API surface in `ffi.rs` for drop-in linking (stretch).

**Effort: M.**

---

## Suggested ordering (dependency-aware)

1. **Quick compatibility wins first** (no deps): combined short flags, `-z`,
   `-e ;auto`, `--retry-*`, `--proto*`, `--output-dir`, `--fail-with-body`,
   URL globbing (M7), `--connect-to`. These each close visible `-h` gaps cheaply.
2. **M1 Streaming I/O** — the keystone; schedule early because M5/M8 and large
   files depend on it.
3. **M2 TLS** and **M3 Auth** in parallel (independent subsystems).
4. **M5 UX/transfer-control** once M1 lands; **M8 parallel CLI** after M5.
5. **M4 HTTP breadth** and **M6 connection control** as steady fill-in.
6. **M9 protocols** (SMTP first), **M10 depth**, **M11 polish** ongoing.

## Definition of "parity" (tiers)

- **Parity-90**: every commonly-used curl flag and all mainstream protocols
  (HTTP(S)/FTP(S)/SFTP/SMTP/IMAP/POP3) behave identically — M1–M9 (minus SMB/
  RTMP) + the M10 quick wins. This is the realistic target.
- **Parity-99**: the full option table and SMB/RTMP/TELNET, man page, libcurl-
  shaped API — M10/M11 complete.
- **Never-parity (by design)**: features requiring a C toolchain or non-Rust
  crypto/DNS — OpenSSL `--engine`, GSSAPI/Kerberos `--negotiate` (unless a
  pure-Rust SPNEGO lands), c-ares-specific DNS knobs. Documented as
  intentional divergences.

## Out of scope / caveats

- **`--negotiate` (Kerberos/GSSAPI)**: no pure-Rust GSSAPI today; NTLM and
  Digest are feasible, Negotiate likely deferred or stubbed.
- **`--dns-servers`/`--dns-interface`**: require a pure-Rust resolver to honor
  without C (c-ares). Tracked under M6 with that dependency.
- **`--engine`, PKCS#11**: OpenSSL-specific; not applicable to a pure-Rust TLS
  stack.
