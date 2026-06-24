# curl-compat — a libcurl-ABI drop-in built on rsurl

An **optional** library that exposes libcurl's public C ABI (`curl_*` symbols,
`CURLOPT_*`/`CURLINFO_*`/`CURLcode` values, `curl/curl.h`) implemented on top of
the pure-Rust [`rsurl`](..) crate. It lets a program written for libcurl link —
and, on Linux/ELF, dynamically load — against rsurl instead.

It is **not built by default**. The parent workspace pins `default-members` to
the `rsurl` package, so `cargo build`/`cargo test` ignore this crate.

## License / provenance

This is an independent reimplementation written **solely from libcurl's publicly
documented API** (the curl.se man pages) and the well-known public ABI constant
values, which are interoperability interface facts. No libcurl source code or
headers were consulted. It is a compatibility shim, not libcurl.

## Build

```sh
cargo build -p curl-compat --release
# → target/release/libcurl.so   (SONAME: libcurl.so.4)
#   target/release/libcurl.a
```

The header is in `curl-compat/include/curl/curl.h`; compile C against it with
`-I curl-compat/include`.

## Install as a system drop-in (Linux)

The shared object embeds the SONAME `libcurl.so.4`. Install it under that name:

```sh
sudo cp target/release/libcurl.so /usr/local/lib/libcurl.so.4
sudo ldconfig
# or, without installing:
LD_LIBRARY_PATH=target/release LD_PRELOAD=target/release/libcurl.so.4 ./your-program
```

## Status & limitations

- **Symbol versioning.** Symbols are exported under the `CURL_OPENSSL_4` version
  node (the common Linux node). A **pre-built** binary resolves against this
  library only if its original libcurl used the same node name (distros that
  build libcurl against GnuTLS/NSS use a different node). Programs recompiled
  against this header — or linked at build time — are unaffected.
- **32-bit (ILP32) support, with one caveat.** `curl_easy_setopt` takes the
  variadic third argument as a single pointer-width slot. That is ABI-correct on
  any target for the pointer-width option classes — `long`, pointer, and
  function-pointer options — and for every `curl_easy_getinfo` arm (the caller
  supplies the typed out-pointer), so i686 / 32-bit-ARM embedded builds are
  supported and CI-tested on the pure-Rust backends. The **only** exception is
  64-bit `curl_off_t` (`*_LARGE`) setopt options: on a 32-bit target the 64-bit
  argument spans two arg slots that this non-variadic signature cannot read, so
  `CURLOPT_POSTFIELDSIZE_LARGE` returns `CURLE_NOT_BUILT_IN` there rather than
  truncating — use the `long`-typed `CURLOPT_POSTFIELDSIZE` instead (good for
  bodies under 2 GiB). (The rustls TLS backend additionally needs an i686
  cross-toolchain for its `ring` provider; the pure-Rust default does not.)
- **Subset, growing toward parity.** A high-value set of options/info and the
  easy + multi interfaces are implemented; unimplemented options return
  `CURLE_UNKNOWN_OPTION`/`CURLE_NOT_BUILT_IN` rather than silently succeeding.
  Deferred: the share interface, MIME/form, the cookie *engine*
  (`COOKIEFILE`/`COOKIEJAR` persistence), `curl_ws_*`, and `curl_easy_recv/send`.
- The reported version string is `libcurl/8.4.0 rsurl/<ver>` so version checks
  pass; this is a compatibility value, not the real libcurl.
