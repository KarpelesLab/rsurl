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
- **64-bit Unix ABI.** `curl_easy_setopt`/`curl_easy_getinfo` rely on the
  third (variadic) argument landing in a register, as it does on 64-bit
  SysV/AArch64. 32-bit `curl_off_t` varargs are not handled.
- **Subset, growing toward parity.** A high-value set of options/info and the
  easy + multi interfaces are implemented; unimplemented options return
  `CURLE_UNKNOWN_OPTION`/`CURLE_NOT_BUILT_IN` rather than silently succeeding.
  Deferred: the share interface, MIME/form, the cookie *engine*
  (`COOKIEFILE`/`COOKIEJAR` persistence), `curl_ws_*`, and `curl_easy_recv/send`.
- The reported version string is `libcurl/8.4.0 rsurl/<ver>` so version checks
  pass; this is a compatibility value, not the real libcurl.
