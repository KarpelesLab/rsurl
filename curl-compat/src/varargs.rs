//! C-variadic entry points (`curl_easy_setopt`, `curl_easy_getinfo`,
//! `curl_multi_setopt`).
//!
//! `curl/curl.h` declares these `(handle, int, ...)`. Stable Rust cannot define
//! a C-variadic function, so each is implemented as a fixed-arity
//! `extern "C" fn(handle, int, usize)`. Whether that is ABI-compatible with a
//! variadic call depends on where the calling convention puts the first
//! variadic argument:
//!
//! * **x86-64 SysV, x86-64 Windows, AArch64 AAPCS64 (Linux/Android/BSD),
//!   AArch64 Windows, 32-bit x86 cdecl, 32-bit ARM AAPCS:** an integer or
//!   pointer variadic argument is passed exactly where a fixed third argument
//!   would be (the third integer register, or the next stack slot), so the
//!   fixed-arity function is exported directly under the libcurl name.
//! * **Apple AArch64 (macOS/iOS arm64):** Apple's ABI passes *every* variadic
//!   argument on the stack, 8-byte aligned, while the fixed parameters still
//!   use `x0`/`x1`. A fixed-arity callee would read `x2` — garbage. For this
//!   target the libcurl symbol is a tiny assembly trampoline that loads the
//!   first variadic stack slot (`[sp]` at entry) into `x2` and tail-branches to
//!   the fixed-arity implementation, leaving `sp`/`lr` untouched.
//!
//! On Apple AArch64 the Rust implementations therefore keep their (mangled)
//! Rust names and only the trampolines carry the exported C names; `build.rs`
//! adds those names to the cdylib's export list, since rustc only exports
//! Rust-declared `#[no_mangle]` items.

#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(
    ".text",
    ".globl _curl_easy_setopt",
    ".p2align 2",
    "_curl_easy_setopt:",
    "ldr x2, [sp]",
    "b {setopt}",
    ".globl _curl_easy_getinfo",
    ".p2align 2",
    "_curl_easy_getinfo:",
    "ldr x2, [sp]",
    "b {getinfo}",
    ".globl _curl_multi_setopt",
    ".p2align 2",
    "_curl_multi_setopt:",
    "ldr x2, [sp]",
    "b {multi_setopt}",
    setopt = sym crate::easy::curl_easy_setopt,
    getinfo = sym crate::easy::curl_easy_getinfo,
    multi_setopt = sym crate::multi::curl_multi_setopt,
);
