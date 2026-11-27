// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provides a macro for ensuring only `libcrypto` is linked and not `libssl`.

#![cfg(unix)]
// UNSAFETY: needed for exporting unmangled names and importing openssl
// routines.
#![expect(unsafe_code)]
#![no_std]

use core::ffi::c_int;
use core::ffi::c_void;

unsafe extern "C" {
    #[doc(hidden)]
    pub fn OPENSSL_init_crypto(opts: u64, settings: *const c_void) -> c_int;
}

/// Ensure only libcrypto is linked by its use in the `openssl` crate, instead
/// of both libssl and libcrypto.
///
/// The `openssl` crate calls `OPENSSL_init_ssl` unconditionally, which
/// initializes both libcrypto and libssl.
///
/// This module redefines `OPENSSL_init_ssl` so that it calls
/// `OPENSSL_init_crypto` instead. As a result, the linker will skip pulling in
/// and initializing libssl.
#[macro_export]
macro_rules! openssl_crypto_only {
    () => {
        /// # Safety
        ///
        /// The caller must call as documented for `OPENSSL_init_ssl`.
        // SAFETY: We are purposefully overriding this symbol and we have made
        // sure the definition is compatible with the original.
        #[unsafe(no_mangle)]
        unsafe extern "C" fn OPENSSL_init_ssl(
            opts: u64,
            settings: *const ::core::ffi::c_void,
        ) -> ::core::ffi::c_int {
            // SAFETY: this method has the same interface as `OPENSSL_init_ssl`, so this
            // is guaranteed by the caller.
            unsafe { $crate::OPENSSL_init_crypto(opts, settings) }
        }
    };
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    extern crate std;

    use test_with_tracing::test;

    openssl_crypto_only!();

    // Test: Initialize OpenSSL through its safe API and perform a digest.
    // Expected: Cryptography works without loading the TLS library, including
    //       after repeated initialization.
    #[test]
    fn safe_initialization_uses_only_crypto() {
        openssl::init();
        openssl::init();
        assert_eq!(
            openssl::sha::sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        assert!(
            !maps.lines().any(|line| {
                line.split_whitespace().last().is_some_and(|path| {
                    path.rsplit('/')
                        .next()
                        .is_some_and(|name| name.starts_with("libssl.so"))
                })
            }),
            "crypto-only initialization loaded libssl"
        );
    }
}
