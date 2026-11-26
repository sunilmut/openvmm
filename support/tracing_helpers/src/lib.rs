// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helpers for using the tracing crate more effectively.
//!
//! In particular, this includes extension traits to make it easier to pass
//! errors to tracing events. The events can take a `dyn Error`, but getting a
//! `dyn Error` from an arbitrary error type requires casting.
//!
//! Hopefully this crate will be short lived as `tracing` ergonomics continue
//! to improve.

#![forbid(unsafe_code)]

pub mod formatter;

/// Extension trait to make it easy to trace anyhow errors.
pub trait AnyhowValueExt {
    /// Returns the error as a type that can be traced.
    fn as_error(&self) -> &(dyn 'static + std::error::Error);
}

impl AnyhowValueExt for anyhow::Error {
    fn as_error(&self) -> &(dyn 'static + std::error::Error) {
        &**self
    }
}

/// Extension trait to make it easy to trace errors.
pub trait ErrorValueExt {
    /// Returns the error as a type that can be traced.
    fn as_error(&self) -> &(dyn 'static + std::error::Error);
}

impl<T> ErrorValueExt for T
where
    T: 'static + std::error::Error,
{
    fn as_error(&self) -> &(dyn 'static + std::error::Error) {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    // Test: Convert typed and contextual anyhow errors into traceable error references.
    // Expected: The original message, concrete error kind, and complete source chain are preserved.
    #[test]
    fn error_adapters_preserve_type_and_context_chain() {
        let typed = std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid packet");
        let error = typed.as_error();
        assert_eq!(error.to_string(), "invalid packet");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(error.source().is_none());
        let contextual = anyhow::Error::new(typed).context("decode response");
        let error = contextual.as_error();
        assert_eq!(error.to_string(), "decode response");
        let source = error.source().unwrap();
        assert_eq!(source.to_string(), "invalid packet");
        assert_eq!(
            source.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(source.source().is_none());
    }
}
