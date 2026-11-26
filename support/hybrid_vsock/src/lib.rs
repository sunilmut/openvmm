// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![forbid(unsafe_code)]

//! Provides helper functions for bridging between vsock/hvsocket and Unix domain sockets, utilized
//! by VMBus-based hvsocket and virtio-vsock.

use fs_err::PathExt;
use guid::Guid;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

/// The maximum length of a valid connect request. It could be shorter if it contains a port number
/// instead of a service ID.
pub const HYBRID_CONNECT_REQUEST_LEN: usize =
    "CONNECT 00000000-facb-11e6-bd58-64006a7986d3\n".len();

/// This GUID is an embedding of the AF_VSOCK port into an AF_HYPERV service ID.
const VSOCK_TEMPLATE: Guid = guid::guid!("00000000-facb-11e6-bd58-64006a7986d3");

/// Represents the local or remote port number for a vsock connection, or the service ID or instance
/// ID for an hvsocket connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VsockPortOrId {
    /// The vsock port number.
    Port(u32),
    /// The hvsocket service ID or instance ID, represented as a GUID.
    Id(Guid),
}

impl VsockPortOrId {
    /// Gets the vsock port number. This will return `Some` if the instance either directly uses a
    /// port, or uses a service ID that matches the hvsocket vsock template.
    pub fn port(&self) -> Option<u32> {
        match self {
            VsockPortOrId::Port(port) => Some(*port),
            VsockPortOrId::Id(service_id) => {
                let stripped_id = Guid {
                    data1: 0,
                    ..*service_id
                };
                (VSOCK_TEMPLATE == stripped_id).then_some(service_id.data1)
            }
        }
    }

    /// Gets the vsock service ID. If this instance is a port, it will use the hvsocket vsock
    /// template to construct a service ID.
    pub fn id(&self) -> Guid {
        match self {
            VsockPortOrId::Port(port) => Self::port_to_id(*port),
            VsockPortOrId::Id(service_id) => *service_id,
        }
    }

    /// Converts a vsock port number into a GUID using the hvsocket vsock template.
    pub fn port_to_id(port: u32) -> Guid {
        Guid {
            data1: port,
            ..VSOCK_TEMPLATE
        }
    }

    /// Gets the path of a Unix domain socket listener on the host using this port or id.
    ///
    /// If this instance is a port, or uses a GUID that matches the hvsocket vsock template, this
    /// function will first use a path with that port number appended. If that path doesn't exist,
    /// or if this instance uses a non-vsock GUID, it will use a path with the full ID.
    pub fn host_uds_path(&self, base_path: impl AsRef<Path>) -> Result<PathBuf, UdsPathError> {
        let base_path = base_path.as_ref();
        let mut path = base_path.as_os_str().to_owned();
        if let Some(port) = self.port() {
            // This is a vsock connection, so first try connecting after appending the
            // port to the path.
            path.push(format!("_{port}"));
            if Path::new(&path).fs_err_try_exists()? {
                return Ok(path.into());
            }

            // If the port didn't exist, try again with the service ID.
            path.clear();
            path.push(base_path);
        }

        path.push(format!("_{}", self.id()));
        if !Path::new(&path).fs_err_try_exists()? {
            return Err(UdsPathError::NoListener(path.into()));
        }

        Ok(path.into())
    }

    /// Parses a connection request from a buffer containing a UTF-8 string of the format "CONNECT
    /// \<port or service ID>\n".
    pub fn parse_connect_request(buf: &[u8]) -> Result<Self, ParseError> {
        let rest = strip_ascii_prefix_case_insensitive(buf, b"CONNECT ")
            .ok_or(ParseError::MissingPrefix)?;

        let rest = std::str::from_utf8(rest).map_err(ParseError::InvalidString)?;
        if let Ok(port) = u32::from_str(rest) {
            Ok(VsockPortOrId::Port(port))
        } else if let Ok(service_id) = Guid::from_str(rest) {
            Ok(VsockPortOrId::Id(service_id))
        } else {
            Err(ParseError::InvalidFormat(rest.to_string()))
        }
    }

    /// Gets the response string that should be sent back to the guest on a successful connection,
    /// of the format "OK \<port or service ID>\n".
    ///
    /// In this case, any instance using a GUID will be formatted using the full service ID, even if
    /// it matches the hvsocket vsock template. The format returned should always match the format
    /// that was used in the "CONNECT" request.
    pub fn get_ok_response(&self) -> String {
        match self {
            VsockPortOrId::Port(port) => format!("OK {}\n", port),
            VsockPortOrId::Id(service_id) => format!("OK {}\n", service_id),
        }
    }

    /// Writes the response string that should be sent back to the guest on a successful connection
    /// into the provided buffer, and returns the number of bytes written.
    ///
    /// # Panics
    ///
    /// This function will panic if the buffer is too small to hold the response.
    pub fn write_ok_response(&self, buf: &mut [u8]) -> usize {
        let mut cursor = std::io::Cursor::new(buf);
        match self {
            VsockPortOrId::Port(port) => {
                writeln!(cursor, "OK {}", port).expect("buffer should be large enough")
            }
            VsockPortOrId::Id(service_id) => {
                writeln!(cursor, "OK {}", service_id).expect("buffer should be large enough")
            }
        }

        cursor.position() as usize
    }
}

fn strip_ascii_prefix_case_insensitive<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Error returned by [`VsockPortOrId::host_uds_path`].
#[derive(Debug, thiserror::Error)]
pub enum UdsPathError {
    /// No hybrid vsock listener was found at the specified path.
    #[error("no hybrid vsock listener at {}", _0.display())]
    NoListener(PathBuf),
    /// An I/O error occurred while checking for the listener.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Error returned by [`VsockPortOrId::parse_connect_request`].
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The connect request did not contain a newline within the maximum expected length.
    #[error("connect request did not fit")]
    RequestTooLong,
    /// The connect request did not start with the expected "CONNECT " prefix.
    #[error("missing CONNECT prefix")]
    MissingPrefix,
    /// The connect request contained invalid UTF-8.
    #[error("invalid UTF-8 in connect request")]
    InvalidString(#[from] std::str::Utf8Error),
    /// The connect request did not contain a valid port number or service ID.
    #[error("invalid port or service ID: {0}")]
    InvalidFormat(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use guid::guid;

    #[test]
    fn test_read_hybrid_vsock_connect_uppercase() {
        let connect = b"CONNECT 1234";
        let request = VsockPortOrId::parse_connect_request(connect).unwrap();
        assert_eq!(request, VsockPortOrId::Port(1234));
        assert_eq!(
            request.id(),
            Guid {
                data1: 1234,
                ..VSOCK_TEMPLATE
            }
        );
    }

    #[test]
    fn test_read_hybrid_vsock_connect_lowercase() {
        let connect = b"connect 1234";
        let request = VsockPortOrId::parse_connect_request(connect).unwrap();
        assert_eq!(request, VsockPortOrId::Port(1234));
        assert_eq!(
            request.id(),
            Guid {
                data1: 1234,
                ..VSOCK_TEMPLATE
            }
        );
    }

    #[test]
    fn test_read_hybrid_vsock_connect_guid() {
        let connect = b"CONNECT 00000123-facb-11e6-bd58-64006a7986d3";
        let request = VsockPortOrId::parse_connect_request(connect).unwrap();
        let expected = guid!("00000123-facb-11e6-bd58-64006a7986d3");
        assert_eq!(request, VsockPortOrId::Id(expected));
        assert_eq!(request.port(), Some(0x123));
        assert_eq!(request.id(), expected);

        let connect = b"CONNECT EE59B4BF-A573-48D0-9C51-BB0E72C2B139";
        let request = VsockPortOrId::parse_connect_request(connect).unwrap();
        let expected = guid!("ee59b4bf-a573-48d0-9c51-bb0e72c2b139");
        assert_eq!(request, VsockPortOrId::Id(expected));
        assert_eq!(request.port(), None);
        assert_eq!(request.id(), expected);
    }

    #[test]
    fn test_get_ok_response() {
        let port_request = VsockPortOrId::Port(1234);
        assert_eq!(port_request.get_ok_response(), "OK 1234\n");

        let guid = guid!("00000123-facb-11e6-bd58-64006a7986d3");
        let id_request = VsockPortOrId::Id(guid);
        assert_eq!(
            id_request.get_ok_response(),
            "OK 00000123-facb-11e6-bd58-64006a7986d3\n"
        );
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use test_with_tracing::test;

    // Test: Parse boundary ports and GUID requests, then write bounded replies.
    // Expected: The request's numeric/GUID form survives the handshake, with
    //       canonical reply bytes and no writes outside the response.
    #[test]
    fn handshake_preserves_address_form_and_reply_bounds() {
        for (request, expected, port) in [
            ("CoNnEcT 0", "OK 0\n", Some(0)),
            ("CONNECT 4294967295", "OK 4294967295\n", Some(u32::MAX)),
            (
                "CONNECT ffffffff-facb-11e6-bd58-64006a7986d3",
                "OK ffffffff-facb-11e6-bd58-64006a7986d3\n",
                Some(u32::MAX),
            ),
            (
                "CONNECT 12345678-9abc-def0-1234-56789abcdef0",
                "OK 12345678-9abc-def0-1234-56789abcdef0\n",
                None,
            ),
        ] {
            let parsed = VsockPortOrId::parse_connect_request(request.as_bytes()).unwrap();
            assert_eq!(parsed.port(), port);
            assert_eq!(parsed.get_ok_response(), expected);
            let mut output = [0xa5; 64];
            let len = parsed.write_ok_response(&mut output[3..3 + expected.len()]);
            assert_eq!(len, expected.len());
            assert_eq!(&output[3..3 + len], expected.as_bytes());
            assert!(
                output[..3]
                    .iter()
                    .chain(&output[3 + len..])
                    .all(|byte| *byte == 0xa5)
            );
        }
    }

    // Test: Select host listener paths with both numeric and GUID candidates.
    // Expected: Embedded ports prefer the numeric listener, fall back to the
    //       full ID, and report the exact missing candidate when neither exists.
    #[test]
    fn listener_selection_preserves_port_priority_and_guid_fallback() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let base = directory.path().join("relay");
        let port_path = directory.path().join("relay_291");
        let guid_path = directory
            .path()
            .join("relay_00000123-facb-11e6-bd58-64006a7986d3");
        std::fs::write(&guid_path, []).unwrap();
        for request in [
            VsockPortOrId::Port(291),
            VsockPortOrId::Id(guid::guid!("00000123-facb-11e6-bd58-64006a7986d3")),
        ] {
            assert_eq!(request.host_uds_path(&base).unwrap(), guid_path);
            std::fs::write(&port_path, []).unwrap();
            assert_eq!(request.host_uds_path(&base).unwrap(), port_path);
            std::fs::remove_file(&port_path).unwrap();
        }
        std::fs::remove_file(&guid_path).unwrap();
        assert!(matches!(VsockPortOrId::Port(291).host_uds_path(&base),
            Err(UdsPathError::NoListener(path)) if path == guid_path));
        let custom = VsockPortOrId::Id(guid::guid!("01234567-89ab-cdef-0123-456789abcdef"));
        let custom_path = directory
            .path()
            .join("relay_01234567-89ab-cdef-0123-456789abcdef");
        std::fs::write(&custom_path, []).unwrap();
        std::fs::write(&port_path, []).unwrap();
        assert_eq!(custom.host_uds_path(&base).unwrap(), custom_path);
    }

    // Test: Reject incomplete prefixes, malformed numbers/IDs and invalid UTF-8.
    // Expected: Protocol errors retain their category rather than admitting
    //       truncated, overflowing or non-address payloads.
    #[test]
    fn malformed_handshakes_return_typed_errors() {
        for request in [
            b"".as_slice(),
            b"CONNEC",
            b"CONNECT",
            b"OTHER 7",
            b"CONNECT\t7",
        ] {
            assert!(matches!(
                VsockPortOrId::parse_connect_request(request),
                Err(ParseError::MissingPrefix)
            ));
        }
        for request in [
            "CONNECT ",
            "CONNECT -1",
            "CONNECT 4294967296",
            "CONNECT 12x",
            "CONNECT not-a-guid",
            "CONNECT 7 8",
        ] {
            assert!(matches!(
                VsockPortOrId::parse_connect_request(request.as_bytes()),
                Err(ParseError::InvalidFormat(_))
            ));
        }
        assert!(matches!(
            VsockPortOrId::parse_connect_request(b"CONNECT \xff"),
            Err(ParseError::InvalidString(_))
        ));
    }
}
