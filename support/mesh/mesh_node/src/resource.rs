// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Mesh resource definitions.
//!
//! Resources are things that can be sent across a mesh node boundary that
//! cannot be serialized to a protobuf field type. This includes mesh ports,
//! Unix file descriptors, and Windows file handles and sockets.

use crate::local_node::Port;
use thiserror::Error;

#[derive(Debug)]
pub enum OsResource {
    #[cfg(unix)]
    Fd(std::os::unix::io::OwnedFd),
    #[cfg(windows)]
    Handle(std::os::windows::io::OwnedHandle),
    #[cfg(windows)]
    Socket(std::os::windows::io::OwnedSocket),
}

/// A resource that can be sent via a port.
#[derive(Debug)]
pub enum Resource {
    /// Another port.
    Port(Port),
    /// An OS resource (file descriptor, Windows handle, or socket).
    Os(OsResource),
}

impl From<Port> for Resource {
    fn from(port: Port) -> Self {
        Self::Port(port)
    }
}

#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("wrong resource type")]
    BadResourceType,
    #[cfg(windows)]
    #[error("failed to convert handle to socket")]
    HandleToSocket(#[source] std::io::Error),
}

impl TryFrom<Resource> for Port {
    type Error = ResourceError;

    fn try_from(value: Resource) -> Result<Self, ResourceError> {
        match value {
            Resource::Port(port) => Ok(port),
            _ => Err(ResourceError::BadResourceType),
        }
    }
}

#[cfg(unix)]
impl From<std::os::unix::io::OwnedFd> for Resource {
    fn from(fd: std::os::unix::io::OwnedFd) -> Self {
        Self::Os(OsResource::Fd(fd))
    }
}

#[cfg(unix)]
impl TryFrom<Resource> for std::os::unix::io::OwnedFd {
    type Error = ResourceError;

    fn try_from(value: Resource) -> Result<Self, ResourceError> {
        match value {
            Resource::Os(OsResource::Fd(fd)) => Ok(fd),
            _ => Err(ResourceError::BadResourceType),
        }
    }
}

#[cfg(windows)]
impl From<std::os::windows::io::OwnedHandle> for Resource {
    fn from(port: std::os::windows::io::OwnedHandle) -> Self {
        Self::Os(OsResource::Handle(port))
    }
}

#[cfg(windows)]
impl TryFrom<Resource> for std::os::windows::io::OwnedHandle {
    type Error = ResourceError;

    fn try_from(value: Resource) -> Result<Self, ResourceError> {
        match value {
            Resource::Os(OsResource::Handle(handle)) => Ok(handle),
            _ => Err(ResourceError::BadResourceType),
        }
    }
}

#[cfg(windows)]
impl From<std::os::windows::io::OwnedSocket> for Resource {
    fn from(port: std::os::windows::io::OwnedSocket) -> Self {
        Self::Os(OsResource::Socket(port))
    }
}

#[cfg(windows)]
impl TryFrom<Resource> for std::os::windows::io::OwnedSocket {
    type Error = ResourceError;

    fn try_from(value: Resource) -> Result<Self, ResourceError> {
        match value {
            Resource::Os(OsResource::Socket(socket)) => Ok(socket),
            Resource::Os(OsResource::Handle(handle)) => {
                pal::windows::OwnedSocketExt::from_handle(handle)
                    .map_err(ResourceError::HandleToSocket)
            }
            _ => Err(ResourceError::BadResourceType),
        }
    }
}

pub type SerializedMessage = mesh_protobuf::SerializedMessage<Resource>;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Read;
    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use test_with_tracing::test;

    // Test: Convert live ports and file descriptors through mesh resources.
    // Expected: Correct conversions retain usable ownership; wrong types fail.
    #[test]
    fn resource_conversions_preserve_live_endpoints_and_reject_wrong_types() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let fd: OwnedFd = socket.into();
        let fd = OwnedFd::try_from(Resource::from(fd)).unwrap();
        let mut socket = UnixStream::from(fd);
        socket.write_all(b"mesh").unwrap();
        let mut bytes = [0; 4];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"mesh");
        assert!(matches!(
            Port::try_from(Resource::from(OwnedFd::from(socket))),
            Err(ResourceError::BadResourceType)
        ));
        assert_eq!(peer.read(&mut bytes).unwrap(), 0);
        let (port, peer) = Port::new_pair();
        let port = Port::try_from(Resource::from(port)).unwrap();
        assert!(!peer.is_closed().unwrap());
        assert!(matches!(
            OwnedFd::try_from(Resource::from(port)),
            Err(ResourceError::BadResourceType)
        ));
        assert!(peer.is_closed().unwrap());
    }
}
