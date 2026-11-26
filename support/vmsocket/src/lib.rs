// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Support for `AF_HYPERV` (on Windows) and `AF_VSOCK` (on Linux) socket families.
//!
//! This crate abstracts over the differences between these and provides unified
//! [`VmStream`] and [`VmListener`] types.

#![cfg(any(windows, target_os = "linux"))]

cfg_select! {
    windows => {
        mod af_hyperv;
        use af_hyperv as sys;
    }
    unix => {
        mod af_vsock;
        use af_vsock as sys;
    }
    _ => {}
}

use socket2::SockAddr;
use socket2::Socket;
use std::io;
use std::io::Read;
use std::io::Write;

/// Gets the local AF_VSOCK CID.
#[cfg(target_os = "linux")]
pub fn local_vsock_cid() -> io::Result<u32> {
    sys::local_cid()
}

/// A VM socket address.
#[derive(Debug)]
pub struct VmAddress(sys::Address);

impl std::fmt::Display for VmAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(windows)]
        write!(f, "{}:{}", self.vm_id(), self.service_id())?;
        #[cfg(unix)]
        write!(f, "{}:{}", self.cid(), self.port())?;
        Ok(())
    }
}

impl VmAddress {
    /// Creates a new AF_VSOCK address from `cid` and `port`.
    #[cfg(unix)]
    pub fn vsock(cid: u32, port: u32) -> Self {
        Self(sys::Address::new(cid, port))
    }

    /// Creates a new AF_HYPERV address from `vm_id` and `service_id`.
    #[cfg(windows)]
    pub fn hyperv(vm_id: guid::Guid, service_id: guid::Guid) -> Self {
        Self(sys::Address::new(vm_id, service_id))
    }

    /// Creates a new AF_HYPERV address from `vm_id` and VSOCK `port`.
    #[cfg(windows)]
    pub fn hyperv_vsock(vm_id: guid::Guid, port: u32) -> Self {
        Self(sys::Address::vsock(vm_id, port))
    }

    /// Creates a new AF_HYPERV address referring to any VM and the specified
    /// service ID.
    #[cfg(windows)]
    pub fn hyperv_any(service_id: guid::Guid) -> Self {
        Self(sys::Address::hyperv_any(service_id))
    }

    /// Creates a new AF_HYPERV address referring to the parent VM and the
    /// specified service ID.
    #[cfg(windows)]
    pub fn hyperv_host(service_id: guid::Guid) -> Self {
        Self(sys::Address::hyperv_host(service_id))
    }

    /// Creates a new address referring to any VM, with the specified VSOCK
    /// port.
    pub fn vsock_any(port: u32) -> Self {
        Self(sys::Address::vsock_any(port))
    }

    /// Creates a new address referring to the host, with the specified VSOCK
    /// port.
    pub fn vsock_host(port: u32) -> Self {
        Self(sys::Address::vsock_host(port))
    }

    /// Creates a new address from the specified [`SockAddr`] when the address
    /// is an `AF_HYPERV` (on Windows) or `AF_VSOCK` (on Linux) address.
    pub fn try_from_sock_addr(addr: &SockAddr) -> Option<Self> {
        Some(Self(sys::Address::try_from_sock_addr(addr)?))
    }

    /// Gets the VSOCK CID.
    #[cfg(unix)]
    pub fn cid(&self) -> u32 {
        self.0.cid
    }

    /// Gets the VSOCK port.
    #[cfg(unix)]
    pub fn port(&self) -> u32 {
        self.0.port
    }

    /// Gets the VM ID.
    #[cfg(windows)]
    pub fn vm_id(&self) -> guid::Guid {
        self.0.vm_id
    }

    /// Gets the service ID.
    #[cfg(windows)]
    pub fn service_id(&self) -> guid::Guid {
        self.0.service_id
    }
}

impl From<VmAddress> for SockAddr {
    fn from(address: VmAddress) -> Self {
        address.0.into_sock_addr()
    }
}

/// A VM socket that has not yet been bound.
pub struct VmSocket(Socket);

impl VmSocket {
    /// Creates a new stream socket not bound or connected to anything.
    pub fn new() -> io::Result<Self> {
        Self::new_inner()
    }

    /// Binds the socket to `address`.
    pub fn bind(&mut self, address: VmAddress) -> io::Result<()> {
        self.0.bind(&address.into())?;
        Ok(())
    }

    /// Listens for connections, returning a [`VmListener`].
    pub fn listen(self, backlog: i32) -> io::Result<VmListener> {
        self.0.listen(backlog)?;
        Ok(VmListener(self.0))
    }

    /// Connects to `address`, returning a [`VmStream`].
    pub fn connect(self, address: VmAddress) -> io::Result<VmStream> {
        self.0.connect(&address.into())?;
        Ok(VmStream(self.0))
    }
}

impl From<Socket> for VmSocket {
    fn from(s: Socket) -> Self {
        Self(s)
    }
}

impl From<VmSocket> for Socket {
    fn from(s: VmSocket) -> Self {
        s.0
    }
}

/// A VM socket listener.
#[derive(Debug)]
pub struct VmListener(Socket);

impl VmListener {
    /// Creates a new socket bound to the specified address.
    pub fn bind(address: VmAddress) -> io::Result<Self> {
        let mut s = VmSocket::new()?;
        s.bind(address)?;
        s.listen(4)
    }

    /// Accepts the next connection.
    pub fn accept(&self) -> io::Result<(VmStream, VmAddress)> {
        let (s, addr) = self.0.accept()?;
        Ok((VmStream(s), VmAddress::try_from_sock_addr(&addr).unwrap()))
    }

    /// Retrieves the address that the listener is bound to.
    pub fn local_addr(&self) -> io::Result<VmAddress> {
        Ok(VmAddress::try_from_sock_addr(&self.0.local_addr()?).unwrap())
    }
}

impl pal_async::socket::Listener for VmListener {
    type Socket = VmStream;
    type Address = VmAddress;

    fn accept(&self) -> io::Result<(Self::Socket, Self::Address)> {
        self.accept()
    }

    fn local_addr(&self) -> io::Result<Self::Address> {
        self.local_addr()
    }
}

impl From<Socket> for VmListener {
    fn from(s: Socket) -> Self {
        Self(s)
    }
}

impl From<VmListener> for Socket {
    fn from(s: VmListener) -> Self {
        s.0
    }
}

/// A VM stream socket.
#[derive(Debug)]
pub struct VmStream(Socket);

impl VmStream {
    /// Connects to the specified address.
    pub fn connect(addr: VmAddress) -> io::Result<Self> {
        VmSocket::new()?.connect(addr)
    }

    /// Attempts to clone the underlying socket.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }
}

impl From<Socket> for VmStream {
    fn from(s: Socket) -> Self {
        Self(s)
    }
}

impl From<VmStream> for Socket {
    fn from(s: VmStream) -> Self {
        s.0
    }
}

impl Read for VmStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for VmStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Read for &'_ VmStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.0).read(buf)
    }
}

impl Write for &'_ VmStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.0).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&self.0).flush()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::VmAddress;
    use super::VmSocket;
    use super::VmStream;
    use socket2::SockAddr;
    use socket2::Socket;
    use std::io::Read;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::fd::AsRawFd;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;
    use test_with_tracing::test;

    // Test: Round-trip arbitrary VSOCK CID/port boundaries, host/any shortcuts, and unrelated socket families.
    // Expected: IDs, ports, and decimal display are exact; only VSOCK addresses are accepted.
    #[test]
    fn vsock_address_identity_and_family_validation() {
        for (cid, port, display) in [
            (0, 0, "0:0"),
            (2, 1, "2:1"),
            (u32::MAX, u32::MAX, "4294967295:4294967295"),
            (0x1234_5678, 0x8765_4321, "305419896:2271560481"),
        ] {
            let address = VmAddress::vsock(cid, port);
            assert_eq!(address.to_string(), display);
            assert_eq!(address.cid(), cid);
            assert_eq!(address.port(), port);
            let raw: SockAddr = address.into();
            let restored = VmAddress::try_from_sock_addr(&raw).unwrap();
            assert_eq!((restored.cid(), restored.port()), (cid, port));
        }
        for port in [0, 42, u32::MAX] {
            let any = VmAddress::vsock_any(port);
            assert_eq!((any.cid(), any.port()), (u32::MAX, port));
            let host = VmAddress::vsock_host(port);
            assert_eq!((host.cid(), host.port()), (2, port));
        }
        for address in [
            SockAddr::from("127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap()),
            SockAddr::from("[::1]:1234".parse::<std::net::SocketAddr>().unwrap()),
            SockAddr::unix("/unbound-vmsocket-test").unwrap(),
        ] {
            assert!(VmAddress::try_from_sock_addr(&address).is_none());
        }
    }

    // Test: Transfer binary data through shared/mutable VM stream wrappers and descriptor/clone conversions using a Unix socket pair.
    // Expected: Read/write/flush delegation preserves exact bytes, and surviving clones remain connected after original owners are dropped.
    #[test]
    fn stream_io_and_descriptor_ownership_preserve_binary_data() {
        let (local, mut peer) = UnixStream::pair().unwrap();
        local
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let stream = VmStream::from(Socket::from(local));
        let mut shared = &stream;
        shared.write_all(&[0, 0x11, 0xff]).unwrap();
        shared.flush().unwrap();
        let mut received = [0; 3];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(received, [0, 0x11, 0xff]);
        peer.write_all(&[0xaa, 0, 0x55]).unwrap();
        shared.read_exact(&mut received).unwrap();
        assert_eq!(received, [0xaa, 0, 0x55]);

        let descriptor_number = stream.as_fd().as_raw_fd();
        let descriptor: OwnedFd = stream.into();
        assert_eq!(descriptor.as_raw_fd(), descriptor_number);
        let restored = VmStream::from(descriptor);
        let mut cloned = restored.try_clone().unwrap();
        drop(restored);
        cloned.write_all(&[3, 2, 1]).unwrap();
        cloned.flush().unwrap();
        peer.read_exact(&mut received).unwrap();
        assert_eq!(received, [3, 2, 1]);
        peer.write_all(&[6, 5, 4]).unwrap();
        cloned.read_exact(&mut received).unwrap();
        assert_eq!(received, [6, 5, 4]);
        let socket: Socket = cloned.into();
        let mut restored = VmStream::from(socket);
        peer.write_all(&[9, 8, 7]).unwrap();
        restored.read_exact(&mut received).unwrap();
        assert_eq!(received, [9, 8, 7]);
    }

    // Test: Pass an unrepresentable connect timeout through an owned descriptor round-trip.
    // Expected: Validation returns InvalidInput before the platform socket option and leaves the descriptor alive.
    #[test]
    fn oversized_connect_timeout_returns_error_without_losing_socket() {
        let (local, peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let socket = VmSocket::from(Socket::from(local));
        let descriptor_number = socket.as_fd().as_raw_fd();
        let descriptor: OwnedFd = socket.into();
        let socket = VmSocket::from(descriptor);
        assert!(
            socket
                .set_connect_timeout(Duration::from_micros(42))
                .is_err()
        );
        let error = socket.set_connect_timeout(Duration::MAX).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(socket.as_fd().as_raw_fd(), descriptor_number);
        let mut underlying: Socket = socket.into();
        underlying.write_all(&[0x7f]).unwrap();
        let mut peer = peer;
        let mut received = [0];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(received, [0x7f]);
    }

    // Test: Bind/listen on an ephemeral VSOCK port and round-trip listener descriptors without contacting a VM.
    // Expected: Local address identity survives descriptor ownership transfers, and connect timeout configuration accepts a representable duration.
    #[test]
    #[ignore = "requires an enabled Linux AF_VSOCK transport"]
    fn native_vsock_bind_and_listener_descriptor_ownership() {
        use super::VmListener;

        let mut socket = VmSocket::new().unwrap();
        socket
            .set_connect_timeout(Duration::from_millis(1500))
            .unwrap();
        socket.bind(VmAddress::vsock_any(u32::MAX)).unwrap();
        let listener = socket.listen(4).unwrap();
        let address = listener.local_addr().unwrap();
        assert_eq!(address.cid(), u32::MAX);
        assert_ne!(address.port(), u32::MAX);
        let reported = pal_async::socket::Listener::local_addr(&listener).unwrap();
        assert_eq!(
            (reported.cid(), reported.port()),
            (address.cid(), address.port())
        );
        let borrowed = listener.as_fd().try_clone_to_owned().unwrap();
        let cloned = VmListener::from(borrowed);
        drop(listener);
        let descriptor: OwnedFd = cloned.into();
        let restored = VmListener::from(descriptor);
        let raw: Socket = restored.into();
        let restored = VmListener::from(raw);
        let reported = restored.local_addr().unwrap();
        assert_eq!(
            (reported.cid(), reported.port()),
            (address.cid(), address.port())
        );
        let another = VmListener::bind(VmAddress::vsock_any(u32::MAX)).unwrap();
        assert_ne!(another.local_addr().unwrap().port(), address.port());
    }
}
