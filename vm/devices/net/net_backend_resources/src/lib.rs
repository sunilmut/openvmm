// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resource definitions for network backends (endpoints).
//!
//! TODO: move the resource definitions to separate crates for each endpoint.

#![forbid(unsafe_code)]

pub mod mac_address;

/// Null backend.
pub mod null {
    use mesh::MeshPayload;
    use vm_resource::ResourceId;
    use vm_resource::kind::NetEndpointHandleKind;

    /// Handle to a null network endpoint, which drops sent packets and never
    /// receives packets.
    #[derive(MeshPayload)]
    pub struct NullHandle;

    impl ResourceId<NetEndpointHandleKind> for NullHandle {
        const ID: &'static str = "null";
    }
}

/// Consomme backend.
pub mod consomme {
    use mesh::MeshPayload;
    use vm_resource::ResourceId;
    use vm_resource::kind::NetEndpointHandleKind;

    /// Protocol for host port forwarding.
    #[derive(Clone, Debug, MeshPayload)]
    pub enum HostPortProtocol {
        /// TCP protocol.
        Tcp,
        /// UDP protocol.
        Udp,
    }

    /// An IP address, suitable for serialization via mesh.
    #[derive(Clone, Debug, MeshPayload)]
    pub enum HostIpAddress {
        /// IPv4 address.
        Ipv4(std::net::Ipv4Addr),
        /// IPv6 address.
        Ipv6(std::net::Ipv6Addr),
    }

    impl From<std::net::IpAddr> for HostIpAddress {
        fn from(addr: std::net::IpAddr) -> Self {
            match addr {
                std::net::IpAddr::V4(v4) => HostIpAddress::Ipv4(v4),
                std::net::IpAddr::V6(v6) => HostIpAddress::Ipv6(v6),
            }
        }
    }

    impl From<HostIpAddress> for std::net::IpAddr {
        fn from(addr: HostIpAddress) -> Self {
            match addr {
                HostIpAddress::Ipv4(v4) => std::net::IpAddr::V4(v4),
                HostIpAddress::Ipv6(v6) => std::net::IpAddr::V6(v6),
            }
        }
    }

    /// The host port to listen on for a port forward.
    #[derive(Debug, MeshPayload)]
    pub enum HostPort {
        /// A fixed host port.
        Fixed(u16),
        /// Let the OS assign a port. The assigned port is sent back via the
        /// oneshot sender.
        Dynamic(mesh::OneshotSender<u16>),
    }

    /// Configuration for forwarding a host port into the guest.
    #[derive(Debug, MeshPayload)]
    pub struct HostPortConfig {
        /// The protocol to forward.
        pub protocol: HostPortProtocol,
        /// The host IP address to bind to, or `None` to bind to all interfaces.
        pub host_address: Option<HostIpAddress>,
        /// The host port to listen on.
        pub host_port: HostPort,
        /// The guest port to forward to.
        pub guest_port: u16,
    }

    /// A static DNS `A` record answered directly by Consomme.
    #[derive(Debug, MeshPayload)]
    pub struct DnsRecordConfig {
        /// The query name in presentation form (e.g. `"example.com"`).
        pub name: String,
        /// The IPv4 address returned for the name.
        pub address: std::net::Ipv4Addr,
    }

    /// A runtime request to modify a running Consomme endpoint.
    #[derive(MeshPayload)]
    pub enum ConsommeRequest {
        /// Bind a host port to forward traffic to the guest.
        Bind(mesh::rpc::FailableRpc<HostPortConfig, ()>),
        /// Unbind a previously forwarded port.
        Unbind(mesh::rpc::FailableRpc<HostPortConfig, ()>),
        /// Add a static DNS record.
        AddDnsRecord(mesh::rpc::FailableRpc<DnsRecordConfig, ()>),
        /// Allocate a virtual address in the guest subnet that routes to the
        /// given host address, and return it.
        CreateVirtualAddress(mesh::rpc::FailableRpc<HostIpAddress, HostIpAddress>),
    }

    /// Optional Consomme endpoint settings supplied by the VM creator.
    #[derive(Debug, Default, MeshPayload)]
    pub struct ConsommeParams {
        /// The guest's IPv4 address. Overrides the address derived from the CIDR.
        pub client_ip: Option<std::net::Ipv4Addr>,
        /// The gateway's IPv4 address. Overrides the address derived from the CIDR.
        pub gateway_ip: Option<std::net::Ipv4Addr>,
        /// The IPv4 network mask. Overrides the mask derived from the CIDR.
        pub net_mask: Option<std::net::Ipv4Addr>,
        /// The guest's IPv6 address (link-local or routable), if known before
        /// the guest configures it.
        pub client_ip_ipv6: Option<std::net::Ipv6Addr>,
        /// If true, allow guest traffic to host-local addresses (loopback,
        /// unspecified, link-local).
        pub allow_host_local_access: bool,
    }

    /// Handle to a Consomme network endpoint.
    #[derive(MeshPayload)]
    pub struct ConsommeHandle {
        /// The CIDR of the network to use.
        pub cidr: Option<String>,
        /// Optional network parameters applied after the CIDR.
        pub params: ConsommeParams,
        /// Ports to forward from the host into the guest at creation time.
        pub ports: Vec<HostPortConfig>,
        /// If true, the guest uses the built-in DNS resolver. If false, the
        /// guest uses the host's DNS servers instead.
        pub internal_dns: bool,
        /// Optional channel for runtime port bind/unbind after the endpoint starts.
        pub recv: Option<mesh::Receiver<ConsommeRequest>>,
    }

    impl ResourceId<NetEndpointHandleKind> for ConsommeHandle {
        const ID: &'static str = "consomme";
    }
}

/// Windows vmswitch DirectIO backend.
pub mod dio {
    use guid::Guid;
    use mesh::MeshPayload;
    use vm_resource::ResourceId;
    use vm_resource::kind::NetEndpointHandleKind;

    /// A Hyper-V networking switch port ID.
    #[derive(Copy, Clone, MeshPayload)]
    pub struct SwitchPortId {
        /// The switch ID.
        pub switch: Guid,
        /// The allocated port ID.
        pub port: Guid,
    }

    /// Handle to a DirectIO network endpoint.
    #[derive(MeshPayload)]
    pub struct WindowsDirectIoHandle {
        /// The allocated switch port ID.
        pub switch_port_id: SwitchPortId,
    }

    impl ResourceId<NetEndpointHandleKind> for WindowsDirectIoHandle {
        const ID: &'static str = "dio";
    }
}

/// Linux TAP backend.
#[cfg(target_os = "linux")]
pub mod tap {
    use mesh::MeshPayload;
    use vm_resource::ResourceId;
    use vm_resource::kind::NetEndpointHandleKind;

    /// A handle to a TAP device.
    #[derive(MeshPayload)]
    pub struct TapHandle {
        /// A pre-opened TAP file descriptor, configured with
        /// `IFF_TAP | IFF_NO_PI | IFF_VNET_HDR`.
        pub fd: std::os::fd::OwnedFd,
    }

    impl ResourceId<NetEndpointHandleKind> for TapHandle {
        const ID: &'static str = "tap";
    }
}

#[cfg(test)]
mod tests {
    use super::consomme::HostIpAddress;
    use super::mac_address::MacAddress;
    use std::net::IpAddr;
    use test_with_tracing::test;

    // Test: Send explicitly bound IPv4, IPv6 and mapped IPv6 addresses as resources.
    // Expected: The host bind address retains every bit and its address family;
    //       a mapped IPv6 address must not silently become an IPv4 bind.
    #[test]
    fn host_bind_addresses_preserve_family_across_serialization() {
        for text in [
            "0.0.0.0",
            "127.0.0.1",
            "::",
            "2001:db8:1234::abcd",
            "::ffff:192.0.2.7",
        ] {
            let address: IpAddr = text.parse().unwrap();
            let (encoded, resources) = mesh::Message::new(HostIpAddress::from(address)).serialize();
            let decoded: HostIpAddress = mesh::Message::serialized(&encoded, resources)
                .parse()
                .unwrap();
            assert_eq!(IpAddr::from(decoded), address);
        }
    }

    // Test: Canonicalize a nonuniform MAC supplied in either accepted notation.
    // Expected: Leading zeroes, octet order and all six bytes survive formatting
    //       and reparsing; non-ASCII and malformed separators are rejected.
    #[test]
    fn mac_text_roundtrip_preserves_identity() {
        let expected = [0x02, 0x0a, 0xb0, 0x01, 0xfe, 0x80];
        for address in [
            MacAddress::from(expected),
            MacAddress::new(expected),
            "02:0A:B0:01:Fe:80".parse().unwrap(),
        ] {
            let text = address.to_string();
            assert_eq!(text, "02-0a-b0-01-fe-80");
            let reparsed: MacAddress = text.parse().unwrap();
            assert_eq!(<[u8; 6]>::from(reparsed), expected);
        }
        for text in [
            "02.0a.b0.01.fe.80",
            "é:0a:b0:01:fe:80",
            "02:0a:b0:01:fe:\0\0",
        ] {
            assert!(text.parse::<MacAddress>().is_err(), "{text:?}");
        }
    }
}
