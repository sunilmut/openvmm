// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::tests::{DriverThread, WakeChannel};
use smoltcp::wire::{Icmpv4Message, Icmpv4Packet, Ipv4Repr};
use std::net::{Ipv6Addr, UdpSocket};

fn ipv4(
    params: &ConsommeParams,
    source: Ipv4Address,
    destination: Ipv4Address,
    protocol: IpProtocol,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0; 14 + 20 + payload.len()];
    let mut ethernet = EthernetFrame::new_unchecked(&mut bytes);
    EthernetRepr {
        src_addr: params.client_mac,
        dst_addr: params.gateway_mac,
        ethertype: EthernetProtocol::Ipv4,
    }
    .emit(&mut ethernet);
    let mut ip = Ipv4Packet::new_unchecked(ethernet.payload_mut());
    Ipv4Repr {
        src_addr: source,
        dst_addr: destination,
        next_header: protocol,
        payload_len: payload.len(),
        hop_limit: 64,
    }
    .emit(&mut ip, &ChecksumCapabilities::default());
    ip.payload_mut().copy_from_slice(payload);
    bytes
}

fn udp(
    params: &ConsommeParams,
    source: IpAddress,
    destination: IpAddress,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0; 8 + payload.len()];
    let mut packet = UdpPacket::new_unchecked(&mut bytes);
    packet.set_src_port(source_port);
    packet.set_dst_port(destination_port);
    packet.set_len((8 + payload.len()).try_into().unwrap());
    packet.payload_mut().copy_from_slice(payload);
    packet.fill_checksum(&source, &destination);
    match (source, destination) {
        (IpAddress::Ipv4(source), IpAddress::Ipv4(destination)) => {
            ipv4(params, source, destination, IpProtocol::Udp, &bytes)
        }
        (IpAddress::Ipv6(source), IpAddress::Ipv6(destination)) => {
            ipv6(params, source, destination, IpProtocol::Udp, &bytes)
        }
        _ => panic!("address families must match"),
    }
}

fn echo(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 8 + payload.len()];
    let mut packet = Icmpv4Packet::new_unchecked(&mut bytes);
    packet.set_msg_type(Icmpv4Message::EchoRequest);
    packet.set_msg_code(0);
    packet.set_echo_ident(0x1234);
    packet.set_echo_seq_no(7);
    packet.data_mut().copy_from_slice(payload);
    packet.fill_checksum();
    bytes
}

// Test: Ping the gateway with empty, ordinary and maximum-size echo payloads.
// Expected: Replies preserve identifier, sequence and payload, swap addressing,
//       and contain valid IPv4 and ICMP checksums without opening a host socket.
#[pal_async::async_test]
async fn gateway_echo_replies_preserve_wire_data_at_mtu_boundary(driver: DefaultDriver) {
    let params = params();
    let mut stack = Consomme::new(params.clone());
    let mut client = TestClient::new(driver);
    for length in [0, 1, 128, MIN_MTU - 14 - 20 - 8] {
        let payload = vec![0x5a; length];
        let request = ipv4(
            &params,
            params.client_ip,
            params.gateway_ip,
            IpProtocol::Icmp,
            &echo(&payload),
        );
        stack
            .access(&mut client)
            .send(&request, &ChecksumState::NONE)
            .unwrap();
        assert_eq!(client.received_packets.len(), 1);
        let frame = EthernetFrame::new_checked(&client.received_packets[0]).unwrap();
        assert_eq!(frame.dst_addr(), params.client_mac);
        let ip = Ipv4Packet::new_checked(frame.payload()).unwrap();
        assert_eq!(ip.src_addr(), params.gateway_ip);
        assert_eq!(ip.dst_addr(), params.client_ip);
        assert!(ip.verify_checksum());
        let packet = Icmpv4Packet::new_checked(ip.payload()).unwrap();
        assert_eq!(packet.msg_type(), Icmpv4Message::EchoReply);
        assert_eq!((packet.echo_ident(), packet.echo_seq_no()), (0x1234, 7));
        assert_eq!(packet.data(), payload);
        assert!(packet.verify_checksum());
        client.received_packets.clear();
    }
}

// Test: Send short gateway ICMP messages, an oversized echo and an echo reply.
// Expected: Short/oversized messages return MalformedPacket, while a non-request
//       ICMP message is silently ignored without a response.
#[pal_async::async_test]
async fn gateway_icmp_validates_lengths_and_ignores_non_requests(driver: DefaultDriver) {
    let params = params();
    let mut stack = Consomme::new(params.clone());
    let mut client = TestClient::new(driver);
    for length in 0..8 {
        let bytes = ipv4(
            &params,
            params.client_ip,
            params.gateway_ip,
            IpProtocol::Icmp,
            &vec![0; length],
        );
        assert!(matches!(
            stack.access(&mut client).send(&bytes, &ChecksumState::NONE),
            Err(DropReason::MalformedPacket)
        ));
    }
    let large = ipv4(
        &params,
        params.client_ip,
        params.gateway_ip,
        IpProtocol::Icmp,
        &echo(&vec![0; MIN_MTU]),
    );
    assert!(matches!(
        stack.access(&mut client).send(&large, &ChecksumState::NONE),
        Err(DropReason::MalformedPacket)
    ));
    let mut reply = echo(b"reply");
    let mut packet = Icmpv4Packet::new_unchecked(&mut reply);
    packet.set_msg_type(Icmpv4Message::EchoReply);
    packet.fill_checksum();
    let bytes = ipv4(
        &params,
        params.client_ip,
        params.gateway_ip,
        IpProtocol::Icmp,
        &reply,
    );
    stack
        .access(&mut client)
        .send(&bytes, &ChecksumState::NONE)
        .unwrap();
    assert!(client.received_packets.is_empty());
}

// Test: Send UDP through virtual mappings to host IPv4 and IPv6 loopback sockets,
//       then return two replies on the same connection.
// Expected: Host payloads and guest replies match, source addresses stay virtual,
//       and each IP family retains its guest port and valid UDP checksum.
#[test]
fn mapped_udp_connections_round_trip_both_address_families() {
    for host in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let (thread, driver) = DriverThread::new();
        let mut params = params();
        params.allow_host_local_access = false;
        let source: IpAddress = if host.is_ipv4() {
            params.client_ip.into()
        } else {
            "fe80::2".parse::<Ipv6Address>().unwrap().into()
        };
        let mut stack = Consomme::new(params.clone());
        let mut client = TestClient::new(driver);
        let server = UdpSocket::bind(SocketAddr::new(host, 0)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let destination: IpAddress = stack.create_virtual_address(host).unwrap().into();
        let wake = WakeChannel::new();
        for data in [&b"first"[..], &b"second"[..]] {
            let request = udp(
                &params,
                source,
                destination,
                40123,
                server.local_addr().unwrap().port(),
                data,
            );
            stack
                .access(&mut client)
                .send(&request, &ChecksumState::NONE)
                .unwrap();
            let mut actual = [0; 64];
            let (length, remote) = server.recv_from(&mut actual).unwrap();
            assert_eq!(&actual[..length], data);
            wake.poll(&mut stack, &mut client);
            server.send_to(data, remote).unwrap();
            wake.wait_for_packet(&mut stack, &mut client, |_| true);
            let frame = EthernetFrame::new_checked(&client.received_packets[0]).unwrap();
            let (actual_source, actual_destination, payload) = if host.is_ipv4() {
                let ip = Ipv4Packet::new_checked(frame.payload()).unwrap();
                (
                    IpAddress::from(ip.src_addr()),
                    IpAddress::from(ip.dst_addr()),
                    ip.payload().to_vec(),
                )
            } else {
                let ip = Ipv6Packet::new_checked(frame.payload()).unwrap();
                (
                    IpAddress::from(ip.src_addr()),
                    IpAddress::from(ip.dst_addr()),
                    ip.payload().to_vec(),
                )
            };
            assert_eq!(actual_source, destination);
            assert_eq!(actual_destination, source);
            let reply = UdpPacket::new_checked(&payload).unwrap();
            assert_eq!(reply.dst_port(), 40123);
            assert_eq!(reply.payload(), data);
            assert!(reply.verify_checksum(&actual_source, &actual_destination));
            client.received_packets.clear();
        }
        stack.clear_local_addr_map();
        assert!(stack.create_virtual_address(host).is_some());
        drop((stack, client));
        thread.join();
    }
}

// Test: Send UDP from a guest to its own host-side forwarding listener.
// Expected: Loopback remapping preserves the guest source port rather than
//       exposing the NAT socket's ephemeral port in the returned packet.
#[test]
fn udp_forwarding_loopback_preserves_the_guest_source_port() {
    let (thread, driver) = DriverThread::new();
    let params = params();
    let mut stack = Consomme::new(params.clone());
    let mut client = TestClient::new(driver);
    let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    stack
        .access(&mut client)
        .bind_udp_port(listener.into(), 7777)
        .unwrap();
    let destination: IpAddress = stack
        .create_virtual_address(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .unwrap()
        .into();
    let wake = WakeChannel::new();
    wake.poll(&mut stack, &mut client);
    let request = udp(
        &params,
        params.client_ip.into(),
        destination,
        40123,
        7777,
        b"self",
    );
    stack
        .access(&mut client)
        .send(&request, &ChecksumState::NONE)
        .unwrap();
    wake.wait_for_packet(&mut stack, &mut client, |_| true);
    let frame = EthernetFrame::new_checked(&client.received_packets[0]).unwrap();
    let ip = Ipv4Packet::new_checked(frame.payload()).unwrap();
    let packet = UdpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!((packet.src_port(), packet.dst_port()), (40123, 7777));
    assert_eq!(packet.payload(), b"self");
    assert!(matches!(
        stack
            .access(&mut client)
            .unbind_udp_port(IpVersion::Ipv6, 7777),
        Err(BindError::PortNotBound)
    ));
    stack
        .access(&mut client)
        .unbind_udp_port(IpVersion::Ipv4, 7777)
        .unwrap();
    assert!(matches!(
        stack
            .access(&mut client)
            .unbind_udp_port(IpVersion::Ipv4, 7777),
        Err(BindError::PortNotBound)
    ));
    drop((stack, client));
    thread.join();
}

// IGNORED: UDP_SEGMENT is set with a two-byte option, but Linux requires an
//       integer socket option. Consomme returns EINVAL; a four-byte option
//       succeeds on the same kernel.
//
// Test: Change Linux UDP GSO segmentation size and then send ordinary UDP again.
// Expected: The host receives correctly sized datagrams for each configured
//       segment size, and clearing GSO restores one-datagram transmission.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "product bug: UDP_SEGMENT setsockopt uses u16 instead of an integer"]
fn udp_gso_changes_and_clears_socket_segmentation() {
    let (thread, driver) = DriverThread::new();
    let params = params();
    let mut stack = Consomme::new(params.clone());
    let mut client = TestClient::new(driver);
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    for (segment_size, data) in [
        (Some(16), vec![0x55; 35]),
        (Some(8), vec![0x66; 17]),
        (None, b"plain".to_vec()),
    ] {
        let request = udp(
            &params,
            params.client_ip.into(),
            IpAddress::Ipv4(Ipv4Addr::LOCALHOST),
            40123,
            server.local_addr().unwrap().port(),
            &data,
        );
        let checksum = ChecksumState {
            gso: segment_size,
            ..ChecksumState::NONE
        };
        stack.access(&mut client).send(&request, &checksum).unwrap();
        let expected = segment_size.map_or(data.len(), usize::from);
        let mut received = Vec::new();
        while received.len() < data.len() {
            let mut bytes = [0; 64];
            let length = server.recv(&mut bytes).unwrap();
            assert_eq!(length, expected.min(data.len() - received.len()));
            received.extend_from_slice(&bytes[..length]);
        }
        assert_eq!(received, data);
    }
    drop((stack, client));
    thread.join();
}

#[path = "dns_behavior.rs"]
mod dns_behavior;

#[cfg(target_os = "linux")]
#[path = "driver_behavior.rs"]
mod driver_behavior;

// Test: Apply valid and invalid CIDRs, then ping each configured gateway.
// Expected: Gateway replies use the configured subnet, and invalid CIDR input
//       leaves that externally observable configuration usable.
#[pal_async::async_test]
async fn cidr_configuration_controls_gateway_echo_addressing(driver: DefaultDriver) {
    for (cidr, gateway, guest) in [
        ("192.0.2.0/24", "192.0.2.1", "192.0.2.2"),
        ("10.31.52.9/16", "10.31.0.1", "10.31.0.2"),
    ] {
        let mut params = params();
        params.set_cidr(cidr).unwrap();
        assert!(params.set_cidr("not-an-ip/24").is_err());
        assert!(params.set_cidr("10.0.0.0/33").is_err());
        let gateway = gateway.parse().unwrap();
        let guest = guest.parse().unwrap();
        let frame = ipv4(&params, guest, gateway, IpProtocol::Icmp, &echo(b"cidr"));
        let mut stack = Consomme::new(params);
        let mut client = TestClient::new(driver.clone());
        stack
            .access(&mut client)
            .send(&frame, &ChecksumState::NONE)
            .unwrap();
        let ethernet = EthernetFrame::new_checked(&client.received_packets[0]).unwrap();
        let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
        assert_eq!((ip.src_addr(), ip.dst_addr()), (gateway, guest));
        assert_eq!(
            Icmpv4Packet::new_checked(ip.payload()).unwrap().data(),
            b"cidr"
        );
    }
}

// Test: Exhaust a /30 virtual-address pool, clear it, and change to a /29 subnet.
// Expected: Exhaustion is explicit; reconfiguration plus clearing makes virtual
//       addresses available again without ever allocating the gateway or guest.
#[test]
fn subnet_reconfiguration_recovers_from_virtual_address_exhaustion() {
    let mut params = params();
    params.set_cidr("192.0.2.0/30").unwrap();
    let mut stack = Consomme::new(params);
    assert_eq!(
        stack.create_virtual_address(Ipv4Addr::LOCALHOST.into()),
        None
    );
    stack.params_mut().set_cidr("192.0.2.0/29").unwrap();
    stack.clear_local_addr_map();
    let address = stack
        .create_virtual_address(Ipv4Addr::LOCALHOST.into())
        .unwrap();
    assert_eq!(address, "192.0.2.6".parse::<IpAddr>().unwrap());
    assert_eq!(
        stack.create_virtual_address(Ipv4Addr::LOCALHOST.into()),
        Some(address)
    );
}

// Test: Submit truncated and inconsistent IPv4/IPv6 Ethernet frames.
// Expected: Public send rejects invalid lengths, versions and protocols before
//       forwarding anything or emitting a response.
#[pal_async::async_test]
async fn malformed_ip_frames_are_rejected_at_the_public_boundary(driver: DefaultDriver) {
    let params = params();
    let mut stack = Consomme::new(params.clone());
    let mut client = TestClient::new(driver);
    for (offset, value) in [(0, 0x65), (0, 0x44), (2, 0xff), (3, 10)] {
        let mut frame = ipv4(
            &params,
            params.client_ip,
            params.gateway_ip,
            IpProtocol::Icmp,
            &[],
        );
        frame[14 + offset] = value;
        assert!(
            stack
                .access(&mut client)
                .send(&frame, &ChecksumState::NONE)
                .is_err()
        );
    }
    let source = "fe80::2".parse().unwrap();
    let destination = params.gateway_link_local_ipv6;
    for (offset, value) in [(0, 0x40), (4, 1)] {
        let mut frame = ipv6(
            &params,
            source,
            destination,
            IpProtocol::Icmpv6,
            &[128, 0, 0, 0],
        );
        frame[14 + offset] = value;
        assert!(matches!(
            stack.access(&mut client).send(&frame, &ChecksumState::NONE),
            Err(DropReason::MalformedPacket)
        ));
    }
    for protocol in [IpProtocol::Unknown(253), IpProtocol::Icmpv6] {
        let frame = ipv6(&params, source, destination, protocol, &[128, 0, 0, 0]);
        assert!(
            stack
                .access(&mut client)
                .send(&frame, &ChecksumState::NONE)
                .is_err()
        );
    }
    assert!(client.received_packets.is_empty());
}
