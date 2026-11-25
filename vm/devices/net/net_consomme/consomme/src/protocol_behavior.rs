// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::tests::TestClient;
use pal_async::DefaultDriver;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, Ipv6Repr, NdiscNeighborFlags, NdiscRepr, RawHardwareAddress,
    UdpPacket,
};

fn params() -> ConsommeParams {
    let mut params = ConsommeParams::new().unwrap();
    params.skip_ipv6_checks = true;
    params.allow_host_local_access = true;
    params.internal_dns = false;
    params.nameservers.clear();
    params
}

fn ipv6(
    params: &ConsommeParams,
    source: Ipv6Address,
    destination: Ipv6Address,
    protocol: IpProtocol,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0; 14 + 40 + payload.len()];
    let mut ethernet = EthernetFrame::new_unchecked(&mut bytes);
    EthernetRepr {
        src_addr: params.client_mac,
        dst_addr: params.gateway_mac_ipv6,
        ethertype: EthernetProtocol::Ipv6,
    }
    .emit(&mut ethernet);
    let mut ip = Ipv6Packet::new_unchecked(ethernet.payload_mut());
    Ipv6Repr {
        src_addr: source,
        dst_addr: destination,
        next_header: protocol,
        payload_len: payload.len(),
        hop_limit: 255,
    }
    .emit(&mut ip);
    ip.payload_mut().copy_from_slice(payload);
    bytes
}

fn ndp(params: &ConsommeParams, source: Ipv6Address, message: NdiscRepr<'_>) -> Vec<u8> {
    let destination = "ff02::2".parse().unwrap();
    let mut payload = vec![0; message.buffer_len()];
    let mut packet = Icmpv6Packet::new_unchecked(&mut payload);
    message.emit(&mut packet);
    packet.fill_checksum(&source, &destination);
    ipv6(params, source, destination, IpProtocol::Icmpv6, &payload)
}

fn dhcp6(params: &ConsommeParams, payload: &[u8]) -> Vec<u8> {
    let source = "fe80::2".parse().unwrap();
    let destination = "ff02::1:2".parse().unwrap();
    let mut udp_bytes = vec![0; 8 + payload.len()];
    let mut udp = UdpPacket::new_unchecked(&mut udp_bytes);
    udp.set_src_port(546);
    udp.set_dst_port(547);
    udp.set_len((8 + payload.len()).try_into().unwrap());
    udp.payload_mut().copy_from_slice(payload);
    udp.fill_checksum(&IpAddress::Ipv6(source), &IpAddress::Ipv6(destination));
    ipv6(params, source, destination, IpProtocol::Udp, &udp_bytes)
}

fn option(bytes: &mut Vec<u8>, code: u16, value: &[u8]) {
    bytes.extend_from_slice(&code.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(value);
}

fn options(mut bytes: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let code = u16::from_be_bytes(bytes[..2].try_into().unwrap());
        let length = usize::from(u16::from_be_bytes(bytes[2..4].try_into().unwrap()));
        result.push((code, bytes[4..4 + length].to_vec()));
        bytes = &bytes[4 + length..];
    }
    result
}

// Test: Request ARP for the gateway, another local address, the guest and a
//       remote address, then submit an unsupported reply and truncated request.
// Expected: Only gateway-proxied local addresses receive correctly addressed
//       ARP replies; unsupported and malformed packets return explicit errors.
#[pal_async::async_test]
async fn arp_proxy_replies_only_for_gateway_owned_subnet_addresses(driver: DefaultDriver) {
    let params = params();
    let mut stack = Consomme::new(params.clone());
    let mut client = TestClient::new(driver);
    for (target, answer) in [
        (params.gateway_ip, true),
        (Ipv4Address::new(10, 0, 0, 77), true),
        (params.client_ip, false),
        (Ipv4Address::new(192, 0, 2, 1), false),
    ] {
        let request = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: params.client_mac,
            source_protocol_addr: params.client_ip,
            target_hardware_addr: EthernetAddress([0; 6]),
            target_protocol_addr: target,
        };
        let mut bytes = vec![0; 14 + request.buffer_len()];
        let mut frame = EthernetFrame::new_unchecked(&mut bytes);
        EthernetRepr {
            src_addr: params.client_mac,
            dst_addr: EthernetAddress::BROADCAST,
            ethertype: EthernetProtocol::Arp,
        }
        .emit(&mut frame);
        request.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));
        stack
            .access(&mut client)
            .send(&bytes, &ChecksumState::NONE)
            .unwrap();
        assert_eq!(client.received_packets.len(), usize::from(answer));
        if answer {
            let frame = EthernetFrame::new_checked(&client.received_packets[0]).unwrap();
            assert_eq!(frame.dst_addr(), params.client_mac);
            assert_eq!(
                ArpRepr::parse(&ArpPacket::new_checked(frame.payload()).unwrap()).unwrap(),
                ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Reply,
                    source_hardware_addr: params.gateway_mac,
                    source_protocol_addr: target,
                    target_hardware_addr: params.client_mac,
                    target_protocol_addr: params.client_ip
                }
            );
            let reply = client.received_packets.pop().unwrap();
            assert!(matches!(
                stack.access(&mut client).send(&reply, &ChecksumState::NONE),
                Err(DropReason::UnsupportedArp)
            ));
        }
        assert!(
            stack
                .access(&mut client)
                .send(&bytes[..15], &ChecksumState::NONE)
                .is_err()
        );
    }
}

// Test: Solicit router advertisements with multicast/unicast replies, several
//       prefix lengths, optional autonomous prefix and filtered DNS servers.
// Expected: Emitted Ethernet/IPv6 addressing, prefix, RDNSS and checksum are
//       correct on the wire, including a zero-length prefix and an exact /128.
#[pal_async::async_test]
async fn router_advertisements_encode_prefix_dns_and_reply_addressing(driver: DefaultDriver) {
    for (prefix, advertise, unicast) in [
        (0, true, false),
        (64, true, true),
        (128, true, true),
        (64, false, false),
    ] {
        let mut params = params();
        params.prefix_len_ipv6 = prefix;
        params.advertise_routable_ipv6 = advertise;
        let dns: Ipv6Address = "2001:4860:4860::8888".parse().unwrap();
        if unicast {
            params.nameservers = vec![
                IpAddress::Ipv4(Ipv4Address::new(1, 1, 1, 1)),
                IpAddress::Ipv6("::1".parse().unwrap()),
                IpAddress::Ipv6(dns),
            ];
        }
        let source = if unicast { "fe80::2" } else { "::" }.parse().unwrap();
        let request = ndp(
            &params,
            source,
            NdiscRepr::RouterSolicit {
                lladdr: unicast.then(|| RawHardwareAddress::from(params.client_mac)),
            },
        );
        let mut stack = Consomme::new(params.clone());
        let mut client = TestClient::new(driver.clone());
        stack
            .access(&mut client)
            .send(&request, &ChecksumState::NONE)
            .unwrap();
        assert_eq!(client.received_packets.len(), 1);
        let frame = EthernetFrame::new_checked(&client.received_packets[0]).unwrap();
        assert_eq!(frame.src_addr(), params.gateway_mac_ipv6);
        assert_eq!(
            frame.dst_addr(),
            if unicast {
                params.client_mac
            } else {
                EthernetAddress([0x33, 0x33, 0, 0, 0, 1])
            }
        );
        let ip = Ipv6Packet::new_checked(frame.payload()).unwrap();
        assert_eq!(ip.src_addr(), params.gateway_link_local_ipv6);
        assert_eq!(
            ip.dst_addr(),
            if unicast {
                source
            } else {
                "ff02::1".parse().unwrap()
            }
        );
        assert_eq!(ip.hop_limit(), 255);
        let packet = Icmpv6Packet::new_checked(ip.payload()).unwrap();
        assert!(packet.verify_checksum(&ip.src_addr(), &ip.dst_addr()));
        let NdiscRepr::RouterAdvert {
            prefix_info, flags, ..
        } = NdiscRepr::parse(&packet).unwrap()
        else {
            panic!("expected router advertisement")
        };
        assert!(flags.is_empty());
        assert_eq!(prefix_info.is_some(), advertise);
        if let Some(info) = prefix_info {
            assert_eq!(info.prefix_len, prefix);
            let base: Ipv6Address = "fd64:a050:cea6::".parse().unwrap();
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            assert_eq!(info.prefix.to_bits(), base.to_bits() & mask);
        }
        let mut options = &packet.as_ref()[16..];
        let mut rdnss = None;
        while !options.is_empty() {
            let length = usize::from(options[1]) * 8;
            if options[0] == 25 {
                rdnss = Some(options[..length].to_vec());
            }
            options = &options[length..];
        }
        assert_eq!(rdnss.is_some(), unicast);
        if let Some(option) = rdnss {
            assert_eq!(&option[8..], &dns.octets());
        }
        let incoming_advertisement = packet.as_ref().to_vec();
        client.received_packets.clear();
        let incoming = ipv6(
            &params,
            source,
            "ff02::1".parse().unwrap(),
            IpProtocol::Icmpv6,
            &incoming_advertisement,
        );
        stack
            .access(&mut client)
            .send(&incoming, &ChecksumState::NONE)
            .unwrap();
        assert!(client.received_packets.is_empty());
    }
}

// Test: Solicit the router with an invalid unspecified-source option or another
//       MAC address in the source link-layer option.
// Expected: The invalid source combination returns MalformedPacket, while the
//       foreign MAC is ignored without a response.
#[pal_async::async_test]
async fn router_solicitations_validate_source_link_layer_identity(driver: DefaultDriver) {
    let params = params();
    let mut stack = Consomme::new(params.clone());
    let mut client = TestClient::new(driver);
    let malformed = ndp(
        &params,
        "::".parse().unwrap(),
        NdiscRepr::RouterSolicit {
            lladdr: Some(params.client_mac.into()),
        },
    );
    assert!(matches!(
        stack
            .access(&mut client)
            .send(&malformed, &ChecksumState::NONE),
        Err(DropReason::MalformedPacket)
    ));
    let foreign = ndp(
        &params,
        "fe80::2".parse().unwrap(),
        NdiscRepr::RouterSolicit {
            lladdr: Some(EthernetAddress([2, 3, 4, 5, 6, 7]).into()),
        },
    );
    stack
        .access(&mut client)
        .send(&foreign, &ChecksumState::NONE)
        .unwrap();
    assert!(client.received_packets.is_empty());
}

// Test: Resolve IPv6 neighbors for the gateway and a proxied local address,
//       while attempting resolution of a remote address or the guest itself.
// Expected: Only gateway-owned local targets receive solicited advertisements
//       with the gateway MAC, router/override flags and valid checksums.
#[pal_async::async_test]
async fn neighbor_resolution_advertises_only_gateway_owned_addresses(driver: DefaultDriver) {
    let params = params();
    let mut stack = Consomme::new(params.clone());
    let mut client = TestClient::new(driver);
    let source = "fe80::2".parse().unwrap();
    for (target, answer) in [
        (params.gateway_link_local_ipv6, true),
        ("fe80::77".parse().unwrap(), true),
        (source, false),
        ("2001:db8::77".parse().unwrap(), false),
    ] {
        let request = ndp(
            &params,
            source,
            NdiscRepr::NeighborSolicit {
                target_addr: target,
                lladdr: Some(params.client_mac.into()),
            },
        );
        stack
            .access(&mut client)
            .send(&request, &ChecksumState::NONE)
            .unwrap();
        assert_eq!(client.received_packets.len(), usize::from(answer));
        if answer {
            let frame = EthernetFrame::new_checked(&client.received_packets[0]).unwrap();
            assert_eq!(frame.dst_addr(), params.client_mac);
            let ip = Ipv6Packet::new_checked(frame.payload()).unwrap();
            assert_eq!(ip.src_addr(), target);
            assert_eq!(ip.dst_addr(), source);
            let packet = Icmpv6Packet::new_checked(ip.payload()).unwrap();
            assert!(packet.verify_checksum(&ip.src_addr(), &ip.dst_addr()));
            let NdiscRepr::NeighborAdvert {
                flags,
                target_addr,
                lladdr,
            } = NdiscRepr::parse(&packet).unwrap()
            else {
                panic!("expected neighbor advertisement")
            };
            assert_eq!(target_addr, target);
            assert!(flags.contains(
                NdiscNeighborFlags::SOLICITED
                    | NdiscNeighborFlags::OVERRIDE
                    | NdiscNeighborFlags::ROUTER
            ));
            assert_eq!(lladdr, Some(params.gateway_mac_ipv6.into()));
            client.received_packets.clear();
        }
    }
}

// Test: Send DAD solicitations, invalid source/option combinations, missing or
//       foreign link-layer identities, and an unsolicited neighbor advertisement.
// Expected: DAD and irrelevant neighbors get no reply, invalid DAD is rejected,
//       and unsolicited advertisements do not trigger another advertisement.
#[pal_async::async_test]
async fn neighbor_validation_and_duplicate_address_detection(driver: DefaultDriver) {
    let params = params();
    let mut stack = Consomme::new(params.clone());
    let mut client = TestClient::new(driver);
    for target in ["fe80::2", "2001:db8::2", "2001:db8::200:ff:fe00:100"] {
        let bytes = ndp(
            &params,
            "::".parse().unwrap(),
            NdiscRepr::NeighborSolicit {
                target_addr: target.parse().unwrap(),
                lladdr: None,
            },
        );
        stack
            .access(&mut client)
            .send(&bytes, &ChecksumState::NONE)
            .unwrap();
    }
    let malformed = ndp(
        &params,
        "::".parse().unwrap(),
        NdiscRepr::NeighborSolicit {
            target_addr: params.gateway_link_local_ipv6,
            lladdr: Some(params.client_mac.into()),
        },
    );
    assert!(matches!(
        stack
            .access(&mut client)
            .send(&malformed, &ChecksumState::NONE),
        Err(DropReason::MalformedPacket)
    ));
    for lladdr in [None, Some(EthernetAddress([2, 3, 4, 5, 6, 7]).into())] {
        let bytes = ndp(
            &params,
            "fe80::2".parse().unwrap(),
            NdiscRepr::NeighborSolicit {
                target_addr: params.gateway_link_local_ipv6,
                lladdr,
            },
        );
        stack
            .access(&mut client)
            .send(&bytes, &ChecksumState::NONE)
            .unwrap();
    }
    let advert = ndp(
        &params,
        "fe80::2".parse().unwrap(),
        NdiscRepr::NeighborAdvert {
            target_addr: "fe80::2".parse().unwrap(),
            flags: NdiscNeighborFlags::empty(),
            lladdr: None,
        },
    );
    stack
        .access(&mut client)
        .send(&advert, &ChecksumState::NONE)
        .unwrap();
    assert!(client.received_packets.is_empty());
}

// Test: Request DHCPv6 information with client, server, unknown and DNS options.
// Expected: Replies echo transaction/client identity, identify the gateway's
//       DUID-LL, and advertise only configured, valid IPv6 DNS servers.
#[pal_async::async_test]
async fn dhcpv6_information_replies_encode_identity_and_dns(driver: DefaultDriver) {
    for advertise_dns in [false, true] {
        let mut params = params();
        let dns: Ipv6Address = "2606:4700:4700::1111".parse().unwrap();
        if advertise_dns {
            params.nameservers.push(IpAddress::Ipv6(dns));
        }
        let mut request = vec![11, 0x12, 0x34, 0x56];
        option(&mut request, 1, b"client-identity");
        option(&mut request, 2, b"ignored-server");
        option(&mut request, 23, &dns.octets());
        option(&mut request, 999, b"ignored-option");
        let mut stack = Consomme::new(params.clone());
        let mut client = TestClient::new(driver.clone());
        stack
            .access(&mut client)
            .send(&dhcp6(&params, &request), &ChecksumState::NONE)
            .unwrap();
        assert_eq!(client.received_packets.len(), 1);
        let frame = EthernetFrame::new_checked(&client.received_packets[0]).unwrap();
        assert_eq!(frame.dst_addr(), params.client_mac);
        let ip = Ipv6Packet::new_checked(frame.payload()).unwrap();
        assert_eq!(ip.src_addr(), params.gateway_link_local_ipv6);
        assert_eq!(ip.dst_addr(), "fe80::2".parse::<Ipv6Address>().unwrap());
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!((udp.src_port(), udp.dst_port()), (547, 546));
        assert!(udp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));
        assert_eq!(&udp.payload()[..4], &[7, 0x12, 0x34, 0x56]);
        let options = options(&udp.payload()[4..]);
        assert_eq!(
            options.iter().find(|(code, _)| *code == 1).unwrap().1,
            b"client-identity"
        );
        let mut expected_duid = vec![0, 3, 0, 1];
        expected_duid.extend_from_slice(&params.gateway_mac_ipv6.0);
        assert_eq!(
            options.iter().find(|(code, _)| *code == 2).unwrap().1,
            expected_duid
        );
        let advertised_dns = options.iter().find(|(code, _)| *code == 23);
        assert_eq!(advertised_dns.is_some(), advertise_dns);
        if let Some((_, address)) = advertised_dns {
            assert_eq!(address, &dns.octets());
        }
    }
}

// Test: Send DHCPv6 messages with short headers, overlong options, malformed DNS
//       lists and a valid but unsupported message type.
// Expected: Every bad datagram returns an explicit drop reason and no response;
//       a later valid request still receives its matching transaction ID.
#[pal_async::async_test]
async fn dhcpv6_rejects_malformed_input_and_recovers(driver: DefaultDriver) {
    let params = params();
    let mut stack = Consomme::new(params.clone());
    let mut client = TestClient::new(driver);
    for payload in [
        &[][..],
        &[11, 1, 2][..],
        &[11, 1, 2, 3, 0, 1, 0, 9, 0][..],
        &[11, 1, 2, 3, 0, 23, 0, 1, 0][..],
        &[1, 1, 2, 3][..],
    ] {
        assert!(
            stack
                .access(&mut client)
                .send(&dhcp6(&params, payload), &ChecksumState::NONE)
                .is_err()
        );
        assert!(client.received_packets.is_empty());
    }
    stack
        .access(&mut client)
        .send(&dhcp6(&params, &[11, 1, 2, 3]), &ChecksumState::NONE)
        .unwrap();
    assert_eq!(client.received_packets.len(), 1);
}

#[path = "transport_behavior.rs"]
mod transport_behavior;

// IGNORED: Consomme sends advertisements for NDP solicitations whose IPv6 hop
//       limit is not 255, instead of discarding them as RFC 4861 requires.
//
// Test: Send router and neighbor solicitations with valid and invalid hop limits.
// Expected: Hop limit 255 permits a reply; lower limits produce no reply.
#[pal_async::async_test]
#[ignore = "NDP receive path does not validate the IPv6 hop limit"]
async fn ndp_solicitations_require_the_link_local_hop_limit(driver: DefaultDriver) {
    let params = params();
    for message in [
        NdiscRepr::RouterSolicit {
            lladdr: Some(params.client_mac.into()),
        },
        NdiscRepr::NeighborSolicit {
            target_addr: params.gateway_link_local_ipv6,
            lladdr: Some(params.client_mac.into()),
        },
    ] {
        let mut stack = Consomme::new(params.clone());
        let mut client = TestClient::new(driver.clone());
        let mut bytes = ndp(&params, "fe80::2".parse().unwrap(), message);
        for hop_limit in [255, 254, 64, 0] {
            let mut frame = EthernetFrame::new_unchecked(&mut bytes);
            Ipv6Packet::new_unchecked(frame.payload_mut()).set_hop_limit(hop_limit);
            let result = stack.access(&mut client).send(&bytes, &ChecksumState::NONE);
            if hop_limit == 255 {
                result.unwrap();
                assert_eq!(client.received_packets.len(), 1);
            } else {
                assert!(
                    client.received_packets.is_empty(),
                    "NDP solicitation with hop limit {hop_limit} produced a reply: {result:?}"
                );
            }
            client.received_packets.clear();
        }
    }
}
