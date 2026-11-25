// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::kvp::body;
use super::kvp::connected;
use super::kvp::packet;
use hyperv_ic_protocol::MessageType;
use hyperv_ic_protocol::Status;
use hyperv_ic_protocol::kvp as proto;
use hyperv_ic_resources::kvp as r;
use mesh::rpc::RpcSend;
use pal_async::DefaultDriver;
use pal_async::async_test;
use test_with_tracing::test;
use vmbus_channel::test_helpers::stop_with_timeout;
use vmbus_channel::test_helpers::with_timeout;
use zerocopy::FromZeros;

fn ip_info() -> r::IpInfo {
    r::IpInfo {
        ipv4: true,
        ipv6: true,
        dhcp_enabled: true,
        ipv4_addresses: vec![r::Ipv4AddressInfo {
            address: "192.0.2.7".parse().unwrap(),
            subnet: "255.255.255.0".parse().unwrap(),
            origin: r::AddressOrigin::Static,
        }],
        ipv6_addresses: vec![r::Ipv6AddressInfo {
            address: "2001:db8::7".parse().unwrap(),
            subnet: 64,
            origin: r::AddressOrigin::Other,
        }],
        ipv4_gateways: vec!["192.0.2.1".parse().unwrap()],
        ipv6_gateways: vec!["fe80::1".parse().unwrap()],
        ipv4_dns_servers: vec!["203.0.113.53".parse().unwrap()],
        ipv6_dns_servers: vec!["2001:db8::53".parse().unwrap()],
    }
}

// Test: Set IPv4, IPv6, dual-stack, and disabled configurations over KVP v5.
// Expected: All address bytes, masks, prefixes, gateways, DNS servers, DHCP and
//       family settings reach the guest; guest failures reach the caller.
#[async_test]
async fn set_ip_info_encodes_network_configuration(driver: DefaultDriver) {
    let (mut task, mut guest, rpc, _disconnected) = connected(&driver, proto::KVP_VERSION_5).await;
    for (ipv4, ipv6, family) in [
        (false, false, proto::AddressFamily::NONE),
        (true, false, proto::AddressFamily::IPV4),
        (false, true, proto::AddressFamily::IPV6),
        (true, true, proto::AddressFamily::IPV4V6),
    ] {
        let mut info = ip_info();
        info.ipv4 = ipv4;
        info.ipv6 = ipv6;
        info.dhcp_enabled = ipv4;
        for status in [Status::SUCCESS, Status::FAIL] {
            let result = rpc.call_failable(
                r::KvpRpc::SetIpInfo,
                r::SetIpInfoParams {
                    adapter_id: "adapter-7".into(),
                    info: info.clone(),
                },
            );
            let frame = guest.receive(MessageType::KVP_EXCHANGE).await;
            let actual: proto::MessageIpAddressInfoBinary =
                body(&frame.body, proto::KvpOperation::SET_IP_ADDRESS_INFO);
            assert_eq!(actual.address_family, family);
            assert_eq!(actual.dhcp_enabled != 0, info.dhcp_enabled);
            let adapter: Vec<_> = "adapter-7".encode_utf16().chain([0]).collect();
            assert_eq!(&actual.adapter_id[..adapter.len()], adapter);
            assert_eq!(actual.ipv4_address_count, 1);
            assert_eq!(actual.ipv6_address_count, 1);
            assert_eq!(actual.ipv4_gateway_count, 1);
            assert_eq!(actual.ipv6_gateway_count, 1);
            assert_eq!(actual.ipv4_dns_server_count, 1);
            assert_eq!(actual.ipv6_dns_server_count, 1);
            assert_eq!(
                actual.ipv4_addresses[0].0,
                info.ipv4_addresses[0].address.octets()
            );
            assert_eq!(
                actual.ipv4_subnets[0].0,
                info.ipv4_addresses[0].subnet.octets()
            );
            assert_eq!(
                actual.ipv6_addresses[0].0,
                info.ipv6_addresses[0].address.octets()
            );
            assert_eq!(actual.ipv6_subnets[0], 64);
            assert_eq!(actual.ipv4_gateways[0].0, info.ipv4_gateways[0].octets());
            assert_eq!(actual.ipv6_gateways[0].0, info.ipv6_gateways[0].octets());
            assert_eq!(
                actual.ipv4_dns_servers[0].0,
                info.ipv4_dns_servers[0].octets()
            );
            assert_eq!(
                actual.ipv6_dns_servers[0].0,
                info.ipv6_dns_servers[0].octets()
            );
            guest.respond(&frame, status, &[]).await;
            assert_eq!(
                with_timeout(&driver, result).await.is_ok(),
                status == Status::SUCCESS
            );
        }
    }
    stop_with_timeout(&mut task, &driver).await;
}

fn guest_ip_info() -> proto::MessageIpAddressInfoBinary {
    let mut response = proto::MessageIpAddressInfoBinary::new_zeroed();
    response.ipv4_address_count = 4;
    response.ipv6_address_count = 1;
    response.ipv4_gateway_count = 1;
    response.ipv6_gateway_count = 1;
    response.ipv4_dns_server_count = 1;
    response.ipv6_dns_server_count = 1;
    for (i, address) in response.ipv4_addresses[..4].iter_mut().enumerate() {
        address.0 = [192, 0, 2, i as u8 + 7];
    }
    for subnet in &mut response.ipv4_subnets[..4] {
        subnet.0 = [255, 255, 255, 0];
    }
    response.ipv6_addresses[0].0 = "2001:db8::7"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets();
    response.ipv6_subnets[0] = 64;
    response.ipv4_gateways[0].0 = [192, 0, 2, 1];
    response.ipv6_gateways[0].0 = "fe80::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
    response.ipv4_dns_servers[0].0 = [203, 0, 113, 53];
    response.ipv6_dns_servers[0].0 = "2001:db8::53"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets();
    response.ip_address_origins[..5].copy_from_slice(&[
        proto::IpAddressOrigin::STATIC,
        proto::IpAddressOrigin::OTHER,
        proto::IpAddressOrigin::UNKNOWN,
        proto::IpAddressOrigin(99),
        proto::IpAddressOrigin::OTHER,
    ]);
    response
}

// Test: Read network information for all address families, including an unknown
//       guest origin, then return a guest failure.
// Expected: Addresses and origins decode correctly, unknown origins remain
//       Unknown, and a failed request is not returned as an empty configuration.
#[async_test]
async fn get_ip_info_decodes_addresses_origins_and_status(driver: DefaultDriver) {
    let (mut task, mut guest, rpc, _disconnected) = connected(&driver, proto::KVP_VERSION_5).await;
    for (family, ipv4, ipv6) in [
        (proto::AddressFamily::NONE, false, false),
        (proto::AddressFamily::IPV4, true, false),
        (proto::AddressFamily::IPV6, false, true),
        (proto::AddressFamily::IPV4V6, true, true),
    ] {
        let result = rpc.call_failable(
            r::KvpRpc::GetIpInfo,
            r::GetIpInfoParams {
                adapter_id: "adapter-7".into(),
            },
        );
        let frame = guest.receive(MessageType::KVP_EXCHANGE).await;
        let request: proto::MessageIpAddressInfoBinary =
            body(&frame.body, proto::KvpOperation::GET_IP_ADDRESS_INFO);
        let expected: Vec<_> = "adapter-7".encode_utf16().chain([0]).collect();
        assert_eq!(&request.adapter_id[..expected.len()], expected);
        let mut response = guest_ip_info();
        response.address_family = family;
        response.dhcp_enabled = u8::from(ipv6);
        guest
            .respond(
                &frame,
                Status::SUCCESS,
                &packet(proto::KvpOperation::GET_IP_ADDRESS_INFO, &response),
            )
            .await;
        let actual = with_timeout(&driver, result).await.unwrap();
        assert_eq!(actual.ipv4, ipv4);
        assert_eq!(actual.ipv6, ipv6);
        assert_eq!(actual.dhcp_enabled, ipv6);
        assert_eq!(actual.ipv4_addresses.len(), 4);
        for (i, address) in actual.ipv4_addresses.iter().enumerate() {
            assert_eq!(address.address.octets(), [192, 0, 2, i as u8 + 7]);
            assert_eq!(address.subnet.octets(), [255, 255, 255, 0]);
        }
        assert!(matches!(
            actual.ipv4_addresses[0].origin,
            r::AddressOrigin::Static
        ));
        assert!(matches!(
            actual.ipv4_addresses[1].origin,
            r::AddressOrigin::Other
        ));
        assert!(matches!(
            actual.ipv4_addresses[2].origin,
            r::AddressOrigin::Unknown
        ));
        assert!(matches!(
            actual.ipv4_addresses[3].origin,
            r::AddressOrigin::Unknown
        ));
        let expected = ip_info();
        assert_eq!(actual.ipv6_addresses.len(), 1);
        assert_eq!(
            actual.ipv6_addresses[0].address,
            expected.ipv6_addresses[0].address
        );
        assert_eq!(actual.ipv6_addresses[0].subnet, 64);
        assert!(matches!(
            actual.ipv6_addresses[0].origin,
            r::AddressOrigin::Other
        ));
        assert_eq!(actual.ipv4_gateways, expected.ipv4_gateways);
        assert_eq!(actual.ipv6_gateways, expected.ipv6_gateways);
        assert_eq!(actual.ipv4_dns_servers, expected.ipv4_dns_servers);
        assert_eq!(actual.ipv6_dns_servers, expected.ipv6_dns_servers);
    }
    let result = rpc.call_failable(
        r::KvpRpc::GetIpInfo,
        r::GetIpInfoParams {
            adapter_id: "adapter-7".into(),
        },
    );
    let frame = guest.receive(MessageType::KVP_EXCHANGE).await;
    guest.respond(&frame, Status::FAIL, &[]).await;
    assert!(with_timeout(&driver, result).await.is_err());
    stop_with_timeout(&mut task, &driver).await;
}

// Test: Return counts exceeding each address, gateway, DNS, or origin array.
// Expected: The caller and disconnect observer receive failure rather than a
//       panic, truncated list, or fabricated network configuration.
#[async_test]
async fn invalid_guest_ip_counts_are_reported(driver: DefaultDriver) {
    for case in 0..8 {
        let (mut task, mut guest, rpc, disconnected) =
            connected(&driver, proto::KVP_VERSION_5).await;
        let result = rpc.call_failable(
            r::KvpRpc::GetIpInfo,
            r::GetIpInfoParams {
                adapter_id: "adapter".into(),
            },
        );
        let frame = guest.receive(MessageType::KVP_EXCHANGE).await;
        let mut response = guest_ip_info();
        match case {
            0 => response.ipv4_address_count = u32::MAX,
            1 => response.ipv6_address_count = u32::MAX,
            2 => response.ipv4_address_count = 65,
            3 => response.ipv6_address_count = 65,
            4 => response.ipv4_gateway_count = 6,
            5 => response.ipv6_gateway_count = 6,
            6 => response.ipv4_dns_server_count = 65,
            7 => response.ipv6_dns_server_count = 65,
            _ => unreachable!(),
        }
        guest
            .respond(
                &frame,
                Status::SUCCESS,
                &packet(proto::KvpOperation::GET_IP_ADDRESS_INFO, &response),
            )
            .await;
        assert!(with_timeout(&driver, result).await.is_err(), "case {case}");
        assert!(with_timeout(&driver, disconnected).await.is_err());
        stop_with_timeout(&mut task, &driver).await;
    }
}

// Test: Submit binary IP requests to older guests and invalid inputs to v5.
// Expected: Unsupported versions and oversized fields fail locally, while the
//       connection remains usable for a subsequent enumeration request.
#[async_test]
async fn invalid_ip_requests_do_not_break_later_operations(driver: DefaultDriver) {
    for version in [
        proto::KVP_VERSION_3,
        proto::KVP_VERSION_4,
        proto::KVP_VERSION_5,
    ] {
        let (mut task, mut guest, rpc, _disconnected) = connected(&driver, version).await;
        let get = rpc.call_failable(
            r::KvpRpc::GetIpInfo,
            r::GetIpInfoParams {
                adapter_id: "a".repeat(128),
            },
        );
        assert!(with_timeout(&driver, get).await.is_err());
        for case in 0..7 {
            let mut info = ip_info();
            match case {
                0 => {}
                1 => info.ipv4_addresses = vec![info.ipv4_addresses[0].clone(); 65],
                2 => info.ipv6_addresses = vec![info.ipv6_addresses[0].clone(); 65],
                3 => info.ipv4_gateways = vec![info.ipv4_gateways[0]; 6],
                4 => info.ipv6_gateways = vec![info.ipv6_gateways[0]; 6],
                5 => info.ipv4_dns_servers = vec![info.ipv4_dns_servers[0]; 65],
                6 => info.ipv6_dns_servers = vec![info.ipv6_dns_servers[0]; 65],
                _ => unreachable!(),
            }
            let set = rpc.call_failable(
                r::KvpRpc::SetIpInfo,
                r::SetIpInfoParams {
                    adapter_id: if case == 0 {
                        "a".repeat(128)
                    } else {
                        "adapter".into()
                    },
                    info,
                },
            );
            assert!(with_timeout(&driver, set).await.is_err(), "case {case}");
        }
        let result = rpc.call_failable(
            r::KvpRpc::Enumerate,
            r::EnumerateParams {
                pool: r::KvpPool::Guest,
                index: 0,
            },
        );
        // No invalid request may leak onto the guest wire.
        let frame = guest.receive(MessageType::KVP_EXCHANGE).await;
        let _: proto::MessageEnumerate = body(&frame.body, proto::KvpOperation::ENUMERATE);
        guest.respond(&frame, Status::NO_MORE_ITEMS, &[]).await;
        assert!(with_timeout(&driver, result).await.unwrap().is_none());
        stop_with_timeout(&mut task, &driver).await;
    }
}
