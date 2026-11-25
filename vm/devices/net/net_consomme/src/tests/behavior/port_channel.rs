// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::resolver::ConsommeResolver;
use crate::resolver::ResolveConsommeError;
use net_backend::resolve::ResolveEndpointParams;
use test_with_tracing::test;
use vm_resource::ResolveResource;

fn config(
    protocol: HostPortProtocol,
    address: IpAddr,
    guest_port: u16,
    host_port: HostPort,
) -> HostPortConfig {
    HostPortConfig {
        protocol,
        host_address: Some(address.into()),
        host_port,
        guest_port,
    }
}

fn resolve_input() -> ResolveEndpointParams {
    ResolveEndpointParams {
        mac_address: "02:00:00:00:00:02".parse().unwrap(),
    }
}

fn resource() -> ConsommeHandle {
    ConsommeHandle {
        cidr: None,
        params: Default::default(),
        ports: Vec::new(),
        internal_dns: false,
        recv: None,
    }
}

// Test: Forward ports through the external request channel and restart its queue.
// Expected: Both protocols/families bind and release sockets; pending RPCs survive restart.
#[pal_async::async_test]
async fn port_requests_bind_unbind_notify_and_survive_queue_restart(driver: DefaultDriver) {
    let (sender, receiver) = mesh::channel();
    let mut endpoint = ConsommeEndpoint::new_with_port_channel(params(), Vec::new(), receiver);
    let mut active = queue(&mut endpoint, &driver).await;
    let mut pool = pool();
    for (protocol, address) in [
        (HostPortProtocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        (HostPortProtocol::Udp, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        (HostPortProtocol::Tcp, IpAddr::V6(Ipv6Addr::LOCALHOST)),
        (HostPortProtocol::Udp, IpAddr::V6(Ipv6Addr::LOCALHOST)),
    ] {
        let (notify, port) = mesh::oneshot();
        let bind = config(protocol.clone(), address, 8080, HostPort::Dynamic(notify));
        run(
            &mut *active,
            &mut pool,
            sender.call_failable(ConsommeRequest::Bind, bind),
        )
        .await
        .unwrap();
        let port = port.await.unwrap();
        assert_ne!(port, 0);
        let ip_protocol = IpProtocol::from(protocol.clone());
        assert!(create_bound_socket(&ip_protocol, Some(address), port).is_err());
        let unbind = config(protocol, address, 8080, HostPort::Fixed(port));
        run(
            &mut *active,
            &mut pool,
            sender.call_failable(ConsommeRequest::Unbind, unbind),
        )
        .await
        .unwrap();
        assert!(create_bound_socket(&ip_protocol, Some(address), port).is_ok());
    }
    let pending = sender.call_failable(
        ConsommeRequest::CreateVirtualAddress,
        HostIpAddress::Ipv4(Ipv4Addr::LOCALHOST),
    );
    drop(active);
    let mut active = queue(&mut endpoint, &driver).await;
    let mapping = run(&mut *active, &mut pool, pending).await.unwrap();
    let IpAddr::V4(mapping) = IpAddr::from(mapping) else {
        panic!("expected IPv4 mapping")
    };
    assert_eq!(mapping.octets()[..3], [10, 0, 0]);
    drop(sender);
    let _ = active.poll_ready(&mut Context::from_waker(Waker::noop()), &mut pool);
    drop(active);
    endpoint.stop().await;
}

// Test: Send invalid port configurations, a missing unbind and an occupied host-port request.
// Expected: Failable RPC callers receive contextual errors for each rejected operation.
#[pal_async::async_test]
async fn port_request_errors_are_returned_to_the_caller(driver: DefaultDriver) {
    let (sender, receiver) = mesh::channel();
    let mut endpoint = ConsommeEndpoint::new_with_port_channel(params(), Vec::new(), receiver);
    let mut active = queue(&mut endpoint, &driver).await;
    let mut pool = pool();
    for (guest, expected) in [
        (0, "guest_port must be non-zero"),
        (8080, "host_port must be non-zero"),
    ] {
        let error = run(
            &mut *active,
            &mut pool,
            sender.call_failable(
                ConsommeRequest::Bind,
                config(
                    HostPortProtocol::Tcp,
                    Ipv4Addr::LOCALHOST.into(),
                    guest,
                    HostPort::Fixed(0),
                ),
            ),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains(expected));
    }
    let error = run(
        &mut *active,
        &mut pool,
        sender.call_failable(
            ConsommeRequest::Unbind,
            config(
                HostPortProtocol::Udp,
                Ipv4Addr::LOCALHOST.into(),
                9999,
                HostPort::Fixed(1),
            ),
        ),
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("failed to unbind port"));
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let error = run(
        &mut *active,
        &mut pool,
        sender.call_failable(
            ConsommeRequest::Bind,
            config(
                HostPortProtocol::Tcp,
                Ipv4Addr::LOCALHOST.into(),
                8080,
                HostPort::Fixed(occupied.local_addr().unwrap().port()),
            ),
        ),
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("failed to create and bind socket"));
}

// Test: Submit invalid and valid static DNS records over the external request channel.
// Expected: Invalid names report errors; a subsequent valid record is answered on the guest wire.
#[pal_async::async_test]
async fn static_dns_requests_recover_after_an_invalid_name(driver: DefaultDriver) {
    let params = params();
    let (sender, receiver) = mesh::channel();
    let mut endpoint =
        ConsommeEndpoint::new_with_port_channel(params.clone(), Vec::new(), receiver);
    let mut active = queue(&mut endpoint, &driver).await;
    let mut pool = pool();
    let error = run(
        &mut *active,
        &mut pool,
        sender.call_failable(
            ConsommeRequest::AddDnsRecord,
            DnsRecordConfig {
                name: "".into(),
                address: Ipv4Addr::LOCALHOST,
            },
        ),
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("query name"));
    run(
        &mut *active,
        &mut pool,
        sender.call_failable(
            ConsommeRequest::AddDnsRecord,
            DnsRecordConfig {
                name: "local.test".into(),
                address: Ipv4Addr::new(192, 0, 2, 8),
            },
        ),
    )
    .await
    .unwrap();
    active.rx_avail(&mut pool, &[RxId(0)]);
    let query =
        b"\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05local\x04test\x00\x00\x01\x00\x01";
    send(
        &mut *active,
        &mut pool,
        &udp(&params, params.gateway_ip, 53, query),
        0,
    );
    let reply = receive(&mut *active, &mut pool, RxId(0));
    assert_eq!(&reply[42..44], &[0x56, 0x78]);
    assert_eq!(&reply[48..50], &[0, 1]);
    assert_eq!(&reply[reply.len() - 4..], &[192, 0, 2, 8]);
}

// Test: Resolve an endpoint with explicit addressing, initial port forwards and runtime requests.
// Expected: Guest wire replies use the configured MAC/IP, while host ports remain reserved.
#[pal_async::async_test]
async fn resolver_applies_address_overrides_and_initial_forwards(driver: DefaultDriver) {
    let (sender, receiver) = mesh::channel();
    let (tcp_notify, tcp_port) = mesh::oneshot();
    let (udp_notify, udp_port) = mesh::oneshot();
    let mut handle = resource();
    handle.cidr = Some("192.0.2.0/24".into());
    handle.params.client_ip = Some(Ipv4Addr::new(192, 0, 2, 33));
    handle.params.gateway_ip = Some(Ipv4Addr::new(192, 0, 2, 9));
    handle.params.net_mask = Some(Ipv4Addr::new(255, 255, 255, 0));
    handle.recv = Some(receiver);
    handle.ports = vec![
        config(
            HostPortProtocol::Tcp,
            Ipv4Addr::LOCALHOST.into(),
            8080,
            HostPort::Dynamic(tcp_notify),
        ),
        config(
            HostPortProtocol::Udp,
            Ipv6Addr::LOCALHOST.into(),
            8081,
            HostPort::Dynamic(udp_notify),
        ),
    ];
    let mut endpoint = ConsommeResolver.resolve(handle, resolve_input()).unwrap().0;
    let tcp_port = tcp_port.await.unwrap();
    let udp_port = udp_port.await.unwrap();
    let mut active = queue(&mut *endpoint, &driver).await;
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, tcp_port)).is_err());
    assert!(std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, udp_port)).is_err());
    let mut expected = params();
    expected.client_mac.0 = [2, 0, 0, 0, 0, 2];
    expected.client_ip = Ipv4Addr::new(192, 0, 2, 33);
    expected.gateway_ip = Ipv4Addr::new(192, 0, 2, 9);
    let mut pool = pool();
    active.rx_avail(&mut pool, &[RxId(0)]);
    send(&mut *active, &mut pool, &arp(&expected, false), 0);
    assert_eq!(
        receive(&mut *active, &mut pool, RxId(0)),
        arp(&expected, true)
    );
    run(
        &mut *active,
        &mut pool,
        sender.call_failable(
            ConsommeRequest::Unbind,
            config(
                HostPortProtocol::Tcp,
                Ipv4Addr::LOCALHOST.into(),
                8080,
                HostPort::Fixed(tcp_port),
            ),
        ),
    )
    .await
    .unwrap();
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, tcp_port)).is_ok());
    drop(active);
    endpoint.stop().await;
    drop(endpoint);
    assert!(std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, udp_port)).is_ok());
}

// Test: Resolve malformed CIDR and an initial forward whose host socket is already bound.
// Expected: Typed resolver errors distinguish invalid networks from socket failures.
#[test]
fn resolver_reports_invalid_cidr_and_occupied_host_port() {
    let mut handle = resource();
    handle.cidr = Some("not-a-cidr".into());
    assert!(matches!(
        ConsommeResolver.resolve(handle, resolve_input()),
        Err(ResolveConsommeError::InvalidCidr(_))
    ));
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut handle = resource();
    handle.ports.push(config(
        HostPortProtocol::Tcp,
        Ipv4Addr::LOCALHOST.into(),
        8080,
        HostPort::Fixed(occupied.local_addr().unwrap().port()),
    ));
    assert!(
        matches!(ConsommeResolver.resolve(handle, resolve_input()), Err(ResolveConsommeError::SocketCreation { source, .. })
        if source.kind() == std::io::ErrorKind::AddrInUse)
    );
}
