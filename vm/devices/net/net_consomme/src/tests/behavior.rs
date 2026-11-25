// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use net_backend::Endpoint;
use net_backend::Queue;
use net_backend::TxMetadata;
use net_backend::TxSegmentType;
use net_backend_resources::consomme::*;
use std::future::Future;
use std::future::poll_fn;
use std::net::Ipv6Addr;
use std::net::TcpListener;
use std::pin::pin;
use std::task::Waker;
use test_with_tracing::test;

fn params() -> consomme::ConsommeParams {
    let mut params = consomme::ConsommeParams::new().unwrap();
    params.nameservers.clear();
    params.internal_dns = false;
    params
}

fn pool() -> Bufs {
    Bufs::new(GuestMemory::allocate(256 * 1024))
}

async fn queue(endpoint: &mut dyn Endpoint, driver: &DefaultDriver) -> Box<dyn Queue> {
    let mut queues = Vec::new();
    endpoint
        .get_queues(
            vec![QueueConfig {
                driver: Box::new(driver.clone()),
                enabled_rx_offloads: Default::default(),
            }],
            None,
            &mut queues,
        )
        .await
        .unwrap();
    assert_eq!(queues.len(), 1);
    queues.pop().unwrap()
}

async fn run<F: Future>(queue: &mut dyn Queue, pool: &mut Bufs, future: F) -> F::Output {
    let mut future = pin!(future);
    poll_fn(|cx| {
        if let Poll::Ready(value) = future.as_mut().poll(cx) {
            return Poll::Ready(value);
        }
        let _ = queue.poll_ready(cx, pool);
        future.as_mut().poll(cx)
    })
    .await
}

fn send(queue: &mut dyn Queue, pool: &mut Bufs, frame: &[u8], id: u32) {
    const GPA: u64 = 128 * 1024;
    pool.guest_memory().write_at(GPA, frame).unwrap();
    // Split the Ethernet header to catch truncated or reordered guest segments.
    let split = frame.len().min(7);
    let segments = [
        TxSegment {
            ty: TxSegmentType::Head(TxMetadata {
                id: TxId(id),
                segment_count: 2,
                len: frame.len() as u32,
                ..Default::default()
            }),
            gpa: GPA,
            len: split as u32,
        },
        TxSegment {
            ty: TxSegmentType::Tail,
            gpa: GPA + split as u64,
            len: (frame.len() - split) as u32,
        },
    ];
    assert_eq!(queue.tx_avail(pool, &segments).unwrap(), (false, 2));
    assert!(
        queue
            .poll_ready(&mut Context::from_waker(Waker::noop()), pool)
            .is_ready()
    );
    assert_eq!(queue.tx_poll(pool, &mut []).unwrap(), 0);
    let mut done = [TxId(u32::MAX)];
    assert_eq!(queue.tx_poll(pool, &mut done).unwrap(), 1);
    assert_eq!(done[0].0, id);
    assert_eq!(queue.tx_poll(pool, &mut done).unwrap(), 0);
}

fn receive(queue: &mut dyn Queue, pool: &mut Bufs, expected: RxId) -> Vec<u8> {
    assert_eq!(queue.rx_poll(pool, &mut []).unwrap(), 0);
    let mut received = [RxId(u32::MAX)];
    assert_eq!(queue.rx_poll(pool, &mut received).unwrap(), 1);
    assert_eq!(received[0].0, expected.0);
    let metadata = pool.rx_metadata(expected).unwrap();
    let mut bytes = vec![0; metadata.len];
    pool.guest_memory()
        .read_at(u64::from(expected.0) * 2048, &mut bytes)
        .unwrap();
    assert_eq!(queue.rx_poll(pool, &mut received).unwrap(), 0);
    bytes
}

fn arp(params: &consomme::ConsommeParams, reply: bool) -> Vec<u8> {
    let guest = params.client_mac.0;
    let gateway = params.gateway_mac.0;
    let mut frame = Vec::new();
    frame.extend_from_slice(if reply { &guest } else { &[0xff; 6] });
    frame.extend_from_slice(if reply { &gateway } else { &guest });
    frame.extend_from_slice(&[
        0x08,
        0x06,
        0,
        1,
        0x08,
        0,
        6,
        4,
        0,
        if reply { 2 } else { 1 },
    ]);
    frame.extend_from_slice(if reply { &gateway } else { &guest });
    frame.extend_from_slice(
        &if reply {
            params.gateway_ip
        } else {
            params.client_ip
        }
        .octets(),
    );
    frame.extend_from_slice(if reply { &guest } else { &[0; 6] });
    frame.extend_from_slice(
        &if reply {
            params.client_ip
        } else {
            params.gateway_ip
        }
        .octets(),
    );
    frame
}

fn udp(
    params: &consomme::ConsommeParams,
    destination: Ipv4Addr,
    port: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut frame = vec![0; 42 + data.len()];
    frame[..6].copy_from_slice(&params.gateway_mac.0);
    frame[6..12].copy_from_slice(&params.client_mac.0);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    let ip = &mut frame[14..34];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((28 + data.len()) as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&params.client_ip.octets());
    ip[16..20].copy_from_slice(&destination.octets());
    // IPv4 permits a zero UDP checksum; only the IP header needs a checksum here.
    let mut sum: u32 = ip
        .chunks_exact(2)
        .map(|p| u32::from(u16::from_be_bytes([p[0], p[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    frame[34..36].copy_from_slice(&12345u16.to_be_bytes());
    frame[36..38].copy_from_slice(&port.to_be_bytes());
    frame[38..40].copy_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    frame[42..].copy_from_slice(data);
    frame
}

fn forward(protocol: IpProtocol, family: IpVersion, guest_port: u16) -> PortForwardConfig {
    let address = match family {
        IpVersion::Ipv4 => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpVersion::Ipv6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
    };
    PortForwardConfig {
        protocol,
        socket: create_bound_socket(&protocol, Some(address), 0).unwrap(),
        guest_port,
    }
}

// Test: Run split-descriptor ARP requests without buffers, with a tiny buffer, and after resizing.
// Expected: TX completes once per request; only a fitting reply consumes the posted RX buffer.
#[pal_async::async_test]
async fn arp_queue_backpressure_preserves_receive_buffers(driver: DefaultDriver) {
    let params = params();
    let mut endpoint = ConsommeEndpoint::new(params.clone());
    let mut queue = queue(&mut endpoint, &driver).await;
    let mut pool = pool();
    send(&mut *queue, &mut pool, &arp(&params, false), 1);
    let mut ids = [RxId(0)];
    assert_eq!(queue.rx_poll(&mut pool, &mut ids).unwrap(), 0);
    pool.set_capacity(RxId(0), 8);
    queue.rx_avail(&mut pool, &[RxId(0)]);
    send(&mut *queue, &mut pool, &arp(&params, false), 2);
    assert_eq!(queue.rx_poll(&mut pool, &mut ids).unwrap(), 0);
    pool.set_capacity(RxId(0), 2048);
    send(&mut *queue, &mut pool, &arp(&params, false), 3);
    assert_eq!(receive(&mut *queue, &mut pool, RxId(0)), arp(&params, true));
    let metadata = pool.rx_metadata(RxId(0)).unwrap();
    assert_eq!(metadata.l4_protocol, L4Protocol::Unknown);
    assert_eq!(metadata.ip_checksum, RxChecksumState::Unknown);
    assert_eq!(metadata.l4_checksum, RxChecksumState::Unknown);
    drop(queue);
    endpoint.stop().await;
}

// Test: Use dynamic RPCs to bind and unbind TCP/UDP forwards in both IP families.
// Expected: Unbinding releases the host socket; duplicate, missing and occupied ports report errors.
#[pal_async::async_test]
async fn dynamic_controls_bind_unbind_and_report_socket_errors(driver: DefaultDriver) {
    let (mut endpoint, control) = ConsommeEndpoint::new_dynamic(params());
    let mut queue = queue(&mut endpoint, &driver).await;
    let mut pool = pool();
    for (protocol, family, address) in [
        (
            IpProtocol::Tcp,
            IpVersion::Ipv4,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ),
        (
            IpProtocol::Udp,
            IpVersion::Ipv4,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ),
        (
            IpProtocol::Tcp,
            IpVersion::Ipv6,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ),
        (
            IpProtocol::Udp,
            IpVersion::Ipv6,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ),
    ] {
        let port = run(
            &mut *queue,
            &mut pool,
            control.bind_port(protocol, Some(address), 0, 8080),
        )
        .await
        .unwrap();
        assert_ne!(port, 0);
        assert!(create_bound_socket(&protocol, Some(address), port).is_err());
        let err = run(
            &mut *queue,
            &mut pool,
            control.bind_port(protocol, Some(address), 0, 8080),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            ConsommeMessageError::Bind(consomme::BindError::PortAlreadyBound(8080))
        ));
        run(
            &mut *queue,
            &mut pool,
            control.unbind_port(protocol, family, 8080),
        )
        .await
        .unwrap();
        assert!(create_bound_socket(&protocol, Some(address), port).is_ok());
        assert!(matches!(
            run(
                &mut *queue,
                &mut pool,
                control.unbind_port(protocol, family, 8080)
            )
            .await,
            Err(ConsommeMessageError::Bind(
                consomme::BindError::PortNotBound
            ))
        ));
    }
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let err = run(
        &mut *queue,
        &mut pool,
        control.bind_port(
            IpProtocol::Tcp,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            occupied.local_addr().unwrap().port(),
            9090,
        ),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, ConsommeMessageError::Bind(consomme::BindError::Io(e)) if e.kind() == std::io::ErrorKind::AddrInUse)
    );
}

// Test: Install a static DNS record dynamically and reject an empty record name.
// Expected: Invalid input returns a typed error; the valid record appears in the guest DNS reply.
#[pal_async::async_test]
async fn dynamic_static_dns_answers_guest_queries(driver: DefaultDriver) {
    let params = params();
    let (mut endpoint, control) = ConsommeEndpoint::new_dynamic(params.clone());
    let mut queue = queue(&mut endpoint, &driver).await;
    let mut pool = pool();
    run(
        &mut *queue,
        &mut pool,
        control.add_dns_record(StaticDnsRecord::A([192, 0, 2, 9]), "local.test".into()),
    )
    .await
    .unwrap();
    assert!(matches!(
        run(
            &mut *queue,
            &mut pool,
            control.add_dns_record(StaticDnsRecord::A([1, 2, 3, 4]), "".into())
        )
        .await,
        Err(ConsommeMessageError::DnsRecord(
            StaticDnsRecordError::InvalidName
        ))
    ));
    let query =
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05local\x04test\x00\x00\x01\x00\x01";
    queue.rx_avail(&mut pool, &[RxId(0)]);
    send(
        &mut *queue,
        &mut pool,
        &udp(&params, params.gateway_ip, 53, query),
        4,
    );
    let reply = receive(&mut *queue, &mut pool, RxId(0));
    assert_eq!(&reply[42..44], &[0x12, 0x34]);
    assert_ne!(reply[44] & 0x80, 0);
    assert_eq!(&reply[48..50], &[0, 1]);
    assert_eq!(&reply[reply.len() - 4..], &[192, 0, 2, 9]);
    drop(control);
    let _ = queue.poll_ready(&mut Context::from_waker(Waker::noop()), &mut pool);
    drop(queue);
    endpoint.stop().await;
}

// Test: Allocate stable virtual addresses, then change the subnet through the control channel.
// Expected: Addresses avoid guest/gateway collisions; a subnet with no free hosts reports exhaustion.
#[pal_async::async_test]
async fn virtual_address_allocation_and_dynamic_subnet_update(driver: DefaultDriver) {
    let params = params();
    let (mut endpoint, control) = ConsommeEndpoint::new_dynamic(params.clone());
    let mut queue = queue(&mut endpoint, &driver).await;
    let mut pool = pool();
    let destination = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let first = run(
        &mut *queue,
        &mut pool,
        control.create_virtual_address(destination),
    )
    .await
    .unwrap();
    assert_eq!(
        run(
            &mut *queue,
            &mut pool,
            control.create_virtual_address(destination)
        )
        .await
        .unwrap(),
        first
    );
    let IpAddr::V4(first) = first else {
        panic!("expected an IPv4 mapping")
    };
    assert_eq!(first.octets()[..3], [10, 0, 0]);
    assert_ne!(first, params.gateway_ip);
    assert_ne!(first, params.client_ip);
    run(
        &mut *queue,
        &mut pool,
        control.update_state(Box::new(|state| state.set_cidr("192.0.2.0/30").unwrap())),
    )
    .await
    .unwrap();
    assert!(matches!(
        run(
            &mut *queue,
            &mut pool,
            control.create_virtual_address(destination)
        )
        .await,
        Err(ConsommeMessageError::VirtualAddressPoolExhausted)
    ));
    let mut changed = params;
    changed.set_cidr("192.0.2.0/30").unwrap();
    queue.rx_avail(&mut pool, &[RxId(0)]);
    send(&mut *queue, &mut pool, &arp(&changed, false), 5);
    assert_eq!(
        receive(&mut *queue, &mut pool, RxId(0)),
        arp(&changed, true)
    );
}

// Test: Fail initial forwarding after one successful bind by reusing the same guest TCP port.
// Expected: Successful binds roll back, host sockets close, and endpoint queue creation can retry.
#[pal_async::async_test]
async fn initial_forward_failure_rolls_back_and_allows_restart(driver: DefaultDriver) {
    let first = forward(IpProtocol::Tcp, IpVersion::Ipv4, 8080);
    let second = forward(IpProtocol::Tcp, IpVersion::Ipv4, 8080);
    let addresses = [
        first.socket.local_addr().unwrap().as_socket().unwrap(),
        second.socket.local_addr().unwrap().as_socket().unwrap(),
    ];
    let mut endpoint = ConsommeEndpoint::new_with_ports(params(), vec![first, second]);
    let mut queues = Vec::new();
    let error = endpoint
        .get_queues(
            vec![QueueConfig {
                driver: Box::new(driver.clone()),
                enabled_rx_offloads: Default::default(),
            }],
            None,
            &mut queues,
        )
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("failed to bind port"));
    assert!(queues.is_empty());
    for address in addresses {
        assert!(TcpListener::bind(address).is_ok());
    }
    let queue = queue(&mut endpoint, &driver).await;
    drop(queue);
    endpoint.stop().await;
}

// Test: Submit malformed/unsupported packets and traffic forbidden by host-local policy.
// Expected: Every TX descriptor completes without RX or delivery to a host-local socket.
#[pal_async::async_test]
async fn rejected_guest_frames_still_complete_transmit(driver: DefaultDriver) {
    let params = params();
    let mut endpoint = ConsommeEndpoint::new(params.clone());
    let mut queue = queue(&mut endpoint, &driver).await;
    let mut pool = pool();
    let host = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    host.set_nonblocking(true).unwrap();
    for (index, frame) in [
        vec![0; 2],
        vec![0; 14],
        udp(
            &params,
            Ipv4Addr::LOCALHOST,
            host.local_addr().unwrap().port(),
            b"blocked",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        send(&mut *queue, &mut pool, &frame, index as u32);
    }
    assert_eq!(queue.rx_poll(&mut pool, &mut [RxId(0)]).unwrap(), 0);
    assert_eq!(
        host.recv(&mut [0; 64]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

// Test: Batch differently segmented ARP/drop/ARP frames, then drain TX
//       completions through a short output slice while two RX replies wait.
// Expected: Each packet returns its original ID once and in order, including
//       the dropped middle frame; only valid packets consume RX buffers.
#[pal_async::async_test]
async fn batched_packet_completions_preserve_ids_and_receive_ownership(driver: DefaultDriver) {
    let params = params();
    let mut endpoint = ConsommeEndpoint::new(params.clone());
    let mut queue = queue(&mut endpoint, &driver).await;
    let mut pool = pool();
    queue.rx_avail(&mut pool, &[RxId(7), RxId(2)]);
    let mut segments = Vec::new();
    for (index, (id, frame, chunk_size)) in [
        (17, arp(&params, false), 7),
        (3, vec![0; 2], 2),
        (99, arp(&params, false), 14),
    ]
    .into_iter()
    .enumerate()
    {
        let gpa = 128 * 1024 + index as u64 * 4096;
        pool.guest_memory().write_at(gpa, &frame).unwrap();
        let count = frame.len().div_ceil(chunk_size);
        for (part, bytes) in frame.chunks(chunk_size).enumerate() {
            segments.push(TxSegment {
                ty: if part == 0 {
                    TxSegmentType::Head(TxMetadata {
                        id: TxId(id),
                        segment_count: count.try_into().unwrap(),
                        len: frame.len() as u32,
                        ..Default::default()
                    })
                } else {
                    TxSegmentType::Tail
                },
                gpa: gpa + (part * chunk_size) as u64,
                len: bytes.len() as u32,
            });
        }
    }
    assert_eq!(
        queue.tx_avail(&mut pool, &segments).unwrap(),
        (false, segments.len())
    );
    let mut done = [TxId(u32::MAX); 2];
    assert_eq!(queue.tx_poll(&mut pool, &mut done).unwrap(), 0);
    assert!(
        queue
            .poll_ready(&mut Context::from_waker(Waker::noop()), &mut pool)
            .is_ready()
    );
    assert_eq!(queue.tx_poll(&mut pool, &mut []).unwrap(), 0);
    assert_eq!(queue.tx_poll(&mut pool, &mut done[..1]).unwrap(), 1);
    assert_eq!(done[0].0, 17);
    assert_eq!(queue.tx_poll(&mut pool, &mut done).unwrap(), 2);
    assert_eq!(done.map(|id| id.0), [3, 99]);
    assert_eq!(queue.tx_poll(&mut pool, &mut done).unwrap(), 0);

    assert_eq!(queue.rx_poll(&mut pool, &mut []).unwrap(), 0);
    let mut received = [RxId(u32::MAX); 2];
    assert_eq!(queue.rx_poll(&mut pool, &mut received).unwrap(), 2);
    assert_eq!(received.map(|id| id.0), [7, 2]);
    for id in received {
        let metadata = pool.rx_metadata(id).unwrap();
        let mut bytes = vec![0; metadata.len];
        pool.guest_memory()
            .read_at(u64::from(id.0) * 2048, &mut bytes)
            .unwrap();
        assert_eq!(bytes, arp(&params, true));
    }
    assert_eq!(queue.rx_poll(&mut pool, &mut received).unwrap(), 0);
    drop(queue);
    endpoint.stop().await;
}

mod port_channel;
