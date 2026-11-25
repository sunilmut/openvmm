// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use pal_async::fd::FdReadyDriver;
use pal_async::io_uring::{IoUringDriver, NoIoUring};
use pal_async::timer::{PolledTimer, TimerDriver};
use pal_async::wait::WaitDriver;
use std::io::{self, Read};
use std::net::TcpListener;
use std::os::fd::RawFd;
use std::task::{Poll, Waker};

struct SwitchableDriver {
    inner: DefaultDriver,
    fail_registration: bool,
}

impl FdReadyDriver for SwitchableDriver {
    type FdReady = <DefaultDriver as FdReadyDriver>::FdReady;
    fn new_fd_ready(&self, fd: RawFd) -> io::Result<Self::FdReady> {
        if self.fail_registration {
            Err(io::Error::other("injected driver registration failure"))
        } else {
            self.inner.new_fd_ready(fd)
        }
    }
}

impl TimerDriver for SwitchableDriver {
    type Timer = <DefaultDriver as TimerDriver>::Timer;
    fn new_timer(&self) -> Self::Timer {
        self.inner.new_timer()
    }
}

impl WaitDriver for SwitchableDriver {
    type Wait = <DefaultDriver as WaitDriver>::Wait;
    fn new_wait(&self, fd: RawFd, size: usize) -> io::Result<Self::Wait> {
        self.inner.new_wait(fd, size)
    }
}

impl IoUringDriver for SwitchableDriver {
    type Submitter = NoIoUring;
    fn io_uring_submitter(&self) -> Option<&Self::Submitter> {
        None
    }
}

struct CaptureClient {
    driver: SwitchableDriver,
    ready: bool,
    packets: Vec<(Vec<u8>, ChecksumState)>,
}

impl CaptureClient {
    fn new(driver: DefaultDriver) -> Self {
        Self {
            driver: SwitchableDriver {
                inner: driver,
                fail_registration: false,
            },
            ready: true,
            packets: Vec::new(),
        }
    }

    async fn receive(&mut self, stack: &mut Consomme) {
        let driver = self.driver.inner.clone();
        let wait = std::future::poll_fn(|cx| {
            stack.access(self).poll(cx);
            if self.packets.is_empty() {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        });
        let mut timer = PolledTimer::new(&driver);
        let timeout = timer.sleep(Duration::from_secs(3));
        assert!(
            matches!(
                futures::future::select(std::pin::pin!(wait), std::pin::pin!(timeout)).await,
                futures::future::Either::Left(_)
            ),
            "timed out waiting for a guest-visible packet"
        );
    }
}

impl Client for CaptureClient {
    fn driver(&self) -> &dyn Driver {
        &self.driver
    }
    fn recv(&mut self, bytes: &[u8], checksum: &ChecksumState) {
        self.packets.push((bytes.to_vec(), *checksum));
    }
    fn rx_mtu(&mut self) -> usize {
        if self.ready { 1514 } else { 0 }
    }
    fn rx_checksum_supported(&self) -> bool {
        true
    }
}

// Test: Forward host datagrams with receive backpressure and checksum offload
//       across IPv4 pool exhaustion and IPv6 link-local/routable-only guests.
// Expected: Datagrams wait for receive buffers, use a reachable guest address,
//       preserve payload/ports, and advertise the promised partial checksum.
#[pal_async::async_test]
async fn udp_forwarding_honors_receive_credit_and_guest_address_fallbacks(driver: DefaultDriver) {
    for case in 0..3 {
        let mut params = params();
        params.client_ip_ipv6 = None;
        params.client_ip_ipv6_routable = None;
        let host = if case == 0 {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        };
        let guest = match case {
            0 => {
                params.set_cidr("192.0.2.0/30").unwrap();
                IpAddress::Ipv4(params.client_ip)
            }
            1 => {
                params.client_ip_ipv6 = Some("fe80::2".parse().unwrap());
                IpAddress::Ipv6(params.client_ip_ipv6.unwrap())
            }
            _ => {
                params.client_ip_ipv6_routable = Some("2001:db8::2".parse().unwrap());
                IpAddress::Ipv6(params.client_ip_ipv6_routable.unwrap())
            }
        };
        let socket = UdpSocket::bind((host, 0)).unwrap();
        let destination = socket.local_addr().unwrap();
        let sender = UdpSocket::bind((host, 0)).unwrap();
        let mut stack = Consomme::new(params.clone());
        let mut client = CaptureClient::new(driver.clone());
        stack
            .access(&mut client)
            .bind_udp_port(socket.into(), 7777)
            .unwrap();
        sender.send_to(b"receive credit", destination).unwrap();
        client.ready = false;
        stack
            .access(&mut client)
            .poll(&mut Context::from_waker(Waker::noop()));
        assert!(client.packets.is_empty());
        client.ready = true;
        client.receive(&mut stack).await;
        let (bytes, checksum) = &client.packets[0];
        let frame = EthernetFrame::new_checked(bytes).unwrap();
        let (source, destination, payload) = if case == 0 {
            let ip = Ipv4Packet::new_checked(frame.payload()).unwrap();
            assert!(ip.verify_checksum());
            assert_eq!(ip.src_addr(), params.gateway_ip);
            (
                IpAddress::Ipv4(ip.src_addr()),
                IpAddress::Ipv4(ip.dst_addr()),
                ip.payload(),
            )
        } else {
            let ip = Ipv6Packet::new_checked(frame.payload()).unwrap();
            (
                IpAddress::Ipv6(ip.src_addr()),
                IpAddress::Ipv6(ip.dst_addr()),
                ip.payload(),
            )
        };
        let udp = UdpPacket::new_checked(payload).unwrap();
        assert_eq!(destination, guest);
        assert_eq!(udp.payload(), b"receive credit");
        assert_eq!(
            (udp.src_port(), udp.dst_port()),
            (sender.local_addr().unwrap().port(), 7777)
        );
        assert!(checksum.udp && checksum.partial);
        assert_eq!(checksum.ipv4, case == 0);
        assert_eq!(
            udp.checksum(),
            smoltcp::wire::checksum::pseudo_header(
                &source,
                &destination,
                IpProtocol::Udp,
                payload.len().try_into().unwrap()
            )
        );
    }
}

// Test: Fail readiness registration during driver refresh with TCP/UDP listeners
//       and an active UDP flow, then restore a working driver.
// Expected: Failed listeners release their ports, new sends report IO failures,
//       and a working replacement can bind those ports and send again.
#[pal_async::async_test]
async fn driver_refresh_failures_release_listeners_and_allow_recovery(driver: DefaultDriver) {
    let params = params();
    let mut stack = Consomme::new(params.clone());
    let mut client = CaptureClient::new(driver);
    let udp_listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let udp_address = udp_listener.local_addr().unwrap();
    let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let tcp_address = tcp_listener.local_addr().unwrap();
    stack
        .access(&mut client)
        .bind_udp_port(udp_listener.into(), 7777)
        .unwrap();
    stack
        .access(&mut client)
        .bind_tcp_port(tcp_listener.into(), 8888)
        .unwrap();
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let request = udp(
        &params,
        params.client_ip.into(),
        Ipv4Addr::LOCALHOST.into(),
        40123,
        server.local_addr().unwrap().port(),
        b"retry",
    );
    stack
        .access(&mut client)
        .send(&request, &ChecksumState::NONE)
        .unwrap();
    let mut buffer = [0; 32];
    assert_eq!(server.recv_from(&mut buffer).unwrap().0, 5);
    client.driver.fail_registration = true;
    stack.access(&mut client).refresh_driver();
    assert!(matches!(
        stack
            .access(&mut client)
            .unbind_udp_port(IpVersion::Ipv4, 7777),
        Err(BindError::PortNotBound)
    ));
    assert!(matches!(
        stack
            .access(&mut client)
            .unbind_tcp_port(IpVersion::Ipv4, 8888),
        Err(BindError::PortNotBound)
    ));
    assert!(matches!(
        stack
            .access(&mut client)
            .send(&request, &ChecksumState::NONE),
        Err(DropReason::Io(_))
    ));
    client.driver.fail_registration = false;
    stack
        .access(&mut client)
        .bind_udp_port(UdpSocket::bind(udp_address).unwrap().into(), 7777)
        .unwrap();
    stack
        .access(&mut client)
        .bind_tcp_port(TcpListener::bind(tcp_address).unwrap().into(), 8888)
        .unwrap();
    stack
        .access(&mut client)
        .send(&request, &ChecksumState::NONE)
        .unwrap();
    let (length, _) = server.recv_from(&mut buffer).unwrap();
    assert_eq!(&buffer[..length], b"retry");
}

fn tcp_syn(params: &ConsommeParams, port: u16) -> Vec<u8> {
    use smoltcp::wire::{TcpControl, TcpPacket, TcpRepr, TcpSeqNumber};

    let destination: IpAddress = Ipv4Addr::LOCALHOST.into();
    let source = params.client_ip.into();
    let syn = TcpRepr {
        src_port: 40123,
        dst_port: port,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(1000),
        ack_number: None,
        window_len: 65535,
        window_scale: None,
        max_seg_size: Some(1460),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    let mut bytes = vec![0; syn.buffer_len()];
    syn.emit(
        &mut TcpPacket::new_unchecked(&mut bytes),
        &source,
        &destination,
        &ChecksumCapabilities::default(),
    );
    ipv4(
        params,
        params.client_ip,
        Ipv4Addr::LOCALHOST,
        IpProtocol::Tcp,
        &bytes,
    )
}

// Test: Fail initial TCP readiness registration, retry the same SYN, then fail
//       registration again while refreshing the established host socket.
// Expected: Initial failure is explicit, retry produces a SYN-ACK, and refresh
//       closes the host connection instead of keeping an unusable socket alive.
#[pal_async::async_test]
async fn tcp_registration_failure_retries_and_refresh_closes_the_host_socket(
    driver: DefaultDriver,
) {
    use smoltcp::wire::{TcpPacket, TcpSeqNumber};

    let params = params();
    let mut stack = Consomme::new(params.clone());
    let mut client = CaptureClient::new(driver);
    let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let frame = tcp_syn(&params, server.local_addr().unwrap().port());
    client.driver.fail_registration = true;
    assert!(matches!(
        stack.access(&mut client).send(&frame, &ChecksumState::NONE),
        Err(DropReason::Io(_))
    ));
    assert!(client.packets.is_empty());
    client.driver.fail_registration = false;
    stack
        .access(&mut client)
        .send(&frame, &ChecksumState::NONE)
        .unwrap();
    client.receive(&mut stack).await;
    let ethernet = EthernetFrame::new_checked(&client.packets[0].0).unwrap();
    let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
    let packet = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(packet.syn() && packet.ack());
    assert_eq!(packet.ack_number(), TcpSeqNumber(1001));
    let (mut peer, _) = server.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    client.driver.fail_registration = true;
    stack.access(&mut client).refresh_driver();
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
}

// Test: Connect to a closed host loopback TCP port, then bind a listener and
//       retry the same guest SYN.
// Expected: Refusal resets the guest flow, and the failed attempt does not
//       prevent a later SYN from receiving a valid SYN-ACK.
#[pal_async::async_test]
async fn refused_tcp_connections_reset_the_guest_and_allow_retry(driver: DefaultDriver) {
    use smoltcp::wire::{TcpPacket, TcpSeqNumber};

    let params = params();
    let mut stack = Consomme::new(params.clone());
    let mut client = CaptureClient::new(driver);
    let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = server.local_addr().unwrap();
    let frame = tcp_syn(&params, address.port());
    drop(server);
    stack
        .access(&mut client)
        .send(&frame, &ChecksumState::NONE)
        .unwrap();
    client.receive(&mut stack).await;
    let ethernet = EthernetFrame::new_checked(&client.packets[0].0).unwrap();
    let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
    let reset = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(reset.rst() && reset.ack());
    assert_eq!(reset.ack_number(), TcpSeqNumber(1001));
    client.packets.clear();
    let _server = TcpListener::bind(address).unwrap();
    stack
        .access(&mut client)
        .send(&frame, &ChecksumState::NONE)
        .unwrap();
    client.receive(&mut stack).await;
    let ethernet = EthernetFrame::new_checked(&client.packets[0].0).unwrap();
    let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
    let reply = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(reply.syn() && reply.ack());
    assert_eq!(reply.ack_number(), TcpSeqNumber(1001));
}

// Test: Forward IPv6 UDP before the guest has an address, then learn its
//       routable address from an outgoing frame and forward another datagram.
// Expected: Unroutable input is dropped; later traffic reaches the learned
//       guest address without replaying the previously dropped datagram.
#[pal_async::async_test]
async fn udp_forwarding_recovers_after_learning_the_guest_ipv6_address(driver: DefaultDriver) {
    let mut params = params();
    params.client_ip_ipv6 = None;
    params.client_ip_ipv6_routable = None;
    let mut stack = Consomme::new(params.clone());
    let mut client = CaptureClient::new(driver.clone());
    let socket = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
    let destination = socket.local_addr().unwrap();
    let sender = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
    stack
        .access(&mut client)
        .bind_udp_port(socket.into(), 7777)
        .unwrap();
    sender.send_to(b"before", destination).unwrap();
    let mut timer = PolledTimer::new(&driver);
    {
        let unexpected = std::future::poll_fn(|cx| {
            stack.access(&mut client).poll(cx);
            if client.packets.is_empty() {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        });
        assert!(matches!(
            futures::future::select(
                std::pin::pin!(unexpected),
                std::pin::pin!(timer.sleep(Duration::from_millis(50)))
            )
            .await,
            futures::future::Either::Right(_)
        ));
    }
    let mut address = ConsommeParams::compute_link_local_address(params.client_mac).octets();
    address[..8].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0]);
    let guest = Ipv6Address::from(address);
    let frame = ipv6(
        &params,
        guest,
        params.gateway_link_local_ipv6,
        IpProtocol::Unknown(253),
        &[],
    );
    assert!(matches!(
        stack.access(&mut client).send(&frame, &ChecksumState::NONE),
        Err(DropReason::UnsupportedIpProtocol(_))
    ));
    sender.send_to(b"after", destination).unwrap();
    client.receive(&mut stack).await;
    assert_eq!(client.packets.len(), 1);
    let ethernet = EthernetFrame::new_checked(&client.packets[0].0).unwrap();
    let ip = Ipv6Packet::new_checked(ethernet.payload()).unwrap();
    assert_eq!(ip.dst_addr(), guest);
    assert_eq!(
        UdpPacket::new_checked(ip.payload()).unwrap().payload(),
        b"after"
    );
}

// Test: Supply a datagram socket as a TCP listener and inject registration
//       failures during both public forwarding APIs.
// Expected: Each operation reports an IO error and leaves its guest port free
//       for a subsequent correctly typed socket and working driver.
#[pal_async::async_test]
async fn invalid_listener_sockets_and_driver_errors_do_not_reserve_guest_ports(
    driver: DefaultDriver,
) {
    let mut stack = Consomme::new(params());
    let mut client = CaptureClient::new(driver);
    assert!(matches!(
        stack.access(&mut client).bind_tcp_port(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().into(),
            7777
        ),
        Err(BindError::Io(_))
    ));
    client.driver.fail_registration = true;
    assert!(matches!(
        stack.access(&mut client).bind_tcp_port(
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().into(),
            7777
        ),
        Err(BindError::Io(_))
    ));
    assert!(matches!(
        stack.access(&mut client).bind_udp_port(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().into(),
            7777
        ),
        Err(BindError::Io(_))
    ));
    client.driver.fail_registration = false;
    stack
        .access(&mut client)
        .bind_tcp_port(
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().into(),
            7777,
        )
        .unwrap();
    stack
        .access(&mut client)
        .bind_udp_port(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().into(),
            7777,
        )
        .unwrap();
    stack
        .access(&mut client)
        .unbind_tcp_port(IpVersion::Ipv4, 7777)
        .unwrap();
    stack
        .access(&mut client)
        .unbind_udp_port(IpVersion::Ipv4, 7777)
        .unwrap();
}
