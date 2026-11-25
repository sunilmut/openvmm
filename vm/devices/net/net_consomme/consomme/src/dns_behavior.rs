// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use smoltcp::wire::{TcpControl, TcpPacket, TcpRepr, TcpSeqNumber};
use std::task::Waker;

struct GuestTcp {
    stack: Consomme,
    client: TestClient,
    params: ConsommeParams,
    source: IpAddress,
    destination: IpAddress,
    sequence: TcpSeqNumber,
    acknowledgement: Option<TcpSeqNumber>,
}

struct Reply {
    control: TcpControl,
    sequence: TcpSeqNumber,
    acknowledgement: Option<TcpSeqNumber>,
    payload: Vec<u8>,
}

impl GuestTcp {
    fn new(driver: DefaultDriver, ipv6: bool) -> Self {
        let params = params();
        let mut stack = Consomme::new(params.clone());
        stack
            .add_dns_record(StaticDnsRecord::A([192, 0, 2, 55]), "guest.test")
            .unwrap();
        let (source, destination) = if ipv6 {
            (
                IpAddress::Ipv6("fe80::2".parse().unwrap()),
                IpAddress::Ipv6(params.gateway_link_local_ipv6),
            )
        } else {
            (params.client_ip.into(), params.gateway_ip.into())
        };
        Self {
            stack,
            client: TestClient::new(driver),
            params,
            source,
            destination,
            sequence: TcpSeqNumber(1000),
            acknowledgement: None,
        }
    }

    fn send_with_scale(
        &mut self,
        control: TcpControl,
        payload: &[u8],
        scale: Option<u8>,
    ) -> Result<(), DropReason> {
        let tcp = TcpRepr {
            src_port: 40123,
            dst_port: 53,
            control,
            seq_number: self.sequence,
            ack_number: self.acknowledgement,
            window_len: 65535,
            window_scale: scale,
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload,
        };
        let mut bytes = vec![0; tcp.buffer_len()];
        tcp.emit(
            &mut TcpPacket::new_unchecked(&mut bytes),
            &self.source,
            &self.destination,
            &ChecksumCapabilities::default(),
        );
        let frame = match (self.source, self.destination) {
            (IpAddress::Ipv4(source), IpAddress::Ipv4(destination)) => {
                ipv4(&self.params, source, destination, IpProtocol::Tcp, &bytes)
            }
            (IpAddress::Ipv6(source), IpAddress::Ipv6(destination)) => {
                ipv6(&self.params, source, destination, IpProtocol::Tcp, &bytes)
            }
            _ => unreachable!(),
        };
        self.stack
            .access(&mut self.client)
            .send(&frame, &ChecksumState::NONE)?;
        self.sequence +=
            payload.len() + usize::from(matches!(control, TcpControl::Syn | TcpControl::Fin));
        Ok(())
    }

    fn send(&mut self, control: TcpControl, payload: &[u8]) {
        self.send_with_scale(control, payload, None).unwrap();
    }

    fn replies(&mut self) -> Vec<Reply> {
        std::mem::take(&mut self.client.received_packets)
            .into_iter()
            .map(|bytes| {
                let frame = EthernetFrame::new_checked(&bytes).unwrap();
                let payload = if frame.ethertype() == EthernetProtocol::Ipv4 {
                    let ip = Ipv4Packet::new_checked(frame.payload()).unwrap();
                    ip.payload()
                } else {
                    let ip = Ipv6Packet::new_checked(frame.payload()).unwrap();
                    ip.payload()
                };
                let packet = TcpPacket::new_checked(payload).unwrap();
                let reply = TcpRepr::parse(
                    &packet,
                    &self.destination,
                    &self.source,
                    &ChecksumCapabilities::default(),
                )
                .unwrap();
                assert_eq!((reply.src_port, reply.dst_port), (53, 40123));
                Reply {
                    control: reply.control,
                    sequence: reply.seq_number,
                    acknowledgement: reply.ack_number,
                    payload: reply.payload.to_vec(),
                }
            })
            .collect()
    }

    fn establish(&mut self) {
        self.send_with_scale(TcpControl::Syn, &[], Some(7)).unwrap();
        let replies = self.replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].control, TcpControl::Syn);
        assert_eq!(replies[0].acknowledgement, Some(self.sequence));
        self.acknowledgement = Some(replies[0].sequence + 1);
        self.send(TcpControl::None, &[]);
        self.replies();
    }

    fn poll(&mut self) -> Vec<Reply> {
        self.stack
            .access(&mut self.client)
            .poll(&mut Context::from_waker(Waker::noop()));
        self.replies()
    }
}

fn query(id: u16, name: &str) -> Vec<u8> {
    let mut bytes = vec![0; 12];
    bytes[..2].copy_from_slice(&id.to_be_bytes());
    bytes[2] = 1;
    bytes[5] = 1;
    for label in name.split('.') {
        bytes.push(label.len().try_into().unwrap());
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.extend_from_slice(&[0, 0, 1, 0, 1]);
    bytes
}

// Test: Complete IPv4/IPv6 DNS TCP handshakes and send fragmented framed queries
//       followed by a second request after refreshing the IO driver.
// Expected: Static answers preserve DNS IDs and address bytes, ACK all input,
//       and remain usable across query boundaries without any host DNS traffic.
#[pal_async::async_test]
async fn dns_tcp_answers_fragmented_queries_over_both_ip_families(driver: DefaultDriver) {
    for ipv6 in [false, true] {
        let mut flow = GuestTcp::new(driver.clone(), ipv6);
        flow.establish();
        for id in [0x1234, 0x5678] {
            let query = query(id, "guest.test");
            let mut framed = u16::try_from(query.len()).unwrap().to_be_bytes().to_vec();
            framed.extend_from_slice(&query);
            flow.send(TcpControl::None, &framed[..1]);
            assert!(flow.poll().iter().all(|reply| reply.payload.is_empty()));
            flow.send(TcpControl::None, &framed[1..]);
            let replies = flow.poll();
            let response = replies
                .iter()
                .flat_map(|reply| reply.payload.iter().copied())
                .collect::<Vec<_>>();
            assert_eq!(
                usize::from(u16::from_be_bytes(response[..2].try_into().unwrap())),
                response.len() - 2
            );
            assert_eq!(&response[2..4], &id.to_be_bytes());
            assert_eq!(response[5] & 15, 0);
            assert_eq!(u16::from_be_bytes(response[8..10].try_into().unwrap()), 1);
            assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 55]);
            assert!(
                replies
                    .iter()
                    .all(|reply| reply.acknowledgement == Some(flow.sequence))
            );
            flow.acknowledgement = Some(flow.acknowledgement.unwrap() + response.len());
            flow.send(TcpControl::None, &[]);
            flow.poll();
            flow.stack.access(&mut flow.client).refresh_driver();
        }
        flow.send(TcpControl::Fin, &[]);
        let replies = flow.poll();
        assert!(replies.iter().any(|reply| reply.control == TcpControl::Fin));
    }
}

// Test: Request a name not present in the static table without a resolver backend.
// Expected: DNS-over-TCP returns a framed SERVFAIL with the original ID rather
//       than opening an external resolver connection or hanging.
#[pal_async::async_test]
async fn dns_tcp_static_miss_returns_servfail_without_external_resolution(driver: DefaultDriver) {
    let mut flow = GuestTcp::new(driver, false);
    flow.establish();
    let query = query(0x4567, "missing.test");
    let mut framed = u16::try_from(query.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(&query);
    flow.send(TcpControl::None, &framed);
    let response: Vec<_> = flow
        .poll()
        .into_iter()
        .flat_map(|reply| reply.payload)
        .collect();
    assert_eq!(&response[2..4], &0x4567u16.to_be_bytes());
    assert_eq!(response[5] & 15, 2);
}

// Test: Complete a DNS TCP handshake and submit a zero-length DNS frame.
// Expected: Malformed framing resets the connection rather than delivering a
//       partial DNS answer or waiting indefinitely for another packet.
#[pal_async::async_test]
async fn invalid_dns_tcp_framing_resets_the_guest_connection(driver: DefaultDriver) {
    let mut flow = GuestTcp::new(driver, false);
    flow.establish();
    flow.send(TcpControl::None, &[0, 0]);
    assert!(
        flow.poll()
            .iter()
            .any(|reply| reply.control == TcpControl::Rst)
    );
}

// Test: Send stale ACK and RST segments before opening an unscaled DNS TCP flow.
// Expected: Unknown ACKs receive a reset, unknown resets are ignored, and the
//       same tuple can subsequently complete its handshake without scaling.
#[pal_async::async_test]
async fn unknown_tcp_segments_do_not_reserve_the_guest_tuple(driver: DefaultDriver) {
    let mut flow = GuestTcp::new(driver, false);
    flow.acknowledgement = Some(TcpSeqNumber(987));
    flow.send(TcpControl::None, &[]);
    let replies = flow.replies();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].control, TcpControl::Rst);
    assert_eq!(replies[0].sequence, TcpSeqNumber(987));
    flow.send(TcpControl::Rst, &[]);
    assert!(flow.replies().is_empty());
    flow.acknowledgement = None;
    flow.send(TcpControl::Syn, &[]);
    let replies = flow.replies();
    assert_eq!(replies[0].control, TcpControl::Syn);
    flow.acknowledgement = Some(replies[0].sequence + 1);
    flow.send(TcpControl::None, &[]);
}

// Test: Inject missing ACKs, future ACKs, old data, and in-window SYN/RST packets
//       into established guest DNS flows.
// Expected: Invalid packets are rejected or challenged with ACKs as appropriate;
//       a subsequent correctly sequenced DNS query still receives its answer.
#[pal_async::async_test]
async fn established_tcp_validation_preserves_a_usable_dns_connection(driver: DefaultDriver) {
    for case in 0..5 {
        let mut flow = GuestTcp::new(driver.clone(), false);
        flow.establish();
        let sequence = flow.sequence;
        let acknowledgement = flow.acknowledgement;
        match case {
            0 => {
                flow.acknowledgement = None;
                assert!(flow.send_with_scale(TcpControl::None, &[], None).is_err());
                assert!(flow.replies().is_empty());
            }
            1 => {
                flow.acknowledgement = Some(acknowledgement.unwrap() + 100);
                assert!(flow.send_with_scale(TcpControl::None, &[], None).is_err());
                assert_eq!(flow.replies()[0].acknowledgement, Some(sequence));
            }
            2 => {
                flow.sequence = sequence - 20;
                assert!(
                    flow.send_with_scale(TcpControl::None, b"old", None)
                        .is_err()
                );
                assert_eq!(flow.replies()[0].acknowledgement, Some(sequence));
            }
            3 => {
                flow.send(TcpControl::Syn, &[]);
                assert_eq!(flow.replies()[0].acknowledgement, Some(sequence));
            }
            4 => {
                flow.sequence = sequence + 1;
                flow.send(TcpControl::Rst, &[]);
                assert_eq!(flow.replies()[0].acknowledgement, Some(sequence));
            }
            _ => unreachable!(),
        }
        flow.sequence = sequence;
        flow.acknowledgement = acknowledgement;
        let query = query(123, "guest.test");
        let mut framed = u16::try_from(query.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(&query);
        flow.send(TcpControl::None, &framed);
        let response: Vec<_> = flow
            .poll()
            .into_iter()
            .flat_map(|reply| reply.payload)
            .collect();
        assert_eq!(&response[2..4], &123u16.to_be_bytes());
        assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 55]);
    }
}

// Test: Reject an ACK outside the pending SYN-ACK sequence, then open a fresh
//       flow on the same tuple and terminate it with an exactly sequenced RST.
// Expected: The bad handshake is reset, retry succeeds, and a subsequent ACK
//       after the valid RST is treated as an unknown connection.
#[pal_async::async_test]
async fn failed_handshakes_and_exact_resets_release_the_guest_tuple(driver: DefaultDriver) {
    let mut flow = GuestTcp::new(driver, false);
    flow.send(TcpControl::Syn, &[]);
    let syn = flow.replies();
    flow.acknowledgement = Some(syn[0].sequence + 2);
    flow.send(TcpControl::None, &[]);
    assert_eq!(flow.replies()[0].control, TcpControl::Rst);
    flow.acknowledgement = None;
    flow.establish();
    flow.send(TcpControl::Rst, &[]);
    assert!(flow.replies().is_empty());
    flow.send(TcpControl::None, &[]);
    assert_eq!(flow.replies()[0].control, TcpControl::Rst);
}

// Test: Ask the gateway and alternate IPv4/IPv6 resolvers for a static DNS name.
// Expected: Each UDP query is answered locally with the queried resolver's
//       source address, original DNS ID, and the configured static answer.
#[pal_async::async_test]
async fn udp_static_dns_intercepts_gateway_and_alternate_resolver_queries(driver: DefaultDriver) {
    for v6 in [false, true] {
        let mut flow = GuestTcp::new(driver.clone(), v6);
        let alternate = if v6 {
            IpAddress::Ipv6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddress::Ipv4(Ipv4Addr::LOCALHOST)
        };
        for destination in [flow.destination, alternate] {
            let frame = udp(
                &flow.params,
                flow.source,
                destination,
                40123,
                53,
                &query(0x6789, "guest.test"),
            );
            flow.stack
                .access(&mut flow.client)
                .send(&frame, &ChecksumState::NONE)
                .unwrap();
            assert_eq!(flow.client.received_packets.len(), 1);
            let ethernet = EthernetFrame::new_checked(&flow.client.received_packets[0]).unwrap();
            let (source, guest, bytes) = if v6 {
                let ip = Ipv6Packet::new_checked(ethernet.payload()).unwrap();
                (
                    IpAddress::Ipv6(ip.src_addr()),
                    IpAddress::Ipv6(ip.dst_addr()),
                    ip.payload(),
                )
            } else {
                let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
                assert!(ip.verify_checksum());
                (
                    IpAddress::Ipv4(ip.src_addr()),
                    IpAddress::Ipv4(ip.dst_addr()),
                    ip.payload(),
                )
            };
            assert_eq!((source, guest), (destination, flow.source));
            let packet = UdpPacket::new_checked(bytes).unwrap();
            assert_eq!((packet.src_port(), packet.dst_port()), (53, 40123));
            assert!(packet.verify_checksum(&source, &guest));
            let response = packet.payload();
            assert_eq!(&response[..2], &0x6789u16.to_be_bytes());
            assert_eq!(response[3] & 15, 0);
            assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 55]);
            flow.client.received_packets.clear();
        }
    }
}
