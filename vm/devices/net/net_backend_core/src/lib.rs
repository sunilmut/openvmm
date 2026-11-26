// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! This crate contains just the plain-data descriptors (RX/TX buffers and
//! metadata, VLAN info, offload/RSS capability flags, endpoint-action
//! signals, and small helper functions on `TxSegment` slices).

#![no_std]
#![expect(missing_docs)]
#![forbid(unsafe_code)]

use bitfield_struct::bitfield;
use core::mem::size_of;

pub const ETHERNET_HEADER_LEN: u32 = 14;
pub const ETHERNET_VLAN_HEADER_LEN: u32 = 18;

pub const IPV4_MIN_HEADER_LEN: u16 = 20;
pub const IPV6_MIN_HEADER_LEN: u16 = 40;

#[bitfield(u16)]
pub struct VlanMetadata {
    /// Priority for 802.1Q.
    #[bits(3)]
    pub priority: u8,
    /// In pretty much every circumstance this is false. When
    /// it is used, setting DEI will inform switches/routing infra
    /// that this can be dropped before higher priority traffic.
    pub drop_eligible_indicator: bool,
    /// The 802.1Q ID for this transmission.
    #[bits(12)]
    pub vlan_id: u16,
}

/// A receive buffer ID.
#[derive(Debug, Copy, Clone)]
#[repr(transparent)]
pub struct RxId(pub u32);

/// An individual segment in guest memory of a receive buffer.
#[derive(Debug, Copy, Clone)]
pub struct RxBufferSegment {
    /// Guest physical address.
    pub gpa: u64,
    /// The number of bytes in this range.
    pub len: u32,
}

/// Receive packet metadata.
#[derive(Debug, Copy, Clone)]
pub struct RxMetadata {
    /// The offset of the packet data from the beginning of the receive buffer.
    pub offset: usize,
    /// The length of the packet in bytes.
    pub len: usize,
    /// The IP checksum validation state.
    pub ip_checksum: RxChecksumState,
    /// The L4 checksum validation state.
    pub l4_checksum: RxChecksumState,
    /// The L4 protocol.
    pub l4_protocol: L4Protocol,
    /// Receive checksum or segmentation offload metadata.
    pub offload: RxOffload,
    /// Information about 802.1Q VLAN tagging. When a vlan is in use, this structure
    /// is populated. Only applies when traffic is being received over an L2 connection,
    /// so L3-only or above traffic will not use this option.
    pub vlan: Option<VlanMetadata>,
}

impl Default for RxMetadata {
    fn default() -> Self {
        Self {
            offset: 0,
            len: 0,
            ip_checksum: RxChecksumState::Unknown,
            l4_checksum: RxChecksumState::Unknown,
            l4_protocol: L4Protocol::Unknown,
            offload: RxOffload::default(),
            vlan: None,
        }
    }
}

/// Receive checksum or segmentation offload metadata.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
#[repr(C)]
pub struct RxOffload {
    // Interpreted according to `kind`:
    // - Checksum: value0 = checksum start, value1 = checksum offset.
    // - TcpV4/TcpV6: value0 = header length, value1 = maximum segment size.
    // - TcpV4Checksum/TcpV6Checksum: the TCP fields above, plus
    //   value2 = checksum start. The TCP checksum offset is always 16.
    value0: u16,
    value1: u16,
    value2: u16,
    kind: RxOffloadKind,
}

const _: () = assert!(size_of::<RxOffload>() == 8);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
#[repr(u8)]
enum RxOffloadKind {
    #[default]
    None,
    Checksum,
    TcpV4,
    TcpV4Checksum,
    TcpV6,
    TcpV6Checksum,
}

impl RxOffload {
    pub const fn checksum(start: u16, offset: u16) -> Self {
        Self {
            value0: start,
            value1: offset,
            value2: 0,
            kind: RxOffloadKind::Checksum,
        }
    }

    pub const fn tcp_gso(
        protocol: RxGsoProtocol,
        header_len: u16,
        max_segment_size: u16,
        checksum_start: Option<u16>,
    ) -> Self {
        let (kind, checksum_start) = match (protocol, checksum_start) {
            (RxGsoProtocol::TcpV4, Some(start)) => (RxOffloadKind::TcpV4Checksum, start),
            (RxGsoProtocol::TcpV4, None) => (RxOffloadKind::TcpV4, 0),
            (RxGsoProtocol::TcpV6, Some(start)) => (RxOffloadKind::TcpV6Checksum, start),
            (RxGsoProtocol::TcpV6, None) => (RxOffloadKind::TcpV6, 0),
        };
        Self {
            value0: header_len,
            value1: max_segment_size,
            value2: checksum_start,
            kind,
        }
    }

    pub const fn checksum_metadata(self) -> Option<RxChecksumOffload> {
        match self.kind {
            RxOffloadKind::Checksum => Some(RxChecksumOffload {
                start: self.value0,
                offset: self.value1,
            }),
            RxOffloadKind::TcpV4Checksum | RxOffloadKind::TcpV6Checksum => {
                Some(RxChecksumOffload {
                    start: self.value2,
                    offset: 16,
                })
            }
            _ => None,
        }
    }

    pub const fn gso(self) -> Option<RxGso> {
        let protocol = match self.kind {
            RxOffloadKind::TcpV4 | RxOffloadKind::TcpV4Checksum => RxGsoProtocol::TcpV4,
            RxOffloadKind::TcpV6 | RxOffloadKind::TcpV6Checksum => RxGsoProtocol::TcpV6,
            _ => return None,
        };
        Some(RxGso {
            protocol,
            header_len: self.value0,
            max_segment_size: self.value1,
        })
    }
}

/// Partial-checksum information for a received packet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RxChecksumOffload {
    pub start: u16,
    pub offset: u16,
}

/// Segmentation information for a coalesced receive packet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RxGso {
    pub protocol: RxGsoProtocol,
    pub header_len: u16,
    pub max_segment_size: u16,
}

/// Receive segmentation protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum RxGsoProtocol {
    TcpV4,
    TcpV6,
}

/// Receive offloads that a frontend negotiated with the guest.
///
/// Backends must enable only these capabilities on their host transport.
/// Enabling additional receive offloads can expose packet metadata or
/// oversized aggregate frames that the frontend cannot safely represent.
#[derive(Debug, Copy, Clone, Default)]
pub struct RxOffloadSupport {
    /// The guest can complete a partial transport checksum.
    pub checksum: bool,
    /// The guest can receive TCPv4 GSO packets.
    pub tcpv4_gso: bool,
    /// The guest can receive TCPv6 GSO packets.
    pub tcpv6_gso: bool,
}

/// The "L4" protocol: the TCP/UDP layer.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum L4Protocol {
    Unknown,
    Tcp,
    Udp,
}

/// The receive checksum state for a packet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RxChecksumState {
    /// The checksum was not evaluated.
    Unknown,
    /// The checksum value is correct.
    Good,
    /// The checksum value is incorrect.
    Bad,
    /// The checksum has been validated, but the value in the header is wrong.
    ///
    /// This occurs when LRO/RSC offload has been performed--multiple packet
    /// payloads are glommed together without updating the checksum in the first
    /// packet's header.
    ValidatedButWrong,
}

impl RxChecksumState {
    /// Returns true if the checksum has been validated.
    pub fn is_valid(self) -> bool {
        self == Self::Good || self == Self::ValidatedButWrong
    }
}

/// A transmit ID. This may be used by multiple segments at the same time.
#[derive(Debug, Copy, Clone)]
#[repr(transparent)]
pub struct TxId(pub u32);

#[derive(Debug, Clone)]
/// The segment type.
pub enum TxSegmentType {
    /// The start of a packet.
    Head(TxMetadata),
    /// A packet continuation.
    Tail,
}

#[derive(Debug, Clone)]
/// Transmit packet metadata.
pub struct TxMetadata {
    /// The transmit ID.
    pub id: TxId,
    /// The number of segments, including this one.
    pub segment_count: u8,
    /// Flags.
    pub flags: TxFlags,
    /// The total length of the packet in bytes.
    pub len: u32,
    /// The length of the Ethernet frame header. Only guaranteed to be set if
    /// various offload flags are set.
    pub l2_len: u8,
    /// The length of the IP header. Only guaranteed to be set if various
    /// offload flags are set.
    pub l3_len: u16,
    /// The length of the TCP header. Only guaranteed to be set if various
    /// offload flags are set.
    pub l4_len: u8,
    /// The offset into the buffer where the L4 header begins (TCP or UDP). Only
    /// expected to be set if offload (checksum and/or segmentation) flags are set.
    pub transport_header_offset: u16,
    /// The maximum segment size, used for segmentation offload (TSO or USO).
    /// Only guaranteed to be set if [`TxFlags::offload_tcp_segmentation`] or
    /// [`TxFlags::offload_udp_segmentation`] is set.
    pub max_segment_size: u16,
    /// Information about 802.1Q VLAN tagging. When a vlan is in use, this structure
    /// is populated. Only applies when traffic is being sent over an L2 connection,
    /// so L3-only or above traffic will not use this option.
    pub vlan: Option<VlanMetadata>,
}

/// Flags affecting transmit behavior.
#[bitfield(u8)]
pub struct TxFlags {
    /// Offload IPv4 header checksum calculation.
    ///
    /// `l3_protocol`, `l2_len`, and `l3_len` must be set.
    pub offload_ip_header_checksum: bool,
    /// Offload the TCP checksum calculation.
    ///
    /// `l3_protocol`, `l2_len`, and `l3_len` must be set.
    pub offload_tcp_checksum: bool,
    /// Offload the UDP checksum calculation.
    ///
    /// `l3_protocol`, `l2_len`, and `l3_len` must be set.
    pub offload_udp_checksum: bool,
    /// Offload the TCP segmentation, allowing packets to be larger than the
    /// MTU.
    ///
    /// `l3_protocol`, `l2_len`, `l3_len`, `l4_len`, and `tcp_segment_size` must
    /// be set.
    pub offload_tcp_segmentation: bool,
    /// If true, the packet is IPv4.
    pub is_ipv4: bool,
    /// If true, the packet is IPv6. Mutually exclusive with `is_ipv4`.
    pub is_ipv6: bool,
    /// Offload UDP segmentation (USO), allowing UDP packets larger than the
    /// MTU. `l2_len`, `l3_len`, and `max_segment_size` must be set.
    pub offload_udp_segmentation: bool,
    #[bits(1)]
    _reserved: u8,
}

impl Default for TxMetadata {
    fn default() -> Self {
        Self {
            id: TxId(0),
            segment_count: 0,
            len: 0,
            flags: TxFlags::new(),
            l2_len: 0,
            l3_len: 0,
            l4_len: 0,
            transport_header_offset: 0,
            max_segment_size: 0,
            vlan: None,
        }
    }
}

#[derive(Debug, Clone)]
/// A transmit packet segment.
pub struct TxSegment {
    /// The segment type (head or tail).
    pub ty: TxSegmentType,
    /// The guest address of this segment.
    pub gpa: u64,
    /// The length of this segment.
    pub len: u32,
}

/// Computes the number of packets in `segments`.
pub fn packet_count(mut segments: &[TxSegment]) -> usize {
    let mut packet_count = 0;
    while let Some(head) = segments.first() {
        let TxSegmentType::Head(metadata) = &head.ty else {
            unreachable!()
        };
        segments = &segments[metadata.segment_count as usize..];
        packet_count += 1;
    }
    packet_count
}

/// Gets the next packet from a list of segments, returning the packet metadata,
/// the segments in the packet, and the remaining segments.
pub fn next_packet(segments: &[TxSegment]) -> (&TxMetadata, &[TxSegment], &[TxSegment]) {
    let metadata = if let TxSegmentType::Head(metadata) = &segments[0].ty {
        metadata
    } else {
        unreachable!();
    };
    let (this, rest) = segments.split_at(metadata.segment_count.into());
    (metadata, this, rest)
}

/// Multi-queue related support.
#[derive(Debug, Copy, Clone)]
pub struct MultiQueueSupport {
    /// The number of supported queues.
    pub max_queues: u16,
    /// The size of the RSS indirection table.
    pub indirection_table_size: u16,
}

/// The set of supported transmit offloads.
#[derive(Debug, Copy, Clone, Default)]
pub struct TxOffloadSupport {
    /// IPv4 header checksum offload.
    pub ipv4_header: bool,
    /// TCP checksum offload.
    pub tcp: bool,
    /// UDP checksum offload.
    pub udp: bool,
    /// TCP segmentation offload.
    pub tso: bool,
    /// UDP segmentation offload (USO).
    pub uso: bool,
}

#[derive(Debug, Clone)]
pub struct RssConfig<'a> {
    pub key: &'a [u8],
    pub indirection_table: &'a [u16],
    pub flags: u32, // TODO
}

/// A signal returned from `Endpoint::wait_for_endpoint_action` indicating why
/// the caller was woken.
#[derive(PartialEq, Debug)]
pub enum EndpointAction {
    RestartRequired,
    LinkStatusNotify(bool),
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    // Test: Represent standalone checksums and both TCP GSO protocols with and without partial checksum metadata.
    // Expected: Independent optional fields retain exact boundary values; TCP checksum completion always uses transport offset 16.
    #[test]
    fn receive_offloads_preserve_protocol_and_optional_checksum_metadata() {
        assert_eq!(RxOffload::default().checksum_metadata(), None);
        assert_eq!(RxOffload::default().gso(), None);
        let checksum = RxOffload::checksum(0, u16::MAX);
        assert_eq!(
            checksum.checksum_metadata(),
            Some(RxChecksumOffload {
                start: 0,
                offset: u16::MAX
            })
        );
        assert_eq!(checksum.gso(), None);
        for protocol in [RxGsoProtocol::TcpV4, RxGsoProtocol::TcpV6] {
            for start in [None, Some(0), Some(54), Some(u16::MAX)] {
                let offload = RxOffload::tcp_gso(protocol, 74, 1440, start);
                assert_eq!(
                    offload.gso(),
                    Some(RxGso {
                        protocol,
                        header_len: 74,
                        max_segment_size: 1440
                    })
                );
                assert_eq!(
                    offload.checksum_metadata(),
                    start.map(|start| RxChecksumOffload { start, offset: 16 })
                );
            }
        }
    }

    // Test: Construct default RX/TX metadata and query every receive checksum state.
    // Expected: Defaults advertise no offload or known checksum and only validated states report valid, including coalesced packets with stale checksum bytes.
    #[test]
    fn metadata_defaults_and_checksum_validity_are_conservative() {
        let rx = RxMetadata::default();
        assert_eq!((rx.offset, rx.len), (0, 0));
        assert_eq!(rx.ip_checksum, RxChecksumState::Unknown);
        assert_eq!(rx.l4_checksum, RxChecksumState::Unknown);
        assert_eq!(rx.l4_protocol, L4Protocol::Unknown);
        assert!(rx.vlan.is_none());
        assert_eq!(rx.offload, RxOffload::default());
        let tx = TxMetadata::default();
        assert_eq!((tx.id.0, tx.segment_count, tx.len), (0, 0, 0));
        assert_eq!(
            (
                tx.l2_len,
                tx.l3_len,
                tx.l4_len,
                tx.transport_header_offset,
                tx.max_segment_size
            ),
            (0, 0, 0, 0, 0)
        );
        assert_eq!(u8::from(tx.flags), 0);
        assert!(tx.vlan.is_none());
        for (state, expected) in [
            (RxChecksumState::Unknown, false),
            (RxChecksumState::Bad, false),
            (RxChecksumState::Good, true),
            (RxChecksumState::ValidatedButWrong, true),
        ] {
            assert_eq!(state.is_valid(), expected);
        }
    }

    // Test: Walk a three-segment packet followed by a single-segment packet, including a zero-length scatter entry.
    // Expected: Counts follow packet heads rather than lengths or IDs, returned slices borrow exact input ranges, and the final remainder is empty.
    #[test]
    fn packet_helpers_preserve_scatter_boundaries_and_borrowed_metadata() {
        let segments = [
            TxSegment {
                ty: TxSegmentType::Head(TxMetadata {
                    id: TxId(7),
                    segment_count: 3,
                    len: 1500,
                    ..Default::default()
                }),
                gpa: 0x1003,
                len: 40,
            },
            TxSegment {
                ty: TxSegmentType::Tail,
                gpa: 0x2000,
                len: 0,
            },
            TxSegment {
                ty: TxSegmentType::Tail,
                gpa: 0x8000,
                len: 1460,
            },
            TxSegment {
                ty: TxSegmentType::Head(TxMetadata {
                    id: TxId(7),
                    segment_count: 1,
                    len: 60,
                    ..Default::default()
                }),
                gpa: 0x9000,
                len: 60,
            },
        ];
        assert_eq!(packet_count(&[]), 0);
        assert_eq!(packet_count(&segments), 2);
        let (metadata, first, rest) = next_packet(&segments);
        assert_eq!((metadata.id.0, metadata.len), (7, 1500));
        assert_eq!(first.len(), 3);
        assert!(core::ptr::eq(first.as_ptr(), segments.as_ptr()));
        assert!(core::ptr::eq(rest.as_ptr(), segments[3..].as_ptr()));
        assert_eq!(packet_count(rest), 1);
        let (metadata, second, rest) = next_packet(rest);
        assert_eq!((metadata.id.0, metadata.len), (7, 60));
        assert_eq!(second.len(), 1);
        assert!(core::ptr::eq(second.as_ptr(), &segments[3]));
        assert!(rest.is_empty());
    }
}
