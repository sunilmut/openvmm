// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::gen_if as interfaces;
use super::gen_if_tun as tun;
use std::mem::{align_of, offset_of, size_of};
use test_with_tracing::test;

// Test: Check the native 64-bit Linux interface ioctl structures against their kernel ABI offsets and extents.
// Expected: Interface names occupy the first 16 bytes, request/configuration unions are naturally aligned, and hardware-map fields retain their C layout.
#[test]
fn interface_request_configuration_and_hardware_map_match_linux_abi() {
    assert_eq!(
        (
            size_of::<interfaces::ifreq>(),
            align_of::<interfaces::ifreq>()
        ),
        (40, 8)
    );
    assert_eq!(offset_of!(interfaces::ifreq, ifr_ifrn), 0);
    assert_eq!(offset_of!(interfaces::ifreq, ifr_ifru), 16);
    assert_eq!(size_of::<interfaces::ifreq__bindgen_ty_1>(), 16);
    assert_eq!(size_of::<interfaces::ifreq__bindgen_ty_2>(), 24);
    assert_eq!(
        (
            size_of::<interfaces::ifconf>(),
            align_of::<interfaces::ifconf>()
        ),
        (16, 8)
    );
    assert_eq!(offset_of!(interfaces::ifconf, ifc_len), 0);
    assert_eq!(offset_of!(interfaces::ifconf, ifc_ifcu), 8);
    assert_eq!(size_of::<interfaces::ifmap>(), 24);
    assert_eq!(offset_of!(interfaces::ifmap, mem_start), 0);
    assert_eq!(offset_of!(interfaces::ifmap, mem_end), 8);
    assert_eq!(offset_of!(interfaces::ifmap, base_addr), 16);
    assert_eq!(offset_of!(interfaces::ifmap, irq), 18);
    assert_eq!(offset_of!(interfaces::ifmap, dma), 19);
    assert_eq!(offset_of!(interfaces::ifmap, port), 20);
}

// Test: Construct default interface configuration and protocol settings without supplying a data buffer or protocol descriptor.
// Expected: No buffer bytes or protocol data are advertised until the caller explicitly configures them.
#[test]
fn default_interface_configuration_advertises_no_buffer_or_protocol_data() {
    let configuration = interfaces::ifconf::default();
    assert_eq!(configuration.ifc_len, 0);
    let settings = interfaces::if_settings::default();
    assert_eq!(settings.type_, 0);
    assert_eq!(settings.size, 0);
}

// Test: Invoke every exported TUN ioctl wrapper with an invalid descriptor and live, correctly typed argument storage.
// Expected: Every wrapper propagates EBADF without treating the request as successful or changing the output header size.
#[test]
fn tun_ioctl_wrappers_propagate_invalid_descriptor_errors() {
    let mut request = interfaces::ifreq::default();
    let mut header_size = 0x1234;
    // SAFETY: Pointer arguments reference initialized live storage of the required types.
    // Descriptor -1 cannot identify a device or mutate any host network configuration.
    let results = unsafe {
        [
            ("set interface", super::tun_set_iff(-1, &request)),
            ("set offload", super::tun_set_offload(-1, 0x55)),
            ("get interface", super::tun_get_iff(-1, &mut request)),
            (
                "get header size",
                super::tun_get_vnet_hdr_sz(-1, &mut header_size),
            ),
            (
                "set header size",
                super::tun_set_vnet_hdr_sz(-1, &header_size),
            ),
        ]
    };
    for (operation, result) in results {
        assert_eq!(result, Err(nix::errno::Errno::EBADF), "{operation}");
    }
    assert_eq!(header_size, 0x1234);
}

// Test: Check Ethernet, packet-info, and BPF instruction/program descriptors against their 64-bit Linux ABI, including an empty filter program.
// Expected: Protocol and instruction fields retain kernel-defined offsets, and a default BPF program advertises no instructions or dangling filter pointer.
#[test]
fn tun_packet_and_bpf_headers_match_kernel_layout_and_empty_program_contract() {
    assert_eq!(
        (size_of::<tun::ethhdr>(), align_of::<tun::ethhdr>()),
        (14, 1)
    );
    assert_eq!(offset_of!(tun::ethhdr, h_dest), 0);
    assert_eq!(offset_of!(tun::ethhdr, h_source), 6);
    assert_eq!(offset_of!(tun::ethhdr, h_proto), 12);
    assert_eq!(size_of::<tun::tun_pi>(), 4);
    assert_eq!(offset_of!(tun::tun_pi, proto), 2);
    assert_eq!(size_of::<tun::sock_filter>(), 8);
    assert_eq!(offset_of!(tun::sock_filter, code), 0);
    assert_eq!(offset_of!(tun::sock_filter, jt), 2);
    assert_eq!(offset_of!(tun::sock_filter, jf), 3);
    assert_eq!(offset_of!(tun::sock_filter, k), 4);
    assert_eq!(
        (size_of::<tun::sock_fprog>(), align_of::<tun::sock_fprog>()),
        (16, 8)
    );
    assert_eq!(offset_of!(tun::sock_fprog, filter), 8);
    let program = tun::sock_fprog::default();
    assert_eq!(program.len, 0);
    assert!(program.filter.is_null());
}

// Test: Place two MAC addresses immediately after a TUN filter's flexible-array header and request its const and mutable tail pointers.
// Expected: Both pointer APIs identify the real MAC storage at byte four without overlapping flags/count or changing address bytes.
#[test]
fn tun_filter_tail_pointers_identify_adjacent_mac_storage() {
    #[repr(C)]
    struct FilterBuffer {
        header: tun::tun_filter,
        addresses: [[u8; 6]; 2],
    }
    let mut buffer = FilterBuffer {
        header: tun::tun_filter {
            flags: 1,
            count: 2,
            addr: tun::__IncompleteArrayField::new(),
        },
        addresses: [[0, 1, 2, 3, 4, 5], [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54]],
    };
    assert_eq!(size_of::<tun::tun_filter>(), 4);
    assert_eq!(offset_of!(tun::tun_filter, addr), 4);
    assert_eq!(offset_of!(FilterBuffer, addresses), 4);
    assert_eq!(buffer.header.addr.as_ptr(), buffer.addresses.as_ptr());
    assert_eq!(
        buffer.header.addr.as_mut_ptr(),
        buffer.addresses.as_mut_ptr()
    );
    assert_eq!((buffer.header.flags, buffer.header.count), (1, 2));
    assert_eq!(
        buffer.addresses,
        [[0, 1, 2, 3, 4, 5], [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54]]
    );
}

// Test: Read and mutate a counted TUN MAC-filter tail with an adjacent guard address.
// Expected: Slice helpers expose exactly the counted addresses, update the selected MAC in place, and preserve the header/guard.
#[test]
fn tun_filter_counted_tail_slices_preserve_header_and_adjacent_storage() {
    #[repr(C)]
    struct FilterBuffer {
        header: tun::tun_filter,
        addresses: [[u8; 6]; 3],
    }
    let first = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01];
    let second = [0x33, 0x33, 0x00, 0x00, 0x00, 0x02];
    let replacement = [0x01, 0x00, 0x5e, 0x7f, 0x12, 0x34];
    let guard = [0xcc; 6];
    let mut buffer = FilterBuffer {
        header: tun::tun_filter {
            flags: 1,
            count: 2,
            addr: tun::__IncompleteArrayField::new(),
        },
        addresses: [first, second, guard],
    };
    // SAFETY: The repr(C) tail immediately follows the header, has three live MAC slots,
    // and both requested slices are limited to two slots with exclusive access for mutation.
    unsafe {
        let addresses = buffer
            .header
            .addr
            .as_slice(usize::from(buffer.header.count));
        assert_eq!(addresses, &[first, second]);
        let addresses = buffer
            .header
            .addr
            .as_mut_slice(usize::from(buffer.header.count));
        addresses[1] = replacement;
    }
    assert_eq!(buffer.addresses, [first, replacement, guard]);
    assert_eq!((buffer.header.flags, buffer.header.count), (1, 2));
}
