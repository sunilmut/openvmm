// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// IGNORED: send_arg_data declares only the fixed argument in the frame length.
//          Reproduced a 32-byte declared length for a 37-byte reply.
//
// Test: Send a fixed reply argument followed by a nonempty variable payload.
// Expected: The frame length includes both the fixed argument and all trailing bytes.
#[test]
#[ignore = "product bug: send_arg_data omits trailing data from the frame length"]
fn argument_data_reply_length_includes_the_trailing_payload() {
    let mut capture = Capture::default();
    capture
        .send_arg_data(
            0x1234,
            fuse_ioctl_out {
                result: 17,
                ..FromZeros::new_zeroed()
            },
            b"reply",
        )
        .unwrap();
    assert_eq!(&capture.check(0)[size_of::<fuse_ioctl_out>()..], b"reply");
}

struct IoctlFs;
impl Fuse for IoctlFs {
    fn ioctl(&self, _: &Request, arg: &fuse_ioctl_in, data: &[u8]) -> lx::Result<(i32, Vec<u8>)> {
        assert_eq!((arg.fh, arg.cmd), (42, 73));
        assert_eq!(data, b"input");
        Ok((17, b"output".to_vec()))
    }
}

// IGNORED: The ioctl dispatcher sends the request data instead of the backend output.
//          Reproduced an 'input' payload where the filesystem returned 'output'.
//
// Test: Dispatch an ioctl whose filesystem output differs from its input.
// Expected: The returned wire payload contains the filesystem's output, not the request buffer.
#[test]
#[ignore = "product bug: ioctl replies echo request data instead of backend output"]
fn ioctl_replies_deliver_backend_output_instead_of_echoing_input() {
    let session = Session::new(IoctlFs);
    initialize(&session);
    let input = args(
        fuse_ioctl_in {
            fh: 42,
            cmd: 73,
            in_size: 5,
            out_size: 6,
            ..FromZeros::new_zeroed()
        },
        b"input",
    );
    let mut capture = Capture::default();
    session.dispatch(request(FUSE_IOCTL, &input), &mut capture, None);
    let bytes = capture.messages.last().unwrap();
    let (header, bytes) = fuse_out_header::read_from_prefix(bytes).unwrap();
    assert_eq!(header.error, 0);
    let (reply, data) = fuse_ioctl_out::read_from_prefix(bytes).unwrap();
    assert_eq!(reply.result, 17);
    assert_eq!(data, b"output");
}

// IGNORED: INIT subtracts the header size before validating the minimum length.
//          Reproduced an arithmetic-underflow panic in Request::read_operation.
//
// Test: Parse an INIT header that claims fewer bytes than the header itself.
// Expected: The malformed operation is rejected without arithmetic underflow or a panic.
#[test]
#[ignore = "product bug: undersized INIT header length panics"]
fn init_rejects_a_declared_length_smaller_than_its_header() {
    let mut bytes = wire(FUSE_INIT, fuse_init_in::new_zeroed().as_bytes());
    bytes[..4].copy_from_slice(&((size_of::<fuse_in_header>() - 1) as u32).to_ne_bytes());
    let request = Request::new(bytes.as_slice()).unwrap();
    assert!(matches!(request.operation(), FuseOperation::Invalid));
}
