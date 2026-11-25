// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::protocol::{fuse_init_out, fuse_out_header};
use parking_lot::Mutex;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::time::Duration;
use test_with_tracing::test;
use zerocopy::FromBytes;

struct LifecycleFs(Arc<Mutex<Vec<&'static str>>>);
impl Fuse for LifecycleFs {
    fn init(&self, _: &mut crate::SessionInfo) {
        self.0.lock().push("init");
    }
    fn destroy(&self) {
        self.0.lock().push("destroy");
    }
}

// Test: Run a FUSE connection over an in-process packet transport, ending with an EOF packet.
// Expected: INIT produces a complete negotiated reply and EOF destroys the initialized filesystem once.
#[test]
fn packet_transport_runs_negotiation_and_tears_down_after_eof() {
    let (server, client) = UnixDatagram::pair().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let input = crate::request::tests::FUSE_INIT_REQUEST;
    assert_eq!(client.send(input).unwrap(), input.len());
    assert_eq!(client.send(b"").unwrap(), 0);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut connection = Connection {
        fuse_dev: fs::File::from(OwnedFd::from(server)),
    };
    connection.run(LifecycleFs(calls.clone())).unwrap();
    assert_eq!(calls.lock().as_slice(), &["init", "destroy"]);
    let mut bytes = [0; 256];
    let size = client.recv(&mut bytes).unwrap();
    let (header, payload) = fuse_out_header::read_from_prefix(&bytes[..size]).unwrap();
    assert_eq!(
        (header.len as usize, header.error, header.unique),
        (size, 0, 1)
    );
    let reply = fuse_init_out::read_from_bytes(payload).unwrap();
    assert_eq!(
        (reply.major, reply.minor, reply.max_write),
        (7, 39, 1048576)
    );
}

// Test: Reject a mount-point path containing an embedded NUL before entering the unmount syscall.
// Expected: EINVAL is returned; the test does not mount, unmount or require elevated privileges.
#[test]
fn unmount_rejects_embedded_nul_before_touching_the_host_mount_table() {
    assert_eq!(
        Connection::unmount("bad\0path", 0).unwrap_err(),
        lx::Error::EINVAL
    );
}
