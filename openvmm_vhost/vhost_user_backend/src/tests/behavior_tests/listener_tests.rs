// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Run the public pathname listener over a stale file and terminate its client cleanly or halfway through a protocol header.
// Expected: The stale pathname is replaced by a usable socket, valid requests receive exact replies, and either disconnect path returns from run and resets the device once.
#[async_test]
async fn public_listener_replaces_stale_path_and_cleans_up_disconnects(driver: DefaultDriver) {
    for malformed in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("device.sock");
        std::fs::write(&path, b"stale socket pathname").unwrap();
        let calls = Arc::new(Mutex::new(RegisterCalls::default()));
        let device = ConfigDevice {
            inner: MockDevice::new(),
            calls: calls.clone(),
        };
        let mut serving =
            std::pin::pin!(VhostUserDeviceServer::new(Box::new(device)).run(&driver, &path));
        assert!(futures::poll!(serving.as_mut()).is_pending());
        let connection =
            socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
        connection
            .connect(&socket2::SockAddr::unix(&path).unwrap())
            .unwrap();
        let client = async {
            if malformed {
                assert_eq!(connection.send(&[0x91; 5]).unwrap(), 5);
                connection.shutdown(std::net::Shutdown::Write).unwrap();
                drop(connection);
            } else {
                let stream: UnixStream = connection.into();
                let frontend = VhostUserSocket::new(PolledSocket::new(&driver, stream).unwrap());
                assert_eq!(
                    exchange(&frontend, VhostUserRequestCode::GET_QUEUE_NUM, &[], false).await,
                    2u64.to_le_bytes()
                );
                drop(frontend);
            }
        };
        let (result, ()) = futures::join!(serving, client);
        result.unwrap();
        assert_eq!(calls.lock().resets, 1);
        assert!(calls.lock().reads.is_empty() && calls.lock().writes.is_empty());
    }
}
