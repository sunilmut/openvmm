// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use mesh::rpc::RpcSend;
use test_with_tracing::test;

struct Fixture {
    params: VncParameters<TcpListener>,
    input_recv: mesh::Receiver<InputData>,
    mapping: SparseMapping,
    _format_send: mesh::Sender<FramebufferFormat>,
    dirty_send: mesh::Sender<Vec<DirtyRect>>,
}

impl Fixture {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let memory = alloc_shared_memory(FRAMEBUFFER_SIZE, "vnc-worker-rpc-test").unwrap();
        let mapping = SparseMapping::new(FRAMEBUFFER_SIZE).unwrap();
        mapping
            .map_file(0, FRAMEBUFFER_SIZE, &memory, 0, true)
            .unwrap();
        let (framebuffer, access) = framebuffer::framebuffer(memory, FRAMEBUFFER_SIZE, 0).unwrap();
        let format_send = framebuffer.format_send();
        format_send.send(FramebufferFormat {
            width: 16,
            height: 16,
            bytes_per_line: 16 * 4,
            offset: 0,
        });
        let (input_send, input_recv) = mesh::channel();
        let (dirty_send, dirty_recv) = mesh::channel();
        Self {
            params: VncParameters {
                listener,
                framebuffer: access,
                input_send,
                dirty_recv: Some(dirty_recv),
                max_clients: 2,
                evict_oldest: true,
            },
            input_recv,
            mapping,
            _format_send: format_send,
            dirty_send,
        }
    }
}

// Test: Run the public TCP worker constructor and restart constructor with real handshaken VNC clients, then stop via RPC or by dropping the RPC sender.
// Expected: Both shutdown paths return successfully and close active client connections rather than retaining the worker/listener indefinitely.
#[test]
fn worker_stop_and_rpc_disconnect_close_active_clients() {
    for stop_rpc in [true, false] {
        let fixture = Fixture::new();
        let address = fixture.params.listener.local_addr().unwrap();
        let worker = if stop_rpc {
            VncWorker::<TcpListener>::new(fixture.params).unwrap()
        } else {
            VncWorker::<TcpListener>::restart(fixture.params).unwrap()
        };
        let (send, receive) = mesh::channel();
        let join = thread::spawn(move || worker.run(receive));
        let mut client = Client::connect(address);
        if stop_rpc {
            send.send(WorkerRpc::Stop);
        } else {
            drop(send);
        }
        join.join().unwrap().unwrap();
        let mut byte = [0];
        assert_eq!(client.stream.read(&mut byte).unwrap(), 0);
    }
}

// Test: Restart a worker with an active client, recover its state through the real RPC, and start a replacement worker using that state.
// Expected: The old connection is closed, listener address/client policy persist, and the replacement worker serves the same framebuffer and forwards input/dirty notifications through the original channels.
#[test]
fn restart_rpc_preserves_listener_framebuffer_and_input_dirty_channels() {
    let mut fixture = Fixture::new();
    fixture
        .mapping
        .write_at(0, &pixel(0x12, 0x34, 0x56))
        .unwrap();
    let address = fixture.params.listener.local_addr().unwrap();
    let worker = VncWorker::<TcpListener>::new(fixture.params).unwrap();
    let (send, receive) = mesh::channel();
    let join = thread::spawn(move || worker.run(receive));
    let mut old_client = Client::connect(address);
    old_client.send_update_request(false);
    let initial = old_client.read_update();
    assert_eq!(&initial[0].payload[..4], &pixel(0x12, 0x34, 0x56));
    let state = block_with_io(async |_driver| {
        mesh::CancelContext::new()
            .with_timeout(Duration::from_secs(5))
            .until_cancelled(send.call_failable(WorkerRpc::Restart, ()))
            .await
            .unwrap()
            .unwrap()
    });
    join.join().unwrap().unwrap();
    let mut byte = [0];
    assert_eq!(old_client.stream.read(&mut byte).unwrap(), 0);
    assert_eq!(state.listener.local_addr().unwrap(), address);
    assert_eq!(state.max_clients, 2);
    assert!(state.evict_oldest);
    assert!(state.dirty_recv.is_some());
    let worker = VncWorker::<TcpListener>::restart(state).unwrap();
    let (send, receive) = mesh::channel();
    let join = thread::spawn(move || worker.run(receive));
    let mut client = Client::connect(address);
    assert_eq!((client.width, client.height), (16, 16));
    client.send_update_request(false);
    let update = client.read_update();
    assert_eq!(&update[0].payload[..4], &pixel(0x12, 0x34, 0x56));
    client.send_pointer_event(3, 15, 15);
    match wait_for_input(&mut fixture.input_recv) {
        InputData::Mouse(MouseData {
            button_mask: 3,
            x: 0x7fff,
            y: 0x7fff,
        }) => {}
        other => panic!("unexpected restarted input: {other:?}"),
    }
    fixture
        .mapping
        .write_at(0, &pixel(0xaa, 0xbb, 0xcc))
        .unwrap();
    fixture.dirty_send.send(vec![DirtyRect {
        left: 0,
        top: 0,
        right: 16,
        bottom: 16,
    }]);
    client.send_update_request(true);
    let dirty = client.read_update();
    assert_eq!(
        (dirty[0].x, dirty[0].y, dirty[0].width, dirty[0].height),
        (0, 0, 16, 16)
    );
    assert_eq!(&dirty[0].payload[..4], &pixel(0xaa, 0xbb, 0xcc));
    send.send(WorkerRpc::Stop);
    join.join().unwrap().unwrap();
}

// Test: Reach the one-client limit under reject-new and evict-oldest policy, then send keyboard input through the surviving connection.
// Expected: Reject-new closes only the extra connection, eviction closes only the old connection, and the retained/replacement client forwards exact make/break scancodes to the original input channel.
#[test]
fn client_limit_policy_preserves_the_right_connection_and_keyboard_input() {
    for evict_oldest in [false, true] {
        let mut fixture = Fixture::new();
        fixture.params.max_clients = 1;
        fixture.params.evict_oldest = evict_oldest;
        let address = fixture.params.listener.local_addr().unwrap();
        let worker = VncWorker::<TcpListener>::new(fixture.params).unwrap();
        let (send, receive) = mesh::channel();
        let join = thread::spawn(move || worker.run(receive));
        let mut first = Client::connect(address);
        let mut byte = [0];
        let mut active = if evict_oldest {
            let second = Client::connect(address);
            assert_eq!(first.stream.read(&mut byte).unwrap(), 0);
            second
        } else {
            let mut rejected = TcpStream::connect(address).unwrap();
            rejected
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            assert_eq!(rejected.read(&mut byte).unwrap(), 0);
            first
        };
        for make in [true, false] {
            active
                .stream
                .write_all(&[4, u8::from(make), 0, 0, 0, 0, 0, b'a'])
                .unwrap();
            match wait_for_input(&mut fixture.input_recv) {
                InputData::Keyboard(KeyboardData {
                    code: 0x1e,
                    make: actual,
                }) => assert_eq!(actual, make),
                other => panic!("unexpected key input after client limit: {other:?}"),
            }
        }
        send.send(WorkerRpc::Stop);
        join.join().unwrap().unwrap();
    }
}
