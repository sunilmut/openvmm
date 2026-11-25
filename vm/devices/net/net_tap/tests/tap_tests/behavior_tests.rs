// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use net_backend::RxOffloadSupport;
use net_backend::resolve::ResolveEndpointParams;
use net_backend_resources::mac_address::MacAddress;
use net_backend_resources::tap::TapHandle;
use net_tap::resolver::TapResolver;
use vm_resource::ResolveResource;

// Test: Resolve a real TAP handle, receive exact Ethernet frames across queue stop/drop/recreate with every supported RX offload configuration, and reject a non-TAP handle.
// Expected: Endpoint capabilities advertise supported checksum/segmentation operations, every configuration preserves working packet I/O and metadata, stop/restart releases queue ownership correctly, and an invalid fd yields a typed ioctl error.
pub(super) async fn resolve_reconfigure(driver: DefaultDriver) {
    let params = || ResolveEndpointParams {
        mac_address: MacAddress::new([2, 0, 0, 0, 0, 1]),
    };
    let invalid = TapResolver.resolve(
        TapHandle {
            fd: std::fs::File::open("/dev/null").unwrap().into(),
        },
        params(),
    );
    assert!(matches!(invalid, Err(tap::Error::GetTapAttributes(_))));
    let mut endpoint = TapResolver
        .resolve(
            TapHandle {
                fd: tap::open_tap("tap_cycle").unwrap(),
            },
            params(),
        )
        .unwrap()
        .0;
    configure_tap("tap_cycle", "10.2.0.1/24");
    disable_ipv6("tap_cycle");
    assert_eq!(endpoint.endpoint_type(), "tap");
    assert!(endpoint.is_ordered());
    let support = endpoint.tx_offload_support();
    assert!(support.ipv4_header && support.tcp && support.udp && support.tso && support.uso);
    let (mut pool, memory) = make_pool();
    for (index, enabled) in [
        RxOffloadSupport::default(),
        RxOffloadSupport {
            checksum: true,
            tcpv4_gso: true,
            tcpv6_gso: true,
        },
        RxOffloadSupport::default(),
    ]
    .into_iter()
    .enumerate()
    {
        let mut queues = Vec::new();
        endpoint
            .get_queues(
                vec![QueueConfig {
                    driver: Box::new(driver.clone()),
                    enabled_rx_offloads: enabled,
                }],
                None,
                &mut queues,
            )
            .await
            .unwrap();
        let queue = &mut queues[0];
        let id = RxId(index as u32 + 1);
        queue.rx_avail(&mut pool, &[id]);
        let mut frame = vec![0x71 + index as u8; 60];
        frame[..14].copy_from_slice(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 2, 0x88, 0xb5,
        ]);
        send_ethernet_frame("tap_cycle", &frame);
        let mut timer = pal_async::timer::PolledTimer::new(&driver);
        use futures::FutureExt;
        futures::select! {
            _ = poll_fn(|cx| queue.poll_ready(cx, &mut pool)).fuse() => {},
            _ = timer.sleep(std::time::Duration::from_secs(5)).fuse() => panic!("real TAP RX timed out"),
        }
        let mut done = [RxId(99)];
        assert_eq!(queue.rx_poll(&mut pool, &mut done).unwrap(), 1);
        assert_eq!(done[0].0, id.0);
        assert_eq!(pool.rx_metadata(done[0]).unwrap().len, frame.len());
        let mut received = vec![0; frame.len()];
        memory
            .read_at(done[0].0 as u64 * 2048, &mut received)
            .unwrap();
        assert_eq!(received, frame);
        drop(queues);
        endpoint.stop().await;
    }
}
