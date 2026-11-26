// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire-transport conformance for PCIe simulator configuration.

use mesh::OwnedMessage;
use pcie_remote_resources::PcieRemoteHandle;
use test_with_tracing::test;

// Test: Transport PCIe simulator configuration with absent and explicit IPv6
//       endpoints and distinct full-width host-unit and controller identities.
// Expected: Endpoint selection and every independent routing identity survive
//       actual wire serialization without collapsing absence into an override.
#[test]
fn simulator_endpoint_and_route_survive_transport() {
    let instance_id = guid::guid!("9f735b2a-6c8d-4e10-b2a5-3901c6e8df74");
    for (socket_addr, endpoint) in [
        (None, "localhost:48914"),
        (Some("[2001:db8::7]:49152"), "[2001:db8::7]:49152"),
    ] {
        let handle = PcieRemoteHandle {
            instance_id,
            socket_addr: socket_addr.map(str::to_owned),
            hu: u16::MAX,
            controller: 0x1234,
        };
        let wire = OwnedMessage::new(handle).serialize();
        let decoded: PcieRemoteHandle = OwnedMessage::serialized(wire).parse().unwrap();
        assert_eq!(decoded.instance_id, instance_id);
        assert_eq!(decoded.hu, u16::MAX);
        assert_eq!(decoded.controller, 0x1234);
        assert_eq!(decoded.socket_addr.as_deref(), socket_addr);
        assert_eq!(decoded.socket_addr(), endpoint);
    }
}
