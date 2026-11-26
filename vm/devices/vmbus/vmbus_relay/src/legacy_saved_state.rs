// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provides saved state structures for compatibility with the 2411 release,
//! where the relay and `vmbus_client` were saved together as a single state
//! unit.

pub use relay::SavedState;

use crate::saved_state;

mod relay {
    use mesh::payload::Protobuf;
    use vmcore::save_restore::SavedStateRoot;

    /// The legacy, 2411 saved state for the relay.
    #[derive(Clone, Protobuf, SavedStateRoot)]
    #[mesh(package = "vmbus.relay")]
    pub struct SavedState {
        #[mesh(1)]
        pub(crate) use_interrupt_relay: bool,
        #[mesh(2)]
        pub(super) relay_state: RelayState,
        #[mesh(3)]
        pub(super) client_saved_state: vmbus_client::SavedState,
        #[mesh(4)]
        pub(crate) channels: Vec<Channel>,
    }

    #[derive(Clone, Protobuf)]
    #[mesh(package = "vmbus.relay")]
    pub(crate) struct Channel {
        #[mesh(1)]
        pub(crate) channel_id: u32,
        #[mesh(2)]
        pub(crate) event_flag: Option<u16>,
        #[mesh(3)]
        pub(crate) intercepted: bool,
        #[mesh(4)]
        pub(crate) intercepted_save_state: Vec<u8>,
    }

    #[derive(Copy, Clone, Eq, PartialEq, Protobuf)]
    #[mesh(package = "vmbus.relay")]
    pub(super) enum RelayState {
        #[mesh(1)]
        Disconnected,
        #[mesh(2)]
        Connected,
    }
}

impl SavedState {
    /// Constructs a legacy saved state from the current relay and client saved
    /// states.
    pub fn from_relay_and_client(
        relay: &saved_state::SavedState,
        client: &vmbus_client::SavedState,
    ) -> Self {
        Self {
            use_interrupt_relay: relay.use_interrupt_relay,
            relay_state: relay::RelayState::Connected,
            client_saved_state: client.clone(),
            channels: relay
                .channels
                .iter()
                .map(|channel| relay::Channel {
                    channel_id: channel.channel_id,
                    event_flag: channel.event_flag,
                    intercepted: channel.intercepted,
                    intercepted_save_state: channel.intercepted_save_state.clone(),
                })
                .collect(),
        }
    }

    /// Produces a current relay saved state from the legacy saved state.
    pub fn relay_saved_state(&mut self) -> saved_state::SavedState {
        self.client_saved_state
            .channels
            .sort_by_key(|channel| channel.offer.channel_id);

        saved_state::SavedState {
            use_interrupt_relay: self.use_interrupt_relay,
            channels: self
                .channels
                .iter()
                .map(|channel| saved_state::Channel {
                    channel_id: channel.channel_id,
                    event_flag: channel.event_flag,
                    intercepted: channel.intercepted,
                    intercepted_save_state: channel.intercepted_save_state.clone(),
                    is_open: self
                        .client_saved_state
                        .channels
                        .binary_search_by_key(&channel.channel_id, |channel| {
                            channel.offer.channel_id
                        })
                        .is_ok_and(|i| {
                            matches!(
                                self.client_saved_state.channels[i].state,
                                vmbus_client::saved_state::ChannelState::Opened
                            )
                        }),
                })
                .collect(),
        }
    }

    /// Produces a current client saved state from the legacy saved state.
    pub fn client_saved_state(&self) -> vmbus_client::SavedState {
        self.client_saved_state.clone()
    }
}

#[cfg(test)]
mod tests {
    use guid::Guid;
    use mesh::payload::Protobuf;
    use test_with_tracing::test;
    use vmbus_client::saved_state::ChannelState;
    use vmbus_client::saved_state::ClientState;
    use vmbus_client::saved_state::Offer;

    // Consumer-side wire views avoid inspecting the relay's private fields.
    #[derive(Clone, Debug, PartialEq, Eq, Protobuf)]
    struct RelayWire {
        #[mesh(1)]
        interrupt_relay: bool,
        #[mesh(5)]
        channels: Vec<ChannelWire>,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Protobuf)]
    struct ChannelWire {
        #[mesh(1)]
        id: u32,
        #[mesh(2)]
        event_flag: Option<u16>,
        #[mesh(3)]
        intercepted: bool,
        #[mesh(4)]
        payload: Vec<u8>,
        #[mesh(5)]
        open: bool,
    }

    fn client_channel(id: u32, state: ChannelState) -> vmbus_client::saved_state::Channel {
        vmbus_client::saved_state::Channel {
            id,
            state,
            offer: Offer {
                interface_id: Guid::ZERO,
                instance_id: Guid::ZERO,
                flags: 0,
                mmio_megabytes: 0,
                user_defined: [0; 120],
                subchannel_index: 0,
                mmio_megabytes_optional: 0,
                channel_id: id,
                monitor_id: 0,
                monitor_allocated: 0,
                is_dedicated: 0,
                connection_id: id + 100,
            },
        }
    }

    // Test: Convert servicing state with unsorted client offers and a revoked
    //       relay channel through the public legacy compatibility APIs.
    // Expected: Open state follows matching channel IDs, not vector positions;
    //       missing/offered channels stay closed, and metadata survives.
    #[test]
    fn legacy_conversion_matches_open_channels_by_offer_id() {
        let wire = RelayWire {
            interrupt_relay: true,
            channels: vec![
                ChannelWire {
                    id: 40,
                    event_flag: Some(0),
                    intercepted: false,
                    payload: Vec::new(),
                    open: false,
                },
                ChannelWire {
                    id: 30,
                    event_flag: Some(9),
                    intercepted: false,
                    payload: Vec::new(),
                    open: true,
                },
                ChannelWire {
                    id: 10,
                    event_flag: None,
                    intercepted: true,
                    payload: vec![0, 255, 17],
                    open: false,
                },
            ],
        };
        let relay: crate::SavedState =
            mesh_protobuf::decode(&mesh_protobuf::encode(wire.clone())).unwrap();
        let client = vmbus_client::SavedState {
            client_state: ClientState::Connected {
                version: vmbus_core::protocol::Version::Copper as u32,
                feature_flags: 0,
            },
            channels: vec![
                client_channel(40, ChannelState::Opened),
                client_channel(10, ChannelState::Offered),
                client_channel(20, ChannelState::Opened),
            ],
            gpadls: Vec::new(),
            pending_messages: vec![vmbus_client::saved_state::PendingMessage {
                data: vec![1, 2, 3],
            }],
        };
        let mut legacy: super::SavedState = mesh_protobuf::decode(&mesh_protobuf::encode(
            super::SavedState::from_relay_and_client(&relay, &client),
        ))
        .unwrap();
        assert_eq!(
            mesh_protobuf::encode(legacy.client_saved_state()),
            mesh_protobuf::encode(client)
        );
        let mut expected = wire;
        expected.channels[0].open = true;
        expected.channels[1].open = false;
        for _ in 0..2 {
            let actual: RelayWire =
                mesh_protobuf::decode(&mesh_protobuf::encode(legacy.relay_saved_state())).unwrap();
            assert_eq!(actual, expected);
        }
        assert_eq!(
            legacy.client_saved_state().pending_messages[0].data,
            [1, 2, 3]
        );
    }
}
