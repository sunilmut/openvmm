// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::filter::ClientFilterBuilder;
use crate::filter::FilterDefinition;
use test_with_tracing::test;

// Test: Route initial and hot-added offers through instance, interface, and rest filters.
// Expected: Instance matches take precedence over interface matches; remaining
//       offers go only to the catch-all consumer, preserving offer IDs.
#[async_test]
async fn filters_route_initial_and_dynamic_offers_with_instance_precedence(driver: DefaultDriver) {
    let (mut server, mut client) = test_init(&driver);
    let mut connection = server.get_channels(&mut client, 4).await;
    let interface = connection.offers[0].offer.interface_id;
    let instance = connection.offers[0].offer.instance_id;
    connection.offers[2].offer.interface_id = interface;
    let version = connection.version;
    let mut by_interface = FilterDefinition::new("interface").by_interface(interface);
    let mut by_instance = FilterDefinition::new("instance").by_instance(interface, instance);
    let mut rest = FilterDefinition::new("rest").rest();
    let mut builder = ClientFilterBuilder::new();
    builder
        .add(&mut by_interface)
        .add(&mut by_instance)
        .add(&mut rest);
    let filter = builder.build(driver, connection);
    let mut by_interface = by_interface.take();
    let mut by_instance = by_instance.take();
    let mut rest = rest.take();
    assert_eq!(by_instance.version, version);
    assert_eq!(
        by_instance
            .offers
            .iter()
            .map(|o| o.offer.channel_id.0)
            .collect::<Vec<_>>(),
        [0]
    );
    assert_eq!(
        by_interface
            .offers
            .iter()
            .map(|o| o.offer.channel_id.0)
            .collect::<Vec<_>>(),
        [2]
    );
    assert_eq!(
        rest.offers
            .iter()
            .map(|o| o.offer.channel_id.0)
            .collect::<Vec<_>>(),
        [1, 3]
    );
    for (id, iface, inst) in [
        (4, interface, instance),
        (5, interface, Guid::new_random()),
        (6, Guid::new_random(), Guid::new_random()),
    ] {
        server.send(in_msg(
            MessageType::OFFER_CHANNEL,
            protocol::OfferChannel {
                channel_id: ChannelId(id),
                interface_id: iface,
                instance_id: inst,
                ..FromZeros::new_zeroed()
            },
        ));
    }
    assert_eq!(
        by_instance
            .offer_recv
            .next()
            .await
            .unwrap()
            .offer
            .channel_id
            .0,
        4
    );
    assert_eq!(
        by_interface
            .offer_recv
            .next()
            .await
            .unwrap()
            .offer
            .channel_id
            .0,
        5
    );
    assert_eq!(rest.offer_recv.next().await.unwrap().offer.channel_id.0, 6);
    filter.shutdown().await;
    assert!(by_instance.offer_recv.next().await.is_none());
    assert!(by_interface.offer_recv.next().await.is_none());
    assert!(rest.offer_recv.next().await.is_none());
}

// Test: Register overlapping interface filters without a catch-all.
// Expected: The first matching consumer receives offers; unmatched initial and
//       dynamic offers are rejected rather than leaking to either consumer.
#[async_test]
async fn filters_choose_first_match_and_reject_unmatched_offers(driver: DefaultDriver) {
    let (mut server, mut client) = test_init(&driver);
    let connection = server.get_channels(&mut client, 2).await;
    let interface = connection.offers[0].offer.interface_id;
    let mut first = FilterDefinition::new("first").by_interface(interface);
    let mut second = FilterDefinition::new("second").by_interface(interface);
    let mut builder = ClientFilterBuilder::new();
    builder.add(&mut first).add(&mut second);
    let filter = builder.build(driver, connection);
    let mut first = first.take();
    let mut second = second.take();
    assert_eq!(first.offers.len(), 1);
    assert_eq!(first.offers[0].offer.channel_id.0, 0);
    assert!(second.offers.is_empty());
    for (id, interface_id) in [(2, Guid::new_random()), (3, interface)] {
        server.send(in_msg(
            MessageType::OFFER_CHANNEL,
            protocol::OfferChannel {
                channel_id: ChannelId(id),
                interface_id,
                instance_id: Guid::new_random(),
                ..FromZeros::new_zeroed()
            },
        ));
    }
    assert_eq!(first.offer_recv.next().await.unwrap().offer.channel_id.0, 3);
    filter.shutdown().await;
    assert!(first.offer_recv.next().await.is_none());
    assert!(second.offer_recv.next().await.is_none());
}
