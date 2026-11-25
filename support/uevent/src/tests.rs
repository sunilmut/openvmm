// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use pal_async::DefaultDriver;
use pal_async::task::Spawn;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn fixture(driver: &DefaultDriver) -> (UeventListener, UnixDatagram) {
    let (receive, peer) = UnixDatagram::pair().unwrap();
    let socket = PolledSocket::new(driver, Socket::from(receive)).unwrap();
    let (send, recv) = mesh::mpsc_channel();
    let task = ListenerTask {
        socket,
        callbacks: Vec::new(),
        recv,
        next_id: 0,
    };
    let task = driver.spawn("uevent-test", task.run());
    (UeventListener { _task: task, send }, peer)
}

async fn barrier(listener: &UeventListener) {
    drop(listener.add_custom_callback(|_| {}).await);
}

fn emit(peer: &UnixDatagram, bytes: &[u8]) {
    assert_eq!(peer.send(bytes).unwrap(), bytes.len());
}

// Test: Decode an injected datagram and deliver it to multiple public callbacks.
// Expected: Header and properties survive unsorted input, malformed fields are
//       ignored, embedded equals signs survive, and dropping a handle unregisters it.
#[pal_async::async_test]
async fn callbacks_decode_properties_and_unregister(driver: DefaultDriver) {
    let (listener, peer) = fixture(&driver);
    let count = Arc::new(AtomicUsize::new(0));
    let handle = listener
        .add_custom_callback({
            let count = count.clone();
            move |_| {
                count.fetch_add(1, Ordering::SeqCst);
            }
        })
        .await;
    let (send, mut receive) = mesh::channel();
    let _observer = listener
        .add_custom_callback(move |Notification::Event(event)| {
            send.send((
                event.header().to_owned(),
                ["A", "B", "VAL", "MISSING"].map(|key| event.get(key).map(str::to_owned)),
            ));
        })
        .await;
    emit(
        &peer,
        b"change@/devices/example\0B=second\0ignored\0VAL=left=right\0A=first\0",
    );
    let (header, properties) = receive.next().await.unwrap();
    assert_eq!(header, "change@/devices/example");
    assert_eq!(
        properties,
        [
            Some("first".into()),
            Some("second".into()),
            Some("left=right".into()),
            None
        ]
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    drop(handle);
    barrier(&listener).await;
    emit(&peer, b"another\0");
    assert_eq!(receive.next().await.unwrap().0, "another");
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

// Test: Inject block-resize events with matching, absent and malformed filters.
// Expected: Only the exact block/change/major/minor/resize tuple or a rescan
//       notification invokes the resize callback.
#[pal_async::async_test]
async fn resize_callbacks_require_matching_fields_or_rescan(driver: DefaultDriver) {
    let (listener, peer) = fixture(&driver);
    let count = Arc::new(AtomicUsize::new(0));
    let _resize = listener
        .add_block_resize_callback(8, 1, {
            let count = count.clone();
            move || {
                count.fetch_add(1, Ordering::SeqCst);
            }
        })
        .await;
    let (send, mut receive) = mesh::channel();
    let _observer = listener.add_custom_callback(move |_| send.send(())).await;
    for (fields, expected) in [
        (
            "RESIZE=1\0SUBSYSTEM=block\0ACTION=change\0MAJOR=8\0MINOR=1",
            1,
        ),
        ("RESIZE=1\0SUBSYSTEM=block\0ACTION=add\0MAJOR=8\0MINOR=1", 1),
        (
            "RESIZE=1\0SUBSYSTEM=other\0ACTION=change\0MAJOR=8\0MINOR=1",
            1,
        ),
        (
            "RESIZE=1\0SUBSYSTEM=block\0ACTION=change\0MAJOR=bad\0MINOR=1",
            1,
        ),
        (
            "RESIZE=1\0SUBSYSTEM=block\0ACTION=change\0MAJOR=9\0MINOR=1",
            1,
        ),
        (
            "RESIZE=1\0SUBSYSTEM=block\0ACTION=change\0MAJOR=8\0MINOR=bad",
            1,
        ),
        (
            "RESIZE=1\0SUBSYSTEM=block\0ACTION=change\0MAJOR=8\0MINOR=2",
            1,
        ),
        ("RESIZE=1\0SUBSYSTEM=block\0ACTION=change\0MAJOR=8", 1),
        (
            "RESIZE=0\0SUBSYSTEM=block\0ACTION=change\0MAJOR=8\0MINOR=1",
            1,
        ),
        ("RESCAN=true", 2),
        ("RESCAN=false", 2),
    ] {
        emit(&peer, format!("event\0{fields}\0").as_bytes());
        receive.next().await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), expected, "{fields:?}");
    }
}

// Test: Wait for a nonexistent path, ignore irrelevant events, then create it.
// Expected: The waiter stays pending until an add event observes the new path.
#[pal_async::async_test]
async fn devpath_waiter_observes_creation_after_registration(driver: DefaultDriver) {
    let (listener, peer) = fixture(&driver);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("device");
    let wait = listener.wait_for_devpath(&path);
    let mut wait = std::pin::pin!(wait);
    assert!(futures::poll!(wait.as_mut()).is_pending());
    barrier(&listener).await;
    assert!(futures::poll!(wait.as_mut()).is_pending());
    let (send, mut receive) = mesh::channel();
    let _observer = listener.add_custom_callback(move |_| send.send(())).await;
    for bytes in [&b"event\0ACTION=change\0"[..], &b"event\0ACTION=add\0"[..]] {
        emit(&peer, bytes);
        receive.next().await.unwrap();
        assert!(futures::poll!(wait.as_mut()).is_pending());
    }
    std::fs::write(&path, []).unwrap();
    emit(&peer, b"event\0ACTION=add\0");
    wait.await.unwrap();
}

// Test: Check existing paths, dangling symlinks and an invalid path through a file.
// Expected: Existing paths and symlink metadata complete successfully, while
//       NotADirectory is returned rather than waiting forever.
#[pal_async::async_test]
async fn devpath_fast_paths_and_metadata_errors(driver: DefaultDriver) {
    let (listener, _) = fixture(&driver);
    let directory = tempfile::tempdir().unwrap();
    listener.wait_for_devpath(directory.path()).await.unwrap();
    let link = directory.path().join("dangling");
    std::os::unix::fs::symlink(directory.path().join("absent"), &link).unwrap();
    listener.wait_for_devpath(&link).await.unwrap();
    let file = directory.path().join("file");
    std::fs::write(&file, []).unwrap();
    assert_eq!(
        listener
            .wait_for_devpath(&file.join("child"))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotADirectory
    );
}

// Test: Look for an existing child, reject a non-directory, and request a slow
//       scan outside sysfs when no child matches.
// Expected: Matching children are returned with the filesystem flag, and invalid
//       parent paths return their explicit filesystem or devpath errors.
#[pal_async::async_test]
async fn child_scan_returns_matches_and_rejects_invalid_parents(driver: DefaultDriver) {
    let (listener, _) = fixture(&driver);
    let directory = tempfile::tempdir().unwrap();
    let child = directory.path().join("child");
    std::fs::write(&child, []).unwrap();
    let found = listener
        .wait_for_matching_child(directory.path(), |path, from_event| async move {
            assert!(!from_event);
            (path.file_name().unwrap() == "child").then_some(path)
        })
        .await
        .unwrap();
    assert_eq!(found, child);
    assert_eq!(
        listener
            .wait_for_matching_child(&child, |_, _| async { None::<()> })
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotADirectory
    );
    assert_eq!(
        listener
            .wait_for_matching_child(directory.path(), |_, _| async { None::<()> })
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
}

// Test: Wait for a direct sysfs child using an isolated simulated uevent socket.
// Expected: Non-add events, missing paths and unrelated parents are ignored;
//       the matching add event supplies its child path and event-origin flag.
#[pal_async::async_test]
async fn child_waiter_filters_events_without_modifying_sysfs(driver: DefaultDriver) {
    let (listener, peer) = fixture(&driver);
    let wait = listener.wait_for_matching_child(Path::new("/sys"), |path, from_event| async move {
        from_event.then_some(path)
    });
    let mut wait = std::pin::pin!(wait);
    assert!(futures::poll!(wait.as_mut()).is_pending());
    barrier(&listener).await;
    assert!(futures::poll!(wait.as_mut()).is_pending());
    let (send, mut receive) = mesh::channel();
    let _observer = listener.add_custom_callback(move |_| send.send(())).await;
    for bytes in [
        &b"event\0ACTION=change\0DEVPATH=/unit-test-child\0"[..],
        &b"event\0ACTION=add\0"[..],
        &b"event\0ACTION=add\0DEVPATH=/unrelated/child\0"[..],
    ] {
        emit(&peer, bytes);
        receive.next().await.unwrap();
        assert!(futures::poll!(wait.as_mut()).is_pending());
    }
    emit(&peer, b"event\0ACTION=add\0DEVPATH=/unit-test-child\0");
    assert_eq!(wait.await.unwrap(), Path::new("/sys/unit-test-child"));
}

// Test: Change a child's matching condition after the waiter is registered and
//       issue a rescan notification through the simulated event socket.
// Expected: The rescan revisits existing sysfs children and reports a filesystem
//       match without requiring any host sysfs modification.
#[pal_async::async_test]
async fn rescan_rechecks_existing_children(driver: DefaultDriver) {
    let (listener, peer) = fixture(&driver);
    let ready = Arc::new(AtomicBool::new(false));
    let wait = listener.wait_for_matching_child(Path::new("/sys"), {
        let ready = ready.clone();
        move |path, from_event| {
            let ready = ready.clone();
            async move {
                assert!(!from_event);
                ready.load(Ordering::SeqCst).then_some(path)
            }
        }
    });
    let mut wait = std::pin::pin!(wait);
    assert!(futures::poll!(wait.as_mut()).is_pending());
    barrier(&listener).await;
    assert!(futures::poll!(wait.as_mut()).is_pending());
    ready.store(true, Ordering::SeqCst);
    emit(&peer, b"rescan\0RESCAN=true\0");
    let found = wait.await.unwrap();
    assert_eq!(found.parent(), Some(Path::new("/sys")));
    assert!(found.exists());
}

// Test: Create a devpath while callback registration is being acknowledged.
// Expected: The registration-race recheck finds it without needing an event.
#[pal_async::async_test]
async fn devpath_registration_race_does_not_lose_creation(driver: DefaultDriver) {
    let (listener, _) = fixture(&driver);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("device");
    let wait = listener.wait_for_devpath(&path);
    let mut wait = std::pin::pin!(wait);
    assert!(futures::poll!(wait.as_mut()).is_pending());
    barrier(&listener).await;
    std::fs::write(&path, []).unwrap();
    wait.await.unwrap();
}

// Test: Inject invalid UTF-8 while a callback is registered.
// Expected: The listener closes the callback stream instead of delivering a
//       partially decoded event, and its worker terminates cleanly.
#[pal_async::async_test]
async fn invalid_utf8_terminates_delivery_without_partial_notification(driver: DefaultDriver) {
    let (listener, peer) = fixture(&driver);
    let (send, mut receive) = mesh::channel();
    let handle = listener.add_custom_callback(move |_| send.send(())).await;
    emit(&peer, &[0xff]);
    assert!(receive.next().await.is_none());
    drop(handle);
    listener._task.await;
}

// Test: Drop all listener request senders without sending a device event.
// Expected: The worker stops when its request channel closes.
#[pal_async::async_test]
async fn listener_worker_stops_when_its_owner_is_dropped(driver: DefaultDriver) {
    let (listener, _peer) = fixture(&driver);
    let UeventListener { _task, send } = listener;
    drop(send);
    _task.await;
}

// Test: Construct the public listener on its real read-only netlink source.
// Expected: Callback registration and removal succeed without injecting kernel
//       events or changing any host device.
#[pal_async::async_test]
async fn real_listener_registers_and_removes_callbacks(driver: DefaultDriver) {
    let listener = UeventListener::new(&driver).unwrap();
    drop(listener.add_custom_callback(|_| {}).await);
    barrier(&listener).await;
}

// Test: Lose the listener to an invalid datagram while waiting for a sysfs child.
// Expected: The pending child search returns an explicit error instead of
//       hanging after its event source has terminated.
#[pal_async::async_test]
async fn child_waiter_reports_a_failed_event_source(driver: DefaultDriver) {
    let (listener, peer) = fixture(&driver);
    let wait = listener.wait_for_matching_child(Path::new("/sys"), |_, _| async { None::<()> });
    let mut wait = std::pin::pin!(wait);
    assert!(futures::poll!(wait.as_mut()).is_pending());
    barrier(&listener).await;
    assert!(futures::poll!(wait.as_mut()).is_pending());
    emit(&peer, &[0xff]);
    let error = wait.await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("Did not find a matching path"));
}

// Test: A child's matching condition changes while registration is acknowledged.
// Expected: The post-registration scan returns the filesystem match without
//       requiring a device event.
#[pal_async::async_test]
async fn child_registration_race_rechecks_the_matching_condition(driver: DefaultDriver) {
    let (listener, _peer) = fixture(&driver);
    let ready = AtomicBool::new(false);
    let wait = listener.wait_for_matching_child(Path::new("/sys"), |path, from_event| {
        let matches = ready.load(Ordering::SeqCst);
        async move {
            assert!(!from_event);
            matches.then_some(path)
        }
    });
    let mut wait = std::pin::pin!(wait);
    assert!(futures::poll!(wait.as_mut()).is_pending());
    barrier(&listener).await;
    ready.store(true, Ordering::SeqCst);
    let found = wait.await.unwrap();
    assert_eq!(found.parent(), Some(Path::new("/sys")));
    assert!(found.exists());
}

// Test: Interleave resize events for two devices and remove their callbacks.
// Expected: Each resize reaches only its device, rescan reaches both, and
//       removing one callback leaves the other's delivery and removal intact.
#[pal_async::async_test]
async fn resize_subscriptions_stay_independent_during_removal(driver: DefaultDriver) {
    let (listener, peer) = fixture(&driver);
    let counts = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    let mut handles = Vec::new();
    for index in 0..2 {
        let counts = counts.clone();
        handles.push(
            listener
                .add_block_resize_callback(8, index as u32 + 1, move || {
                    counts[index].fetch_add(1, Ordering::SeqCst);
                })
                .await,
        );
    }
    let (send, mut receive) = mesh::channel();
    let _observer = listener.add_custom_callback(move |_| send.send(())).await;
    for (minor, expected) in [(2, [0, 1]), (1, [1, 1]), (2, [1, 2])] {
        emit(
            &peer,
            format!("change@/devices/disk{minor}\0ACTION=change\0SUBSYSTEM=block\0MAJOR=8\0MINOR={minor}\0RESIZE=1\0").as_bytes(),
        );
        receive.next().await.unwrap();
        barrier(&listener).await;
        assert_eq!(
            counts.each_ref().map(|count| count.load(Ordering::SeqCst)),
            expected
        );
    }
    for (remove_first, expected) in [(false, [2, 3]), (true, [2, 4])] {
        if remove_first {
            drop(handles.remove(0));
            barrier(&listener).await;
        }
        emit(&peer, b"rescan\0RESCAN=true\0");
        receive.next().await.unwrap();
        barrier(&listener).await;
        assert_eq!(
            counts.each_ref().map(|count| count.load(Ordering::SeqCst)),
            expected
        );
    }
    drop(handles);
    barrier(&listener).await;
    emit(&peer, b"rescan\0RESCAN=true\0");
    receive.next().await.unwrap();
    barrier(&listener).await;
    assert_eq!(
        counts.each_ref().map(|count| count.load(Ordering::SeqCst)),
        [2, 4]
    );
}
