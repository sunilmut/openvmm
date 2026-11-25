// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use futures::FutureExt;
use get_resources::ged::SaveRestoreError;
use get_resources::ged::Vtl0StartError;
use test_with_tracing::test;

// Test: Save Underhill with each servicing-flag combination and a supplied image file.
// Expected: The worker receives that image before GET sees the unchanged flags.
#[test]
fn save_stages_image_before_requesting_guest_state() {
    for (nvme_keepalive, mana_keepalive) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let (vm_send, mut vm_recv) = mesh::channel();
        let (ged_send, mut ged_recv) = mesh::channel();
        let image = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(image.path(), b"new IGVM image").unwrap();
        let flags = GuestServicingFlags {
            nvme_keepalive,
            mana_keepalive,
        };
        let mut save = std::pin::pin!(save_underhill(
            &vm_send,
            &ged_send,
            flags,
            std::fs::File::open(image.path()).unwrap()
        ));

        assert!(save.as_mut().now_or_never().is_none());
        assert!(matches!(
            ged_recv.try_recv(),
            Err(mesh::TryRecvError::Empty)
        ));
        let VmRpc::StartReloadIgvm(rpc) = vm_recv.try_recv().unwrap() else {
            panic!("expected image staging");
        };
        rpc.handle_sync(|mut file| {
            use std::io::Read;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"new IGVM image");
            Ok(())
        });
        assert!(save.as_mut().now_or_never().is_none());
        let GuestEmulationRequest::SaveGuestVtl2State(rpc) = ged_recv.try_recv().unwrap() else {
            panic!("expected guest save request");
        };
        rpc.handle_sync(|flags| {
            assert_eq!(
                (flags.nvme_keepalive, flags.mana_keepalive),
                (nvme_keepalive, mana_keepalive)
            );
            Ok(())
        });
        save.as_mut().now_or_never().unwrap().unwrap();
        assert!(matches!(vm_recv.try_recv(), Err(mesh::TryRecvError::Empty)));
    }
}

// Test: Reject the image while staging a new Underhill version.
// Expected: The staging error reaches the caller, with no guest-save or reload request.
#[test]
fn staging_failure_does_not_save_or_reload() {
    let (vm_send, mut vm_recv) = mesh::channel();
    let (ged_send, mut ged_recv) = mesh::channel();
    let mut save = std::pin::pin!(save_underhill(
        &vm_send,
        &ged_send,
        GuestServicingFlags {
            nvme_keepalive: false,
            mana_keepalive: false
        },
        tempfile::tempfile().unwrap()
    ));
    assert!(save.as_mut().now_or_never().is_none());
    let VmRpc::StartReloadIgvm(rpc) = vm_recv.try_recv().unwrap() else {
        panic!("expected image staging");
    };
    rpc.fail(std::io::Error::other("staging rejected"));
    let error = save.as_mut().now_or_never().unwrap().unwrap_err();
    assert_eq!(error.to_string(), "failed to stage new IGVM file");
    assert!(format!("{error:#}").contains("staging rejected"));
    assert!(matches!(
        ged_recv.try_recv(),
        Err(mesh::TryRecvError::Empty)
    ));
    assert!(matches!(vm_recv.try_recv(), Err(mesh::TryRecvError::Empty)));
}

// Test: Fail guest-state saving and then accept or reject staged-image cleanup.
// Expected: Cleanup requests cancellation, and its result never replaces the save error.
#[test]
fn save_failure_cancels_staged_image_and_preserves_guest_error() {
    for cleanup_succeeds in [false, true] {
        let (vm_send, mut vm_recv) = mesh::channel();
        let (ged_send, mut ged_recv) = mesh::channel();
        let mut save = std::pin::pin!(save_underhill(
            &vm_send,
            &ged_send,
            GuestServicingFlags {
                nvme_keepalive: true,
                mana_keepalive: true
            },
            tempfile::tempfile().unwrap()
        ));
        assert!(save.as_mut().now_or_never().is_none());
        let VmRpc::StartReloadIgvm(rpc) = vm_recv.try_recv().unwrap() else {
            panic!("expected image staging");
        };
        rpc.complete(Ok(()));
        assert!(save.as_mut().now_or_never().is_none());
        let GuestEmulationRequest::SaveGuestVtl2State(rpc) = ged_recv.try_recv().unwrap() else {
            panic!("expected guest save request");
        };
        rpc.complete(Err(SaveRestoreError::GuestError));
        assert!(save.as_mut().now_or_never().is_none());
        let VmRpc::CompleteReloadIgvm(rpc) = vm_recv.try_recv().unwrap() else {
            panic!("expected staged-image cancellation");
        };
        assert!(!rpc.input());
        if cleanup_succeeds {
            rpc.complete(Ok(()));
        } else {
            rpc.fail(std::io::Error::other("cleanup rejected"));
        }
        let error = save.as_mut().now_or_never().unwrap().unwrap_err();
        assert_eq!(error.to_string(), "failed to save VTL2 state");
        assert!(format!("{error:#}").contains("guest error"));
        assert!(!format!("{error:#}").contains("cleanup rejected"));
        assert!(matches!(
            ged_recv.try_recv(),
            Err(mesh::TryRecvError::Empty)
        ));
        assert!(matches!(vm_recv.try_recv(), Err(mesh::TryRecvError::Empty)));
    }
}

// Test: Restore Underhill and delay each worker/guest acknowledgement.
// Expected: Reload commits before GET is asked to wait, and success waits for VTL0 start.
#[test]
fn restore_commits_reload_before_waiting_for_vtl0() {
    let (vm_send, mut vm_recv) = mesh::channel();
    let (ged_send, mut ged_recv) = mesh::channel();
    let mut restore = std::pin::pin!(restore_underhill(&vm_send, &ged_send));
    assert!(restore.as_mut().now_or_never().is_none());
    assert!(matches!(
        ged_recv.try_recv(),
        Err(mesh::TryRecvError::Empty)
    ));
    let VmRpc::CompleteReloadIgvm(rpc) = vm_recv.try_recv().unwrap() else {
        panic!("expected reload commit");
    };
    assert!(*rpc.input());
    rpc.complete(Ok(()));
    assert!(restore.as_mut().now_or_never().is_none());
    let GuestEmulationRequest::WaitForVtl0Start(rpc) = ged_recv.try_recv().unwrap() else {
        panic!("expected VTL0 start wait");
    };
    rpc.complete(Ok(()));
    restore.as_mut().now_or_never().unwrap().unwrap();
    assert!(matches!(vm_recv.try_recv(), Err(mesh::TryRecvError::Empty)));
    assert!(matches!(
        ged_recv.try_recv(),
        Err(mesh::TryRecvError::Empty)
    ));
}

// Test: Reject a reload commit during Underhill restore.
// Expected: The contextual worker error is returned without waiting for VTL0.
#[test]
fn reload_failure_does_not_wait_for_vtl0() {
    let (vm_send, mut vm_recv) = mesh::channel();
    let (ged_send, mut ged_recv) = mesh::channel();
    let mut restore = std::pin::pin!(restore_underhill(&vm_send, &ged_send));
    assert!(restore.as_mut().now_or_never().is_none());
    let VmRpc::CompleteReloadIgvm(rpc) = vm_recv.try_recv().unwrap() else {
        panic!("expected reload commit");
    };
    rpc.fail(std::io::Error::other("reload rejected"));
    let error = restore.as_mut().now_or_never().unwrap().unwrap_err();
    assert_eq!(error.to_string(), "failed to reload VTL2 firmware");
    assert!(format!("{error:#}").contains("reload rejected"));
    assert!(matches!(
        ged_recv.try_recv(),
        Err(mesh::TryRecvError::Empty)
    ));
}

// Test: Reload successfully but fail while the guest starts VTL0.
// Expected: The start failure and its guest-provided reason reach the caller.
#[test]
fn vtl0_start_failure_retains_guest_reason() {
    let (vm_send, mut vm_recv) = mesh::channel();
    let (ged_send, mut ged_recv) = mesh::channel();
    let mut restore = std::pin::pin!(restore_underhill(&vm_send, &ged_send));
    assert!(restore.as_mut().now_or_never().is_none());
    let VmRpc::CompleteReloadIgvm(rpc) = vm_recv.try_recv().unwrap() else {
        panic!("expected reload commit");
    };
    rpc.complete(Ok(()));
    assert!(restore.as_mut().now_or_never().is_none());
    let GuestEmulationRequest::WaitForVtl0Start(rpc) = ged_recv.try_recv().unwrap() else {
        panic!("expected VTL0 start wait");
    };
    rpc.complete(Err(Vtl0StartError("guest startup rejected".into())));
    let error = restore.as_mut().now_or_never().unwrap().unwrap_err();
    assert_eq!(error.to_string(), "vtl0 start failed");
    assert!(format!("{error:#}").contains("guest startup rejected"));
    assert!(matches!(vm_recv.try_recv(), Err(mesh::TryRecvError::Empty)));
}
