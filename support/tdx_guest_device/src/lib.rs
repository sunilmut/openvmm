// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The crate includes the abstraction layer of Linux TDX Guest APIs.
#![cfg(target_os = "linux")]
// UNSAFETY: unsafe needed to make ioctl calls.
#![expect(unsafe_code)]

use std::fs::File;
use std::os::fd::AsRawFd;
use thiserror::Error;
use x86defs::tdx::TDX_DERIVED_KEY_SIZE;
use x86defs::tdx::TDX_REPORT_DATA_SIZE;
use x86defs::tdx::TdKeyRequest;
use x86defs::tdx::TdReport;
use zerocopy::FromZeros;

/// Ioctl type defined by Linux.
pub const TDX_CMD_GET_REPORT0_IOC_TYPE: u8 = b'T';

#[expect(missing_docs)] // self-explanatory fields
#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to open /dev/tdx_guest")]
    OpenDevTdxGuest(#[source] std::io::Error),
    #[error("TDX_CMD_GET_REPORT0 ioctl failed")]
    TdxGetReportIoctl(#[source] nix::Error),
    #[error("TDX_CMD_KEY_GET ioctl failed with TDCALL error code {1:#x}")]
    TdxGetDerivedKeyIoctl(#[source] nix::Error, u64),
}

/// Ioctl struct defined by Linux.
#[repr(C)]
struct TdxReportReq {
    /// Report data to be included in the report.
    report_data: [u8; TDX_REPORT_DATA_SIZE],
    /// The output report.
    td_report: TdReport,
}

/// Ioctl struct defined by Linux for `TDX_CMD_KEY_GET` (`struct tdx_key_get_req`).
#[repr(C)]
struct TdxKeyGetReq {
    /// `TDKEYREQUEST` input passed to the `TDG.MR.KEY.GET` TDCALL.
    key_request: TdKeyRequest,
    /// The derived key output.
    derived_key: [u8; TDX_DERIVED_KEY_SIZE],
    /// `TDG.MR.KEY.GET` TDCALL return error code.
    err_code: u64,
}

nix::ioctl_readwrite!(
    /// `TDX_CMD_GET_REPORT0` ioctl defined by Linux.
    tdx_get_report0,
    TDX_CMD_GET_REPORT0_IOC_TYPE,
    0x1,
    TdxReportReq
);

nix::ioctl_readwrite!(
    /// `TDX_CMD_KEY_GET` ioctl defined by Linux.
    tdx_key_get,
    TDX_CMD_GET_REPORT0_IOC_TYPE,
    0x5,
    TdxKeyGetReq
);

/// Abstraction of the /dev/tdx_guest device.
pub struct TdxGuestDevice {
    file: File,
}

impl TdxGuestDevice {
    /// Open an /dev/tdx_guest device
    pub fn open() -> Result<Self, Error> {
        let tdx_guest = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tdx_guest")
            .map_err(Error::OpenDevTdxGuest)?;

        Ok(Self { file: tdx_guest })
    }

    /// Invoke the `TDX_CMD_GET_REPORT0` ioctl via the device.
    pub fn get_report(&self, report_data: [u8; 64], _vmpl: u32) -> Result<TdReport, Error> {
        let mut tdx_report_request = TdxReportReq {
            report_data,
            td_report: TdReport::new_zeroed(),
        };

        // SAFETY: Make TDX_CMD_GET_REPORT0 ioctl call to the device with correct types.
        unsafe {
            tdx_get_report0(self.file.as_raw_fd(), &mut tdx_report_request)
                .map_err(Error::TdxGetReportIoctl)?;
        }

        Ok(tdx_report_request.td_report)
    }

    /// Invoke the `TDX_CMD_KEY_GET` ioctl via the device to derive a persistent
    /// key bound to the TD's measurements and policy using the `TDG.MR.KEY.GET`
    /// TDCALL.
    pub fn get_derived_key(
        &self,
        key_request: &TdKeyRequest,
    ) -> Result<[u8; TDX_DERIVED_KEY_SIZE], Error> {
        let mut tdx_key_get_request = TdxKeyGetReq {
            key_request: *key_request,
            derived_key: [0u8; TDX_DERIVED_KEY_SIZE],
            err_code: 0,
        };

        // SAFETY: Make TDX_CMD_KEY_GET ioctl call to the device with correct types.
        // The ioctl is encoded as read-write (`_IOWR`): the kernel reads the
        // `TDKEYREQUEST` input and writes the derived key and error code back
        // through the same structure.
        unsafe {
            tdx_key_get(self.file.as_raw_fd(), &mut tdx_key_get_request)
                .map_err(|e| Error::TdxGetDerivedKeyIoctl(e, tdx_key_get_request.err_code))?;
        }

        Ok(tdx_key_get_request.derived_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    fn unsupported_device() -> TdxGuestDevice {
        // Real ioctl dispatch without a TDX driver or TDCALL.
        TdxGuestDevice {
            file: File::open("/dev/null").expect("open inert ioctl target"),
        }
    }

    // Test: Request a report through a descriptor that cannot serve TDX ioctls.
    // Expected: The report-specific error retains ENOTTY rather than reporting
    //       success or substituting a different operation's error.
    #[test]
    fn report_transport_failure_preserves_operation_and_errno() {
        let device = unsupported_device();
        match device.get_report([0x5a; TDX_REPORT_DATA_SIZE], 0) {
            Err(Error::TdxGetReportIoctl(errno)) => {
                assert_eq!(errno, nix::errno::Errno::ENOTTY);
            }
            Err(_) => panic!("report failure changed operation classification"),
            Ok(_) => panic!("non-TDX descriptor unexpectedly returned a report"),
        }
    }

    // Test: Request a derived key through a descriptor without the TDX driver.
    // Expected: The key-specific error retains ENOTTY and a zero TDCALL code,
    //       since no firmware response occurred; no key value is exposed.
    #[test]
    fn key_transport_failure_preserves_operation_errno_and_firmware_context() {
        let device = unsupported_device();
        let request = TdKeyRequest::new_zeroed();
        match device.get_derived_key(&request) {
            Err(Error::TdxGetDerivedKeyIoctl(errno, code)) => {
                assert_eq!(errno, nix::errno::Errno::ENOTTY);
                assert_eq!(code, 0, "transport failure fabricated a TDCALL result");
            }
            Err(_) => panic!("key failure changed operation classification"),
            Ok(_) => panic!("non-TDX descriptor unexpectedly returned a key"),
        }
    }

    // IGNORED: Requires an isolated TDX guest with a compatible /dev/tdx_guest
    //       driver. Never probe the shared host for firmware or key operations.
    //
    // Test: Request a real TDX report with nonzero caller-supplied report data.
    // Expected: The returned report echoes all64 bytes and identifies a TDX
    //       report, without logging report identity fields or deriving a key.
    #[test]
    #[ignore = "requires an isolated TDX guest and compatible guest driver"]
    fn hardware_report_echoes_caller_data() {
        let device = TdxGuestDevice::open().unwrap();
        let data = std::array::from_fn(|i| i as u8 ^ 0x5a);
        let report = device.get_report(data, 0).unwrap();
        assert!(report.report_mac_struct.report_data == data);
        assert_eq!(report.report_mac_struct.report_type.tee_type, 0x81);
    }
}
