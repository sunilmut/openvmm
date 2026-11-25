// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

fn report(claims: &[u8], change: impl FnOnce(&mut IgvmAttestRequestBase)) -> Vec<u8> {
    let mut request = IgvmAttestRequestBase::default();
    request.header.signature = IGVM_ATTESTATION_SIGNATURE;
    request.header.version = IGVM_ATTESTATION_VERSION;
    request.header.report_size = (IGVM_REQUEST_BASE_SIZE + claims.len()) as u32;
    request.header.request_type = IGVM_REQUEST_TYPE_AK_CERT;
    request.request_data.data_size = (IGVM_REQUEST_DATA_SIZE + claims.len()) as u32;
    request.request_data.version = IGVM_ATTEST_REQUEST_VERSION_1;
    request.request_data.variable_data_size = claims.len() as u32;
    change(&mut request);
    [request.as_bytes(), claims].concat()
}

// Test: Decode exact runtime JSON and empty claims, then independently corrupt every externally controlled report version/signature/type/size boundary.
// Expected: Valid nested/binary-looking values survive decoding, empty claims return None, and each malformed report returns InvalidData with the specific violated contract rather than exposing bytes outside the declared report.
#[test]
fn runtime_report_validation_distinguishes_each_wire_contract() {
    let expected = json!({"nested": {"enabled": true}, "data": [0, 145, 255], "text": "guest"});
    let claims = serde_json::to_vec(&expected).unwrap();
    assert_eq!(
        runtime_claims_json(&report(&claims, |_| {})).unwrap(),
        Some(expected)
    );
    assert_eq!(runtime_claims_json(&report(&[], |_| {})).unwrap(), None);
    type Change = fn(&mut IgvmAttestRequestBase);
    let cases: [(Change, &str); 8] = [
        (
            |request| request.header.version += 1,
            "unexpected header version",
        ),
        (
            |request| request.header.signature ^= 1,
            "unexpected attestation signature",
        ),
        (
            |request| request.header.request_type += 1,
            "unexpected attestation request type",
        ),
        (
            |request| request.header.report_size = IGVM_REQUEST_BASE_SIZE as u32 - 1,
            "smaller than base request",
        ),
        (
            |request| request.header.report_size = IGVM_REQUEST_BASE_SIZE as u32 + 3,
            "bytes but only",
        ),
        (
            |request| request.request_data.version += 1,
            "unexpected attestation request version",
        ),
        (
            |request| request.request_data.data_size += 1,
            "attestation request data size mismatch",
        ),
        (
            |request| {
                request.request_data.variable_data_size = 1;
                request.request_data.data_size = IGVM_REQUEST_DATA_SIZE as u32 + 1;
            },
            "runtime claims extend beyond attestation report",
        ),
    ];
    for (change, expected) in cases {
        let error = runtime_claims_json(&report(b"{}", change)).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
    }
    for length in [0, IGVM_REQUEST_BASE_SIZE - 1] {
        let error = runtime_claims_json(&vec![0; length]).unwrap_err();
        assert!(error.to_string().contains("smaller than base request size"));
    }
    let error = runtime_claims_json(&report(b"{", |_| {})).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed to parse runtime claims JSON")
    );
}
