// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use test_with_tracing::test;

// Test: Format on attachment with explicit/default geometry, fully inferred geometry, and an explicit length overriding lower-layer length.
// Expected: Sector size follows lower metadata or defaults to 512, explicit length wins, logical read-only policy is retained, and geometry/data persist after reopening.
#[async_test]
async fn format_on_attach_infers_and_overrides_geometry_with_persistent_metadata() {
    let dir = tempfile::tempdir().unwrap();
    for (index, lower, len, read_only, expected_size, expected_count) in [
        (0, None, Some(4096), false, 512, 8),
        (1, Some(metadata()), None, true, 512, 8),
        (
            2,
            Some({
                let mut meta = metadata();
                meta.sector_size = 4096;
                meta
            }),
            Some(8192),
            false,
            4096,
            2,
        ),
    ] {
        let path = dir.path().join(format!("format-{index}.dbhd"));
        let layer = FormatOnAttachSqliteDiskLayer::new(
            path.clone(),
            false,
            IncompleteFormatParams {
                logically_read_only: read_only,
                len,
            },
        )
        .attach(lower)
        .await
        .unwrap();
        assert_eq!(layer.sector_size(), expected_size);
        assert_eq!(layer.sector_count(), expected_count);
        assert_eq!(layer.is_logically_read_only(), read_only);
        drop(layer);
        let reopened = SqliteDiskLayer::new(&path, true, None).unwrap();
        assert_eq!(reopened.sector_size(), expected_size);
        assert_eq!(reopened.sector_count(), expected_count);
        assert_eq!(reopened.is_logically_read_only(), read_only);
    }
    let error = FormatOnAttachSqliteDiskLayer::new(
        dir.path().join("missing.dbhd"),
        false,
        IncompleteFormatParams {
            logically_read_only: false,
            len: None,
        },
    )
    .attach(None)
    .await
    .err()
    .unwrap();
    assert_eq!(
        error.to_string(),
        "no base layer to infer sector_count from"
    );
    assert!(!dir.path().join("missing.dbhd").exists());
    let error = SqliteDiskLayer::new(
        &dir.path().join("bad-length.dbhd"),
        false,
        Some(FormatParams {
            logically_read_only: false,
            len: 513,
            sector_size: 512,
        }),
    )
    .err()
    .unwrap();
    assert_eq!(
        error.to_string(),
        "failed to format: len=513 must be multiple of sector_size=512"
    );
}
