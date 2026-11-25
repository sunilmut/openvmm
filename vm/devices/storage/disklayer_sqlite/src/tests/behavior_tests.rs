// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::*;
use guestmem::GuestMemory;
use scsi_buffers::OwnedRequestBuffers;
use test_with_tracing::test;

mod cache_tests;
mod format_tests;
mod resolver_tests;

fn metadata() -> disk_layered::DiskLayerMetadata {
    disk_layered::DiskLayerMetadata {
        disk_id: Some([0x12; 16]),
        sector_size: 512,
        sector_count: 8,
        physical_sector_size: 512,
        unmap_behavior: UnmapBehavior::Zeroes,
        optimal_unmap_sectors: 1,
        read_only: true,
        can_read_cache: true,
        is_fua_respected: false,
    }
}

async fn cache_fill(layer: &SqliteDiskLayer, sector: u64, bytes: &[u8]) -> Result<(), DiskError> {
    let memory = GuestMemory::allocate(bytes.len());
    memory.write_at(0, bytes).unwrap();
    WriteNoOverwrite::write_no_overwrite(
        layer,
        &OwnedRequestBuffers::linear(0, bytes.len(), false).buffer(&memory),
        sector,
    )
    .await
}

fn format(path: &Path, logically_read_only: bool) -> SqliteDiskLayer {
    SqliteDiskLayer::new(
        path,
        false,
        Some(FormatParams {
            logically_read_only,
            len: 8 * 512,
            sector_size: 512,
        }),
    )
    .unwrap()
}

async fn write(layer: &SqliteDiskLayer, sector: u64, bytes: &[u8]) {
    let memory = GuestMemory::allocate(bytes.len());
    memory.write_at(0, bytes).unwrap();
    layer
        .write(
            &OwnedRequestBuffers::linear(0, bytes.len(), false).buffer(&memory),
            sector,
            false,
        )
        .await
        .unwrap();
}

async fn read_layers(paths: &[&Path], sector: u64, count: usize) -> Vec<u8> {
    let mut layers = Vec::new();
    for path in paths {
        layers.push(LayerConfiguration {
            layer: DiskLayer::new(SqliteDiskLayer::new(path, true, None).unwrap()),
            write_through: false,
            read_cache: false,
        });
    }
    let disk = Disk::new(LayeredDisk::new(true, layers).await.unwrap()).unwrap();
    let memory = GuestMemory::allocate(count * 512);
    memory.write_at(0, &vec![0xcc; count * 512]).unwrap();
    disk.read_vectored(
        &OwnedRequestBuffers::linear(0, count * 512, true).buffer(&memory),
        sector,
    )
    .await
    .unwrap();
    let mut bytes = vec![0; count * 512];
    memory.read_at(0, &mut bytes).unwrap();
    bytes
}

// Test: Stack sparse SQLite sectors over patterned lower data, then unmap one sector above nonzero lower data and another above a known-zero successor.
// Expected: Holes fall through, explicit zero sectors suppress lower data, unmap above nonzero data installs zeroes, and unmap above known-zero data removes the upper allocation without disturbing adjacent sectors.
#[async_test]
async fn sparse_reads_and_both_unmap_modes_preserve_layered_data() {
    let dir = tempfile::tempdir().unwrap();
    let lower_path = dir.path().join("lower.dbhd");
    let upper_path = dir.path().join("upper.dbhd");
    let lower = format(&lower_path, false);
    let upper = format(&upper_path, false);
    write(&lower, 0, &vec![0x44; 4 * 512]).await;
    write(&upper, 1, &vec![0xa1; 512]).await;
    write(&upper, 2, &vec![0; 512]).await;
    let mut expected = vec![0x44; 4 * 512];
    expected[512..1024].fill(0xa1);
    expected[1024..1536].fill(0);
    assert_eq!(
        read_layers(&[&upper_path, &lower_path], 0, 4).await,
        expected
    );
    upper.unmap(1, 1, false, false).await.unwrap();
    write(&lower, 2, &vec![0; 512]).await;
    upper.unmap(2, 1, false, true).await.unwrap();
    expected[512..1536].fill(0);
    assert_eq!(
        read_layers(&[&upper_path, &lower_path], 0, 4).await,
        expected
    );
    cache_fill(&upper, 2, &vec![0xb2; 512]).await.unwrap();
    expected[1024..1536].fill(0xb2);
    assert_eq!(
        read_layers(&[&upper_path, &lower_path], 0, 4).await,
        expected
    );
    upper.sync_cache().await.unwrap();
    drop(upper);
    drop(lower);
    assert_eq!(
        read_layers(&[&upper_path, &lower_path], 0, 4).await,
        expected
    );
}

// Test: Abort the third sector statement of a four-sector write after earlier statements replaced both zero and nonzero data, then remove the fault and retry.
// Expected: The failed transaction preserves every original sector; the retry commits all replacement sectors without changing guards, and the result survives reopen.
#[async_test]
async fn interior_sector_failure_rolls_back_whole_write_and_allows_durable_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rollback.dbhd");
    let layer = format(&path, false);
    let original: Vec<u8> = (0..8).flat_map(|sector| [0x20 + sector; 512]).collect();
    write(&layer, 0, &original).await;
    let faults = Connection::open(&path).unwrap();
    faults.execute_batch("CREATE TRIGGER fail_sector BEFORE INSERT ON sectors WHEN NEW.sector = 4 BEGIN SELECT RAISE(ABORT, 'injected sector failure'); END;").unwrap();
    let mut replacement = vec![0; 4 * 512];
    replacement[512..1024].fill(0x81);
    replacement[1536..].fill(0xff);
    let memory = GuestMemory::allocate(replacement.len());
    memory.write_at(0, &replacement).unwrap();
    let request = OwnedRequestBuffers::linear(0, replacement.len(), false);
    let error = layer
        .write(&request.buffer(&memory), 2, false)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, DiskError::Io(source) if source.to_string().contains("injected sector failure")),
        "{error:?}"
    );
    assert_eq!(read_layers(&[&path], 0, 8).await, original);
    faults.execute_batch("DROP TRIGGER fail_sector;").unwrap();
    layer
        .write(&request.buffer(&memory), 2, false)
        .await
        .unwrap();
    let mut expected = original;
    expected[2 * 512..6 * 512].copy_from_slice(&replacement);
    assert_eq!(read_layers(&[&path], 0, 8).await, expected);
    layer.sync_cache().await.unwrap();
    drop(faults);
    drop(layer);
    assert_eq!(read_layers(&[&path], 0, 8).await, expected);
}
