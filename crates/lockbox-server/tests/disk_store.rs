use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use lockbox_protocol::FileId;
use lockbox_protocol::chunk::CHUNK_LEN;
use lockbox_server::adapters::driven::DiskStore;
use lockbox_server::core::ports::driven::{FileStore, StoreError};
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

async fn new_store() -> (TempDir, DiskStore) {
    let dir = tempdir().unwrap();
    let store = DiskStore::new(dir.path().to_path_buf()).await.unwrap();
    (dir, store)
}

async fn put(store: &DiskStore, file_id: FileId, bytes: &[u8]) {
    let mut writer = store.create(file_id).await.unwrap();
    writer.write_all(bytes).await.unwrap();
    writer.shutdown().await.unwrap();
}

async fn read_all(store: &DiskStore, file_id: FileId) -> Vec<u8> {
    let mut reader = store.open(file_id).await.unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await.unwrap();
    bytes
}

#[tokio::test]
async fn bytes_come_back_unchanged_for_every_interesting_size() {
    let (_dir, store) = new_store().await;
    for len in [
        1,
        1000,
        CHUNK_LEN - 1,
        CHUNK_LEN,
        CHUNK_LEN + 1,
        3 * CHUNK_LEN + 5,
    ] {
        let id = FileId::random();
        put(&store, id, &data(len)).await;
        assert_eq!(read_all(&store, id).await, data(len), "{len}");
    }
}

#[tokio::test]
async fn a_file_written_in_several_pieces_reads_back_as_one() {
    let (_dir, store) = new_store().await;
    let id = FileId::random();
    let mut writer = store.create(id).await.unwrap();
    writer.write_all(&data(100)).await.unwrap();
    writer.write_all(&data(50)).await.unwrap();
    writer.shutdown().await.unwrap();
    assert_eq!(read_all(&store, id).await, [data(100), data(50)].concat());
}

#[tokio::test]
async fn an_empty_file_reads_back_empty() {
    let (_dir, store) = new_store().await;
    let id = FileId::random();
    put(&store, id, &[]).await;
    assert!(read_all(&store, id).await.is_empty());
}

#[tokio::test]
async fn reading_past_the_end_keeps_returning_zero() {
    let (_dir, store) = new_store().await;
    let id = FileId::random();
    put(&store, id, &data(10)).await;
    let mut reader = store.open(id).await.unwrap();
    let mut buffer = [0u8; 64];
    assert_eq!(reader.read(&mut buffer).await.unwrap(), 10);
    assert_eq!(reader.read(&mut buffer).await.unwrap(), 0);
    assert_eq!(reader.read(&mut buffer).await.unwrap(), 0);
}

#[tokio::test]
async fn a_file_cannot_be_opened_before_the_writer_is_shut_down() {
    let (_dir, store) = new_store().await;
    let id = FileId::random();
    let mut writer = store.create(id).await.unwrap();
    writer.write_all(&data(10)).await.unwrap();
    writer.flush().await.unwrap();
    assert!(matches!(store.open(id).await, Err(StoreError::NotFound)));
}

#[tokio::test]
async fn shutting_a_writer_down_twice_is_harmless() {
    let (dir, store) = new_store().await;
    let id = FileId::random();
    let mut writer = store.create(id).await.unwrap();
    writer.write_all(&data(10)).await.unwrap();
    writer.shutdown().await.unwrap();
    writer.shutdown().await.unwrap();
    drop(writer);
    assert_eq!(names(dir.path()).len(), 1);
    assert_eq!(read_all(&store, id).await, data(10));
}

#[tokio::test]
async fn a_dropped_unfinished_writer_leaves_nothing_behind() {
    let (dir, store) = new_store().await;
    let id = FileId::random();
    let mut writer = store.create(id).await.unwrap();
    writer.write_all(&data(CHUNK_LEN)).await.unwrap();
    drop(writer);
    assert!(names(dir.path()).is_empty());
    assert!(matches!(store.open(id).await, Err(StoreError::NotFound)));
}

#[tokio::test]
async fn a_finished_file_stays_on_disk() {
    let (dir, store) = new_store().await;
    put(&store, FileId::random(), &data(10)).await;
    assert_eq!(names(dir.path()).len(), 1);
}

#[tokio::test]
async fn opening_or_removing_a_missing_file_fails() {
    let (_dir, store) = new_store().await;
    assert!(matches!(
        store.open(FileId::random()).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store.remove(FileId::random()).await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn a_removed_file_is_gone_from_disk_and_cannot_be_opened() {
    let (dir, store) = new_store().await;
    let id = FileId::random();
    put(&store, id, &data(10)).await;
    store.remove(id).await.unwrap();
    assert!(names(dir.path()).is_empty());
    assert!(matches!(store.open(id).await, Err(StoreError::NotFound)));
}

#[tokio::test]
async fn removing_one_file_leaves_the_others() {
    let (_dir, store) = new_store().await;
    let (first, second) = (FileId::random(), FileId::random());
    put(&store, first, &data(10)).await;
    put(&store, second, &data(20)).await;
    store.remove(first).await.unwrap();
    assert_eq!(read_all(&store, second).await, data(20));
}

#[tokio::test]
async fn a_reader_opened_before_removal_still_reads_the_whole_file() {
    let (_dir, store) = new_store().await;
    let id = FileId::random();
    put(&store, id, &data(CHUNK_LEN + 7)).await;
    let mut reader = store.open(id).await.unwrap();
    store.remove(id).await.unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, data(CHUNK_LEN + 7));
}

#[tokio::test]
async fn file_names_are_random_and_do_not_reveal_the_file_id() {
    let (dir, store) = new_store().await;
    let ids = [FileId::random(), FileId::random(), FileId::random()];
    for id in ids {
        put(&store, id, &data(10)).await;
    }
    let names = names(dir.path());
    assert_eq!(names.len(), 3);
    for name in &names {
        let stem = name.strip_suffix(".lbx").expect("extension");
        assert_eq!(stem.len(), 32);
        assert!(stem.bytes().all(|byte| byte.is_ascii_hexdigit()));
        for id in ids {
            assert!(!name.contains(&id.to_string()));
        }
    }
    let mut unique = names.clone();
    unique.dedup();
    assert_eq!(unique, names);
}

#[tokio::test]
async fn the_same_id_stored_twice_gets_different_names() {
    let (dir, store) = new_store().await;
    let id = FileId::random();
    put(&store, id, &data(10)).await;
    let first = names(dir.path());
    store.remove(id).await.unwrap();
    put(&store, id, &data(10)).await;
    assert_ne!(names(dir.path()), first);
}

#[tokio::test]
async fn a_new_store_creates_a_missing_folder() {
    let dir = tempdir().unwrap();
    let nested = dir.path().join("a").join("b");
    DiskStore::new(nested.clone()).await.unwrap();
    assert!(nested.is_dir());
}

#[tokio::test]
async fn a_new_store_removes_leftover_lockbox_files_and_nothing_else() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("old.lbx"), b"left over").unwrap();
    fs::write(dir.path().join("notes.txt"), b"mine").unwrap();
    fs::create_dir(dir.path().join("folder.lbx")).unwrap();
    DiskStore::new(dir.path().to_path_buf()).await.unwrap();
    assert_eq!(names(dir.path()), ["folder.lbx", "notes.txt"]);
}

#[tokio::test]
async fn files_from_before_a_restart_are_gone() {
    let dir = tempdir().unwrap();
    let id = FileId::random();
    let store = DiskStore::new(dir.path().to_path_buf()).await.unwrap();
    put(&store, id, &data(10)).await;
    let restarted = DiskStore::new(dir.path().to_path_buf()).await.unwrap();
    assert!(names(dir.path()).is_empty());
    assert!(matches!(
        restarted.open(id).await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn dropping_the_store_removes_every_finished_file() {
    let (dir, store) = new_store().await;
    for _ in 0..3 {
        put(&store, FileId::random(), &data(CHUNK_LEN + 1)).await;
    }
    assert_eq!(names(dir.path()).len(), 3);
    drop(store);
    assert!(names(dir.path()).is_empty());
}

#[tokio::test]
async fn dropping_the_store_leaves_files_that_are_not_its_own() {
    let (dir, store) = new_store().await;
    fs::write(dir.path().join("notes.txt"), b"mine").unwrap();
    put(&store, FileId::random(), &data(10)).await;
    drop(store);
    assert_eq!(names(dir.path()), ["notes.txt"]);
}

#[tokio::test]
async fn dropping_a_store_with_a_writer_in_progress_leaves_nothing() {
    let (dir, store) = new_store().await;
    let mut writer = store.create(FileId::random()).await.unwrap();
    writer.write_all(&data(100)).await.unwrap();
    drop(store);
    drop(writer);
    assert!(names(dir.path()).is_empty());
}

#[tokio::test]
async fn a_writer_shut_down_after_the_store_is_dropped_fails_and_leaves_nothing() {
    let (dir, store) = new_store().await;
    let mut writer = store.create(FileId::random()).await.unwrap();
    writer.write_all(&data(100)).await.unwrap();
    drop(store);
    let error = writer.shutdown().await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::BrokenPipe);
    drop(writer);
    assert!(names(dir.path()).is_empty());
}

#[tokio::test]
async fn a_file_deleted_behind_the_stores_back_is_reported_as_not_found() {
    let (dir, store) = new_store().await;
    let (opened, removed) = (FileId::random(), FileId::random());
    put(&store, opened, &data(10)).await;
    put(&store, removed, &data(10)).await;
    for name in names(dir.path()) {
        fs::remove_file(dir.path().join(name)).unwrap();
    }
    assert!(matches!(
        store.open(opened).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store.remove(removed).await,
        Err(StoreError::NotFound)
    ));
}
