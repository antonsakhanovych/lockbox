use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, ready};

use lockbox_protocol::FileId;
use tokio::fs::{self, File};
use tokio::io::AsyncWrite;

use crate::core::ports::driven::{FileStore, StoreError};

const EXTENSION: &str = "lbx";
const NAME_LEN: usize = 16;

#[derive(Default)]
struct State {
    files: HashMap<FileId, PathBuf>,
    closed: bool,
}

#[derive(Default)]
struct Index(Mutex<State>);

impl Index {
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn publish(&self, file_id: FileId, path: PathBuf) -> bool {
        let mut state = self.state();
        if state.closed {
            return false;
        }
        state.files.insert(file_id, path);
        true
    }

    fn lookup(&self, file_id: &FileId) -> Option<PathBuf> {
        self.state().files.get(file_id).cloned()
    }

    fn withdraw(&self, file_id: &FileId) -> Option<PathBuf> {
        self.state().files.remove(file_id)
    }

    fn close(&self) -> Vec<PathBuf> {
        let mut state = self.state();
        state.closed = true;
        state.files.drain().map(|(_, path)| path).collect()
    }
}

pub struct DiskStore {
    dir: PathBuf,
    index: Arc<Index>,
}

pub struct DiskWriter {
    file: File,
    path: PathBuf,
    file_id: FileId,
    index: Arc<Index>,
    finished: bool,
}

impl DiskStore {
    pub async fn new(dir: PathBuf) -> Result<Self, StoreError> {
        fs::create_dir_all(&dir).await?;
        let mut entries = fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let ours = path
                .extension()
                .is_some_and(|extension| extension == EXTENSION);
            if ours && entry.file_type().await?.is_file() {
                fs::remove_file(path).await?;
            }
        }
        Ok(Self {
            dir,
            index: Arc::default(),
        })
    }

    fn random_path(&self) -> PathBuf {
        let mut bytes = [0u8; NAME_LEN];
        rand::fill(&mut bytes[..]);
        let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        self.dir.join(name).with_extension(EXTENSION)
    }
}

impl Drop for DiskStore {
    fn drop(&mut self) {
        for path in self.index.close() {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl FileStore for DiskStore {
    type Writer = DiskWriter;
    type Reader = File;

    async fn create(&self, file_id: FileId) -> Result<DiskWriter, StoreError> {
        let path = self.random_path();
        let file = File::create_new(&path).await?;
        Ok(DiskWriter {
            file,
            path,
            file_id,
            index: self.index.clone(),
            finished: false,
        })
    }

    async fn open(&self, file_id: FileId) -> Result<File, StoreError> {
        let path = self.index.lookup(&file_id).ok_or(StoreError::NotFound)?;
        match File::open(path).await {
            Ok(file) => Ok(file),
            Err(error) if error.kind() == ErrorKind::NotFound => Err(StoreError::NotFound),
            Err(error) => Err(error.into()),
        }
    }

    async fn remove(&self, file_id: FileId) -> Result<(), StoreError> {
        let path = self.index.withdraw(&file_id).ok_or(StoreError::NotFound)?;
        match fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Err(StoreError::NotFound),
            Err(error) => Err(error.into()),
        }
    }
}

impl AsyncWrite for DiskWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().file).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(Ok(()));
        }
        ready!(Pin::new(&mut this.file).poll_flush(cx))?;
        ready!(Pin::new(&mut this.file).poll_shutdown(cx))?;
        if !this.index.publish(this.file_id, this.path.clone()) {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "the store was dropped",
            )));
        }
        this.finished = true;
        Poll::Ready(Ok(()))
    }
}

impl Drop for DiskWriter {
    fn drop(&mut self) {
        if !self.finished {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
