mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{RecordingScheduler, TestClock};
use lockbox_protocol::chunk::CHUNK_LEN;
use lockbox_protocol::codec::{MAX_MESSAGE_LEN, read_message, write_message};
use lockbox_protocol::crypto::SigningKey;
use lockbox_protocol::crypto::envelope::Envelope;
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::{
    Challenge, Chunk, ErrorCode, FileHeader, FileId, Purpose, Request, Response, SignedRequest,
};
use lockbox_server::adapters::driven::DiskStore;
use lockbox_server::adapters::driving::StreamChannel;
use lockbox_server::app::Services;
use lockbox_server::core::ports::driven::{FileStore, StoreError};
use lockbox_server::core::services::Registry;
use lockbox_server::session::{IDLE_TIMEOUT, Session, SessionError};
use tempfile::TempDir;
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const START: u64 = 1_000_000;

type Wired = Services<(TestClock, DiskStore, RecordingScheduler)>;

struct World {
    dir: TempDir,
    clock: Arc<TestClock>,
    store: Arc<DiskStore>,
    services: Arc<Wired>,
}

impl World {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::at(START);
        let store = Arc::new(DiskStore::new(dir.path().to_path_buf()).await.unwrap());
        let services = Arc::new(Services::new(
            clock.clone(),
            store.clone(),
            Arc::new(Registry::new(clock.clone())),
            RecordingScheduler::new(),
        ));

        Self {
            dir,
            clock,
            store,
            services,
        }
    }

    fn connect(&self) -> Client {
        let (stream, server) = tokio::io::duplex(4096);
        let session = Session::new(self.services.clone(), StreamChannel::new(server));

        Client {
            stream,
            task: tokio::spawn(session.run()),
        }
    }

    fn assert_empty(&self) {
        assert_eq!(std::fs::read_dir(self.dir.path()).unwrap().count(), 0);
    }
}

struct Client {
    stream: DuplexStream,
    task: JoinHandle<Result<(), SessionError>>,
}

impl Client {
    async fn send(&mut self, request: Request) {
        write_message(&mut self.stream, &request).await.unwrap();
    }

    async fn response(&mut self) -> Response {
        timeout(Duration::from_secs(5), read_message(&mut self.stream))
            .await
            .unwrap()
            .unwrap()
    }

    async fn challenge(&mut self, request: Request) -> Challenge {
        self.send(request).await;

        match self.response().await {
            Response::Challenge(challenge) => challenge,
            other => panic!("expected challenge, got {other:?}"),
        }
    }

    async fn begin_upload(&mut self, key: &SigningKey, header: FileHeader) -> FileId {
        let challenge = self.challenge(Request::BeginUpload).await;
        assert_eq!(challenge.purpose(), Purpose::Upload);

        self.send(Request::Upload {
            proof: SignedRequest::answer(&challenge, key),
            header,
        })
        .await;
        assert_eq!(self.response().await, Response::ReadyForUpload);

        challenge.file_id()
    }

    async fn upload(&mut self, key: &SigningKey, header: FileHeader, bytes: &[u8]) -> FileId {
        let file_id = self.begin_upload(key, header).await;

        for piece in bytes.chunks(CHUNK_LEN) {
            self.send(Request::UploadChunk(Chunk::new(piece.to_vec()).unwrap()))
                .await;
        }

        assert_eq!(
            self.response().await,
            Response::Uploaded {
                file_id,
                expires_at: START + 300
            }
        );

        file_id
    }

    async fn fetch(&mut self, id: FileId, key: &SigningKey) -> Response {
        let challenge = self.challenge(Request::BeginFetch { file_id: id }).await;
        self.send(Request::Fetch(SignedRequest::answer(&challenge, key)))
            .await;

        self.response().await
    }

    async fn error_and_close(mut self, code: ErrorCode) {
        assert_eq!(self.response().await, Response::Error(code));
        assert!(self.task.await.unwrap().is_err());

        let result = read_message::<Response, _>(&mut self.stream).await;
        assert!(matches!(
            result,
            Err(lockbox_protocol::ProtocolError::ConnectionClosed)
        ));
    }

    async fn close(self) {
        drop(self.stream);
        assert!(self.task.await.unwrap().is_ok());
    }
}

fn prepare(key: &SigningKey, plaintext: &[u8]) -> (FileHeader, Vec<u8>) {
    let (envelope, bytes) = Envelope::encrypt_to_recipients(plaintext, &[key.verifying_key()])
        .unwrap()
        .into_parts();

    (
        FileHeader {
            envelope,
            ciphertext_len: bytes.len() as u64,
            expires_at: START + 10_000,
        },
        bytes,
    )
}

#[tokio::test]
async fn upload_fetch_decrypt_and_delete_run_in_order_on_one_connection() {
    let w = World::new().await;
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let plaintext = vec![123; CHUNK_LEN * 2 + 17];
    let (header, bytes) = prepare(&recipient, &plaintext);
    let mut c = w.connect();
    let id = c.upload(&owner, header, &bytes).await;

    let Response::FetchReady(header) = c.fetch(id, &recipient).await else {
        panic!("fetch denied")
    };
    assert_eq!(header.expires_at, START + 300);

    let mut received = Vec::new();

    while received.len() < header.ciphertext_len as usize {
        let Response::Chunk(chunk) = c.response().await else {
            panic!("expected chunk")
        };
        received.extend_from_slice(chunk.as_bytes());
    }

    assert_eq!(
        header.recipient.decrypt(&recipient, &received).unwrap(),
        plaintext
    );

    let challenge = c.challenge(Request::BeginDelete { file_id: id }).await;

    c.send(Request::Delete(SignedRequest::answer(&challenge, &owner)))
        .await;
    assert_eq!(c.response().await, Response::Deleted);
    assert!(matches!(w.store.open(id).await, Err(StoreError::NotFound)));
    assert_eq!(
        c.fetch(id, &recipient).await,
        Response::Error(ErrorCode::Denied)
    );
    assert!(c.task.await.unwrap().is_err());
    w.assert_empty();
}

#[tokio::test]
async fn requests_outside_a_transaction_are_unexpected() {
    let w = World::new().await;
    let key = generate_keypair();
    let (header, _) = prepare(&key, b"x");
    let proof = SignedRequest::answer(
        &Challenge::new(FileId::random(), Purpose::Upload, START),
        &key,
    );

    for request in [
        Request::Upload {
            proof: proof.clone(),
            header,
        },
        Request::Fetch(proof.clone()),
        Request::Delete(proof),
        Request::UploadChunk(Chunk::new(vec![1]).unwrap()),
    ] {
        let mut c = w.connect();

        c.send(request).await;
        c.error_and_close(ErrorCode::UnexpectedMessage).await;
    }

    w.assert_empty();
}

#[tokio::test]
async fn a_pending_challenge_cannot_be_replaced_or_answered_with_another_operation() {
    let w = World::new().await;
    let key = generate_keypair();

    for begin in [
        Request::BeginUpload,
        Request::BeginFetch {
            file_id: FileId::random(),
        },
        Request::BeginDelete {
            file_id: FileId::random(),
        },
    ] {
        for answer in 0..5 {
            let mut c = w.connect();
            let challenge = c.challenge(begin.clone()).await;
            let proof = SignedRequest::answer(&challenge, &key);
            let (header, _) = prepare(&key, b"x");
            let request = match answer {
                0 => Request::BeginUpload,
                1 => Request::UploadChunk(Chunk::new(vec![1]).unwrap()),
                2 => Request::Upload { proof, header },
                3 => Request::Fetch(proof),
                _ => Request::Delete(proof),
            };

            if matches!(
                (&begin, &request),
                (Request::BeginUpload, Request::Upload { .. })
                    | (Request::BeginFetch { .. }, Request::Fetch(_))
                    | (Request::BeginDelete { .. }, Request::Delete(_))
            ) {
                c.close().await;
                continue;
            }
            c.send(request).await;
            c.error_and_close(ErrorCode::UnexpectedMessage).await;
        }
    }
}

#[tokio::test]
async fn proofs_are_bound_to_the_connection_and_the_issued_challenge() {
    let w = World::new().await;
    let key = generate_keypair();
    let mut first = w.connect();
    let challenge = first.challenge(Request::BeginUpload).await;

    for altered in 0..3 {
        let mut second = w.connect();
        let own = second.challenge(Request::BeginUpload).await;
        let mut proof = SignedRequest::answer(if altered == 0 { &challenge } else { &own }, &key);

        if altered == 1 {
            proof.file_id = FileId::random();
        }

        if altered == 2 {
            proof.nonce[0] ^= 1;
        }

        let (header, _) = prepare(&key, b"x");

        second.send(Request::Upload { proof, header }).await;
        second.error_and_close(ErrorCode::Denied).await;
    }

    first.close().await;
    w.assert_empty();
}

#[tokio::test]
async fn an_expired_or_invalid_signature_is_denied() {
    let w = World::new().await;
    let key = generate_keypair();

    for expired in [false, true] {
        let mut c = w.connect();
        let challenge = c.challenge(Request::BeginUpload).await;
        let mut proof = SignedRequest::answer(&challenge, &key);

        if expired {
            w.clock.advance(60);
        } else {
            proof.public_key = generate_keypair().verifying_key();
        }

        let (header, _) = prepare(&key, b"x");

        c.send(Request::Upload { proof, header }).await;
        c.error_and_close(ErrorCode::Denied).await;
    }

    w.assert_empty();
}

#[tokio::test]
async fn unknown_files_and_forbidden_keys_get_the_same_denial() {
    let w = World::new().await;
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let (header, bytes) = prepare(&recipient, b"secret");
    let mut uploader = w.connect();
    let id = uploader.upload(&owner, header, &bytes).await;

    for (file_id, key) in [(FileId::random(), &recipient), (id, &owner)] {
        let mut c = w.connect();
        assert_eq!(
            c.fetch(file_id, key).await,
            Response::Error(ErrorCode::Denied)
        );
        assert!(c.task.await.unwrap().is_err());
    }

    let mut c = w.connect();
    let challenge = c.challenge(Request::BeginDelete { file_id: id }).await;

    c.send(Request::Delete(SignedRequest::answer(
        &challenge, &recipient,
    )))
    .await;
    c.error_and_close(ErrorCode::Denied).await;
    assert!(w.store.open(id).await.is_ok());

    uploader.close().await;
}

#[tokio::test]
async fn invalid_headers_and_chunks_are_rejected_and_remove_partial_files() {
    let w = World::new().await;
    let key = generate_keypair();

    for case in 0..4 {
        let mut c = w.connect();
        let (mut header, bytes) = prepare(&key, b"x");

        if case == 0 {
            header.ciphertext_len = 0;
            let challenge = c.challenge(Request::BeginUpload).await;

            c.send(Request::Upload {
                proof: SignedRequest::answer(&challenge, &key),
                header,
            })
            .await;
        } else {
            c.begin_upload(&key, header).await;

            let request = match case {
                1 => Request::UploadChunk(Chunk::new(Vec::new()).unwrap()),
                2 => Request::UploadChunk(Chunk::new(vec![0; bytes.len() + 1]).unwrap()),
                _ => Request::BeginUpload,
            };

            c.send(request).await;
        }

        c.error_and_close(if case == 3 {
            ErrorCode::UnexpectedMessage
        } else {
            ErrorCode::InvalidRequest
        })
        .await;
        w.assert_empty();
    }
}

#[tokio::test]
async fn a_proof_cannot_be_replayed_after_a_transaction_completes() {
    let w = World::new().await;
    let key = generate_keypair();
    let (header, bytes) = prepare(&key, b"x");
    let mut c = w.connect();
    let challenge = c.challenge(Request::BeginUpload).await;
    let proof = SignedRequest::answer(&challenge, &key);

    c.send(Request::Upload {
        proof: proof.clone(),
        header: header.clone(),
    })
    .await;
    assert_eq!(c.response().await, Response::ReadyForUpload);
    c.send(Request::UploadChunk(Chunk::new(bytes).unwrap()))
        .await;
    assert!(matches!(c.response().await, Response::Uploaded { .. }));

    c.challenge(Request::BeginUpload).await;
    c.send(Request::Upload { proof, header }).await;
    c.error_and_close(ErrorCode::Denied).await;
}

#[tokio::test]
async fn eof_in_a_partial_upload_or_partial_frame_removes_the_file() {
    let w = World::new().await;
    let key = generate_keypair();

    for partial_frame in [false, true] {
        let mut c = w.connect();
        let (header, _) = prepare(&key, b"a file longer than one byte");
        c.begin_upload(&key, header).await;
        c.send(Request::UploadChunk(Chunk::new(vec![0]).unwrap()))
            .await;

        if partial_frame {
            c.stream.write_all(&[0, 0, 0]).await.unwrap();
        }

        c.close().await;
        w.assert_empty();
    }
}

#[tokio::test]
async fn malformed_and_oversized_frames_get_an_error_then_close() {
    let w = World::new().await;

    for bytes in [
        vec![0, 0, 0, 1, 255],
        ((MAX_MESSAGE_LEN + 1) as u32).to_be_bytes().to_vec(),
    ] {
        let mut c = w.connect();
        c.stream.write_all(&bytes).await.unwrap();
        c.error_and_close(ErrorCode::InvalidRequest).await;
    }
}

#[tokio::test]
async fn idle_connections_and_stalled_uploads_time_out() {
    let w = World::new().await;
    let key = generate_keypair();

    for uploading in [false, true] {
        let mut c = w.connect();

        if uploading {
            let (header, _) = prepare(&key, b"unfinished");
            c.begin_upload(&key, header).await;
        } else {
            c.challenge(Request::BeginUpload).await;
        }

        tokio::time::pause();
        tokio::time::advance(IDLE_TIMEOUT + Duration::from_secs(1)).await;
        assert!(matches!(c.task.await.unwrap(), Err(SessionError::TimedOut)));

        tokio::time::resume();
        w.assert_empty();
    }
}

#[tokio::test]
async fn a_slow_partial_frame_cannot_keep_a_connection_alive() {
    let w = World::new().await;
    let mut c = w.connect();

    c.challenge(Request::BeginUpload).await;
    c.stream.write_all(&[0, 0]).await.unwrap();

    tokio::time::pause();
    tokio::time::advance(IDLE_TIMEOUT + Duration::from_secs(1)).await;
    assert!(matches!(c.task.await.unwrap(), Err(SessionError::TimedOut)));
}

#[tokio::test]
async fn cancelling_a_session_drops_its_unfinished_upload() {
    let w = World::new().await;
    let key = generate_keypair();
    let (header, _) = prepare(&key, b"unfinished");
    let mut c = w.connect();
    c.begin_upload(&key, header).await;

    c.task.abort();
    assert!(c.task.await.unwrap_err().is_cancelled());
    w.assert_empty();
}

#[tokio::test]
async fn concurrent_connections_share_completed_files() {
    let w = World::new().await;
    let mut tasks = Vec::new();

    for _ in 0..8 {
        let mut uploader = w.connect();
        let mut downloader = w.connect();
        tasks.push(tokio::spawn(async move {
            let key = generate_keypair();
            let (header, bytes) = prepare(&key, b"shared services");
            let id = uploader.upload(&key, header, &bytes).await;
            assert!(matches!(
                downloader.fetch(id, &key).await,
                Response::FetchReady(_)
            ));
            let Response::Chunk(chunk) = downloader.response().await else {
                panic!("expected chunk")
            };
            assert_eq!(chunk.as_bytes(), bytes);

            uploader.close().await;
            downloader.close().await;
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn a_peer_that_stops_reading_responses_times_out() {
    use lockbox_server::core::ports::driving::{Channel, ChannelError};
    use tokio::sync::oneshot;

    struct StalledChannel(Option<oneshot::Sender<()>>);

    impl Channel for StalledChannel {
        async fn receive(&mut self) -> Result<Option<Request>, ChannelError> {
            Ok(Some(Request::BeginUpload))
        }

        async fn send(&mut self, _: &Response) -> Result<(), ChannelError> {
            self.0.take().unwrap().send(()).unwrap();
            std::future::pending().await
        }
    }

    let w = World::new().await;
    let (sending, started) = oneshot::channel();
    let session = Session::new(w.services.clone(), StalledChannel(Some(sending)));
    let task = tokio::spawn(session.run());
    started.await.unwrap();

    tokio::time::pause();
    tokio::time::advance(IDLE_TIMEOUT + Duration::from_secs(1)).await;
    assert!(matches!(task.await.unwrap(), Err(SessionError::TimedOut)));
}

#[tokio::test]
async fn store_failures_return_only_the_internal_error_code() {
    let w = World::new().await;
    let key = generate_keypair();
    let (header, _) = prepare(&key, b"x");
    let mut c = w.connect();
    let challenge = c.challenge(Request::BeginUpload).await;
    std::fs::remove_dir(w.dir.path()).unwrap();

    c.send(Request::Upload {
        proof: SignedRequest::answer(&challenge, &key),
        header,
    })
    .await;
    c.error_and_close(ErrorCode::Internal).await;
}
