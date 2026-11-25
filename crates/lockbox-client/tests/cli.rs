use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;

use lockbox_protocol::chunk::CHUNK_LEN;
use lockbox_server::adapters::driven::{DiskStore, SystemClock};
use lockbox_server::app::assemble;
use lockbox_server::transport::tcp::serve;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

fn client(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lockbox-client"))
        .args(args)
        .output()
        .unwrap()
}

fn success(args: &[&str]) -> Output {
    let output = client(args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn help_and_invalid_commands_work_without_a_server() {
    assert!(
        String::from_utf8(success(&["--help"]).stdout)
            .unwrap()
            .contains("upload <server>")
    );

    for args in [
        vec!["unknown"],
        vec!["upload"],
        vec!["delete", "127.0.0.1:1", "missing.pem", "invalid-id"],
    ] {
        let output = client(&args);
        assert!(!output.status.success());
        assert!(!output.stderr.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn separate_cli_processes_share_files_and_enforce_permissions_without_overwriting() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
    let storage = dir.path().join("storage");
    let store = Arc::new(DiskStore::new(storage.clone()).await.unwrap());
    let assembled = assemble(Arc::new(SystemClock), store);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let (stop, stopped) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (result, ()) = tokio::join!(
            serve(listener, assembled.services, async {
                stopped.await.unwrap();
            }),
            assembled.worker.run(),
        );

        result.unwrap();
    });

    let owner = path("owner.secret.pem");
    let owner_public = path("owner.public.pem");
    let recipient = path("recipient.secret.pem");
    let recipient_public = path("recipient.public.pem");
    success(&["keygen", &owner, &owner_public]);
    success(&["keygen", &recipient, &recipient_public]);

    let original = std::fs::read(&owner).unwrap();
    assert!(!client(&["keygen", &owner, &owner_public]).status.success());
    assert_eq!(std::fs::read(&owner).unwrap(), original);

    let rollback = path("rollback.secret.pem");
    assert!(
        !client(&["keygen", &rollback, &recipient_public])
            .status
            .success()
    );
    assert!(!std::path::Path::new(&rollback).exists());

    for (index, plaintext) in [Vec::new(), vec![123; CHUNK_LEN * 2 + 17]]
        .into_iter()
        .enumerate()
    {
        let input = path(&format!("input-{index}"));
        let output = path(&format!("output-{index}"));
        let forbidden = path(&format!("forbidden-{index}"));
        std::fs::write(&input, &plaintext).unwrap();

        let uploaded = success(&["upload", &address, &owner, &input, &recipient_public]);
        let file_id = String::from_utf8(uploaded.stdout).unwrap();
        let file_id = file_id.trim();
        assert!(file_id.parse::<lockbox_protocol::FileId>().is_ok());

        let denied = client(&["fetch", &address, &owner, file_id, &forbidden]);
        assert!(!denied.status.success());
        assert!(String::from_utf8_lossy(&denied.stderr).contains("denied"));
        assert!(!std::path::Path::new(&forbidden).exists());

        success(&["fetch", &address, &recipient, file_id, &output]);
        assert_eq!(std::fs::read(&output).unwrap(), plaintext);

        std::fs::write(&output, b"keep this").unwrap();
        assert!(
            !client(&["fetch", &address, &recipient, file_id, &output])
                .status
                .success()
        );
        assert_eq!(std::fs::read(&output).unwrap(), b"keep this");

        assert!(
            !client(&["delete", &address, &recipient, file_id])
                .status
                .success()
        );
        success(&["delete", &address, &owner, file_id]);
        assert!(
            !client(&["fetch", &address, &recipient, file_id, &forbidden])
                .status
                .success()
        );
        assert!(!std::path::Path::new(&forbidden).exists());
        assert_eq!(std::fs::read_dir(&storage).unwrap().count(), 0);
    }

    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}
