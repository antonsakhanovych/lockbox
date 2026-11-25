# lockbox-server

The Lockbox TCP server stores encrypted files, checks signed challenges before upload, fetch and delete, and removes files when they expire.

Run it from the workspace root:

```sh
cargo run -p lockbox-server -- --listen-addr 127.0.0.1:5625 --storage-dir lockbox-data
```

Each connection runs a `Session` over a `Channel`. Sessions share the services assembled in `app`, including the file registry and expiry scheduler. The binary runs the expiry worker alongside the TCP listener.

A connection handles one transaction at a time. Successful transactions return to the idle state, so a client can reuse its connection.

| Operation | Client requests | Server responses |
| --- | --- | --- |
| Upload | `BeginUpload`, then `Upload` with the signed proof and header, then `UploadChunk` messages | `Challenge`, then `ReadyForUpload`, then `Uploaded` once all announced bytes arrive |
| Fetch | `BeginFetch`, then `Fetch` with the signed proof | `Challenge`, then `FetchReady` with the recipient's header, then `Chunk` messages totaling the announced length |
| Delete | `BeginDelete`, then `Delete` with the owner's signed proof | `Challenge`, then `Deleted` |

The server chooses the upload's file ID when it issues the challenge. A challenge belongs to its connection, names one operation and file ID, lasts 60 seconds, and is consumed when answered. Reconnecting requires a new challenge.

A failed request ends the session. Unexpected messages receive `UnexpectedMessage`, malformed requests receive `InvalidRequest`, authorization failures receive `Denied`, and storage failures receive `Internal`. Internal error text stays in server logs. The session then closes the connection and discards any unfinished upload.

Each complete request and each response write has a 60-second timeout. A timeout or connection failure closes the session. A partial frame does not reset the timeout. Each session can hold at most one unfinished upload. There is no global connection or upload limit.

Files expire after at most five minutes. Startup removes leftover `.lbx` files from the storage folder. Ctrl+C stops the listener, cancels and awaits open sessions, stops the expiry worker, and drops the store to remove completed files. A restart loses all uploaded files.

Traffic has no TLS. File contents are encrypted by the client, but file IDs and public keys are visible on the network.

Run the workspace tests with `cargo test --workspace`. The server tests cover service rules, session ordering, streaming, access checks, timeouts, disconnects, concurrent connections, and TCP shutdown cleanup.
