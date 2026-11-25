# lockbox-client

A minimal CLI with positional arguments, ready for a later Clap parser.

Build with `cargo build --workspace`, then start the server in another terminal with `cargo run -p lockbox-server`.

```sh
target/debug/lockbox-client keygen owner.secret.pem owner.public.pem
target/debug/lockbox-client keygen recipient.secret.pem recipient.public.pem
printf 'hello team\n' > message.txt

file_id=$(target/debug/lockbox-client upload 127.0.0.1:5625 owner.secret.pem message.txt recipient.public.pem)
target/debug/lockbox-client fetch 127.0.0.1:5625 recipient.secret.pem "$file_id" downloaded.txt
target/debug/lockbox-client delete 127.0.0.1:5625 owner.secret.pem "$file_id"
```

Uploads accept multiple recipient public keys and expire after five minutes. Only listed recipients can fetch; only the owner can delete. Existing keys and output files are never overwritten.

Files are held in memory, with a 64 MiB encrypted size limit. TLS and upload resume are unsupported.

- Help: `cargo run -p lockbox-client -- --help`
- Tests: `cargo test -p lockbox-client`
