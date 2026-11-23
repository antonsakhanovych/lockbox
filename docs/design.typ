#set document(title: "Lockbox design")
#set page(paper: "a4", margin: 2.2cm, numbering: "1")
#set text(size: 11pt)
#set par(justify: true, leading: 0.7em)
#set heading(numbering: "1.")
#show raw: set text(size: 0.95em)
#show heading: set block(above: 1.4em, below: 0.8em)

#align(center)[
  #text(size: 22pt, weight: "bold")[Lockbox design]
  #v(0.3em)
  Short-lived encrypted file sharing
]

#v(1em)

= What lockbox is for

Lockbox lets one person send a file to a few chosen people through a server that never sees what is in the file. The sender encrypts on their own machine, names who may open it, and uploads it. The recipients download it, usually within minutes, and decrypt it on their own machines. The server deletes the file after at most five minutes.

People are identified by key pairs instead of accounts. Everyone makes a key pair once, keeps the private file to themselves, and gives the public file to anyone who wants to send them something. There are no passwords and no sign up.

= Who does what

There are three roles.

- The owner uploads a file. They choose the recipients and how long the file lives, and they are the only person who can delete it early.
- A recipient is anyone whose public key the owner listed. A recipient can download the file and decrypt it.
- The server stores the encrypted file for a short time and hands it to the listed recipients. It holds no secret keys and cannot read any file.

The owner is not automatically a recipient. To read their own file back, the owner has to list their own public key too.

= How it works

== Uploading

The owner's program encrypts the file once and locks the file key separately for each recipient. It then asks the server for a challenge, which is a fresh random value that is valid for one minute and can be used once. The owner signs the challenge with their private key. That proves they hold the key they name as owner.

Next the program sends a short header: who the recipients are, how large the encrypted file is, and when it should expire. The encrypted file follows in pieces of 256 KiB. The server answers with the file id, and the owner passes the id to the recipients by any channel they like.

== Fetching

A recipient gives their program the file id. The program asks the server for a challenge, signs it, and sends the answer. The server checks that the signature is valid and that the key is on that file's recipient list. If both hold, it sends a header cut down to that recipient's own entry, and then the pieces. The program puts the pieces back together, unlocks the file key with the recipient's private key, decrypts the file and saves it.

When anything is wrong, the server gives one answer, "denied", whether the file does not exist, the key is not on the list, or the challenge ran out. Nobody can use the server to find out which files exist.

== Deleting

Deleting works like fetching, except the signature must come from the owner's key. The server removes the file at once.

== Expiry

The owner says when the file should expire, and the server never allows more than five minutes from its own clock. Expired files are removed from memory and from disk. The server also empties its storage folder when it starts, so a restart loses every file. That is acceptable because no file lives longer than five minutes.

= The pieces of the system

The project is one Cargo workspace with three crates. The libraries below are our proposal. Each one is added to a crate only when the code that needs it exists.

== lockbox-protocol

This is the shared library, and both programs depend on it so they cannot disagree about anything. It contains:

- the cryptography: making and saving keys, signing and checking signatures, and encrypting a file for several recipients
- the message types for every request and response, and the code that writes and reads them on a connection
- the file id, the challenge and the rules for checking a signed answer
- the splitting of an encrypted file into pieces and putting it back together, with the safety checks on sizes
- the limits listed in the table below

It does not open sockets, and the only files it touches are key files. For messages it currently reads and writes whatever stream it is handed, using the standard blocking read and write calls. It should also offer plain functions that turn a message into bytes and bytes back into a message without any reading or writing, because the server needs them for WebSocket frames. It is already built and tested, and it uses the dalek crates (ed25519-dalek and curve25519-dalek) for keys and signatures, chacha20poly1305 and sha2 for encryption, zeroize to wipe secrets from memory, serde with postcard for messages, base64 and rand, and thiserror for errors.

== lockbox-server

The server is a long-running program. It is built in two layers, so that the rules of lockbox never depend on how a client connected.

The core is the lockbox logic itself. It knows how to begin and finish an upload, a fetch and a delete, and it owns the index, the storage folder, the challenges and the expiry. It knows nothing about sockets, frames or message formats. It is one shared object with plain async methods, and every connection uses the same one.

Around the core sit adapters, one per way of connecting. An adapter accepts clients, turns what they send into calls on the core, and turns the answers back into what that kind of client expects. There are two:

- a TCP adapter, where messages follow each other on a byte stream, used by the command line client
- a WebSocket adapter, where each binary frame holds exactly one message, meant for a browser client later

Both carry the same messages, so they differ only in how a message is cut out of the incoming bytes. The core cannot tell them apart. HTTP is not planned. A browser can already reach the server over WebSocket, so HTTP would add a third adapter without adding anything users need. The layering leaves room for one if it is ever wanted.

Because a client may not stay on one connection, the core keeps issued challenges in a table of its own instead of on the connection. Each entry is found by its random value, which the signed answer repeats, and it is removed when answered or when its minute is up.

The server does the following:

- listens on a TCP address and, if enabled, a WebSocket address, and serves many connections at the same time
- reads requests one at a time and answers each one, and closes the connection if the peer sends something unexpected or goes quiet for too long
- creates challenges and keeps each one in the core's table until it is answered or expires
- checks signatures and then checks permission: a recipient for a fetch, the owner for a delete
- writes an upload straight into a file with a random name in its storage folder, so it never holds a whole file in memory, and checks that the amount received matches what was announced
- keeps an index in memory of every stored file: its recipients, its owner, its expiry and where it lives on disk
- streams a stored file back to a permitted recipient, with the header cut down to that recipient's own entry
- deletes files when the owner asks and when they expire, using a background sweep
- empties the storage folder on start, and logs connections, denials and clean-ups

The libraries it should use:

- `lockbox-protocol` for everything on the wire and every cryptographic check
- `clap` to read the command line options, such as the address to listen on and the storage folder
- `tracing` and `tracing-subscriber` for logs
- `ctrlc`, or the runtime's own signal handling, so that Ctrl+C lets the server stop and delete its files instead of leaving them behind
- `thiserror` for the server's own error type
- an async runtime, either `tokio` or `mio`, chosen by whoever builds the server (see below)
- for the WebSocket adapter, `tokio-tungstenite` if the runtime is `tokio`

The server needs an async runtime, and whoever builds it has to choose between `tokio` and `mio`. `tokio` is a complete runtime. It comes with async sockets, timers and task scheduling, so the server code stays short. `mio` is a thin layer over the operating system's event notifications. It gives non-blocking sockets and an event loop and nothing else, so the server would supply its own scheduling, timers and buffering. The WebSocket adapter tips the balance towards `tokio`, because `tokio-tungstenite` plugs straight into its sockets, while with `mio` the WebSocket handshake and framing would have to be wired in by hand. The choice should be made before the server is written and recorded here once it is made.

The choice reaches into the protocol crate. Its functions for reading and writing messages and file pieces use the blocking standard `Read` and `Write` traits. Those work on plain threads, but not on async streams or non-blocking sockets. With either runtime, the implementor also has to decide how the protocol crate meets it. One way is to add async versions of those functions, which suits `tokio`. The other is to change them so the crate only turns bytes into messages and back, while the server does the socket reads and writes itself, which suits `mio`. The client can stay on the standard library's blocking sockets either way, because it only uses the TCP adapter.

== lockbox-client

The client is a command line tool with four commands.

- `keygen` makes a key pair and writes the private file readable only by its owner and the public file for sharing. It refuses to overwrite an existing file.
- `upload` takes a file, the public key files of the recipients, the owner's private key and a requested lifetime. It encrypts, runs the challenge, sends the file and prints the file id and the expiry time the server granted.
- `fetch` takes a file id and a private key. It downloads the file, decrypts it and writes it out, again without overwriting anything.
- `delete` takes a file id and the owner's private key.

The client also checks that what it receives matches what the header announced, and turns a "denied" answer into a plain message for the user.

The libraries it should use:

- `lockbox-protocol` for the cryptography, the messages and the chunking
- `clap` for the commands and options
- `thiserror` for its error type
- the standard library for the connection

= Limits

#table(
  columns: (1fr, auto),
  align: (left, right),
  stroke: 0.5pt + luma(180),
  inset: 7pt,
  [Largest encrypted file], [64 MiB],
  [Recipients per file], [64],
  [Size of one piece of a file], [256 KiB],
  [Largest single message, also the WebSocket frame limit], [1 MiB],
  [Challenge lifetime], [60 seconds, used once],
  [File lifetime], [5 minutes at most],
)

= Known limitations

These are choices we made for the first version, and the README should list them too.

- Traffic between client and server is not encrypted in transit. File contents are protected by their own encryption, but someone watching the network can see which ids are used, the recipients' public keys, and who talks to the server, and can cut connections. Putting the server behind TLS fixes this.
- Anyone who holds a key can upload. The size, recipient and lifetime limits are the only protection against someone filling the disk.
- The server sees the full list of recipient public keys. Each recipient sees only their own entry.
- A recipient cannot tell who made a file. The file does not carry the sender's identity.
- Once a recipient has decrypted a file, nothing stops them from passing it on, and deleting a file does not take back copies that were already downloaded.
- The client encrypts the whole file in memory, which is why files stop at 64 MiB.
- A server restart loses every file.

= Possible later work

- Encrypting in streams, so files can be larger than memory
- TLS between client and server, which the WebSocket adapter needs anyway because browsers on a secure page only allow `wss://`
- A browser client written in Rust and compiled to WebAssembly, reusing `lockbox-protocol` for messages and encryption. It must not be served by the lockbox server itself. A page the server sends could be changed by a dishonest server to copy keys or files, so it needs a separate host or a pinned build
- An HTTP adapter, if a use for it appears
- Storing the index in SQLite so files survive a restart
- A list of keys allowed to upload
- A way to revoke access before a recipient fetches
