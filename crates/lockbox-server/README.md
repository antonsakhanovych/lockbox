# lockbox-server

The Lockbox server binary.

Planned behavior:

- Store encrypted files and return an ID for each upload.
- On a download request, send a random challenge and check the signed reply: the signature must be valid, and the key must be on the file's recipient list.
- Delete files after they expire.
