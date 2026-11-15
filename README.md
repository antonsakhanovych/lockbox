# Lockbox

Lockbox is a simple encrypted file-sharing protocol where the server cannot read the files it stores, and only authorized clients can read the files' contents.

A client encrypts a file to the public keys of the people who should get it and uploads it.
The server returns a short ID to share.
To download, a client proves it owns a listed key by signing a challenge from the server.
