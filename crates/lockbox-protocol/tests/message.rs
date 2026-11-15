use std::io::Cursor;

use lockbox_protocol::FileId;
use lockbox_protocol::codec::{read_message, write_message};
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::sign::sign;
use lockbox_protocol::message::{
    CHALLENGE_LEN, Challenge, ClientMessage, ErrorCode, ServerMessage,
};

fn round_trip<T>(message: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let mut bytes = Vec::new();

    write_message(&mut bytes, message).unwrap();
    read_message(&mut Cursor::new(bytes)).unwrap()
}

#[test]
fn every_client_message_round_trips() {
    let key = generate_keypair();
    let messages = [
        ClientMessage::Upload {
            envelope_bytes: vec![1, 2, 3],
            ttl_seconds: 3600,
        },
        ClientMessage::RequestDownload(FileId::random()),
        ClientMessage::ChallengeResponse {
            public_key: key.verifying_key(),
            signature: sign(b"challenge", &key),
        },
    ];

    for message in messages {
        assert_eq!(round_trip(&message), message);
    }
}

#[test]
fn every_server_message_round_trips() {
    let messages = [
        ServerMessage::Uploaded(FileId::random()),
        ServerMessage::Challenge(Challenge::random()),
        ServerMessage::File {
            envelope_bytes: vec![9; 100],
        },
        ServerMessage::Error(ErrorCode::NotFound),
        ServerMessage::Error(ErrorCode::Expired),
        ServerMessage::Error(ErrorCode::NotAuthorized),
        ServerMessage::Error(ErrorCode::InvalidSignature),
        ServerMessage::Error(ErrorCode::InvalidRequest),
    ];

    for message in messages {
        assert_eq!(round_trip(&message), message);
    }
}

#[test]
fn random_challenges_are_different() {
    assert_ne!(Challenge::random(), Challenge::random());
}

#[test]
fn a_challenge_is_its_bytes_on_the_wire() {
    let challenge = Challenge::from([7u8; CHALLENGE_LEN]);
    let mut bytes = Vec::new();

    write_message(&mut bytes, &challenge).unwrap();

    assert_eq!(bytes, [7u8; CHALLENGE_LEN]);
    assert_eq!(challenge.as_bytes(), &[7u8; CHALLENGE_LEN]);
}

#[test]
fn messages_sent_in_sequence_are_read_in_order() {
    let id = FileId::random();
    let mut bytes = Vec::new();
    write_message(&mut bytes, &ClientMessage::RequestDownload(id)).unwrap();
    write_message(&mut bytes, &ServerMessage::Error(ErrorCode::NotFound)).unwrap();

    let mut reader = Cursor::new(bytes);

    let first: ClientMessage = read_message(&mut reader).unwrap();
    let second: ServerMessage = read_message(&mut reader).unwrap();

    assert_eq!(first, ClientMessage::RequestDownload(id));
    assert_eq!(second, ServerMessage::Error(ErrorCode::NotFound));
}
