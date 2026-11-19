use std::collections::HashSet;
use std::io::Cursor;

use lockbox_protocol::codec::{LENGTH_PREFIX_LEN, read_message, write_message};
use lockbox_protocol::file_id::FILE_ID_LEN;
use lockbox_protocol::{FileId, ProtocolError};

#[test]
fn random_ids_are_different() {
    let ids: HashSet<FileId> = (0..1000).map(|_| FileId::random()).collect();
    assert_eq!(ids.len(), 1000);
}

#[test]
fn an_id_is_22_url_safe_characters() {
    for _ in 0..200 {
        let text = FileId::random().to_string();
        assert_eq!(text.len(), 22);
        assert!(
            text.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{text}"
        );
    }
}

#[test]
fn an_id_round_trips_through_text() {
    for _ in 0..200 {
        let id = FileId::random();
        assert_eq!(id.to_string().parse::<FileId>().unwrap(), id);
    }
}

#[test]
fn the_text_form_is_fixed_for_known_bytes() {
    assert_eq!(
        FileId::from([0u8; FILE_ID_LEN]).to_string(),
        "AAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(
        FileId::from([0xFFu8; FILE_ID_LEN]).to_string(),
        "_____________________w"
    );
}

#[test]
fn the_bytes_are_kept_as_given() {
    let bytes: [u8; FILE_ID_LEN] = std::array::from_fn(|i| i as u8);
    assert_eq!(FileId::from(bytes).as_bytes(), &bytes);
}

#[test]
fn text_of_the_wrong_length_is_rejected() {
    for text in [
        "",
        "AAAA",
        "AAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert!(
            matches!(text.parse::<FileId>(), Err(ProtocolError::InvalidFileId)),
            "{text:?}"
        );
    }
}

#[test]
fn text_with_characters_outside_the_alphabet_is_rejected() {
    for text in [
        "AAAAAAAAAAAAAAAAAAAAA+",
        "AAAAAAAAAAAAAAAAAAAAA/",
        "AAAAAAAAAAAAAAAAAAAAA ",
        "AAAAAAAAAAAAAAAAAAAAA\n",
        "AAAAAAAAAAAAAAAAAAAA\u{e9}",
    ] {
        assert!(
            matches!(text.parse::<FileId>(), Err(ProtocolError::InvalidFileId)),
            "{text:?}"
        );
    }
}

#[test]
fn padding_is_rejected() {
    assert!(matches!(
        "AAAAAAAAAAAAAAAAAAAAAA==".parse::<FileId>(),
        Err(ProtocolError::InvalidFileId)
    ));
}

#[test]
fn a_second_spelling_of_the_same_bytes_is_rejected() {
    assert!(matches!(
        "AAAAAAAAAAAAAAAAAAAAAB".parse::<FileId>(),
        Err(ProtocolError::InvalidFileId)
    ));
}

#[tokio::test]
async fn on_the_wire_an_id_is_exactly_its_16_bytes() {
    let id = FileId::random();
    let mut bytes = Vec::new();
    write_message(&mut bytes, &id).await.unwrap();
    assert_eq!(bytes[LENGTH_PREFIX_LEN..], *id.as_bytes());
    assert_eq!(bytes[..LENGTH_PREFIX_LEN], 16u32.to_be_bytes());
    assert_eq!(
        read_message::<FileId, _>(&mut Cursor::new(bytes))
            .await
            .unwrap(),
        id
    );
}
