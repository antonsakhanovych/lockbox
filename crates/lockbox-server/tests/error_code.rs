use std::io;

use lockbox_protocol::{ErrorCode, ProtocolError};
use lockbox_server::core::error::CoreError;
use lockbox_server::core::ports::driven::StoreError;
use lockbox_server::core::ports::driving::ChannelError;

#[test]
fn a_denied_request_is_reported_as_denied() {
    assert_eq!(ErrorCode::from(&CoreError::Denied), ErrorCode::Denied);
}

#[test]
fn an_invalid_request_is_reported_as_invalid() {
    assert_eq!(
        ErrorCode::from(&CoreError::Invalid),
        ErrorCode::InvalidRequest
    );
}

#[test]
fn a_store_failure_is_reported_as_internal() {
    let error = CoreError::Store(StoreError::Io(io::Error::other("disk")));
    assert_eq!(ErrorCode::from(&error), ErrorCode::Internal);
}

#[test]
fn a_missing_file_in_the_store_is_reported_as_internal() {
    let error = CoreError::Store(StoreError::NotFound);
    assert_eq!(ErrorCode::from(&error), ErrorCode::Internal);
}

#[test]
fn the_text_of_an_internal_error_is_not_part_of_the_code() {
    let first = CoreError::Store(StoreError::Io(io::Error::other("one")));
    let second = CoreError::Store(StoreError::Io(io::Error::other("two")));
    assert_eq!(ErrorCode::from(&first), ErrorCode::from(&second));
}

#[test]
fn a_channel_i_o_failure_is_reported_as_internal() {
    let error = ChannelError::Io(io::Error::from(io::ErrorKind::BrokenPipe));
    assert_eq!(ErrorCode::from(&error), ErrorCode::Internal);
}

#[test]
fn a_message_the_peer_sent_that_cannot_be_read_is_invalid() {
    for protocol in [
        ProtocolError::MessageLimitExceeded { max: 1 },
        ProtocolError::TrailingBytes,
        ProtocolError::InvalidFileId,
        ProtocolError::UnexpectedMessage,
    ] {
        let error = ChannelError::Codec(protocol);
        assert_eq!(ErrorCode::from(&error), ErrorCode::InvalidRequest);
    }
}

#[test]
fn a_response_the_server_cannot_encode_is_internal() {
    let error = ChannelError::Codec(ProtocolError::MessageTooLarge { len: 2, max: 1 });
    assert_eq!(ErrorCode::from(&error), ErrorCode::Internal);
}
