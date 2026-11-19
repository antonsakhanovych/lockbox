use lockbox_protocol::codec::LENGTH_PREFIX_LEN;

pub fn frame(body: &[u8]) -> Vec<u8> {
    let mut wire = (body.len() as u32).to_be_bytes().to_vec();
    wire.extend_from_slice(body);
    wire
}

pub fn body(mut wire: Vec<u8>) -> Vec<u8> {
    wire.split_off(LENGTH_PREFIX_LEN)
}
