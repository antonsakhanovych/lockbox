pub(crate) const SIGN: &[u8] = b"lockbox/v1/sign";

pub(crate) fn prepend_domain(domain: &[u8], message: &[u8]) -> Vec<u8> {
    let mut byte_vec = Vec::with_capacity(domain.len() + message.len());
    byte_vec.extend_from_slice(domain);
    byte_vec.extend_from_slice(message);
    byte_vec
}
