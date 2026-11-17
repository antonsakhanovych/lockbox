//! One transport per way of connecting. A transport accepts clients and moves
//! messages to and from them, then hands each connection to a [`session`](crate::session).

pub mod tcp;
