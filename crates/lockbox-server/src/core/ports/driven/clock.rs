pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}
