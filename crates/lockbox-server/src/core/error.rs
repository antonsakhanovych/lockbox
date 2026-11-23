#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("the request was denied")]
    Denied,
}

pub type Result<T> = std::result::Result<T, CoreError>;
