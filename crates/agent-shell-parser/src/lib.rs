pub mod hook;
pub mod parse;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("failed to read stdin: {0}")]
    Stdin(#[from] std::io::Error),
    #[error("failed to parse JSON input: {0}")]
    Json(#[from] serde_json::Error),
}
