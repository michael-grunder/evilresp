use std::io;
use std::net::AddrParseError;

use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid socket address: {0}")]
    AddrParse(#[from] AddrParseError),

    #[error("RESP parse error: {0}")]
    Resp(String),

    #[error("invalid evil configuration: {0}")]
    EvilConfig(String),

    #[error("invalid proxy response: {0}")]
    Proxy(String),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}
