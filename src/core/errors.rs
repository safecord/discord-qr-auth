//! The errors types this crate uses.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DiscordQrAuthError {
    #[error("failed to connect to WebSocket")]
    ConnectionFailed(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("failed to create request")]
    RequestFailed(#[from] tokio_tungstenite::tungstenite::http::Error),
    #[error("failed to generate private key")]
    GenerateKeyFailed(#[from] rsa::errors::Error),
    #[error("unknown error")]
    Unknown,
}

#[derive(Error, Debug)]
pub enum DataError {
    #[error("the WebSocket connection hasn't been started")]
    NotConnected,
    #[error("the WebSocket connection is closed")]
    SocketClosed,
    #[error("unknown error")]
    Unknown,
}
