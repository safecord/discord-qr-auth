use std::{str::from_utf8, sync::Arc, time::Duration};

use futures_util::{
    stream::{SplitSink, StreamExt},
    SinkExt,
};
use qrcode::QrCode;
use rand::{prelude::StdRng, SeedableRng};
use rsa::{
    pkcs8::{EncodePublicKey, LineEnding},
    PaddingScheme, RsaPrivateKey,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{net::TcpStream, sync::Mutex, task::JoinHandle, time};

use tokio_tungstenite::{
    connect_async,
    tungstenite::{handshake::client::generate_key, http::Request, Message},
    MaybeTlsStream, WebSocketStream,
};

pub struct DiscordUser {
    pub snowflake: u64,
    pub discriminator: String,
    pub avatar_hash: String,
    pub username: String,
}

pub enum DiscordQrAuthMessage {
    QrCode(QrCode),
    User(DiscordUser),
    Token(String),
    Disconnected,
}

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

pub struct Authwebsocket {
    pub event_receiver: flume::Receiver<DiscordQrAuthMessage>,
    pub handle: Option<JoinHandle<()>>,
    event_sender: flume::Sender<DiscordQrAuthMessage>,
}

impl Default for Authwebsocket {
    fn default() -> Self {
        let (event_sender, event_receiver) = flume::unbounded();

        Self {
            event_receiver,
            handle: None,
            event_sender,
        }
    }
}

macro_rules! ok_or_break {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(_) => {
                break;
            }
        }
    };
}

macro_rules! some_or_break {
    ($res:expr) => {
        match $res {
            Some(val) => val,
            None => {
                break;
            }
        }
    };
}

impl Authwebsocket {
    pub async fn get_code(&self) -> Result<QrCode, DataError> {
        match &self.handle {
            Some(handle) => {
                if handle.is_finished() {
                    return Err(DataError::SocketClosed);
                }
            }
            None => return Err(DataError::NotConnected),
        }

        match self.event_receiver.recv() {
            Ok(DiscordQrAuthMessage::QrCode(qr)) => Ok(qr),
            Ok(DiscordQrAuthMessage::Disconnected) => Err(DataError::SocketClosed),
            _ => Err(DataError::Unknown),
        }
    }

    pub async fn get_user(&self) -> Result<DiscordUser, DataError> {
        match &self.handle {
            Some(handle) => {
                if handle.is_finished() {
                    return Err(DataError::SocketClosed);
                }
            }
            None => return Err(DataError::NotConnected),
        }

        match self.event_receiver.recv() {
            Ok(DiscordQrAuthMessage::User(user)) => Ok(user),
            Ok(DiscordQrAuthMessage::Disconnected) => Err(DataError::SocketClosed),
            _ => Err(DataError::Unknown),
        }
    }

    pub async fn get_token(&self) -> Result<String, DataError> {
        match &self.handle {
            Some(handle) => {
                if handle.is_finished() {
                    return Err(DataError::SocketClosed);
                }
            }
            None => return Err(DataError::NotConnected),
        }

        match self.event_receiver.recv() {
            Ok(DiscordQrAuthMessage::Token(token)) => Ok(token),
            Ok(DiscordQrAuthMessage::Disconnected) => Err(DataError::SocketClosed),
            _ => Err(DataError::Unknown),
        }
    }

    pub async fn connect(&mut self) -> Result<(), DiscordQrAuthError> {
        let request = Request::builder().uri(String::from("wss://remote-auth-gateway.discord.gg/?v=1"))
            .header("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits")
            .header("Origin", "https://discord.com")
            .header("User-Agent", "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Mobile Safari/537.36 Edg/102.0.1245.33")
            .header("Sec-WebSocket-Key", generate_key())
            .header("Sec-WebSocket-Version", "13")
            .header("Host", "remote-auth-gateway.discord.gg")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .body(())?;

        let stream = connect_async(request).await?.0;

        let (ws_sender, mut ws_receiver) = stream.split();

        let ws_sender = Arc::new(Mutex::new(ws_sender));

        let event_sender = self.event_sender.clone();

        let mut rng: StdRng = SeedableRng::from_entropy();

        let privkey = RsaPrivateKey::new(&mut rng, 2048)?;

        let pubkey = privkey.to_public_key();

        let handle = tokio::task::spawn(async move {
            let mut initialized = false;

            while let Some(msg) = ws_receiver.next().await {
                let msg = ok_or_break!(msg);

                if msg.is_text() {
                    let content: Value = ok_or_break!(serde_json::from_str(&msg.to_string()));
                    println!("New message: {}", content);

                    match content["op"].as_str() {
                        Some("hello") => {
                            let tx = ws_sender.clone();
                            let duration = some_or_break!(content["heartbeat_interval"].as_u64());
                            tokio::task::spawn(async move {
                                println!("Heartbeating every {} ms", duration);
                                Authwebsocket::heartbeat(tx.clone(), duration).await;
                            });
                        }
                        Some("heartbeat_ack") => {
                            println!("Heartbeat acknowledged");
                            /* TODO: check if heartbeat_ack did not happen after heartbeat OP */

                            /* TODO: move this to hello OP */
                            if initialized == false {
                                let pem = ok_or_break!(pubkey.to_public_key_pem(LineEnding::LF));

                                let lines: String = pem.lines().skip(1).take(7).collect();

                                let init = Message::Text(
                                    json!({"op": "init", "encoded_public_key": lines}).to_string(),
                                );

                                ok_or_break!(ws_sender.clone().lock().await.send(init).await);

                                initialized = true;
                            }
                        }
                        Some("nonce_proof") => {
                            let encrypted_nonce =
                                ok_or_break!(base64::decode(some_or_break!(content
                                    ["encrypted_nonce"]
                                    .as_str())));

                            let nonce = ok_or_break!(privkey.decrypt(
                                PaddingScheme::new_oaep::<sha2::Sha256>(),
                                encrypted_nonce.as_slice(),
                            ));

                            let mut hasher = Sha256::new();

                            hasher.update(nonce);
                            let hashed_nonce = hasher.finalize();

                            let proof = base64::encode_config(hashed_nonce, base64::URL_SAFE)
                                .replace("=", "");

                            let response = Message::Text(
                                json!({"op": "nonce_proof", "proof": proof}).to_string(),
                            );

                            ok_or_break!(ws_sender.clone().lock().await.send(response).await);
                        }
                        Some("pending_remote_init") => {
                            /* TODO: return QrCode */
                            let fingerprint = some_or_break!(content["fingerprint"].as_str());

                            let code = ok_or_break!(QrCode::new(String::from(
                                "https://discordapp.com/ra/".to_owned() + fingerprint,
                            )));

                            ok_or_break!(event_sender.send(DiscordQrAuthMessage::QrCode(code)));
                        }
                        Some("pending_finish") => {
                            let data_encrypted =
                                ok_or_break!(base64::decode(some_or_break!(content
                                    ["encrypted_user_payload"]
                                    .as_str())));

                            let data = ok_or_break!(privkey.decrypt(
                                PaddingScheme::new_oaep::<sha2::Sha256>(),
                                &data_encrypted.as_slice(),
                            ));

                            let data_str = ok_or_break!(from_utf8(&data));
                            let formatted: Vec<&str> = data_str.split(":").collect();

                            let user = DiscordUser {
                                snowflake: ok_or_break!(formatted[0].parse::<u64>()),
                                discriminator: formatted[1].to_string(),
                                avatar_hash: formatted[2].to_string(),
                                username: formatted[3].to_string(),
                            };

                            ok_or_break!(event_sender.send(DiscordQrAuthMessage::User(user)));
                        }
                        Some("finish") => {
                            let encrypted_token =
                                ok_or_break!(base64::decode(some_or_break!(content
                                    ["encrypted_token"]
                                    .as_str())));

                            let data = ok_or_break!(privkey.decrypt(
                                PaddingScheme::new_oaep::<sha2::Sha256>(),
                                &encrypted_token.as_slice(),
                            ));

                            let token_str = ok_or_break!(from_utf8(&data));

                            ok_or_break!(event_sender
                                .send(DiscordQrAuthMessage::Token(token_str.to_string())));
                        }
                        None => {
                            break;
                        }
                        Some(&_) => (),
                    }
                }
            }

            println!("Disconnected");
            event_sender.send(DiscordQrAuthMessage::Disconnected).ok();
        });

        self.handle = Some(handle);

        Ok(())
    }

    pub async fn heartbeat(
        channel_sender: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
        interval: u64,
    ) {
        let mut interval = time::interval(Duration::from_millis(interval));

        loop {
            interval.tick().await;
            let blood_cell = Message::Text(json!({"op": "heartbeat"}).to_string());

            match channel_sender.lock().await.send(blood_cell).await {
                Ok(_) => println!("Sent heartbeat"),
                Err(_) => {
                    break;
                }
            }
        }
    }
}
