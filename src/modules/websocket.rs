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
}

#[derive(Error, Debug)]
pub enum DiscordQrAuthError {
    #[error("failed to connect to WebSocket")]
    ConnectionFailed(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("failed to create request")]
    RequestFailed(#[from] tokio_tungstenite::tungstenite::http::Error),
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

        while let Ok(msg) = self.event_receiver.recv() {
            if let DiscordQrAuthMessage::QrCode(qr) = msg {
                return Ok(qr);
            }
        }

        Err(DataError::Unknown)
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

        while let Ok(msg) = self.event_receiver.recv() {
            if let DiscordQrAuthMessage::User(user) = msg {
                return Ok(user);
            }
        }
        Err(DataError::Unknown)
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

        while let Ok(msg) = self.event_receiver.recv() {
            if let DiscordQrAuthMessage::Token(token) = msg {
                return Ok(token);
            }
        }
        Err(DataError::Unknown)
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

        let privkey = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate key");

        let pubkey = privkey.to_public_key();

        let handle = tokio::task::spawn(async move {
            let mut initialized = false;

            while let Some(msg) = ws_receiver.next().await {
                let msg = msg.unwrap();

                if msg.is_text() {
                    let content: Value = serde_json::from_str(&msg.to_string()).unwrap();
                    println!("New message: {}", content);

                    match content["op"].as_str() {
                        Some("hello") => {
                            let tx = ws_sender.clone();
                            let duration = content["heartbeat_interval"].as_u64().unwrap();
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
                                let pem = pubkey.to_public_key_pem(LineEnding::LF).unwrap();

                                let lines: String = pem.lines().skip(1).take(7).collect();

                                let init = Message::Text(
                                    json!({"op": "init", "encoded_public_key": lines}).to_string(),
                                );

                                match ws_sender.clone().lock().await.send(init).await {
                                    Ok(_) => println!("Sent init message"),
                                    Err(err) => panic!("AuthWebSocket::parser - Error: {:?}", &err),
                                }

                                initialized = true;
                            }
                        }
                        Some("nonce_proof") => {
                            let encrypted_nonce =
                                base64::decode(content["encrypted_nonce"].as_str().unwrap())
                                    .unwrap();

                            let nonce = match privkey.decrypt(
                                PaddingScheme::new_oaep::<sha2::Sha256>(),
                                encrypted_nonce.as_slice(),
                            ) {
                                Ok(nonce) => nonce,
                                Err(err) => panic!("Failed to decrypt nonce: {:?}", &err),
                            };

                            let mut hasher = Sha256::new();

                            hasher.update(nonce);
                            let hashed_nonce = hasher.finalize();

                            let proof = base64::encode_config(hashed_nonce, base64::URL_SAFE)
                                .replace("=", "");

                            let response = Message::Text(
                                json!({"op": "nonce_proof", "proof": proof}).to_string(),
                            );

                            match ws_sender.clone().lock().await.send(response).await {
                                Ok(_) => println!("Sent nonce_proof message"),
                                Err(err) => panic!("AuthWebSocket::parser - Error: {:?}", &err),
                            }
                        }
                        Some("pending_remote_init") => {
                            /* TODO: return QrCode */
                            let fingerprint = content["fingerprint"].as_str().unwrap();

                            let code = QrCode::new(String::from(
                                "https://discordapp.com/ra/".to_owned() + fingerprint,
                            ))
                            .unwrap();

                            event_sender
                                .send(DiscordQrAuthMessage::QrCode(code))
                                .unwrap();
                        }
                        Some("pending_finish") => {
                            let data_encrypted =
                                base64::decode(content["encrypted_user_payload"].as_str().unwrap())
                                    .unwrap();

                            let data = match privkey.decrypt(
                                PaddingScheme::new_oaep::<sha2::Sha256>(),
                                &data_encrypted.as_slice(),
                            ) {
                                Ok(nonce) => nonce,
                                Err(err) => panic!("Failed to decrypt user payload: {:?}", &err),
                            };

                            let data_str = from_utf8(&data).unwrap();
                            let formatted: Vec<&str> = data_str.split(":").collect();

                            let user = DiscordUser {
                                snowflake: formatted[0]
                                    .parse::<u64>()
                                    .expect("error parsing snowflake."),
                                discriminator: formatted[1].to_string(),
                                avatar_hash: formatted[2].to_string(),
                                username: formatted[3].to_string(),
                            };

                            event_sender.send(DiscordQrAuthMessage::User(user)).unwrap();
                        }
                        Some("finish") => {
                            let encrypted_token =
                                base64::decode(content["encrypted_token"].as_str().unwrap())
                                    .unwrap();

                            let data = match privkey.decrypt(
                                PaddingScheme::new_oaep::<sha2::Sha256>(),
                                &encrypted_token.as_slice(),
                            ) {
                                Ok(token) => token,
                                Err(_) => panic!("Failed to decrypt token"),
                            };

                            let token_str = from_utf8(&data).unwrap();

                            event_sender
                                .send(DiscordQrAuthMessage::Token(token_str.to_string()))
                                .unwrap();
                        }
                        None => {
                            panic!("AuthWebSocket::parser - Error")
                        }
                        Some(&_) => (),
                    }
                }
            }
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
                Err(err) => {
                    panic!("AuthWebSocket::heartbeat - Error: {:?}", &err);
                }
            }
        }
    }
}
