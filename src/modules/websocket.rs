use std::{str::from_utf8, sync::Arc, time::Duration};

use futures_util::{
    stream::{SplitSink, SplitStream, StreamExt},
    SinkExt,
};
use qrcode::QrCode;
use rand::{prelude::StdRng, SeedableRng};
use rsa::{
    pkcs8::{EncodePublicKey, LineEnding},
    PaddingScheme, RsaPrivateKey, RsaPublicKey,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::{
    net::TcpStream,
    sync::Mutex,
    time::{self, Interval},
};

use image::Luma;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{handshake::client::generate_key, http::Request, Message},
    MaybeTlsStream, WebSocketStream,
};

struct DiscordUser {
    snowflake: u64,
    discriminator: u8,
    avatar_hash: String,
    username: String,
}

#[derive(Clone)]
pub struct Authwebsocket {
    pub key: Arc<Mutex<RsaPrivateKey>>,
    pub timeout: Arc<Mutex<Interval>>,
    pub sender: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
    pub receiver: Arc<Mutex<SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>>>,
}

impl Authwebsocket {
    pub async fn new(url: String) -> Self {
        let request = Request::builder().uri(url)
        .header("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits")
        .header("Origin", "https://discord.com")
        .header("User-Agent", "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Mobile Safari/537.36 Edg/102.0.1245.33")
        .header("Sec-WebSocket-Key", generate_key())
        .header("Sec-WebSocket-Version", "13")
        .header("Host", "remote-auth-gateway.discord.gg")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .body(()).unwrap();

        let stream = match connect_async(request).await {
            Ok(stream) => stream.0,
            Err(err) => panic!("Error connecting to the Discord gateway: {:?}", &err),
        };

        let (ws_sender, ws_receiver) = stream.split();

        let mut rng: StdRng = SeedableRng::from_entropy();
        let key = Arc::new(Mutex::new(
            RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate key"),
        ));

        Self {
            sender: Arc::new(Mutex::new(ws_sender)),
            receiver: Arc::new(Mutex::new(ws_receiver)),
            timeout: Arc::new(Mutex::new(time::interval(Duration::from_secs(60)))),
            key,
        }
    }

    pub async fn parser(self) {
        let mut receiver = self.receiver.lock_owned().await;

        let mut initialized = false;

        tokio::task::spawn(async move {
            while let Some(msg) = receiver.next().await {
                let msg = msg.unwrap();

                if msg.is_text() {
                    let content: Value = serde_json::from_str(&msg.to_string()).unwrap();
                    println!("New message: {}", content);

                    match content["op"].as_str() {
                        Some("hello") => {
                            let tx = self.sender.clone();
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
                                let key = self.key.lock().await;
                                let pem = RsaPublicKey::from(&*key)
                                    .to_public_key_pem(LineEnding::LF)
                                    .unwrap();

                                let lines: String = pem.lines().skip(1).take(7).collect();
                                //println!("{:?}", lines);

                                let init = Message::Text(
                                    json!({"op": "init", "encoded_public_key": lines}).to_string(),
                                );

                                match self.sender.clone().lock().await.send(init).await {
                                    Ok(_) => println!("Sent init message"),
                                    Err(err) => panic!("AuthWebSocket::parser - Error: {:?}", &err),
                                }

                                initialized = true;
                            }
                        }
                        Some("nonce_proof") => {
                            let key = self.key.lock().await;
                            let encrypted_nonce =
                                base64::decode(content["encrypted_nonce"].as_str().unwrap())
                                    .unwrap();

                            let nonce = match key.decrypt(
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

                            match self.sender.clone().lock().await.send(response).await {
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

                            let img = code.render::<Luma<u8>>().build();
                            img.save("code.png").unwrap();
                        }
                        Some("pending_finish") => {
                            let data_encrypted =
                                base64::decode(content["encrypted_user_payload"].as_str().unwrap())
                                    .unwrap();
                            let key = self.key.lock().await;

                            let data = match key.decrypt(
                                PaddingScheme::new_oaep::<sha2::Sha256>(),
                                &data_encrypted.as_slice(),
                            ) {
                                Ok(nonce) => nonce,
                                Err(err) => panic!("Failed to decrypt user payload: {:?}", &err),
                            };

                            let data_str = from_utf8(&data).unwrap();
                            let formatted: Vec<&str> = data_str.split(":").collect();

                            let user = DiscordUser {
                                snowflake: formatted[0].parse::<u64>().unwrap(),
                                discriminator: formatted[1].parse::<u8>().unwrap(),
                                avatar_hash: formatted[2].to_string(),
                                username: formatted[3].to_string(),
                            };
                        }
                        None => {
                            panic!("AuthWebSocket::parser - Error")
                        }
                        Some(&_) => (),
                    }
                }
            }
        })
        .await
        .unwrap();
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
