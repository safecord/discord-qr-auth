use std::{sync::Arc, time::Duration};

use futures_util::{
    stream::{SplitSink, SplitStream, StreamExt},
    SinkExt,
};
use serde_json::{json, Value};
use tokio::{
    net::TcpStream,
    sync::{Mutex},
    time::{self, Interval},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{handshake::client::generate_key, http::Request, Message},
    MaybeTlsStream, WebSocketStream,
};

#[derive(Clone)]
pub struct Authwebsocket {
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

        Self {
            sender: Arc::new(Mutex::new(ws_sender)),
            receiver: Arc::new(Mutex::new(ws_receiver)),
            timeout: Arc::new(Mutex::new(time::interval(Duration::from_secs(60)))),
        }
    }

    pub async fn parser(self) {
        let mut receiver = self.receiver.lock_owned().await;

        tokio::task::spawn(async move {
            while let Some(msg) = receiver.next().await {
                let msg = msg.unwrap();

                if msg.is_text() {
                    let content: Value = serde_json::from_str(&msg.to_string()).unwrap();
                    println!("{}", content);

                    match content["op"].as_str() {
                        Some("hello") => {
                            let tx = self.sender.clone();
                            let duration = content["heartbeat_interval"].as_u64().unwrap();
                            tokio::task::spawn(async move {
                                println!("Heartbeating every {} ms", duration);
                                Authwebsocket::heartbeat(tx, duration).await;
                            });
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
