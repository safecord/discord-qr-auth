use std::{sync::Arc, time::Duration};

use futures_util::{stream::StreamExt, SinkExt};
use serde_json::{json, Value};
use tokio::{
    net::TcpStream,
    sync::Mutex,
    time::{self, Interval},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{handshake::client::generate_key, http::Request, Message},
    MaybeTlsStream, WebSocketStream,
};

#[derive(Clone)]
pub struct Authwebsocket {
    pub stream: Arc<Mutex<WebSocketStream<MaybeTlsStream<TcpStream>>>>,
    pub interval: Arc<Mutex<Interval>>,
    pub timeout: Arc<Mutex<Interval>>,
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

        Self {
            stream: match connect_async(request).await {
                Ok(stream) => Arc::new(Mutex::new(stream.0)),
                Err(err) => panic!("Error connecting to the Discord gateway: {:?}", &err),
            },
            interval: Arc::new(Mutex::new(time::interval(Duration::from_secs(60)))),
            timeout: Arc::new(Mutex::new(time::interval(Duration::from_secs(60)))),
        }
    }

    pub async fn parser(mut self) {
        // let mut auth = self.clone();
        while let Some(msg) = self.stream.lock().await.next().await {
            let msg = msg.unwrap();

            if msg.is_text() {
                let content: Value = serde_json::from_str(&msg.to_string()).unwrap();

                match content["op"].as_str() {
                    Some("hello") => {
                        self.interval = Arc::new(Mutex::new(time::interval(
                            Duration::from_millis(content["heartbeat_interval"].as_u64().unwrap()),
                        )));
                        self.timeout = Arc::new(Mutex::new(time::interval(Duration::from_millis(
                            content["timeout_ms"].as_u64().unwrap(),
                        ))));

                        tokio::spawn(async move {
                            loop {
                                self.heartbeat();
                                //Authwebsocket::heartbeat(&mut self);
                            }
                        });
                    }
                    None => {
                        panic!("AuthWebSocket::parser - Error")
                    }
                    Some(&_) => (),
                }
            }
        }
    }

    pub async fn heartbeat(&mut self) {
        self.interval.lock().await.tick().await;

        let blood_cell = Message::Text(json!({"op": "heartbeat"}).to_string());

        match self.stream.lock().await.send(blood_cell).await {
            Ok(_) => println!("sent heartbeat"),
            Err(err) => {
                panic!("AuthWebSocket::heartbeat - Error: {:?}", &err);
            }
        }
    }
}
