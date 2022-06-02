use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, WebSocketStream, MaybeTlsStream, tungstenite::http::{self, Request}};
use futures_util::stream::StreamExt;

pub struct Authwebsocket {
    pub stream: WebSocketStream<MaybeTlsStream<TcpStream>>
}

impl Authwebsocket {
    pub async fn new(url: String) -> Self {
        let req: Request = Request::builder().uri(url).header("Origin", "https://discord.com");

        Self {
            stream: match connect_async(Request::builder().uri(url).header("Origin", "https://discord.com").try_into()).await {
                Ok(stream) => {
                    stream.0
                },
                Err(err) => panic!("Error connecting to the Discord gateway: {:?}", &err),
            }
        }
    }

    pub async fn parser(&mut self) {
        while let Some(msg) = self.stream.next().await {
            let msg = msg.unwrap();
            println!("{:?}", msg);
        }
    }

    pub async fn heartbeat() {

    }
}