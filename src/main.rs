use crate::modules::websocket::Authwebsocket;

pub mod modules {
    pub mod websocket;
}

#[tokio::main]
async fn main() {
    let mut ws = Authwebsocket::new("wss://remote-auth-gateway.discord.gg/?v=1".to_string()).await; 
    ws.parser().await;
}
