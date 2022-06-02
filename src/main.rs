use crate::modules::websocket::Authwebsocket;

pub mod modules {
    pub mod websocket;
}

#[tokio::main]
async fn main() {
    Authwebsocket::new("wss://remote-auth-gateway.discord.gg/?v=1".to_string()).await;
}
