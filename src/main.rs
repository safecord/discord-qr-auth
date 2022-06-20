use qrcode::render::unicode;

use crate::modules::websocket::Authwebsocket;

pub mod modules {
    pub mod websocket;
}

#[tokio::main]
async fn main() {
    let mut ws = Authwebsocket::default();
    ws.connect().await.unwrap();
    let qr = ws.get_code().await.unwrap();

    let image = qr
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    println!("{}", image);

    let user = ws.get_user().await.unwrap();

    println!("User {} scanned QR code!", user.username);

    let token = ws.get_token().await.unwrap();

    println!("And we have a token! {}", token);

    ws.handle.unwrap().abort();

    println!("Handler stopped.");
}
