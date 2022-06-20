use qrcode::render::unicode;
use discord_qr_auth::core::websocket::Client;

#[tokio::main]
async fn main() {
    let mut ws = Client::default();
    ws.connect().await.unwrap();
    let qr = ws.get_code().await.unwrap();

    let image = qr
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    println!("{}\nScan this QR code in the Discord app on your phone.", image);

    let user = ws.get_user().await.unwrap();

    println!("User {} scanned QR code!", user.username);

    let token = ws.get_token().await.unwrap();

    println!("User accepted log-in. Token: {}", token);
}