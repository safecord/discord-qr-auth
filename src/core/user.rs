/// Represents the data that Discord provides when a user scans a QR code.
pub struct DiscordUser {
    /// The user's ID
    pub snowflake: u64,
    /// Often called the "tag"
    pub discriminator: String,
    pub avatar_hash: String,
    pub username: String,
}
