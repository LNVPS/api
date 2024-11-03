use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Settings {
    pub server: String,
    pub user: String,
    pub realm: String,
    pub token_id: String,
    pub secret: String,
}