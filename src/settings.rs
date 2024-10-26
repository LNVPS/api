use http::Uri;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Settings {
    pub server: Uri,
    pub token_id: String,
    pub secret: String,
}