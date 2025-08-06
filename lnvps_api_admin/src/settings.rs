use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Settings {
    /// Listen address for http server
    pub listen: Option<String>,

    /// MYSQL connection string
    pub db: String,
}