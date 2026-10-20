use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapData {
    pub coin: String,
    pub order_id: String,
    pub order_token: String,
    pub deposit_address: String,
    pub deposit_amount: String,
    pub receive_address: String,
}

impl SwapData {
    pub fn parse(raw: &str) -> Result<Self> {
        Ok(serde_json::from_str(raw)?)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> SwapData {
        SwapData {
            coin: "XMR".to_string(),
            order_id: "ABC".to_string(),
            order_token: "tok".to_string(),
            deposit_address: "4deposit".to_string(),
            deposit_amount: "0.5".to_string(),
            receive_address: "bc1qours".to_string(),
        }
    }

    #[test]
    fn swap_data_round_trips_through_json() {
        let d = data();
        assert_eq!(SwapData::parse(&d.to_json().unwrap()).unwrap(), d);
    }

    #[test]
    fn swap_data_rejects_garbage() {
        assert!(SwapData::parse("not json").is_err());
        assert!(SwapData::parse("{}").is_err());
    }
}
