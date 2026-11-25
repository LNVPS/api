use super::{ListRef, ParsedList, parse_eu, parse_ofac};
use anyhow::Result;
use chrono::{TimeZone, Utc};

pub const OFAC_SDN: &[u8] = include_bytes!("fixtures/SDN.CSV");
pub const OFAC_ALT: &[u8] = include_bytes!("fixtures/ALT.CSV");
pub const OFAC_COMMENTS: &[u8] = include_bytes!("fixtures/SDN_COMMENTS.CSV");
pub const EU_CSV: &[u8] = include_bytes!("fixtures/eu.csv");

pub const OFAC_LISTED_ADDRESS: &str = "bc1qsdnfxture00000000000000000000000000000";
pub const OFAC_CONTINUED_ADDRESS: &str = "3FxtrCntnuedAddr2222222222222222";
pub const EU_LISTED_ADDRESS: &str = "bc1qeufxture00000000000000000000000000000000";
pub const UNLISTED_ADDRESS: &str = "bc1qunlistedfixture0000000000000000000000";

pub fn ofac() -> Result<ParsedList> {
    parse_ofac(OFAC_SDN, OFAC_ALT, OFAC_COMMENTS)
}

pub fn eu() -> Result<ParsedList> {
    parse_eu(EU_CSV)
}

pub fn list_ref(list: &ParsedList) -> ListRef {
    ListRef {
        id: None,
        source: list.source.clone(),
        version: "fixture".to_string(),
        fetched: Utc.timestamp_opt(1_800_000_000, 0).single(),
    }
}
