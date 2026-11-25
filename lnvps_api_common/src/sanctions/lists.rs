use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::LazyLock;

pub const SOURCE_OFAC_SDN: &str = "ofac_sdn";
pub const SOURCE_EU_FSF: &str = "eu_fsf";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartyKind {
    Individual,
    Entity,
    Vessel,
    Aircraft,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoAddress {
    pub asset: String,
    pub address: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListEntry {
    pub id: String,
    pub kind: PartyKind,
    pub names: Vec<String>,
    #[serde(default)]
    pub addresses: Vec<CryptoAddress>,
    #[serde(default)]
    pub emails: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedList {
    pub source: String,
    pub published: Option<String>,
    pub entries: Vec<ListEntry>,
}

static OFAC_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Digital Currency Address - ([A-Z0-9]+)\s+([A-Za-z0-9]+)").expect("regex")
});
static OFAC_EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Email Address\s+([^\s;]+)").expect("regex"));
static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+").expect("regex")
});
static BTC_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b((?i:bc1)[ac-hj-np-zAC-HJ-NP-Z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
        .expect("regex")
});

pub fn normalize_address(address: &str) -> String {
    let a = address.trim();
    let lower = a.to_ascii_lowercase();
    if lower.starts_with("bc1") || lower.starts_with("tb1") || lower.starts_with("bcrt1") {
        lower
    } else {
        a.to_string()
    }
}

pub fn normalize_email(email: &str) -> String {
    email.trim().trim_end_matches('.').to_lowercase()
}

fn ofac_field(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty() && t != "-0-").then(|| t.to_string())
}

fn ofac_reader(data: &[u8]) -> csv::Reader<&[u8]> {
    csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(data)
}

fn push_unique<T: PartialEq>(v: &mut Vec<T>, item: T) {
    if !v.contains(&item) {
        v.push(item);
    }
}

fn latin1(data: &[u8]) -> Vec<u8> {
    match std::str::from_utf8(data) {
        Ok(_) => data.to_vec(),
        Err(_) => data
            .iter()
            .map(|&b| b as char)
            .collect::<String>()
            .into_bytes(),
    }
}

pub fn parse_ofac(sdn: &[u8], alt: &[u8], comments: &[u8]) -> Result<ParsedList> {
    let sdn = latin1(sdn);
    let alt = latin1(alt);
    let comments = latin1(comments);
    let mut extra: BTreeMap<String, String> = BTreeMap::new();
    for row in ofac_reader(&comments).records() {
        let row = row.context("reading OFAC comments")?;
        if let (Some(id), Some(text)) = (row.get(0), row.get(1)) {
            extra
                .entry(id.trim().to_string())
                .or_default()
                .push_str(text);
        }
    }
    let mut entries: BTreeMap<String, ListEntry> = BTreeMap::new();
    for row in ofac_reader(&sdn).records() {
        let row = row.context("reading OFAC SDN")?;
        let Some(id) = row.get(0).and_then(ofac_field) else {
            continue;
        };
        if !id.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some(name) = row.get(1).and_then(ofac_field) else {
            continue;
        };
        let kind = match row.get(2).and_then(ofac_field).as_deref() {
            Some("individual") => PartyKind::Individual,
            Some("vessel") => PartyKind::Vessel,
            Some("aircraft") => PartyKind::Aircraft,
            _ => PartyKind::Entity,
        };
        let mut remarks = row
            .get(11)
            .filter(|s| s.trim() != "-0-")
            .unwrap_or_default()
            .to_string();
        if let Some(more) = extra.get(&id) {
            remarks.push_str(more);
        }
        let mut entry = ListEntry {
            id: id.clone(),
            kind,
            names: vec![name],
            ..Default::default()
        };
        for c in OFAC_ADDRESS.captures_iter(&remarks) {
            push_unique(
                &mut entry.addresses,
                CryptoAddress {
                    asset: c[1].to_string(),
                    address: normalize_address(&c[2]),
                },
            );
        }
        for c in OFAC_EMAIL.captures_iter(&remarks) {
            push_unique(&mut entry.emails, normalize_email(&c[1]));
        }
        entries.insert(id, entry);
    }
    for row in ofac_reader(&alt).records() {
        let row = row.context("reading OFAC ALT")?;
        let (Some(id), Some(name)) = (
            row.get(0).and_then(ofac_field),
            row.get(3).and_then(ofac_field),
        ) else {
            continue;
        };
        if let Some(e) = entries.get_mut(&id) {
            push_unique(&mut e.names, name);
        }
    }
    if entries.is_empty() {
        bail!("OFAC SDN list has no entries");
    }
    Ok(ParsedList {
        source: SOURCE_OFAC_SDN.to_string(),
        published: None,
        entries: entries.into_values().collect(),
    })
}

fn wallet_context(text: &str) -> bool {
    let l = text.to_lowercase();
    l.contains("wallet") || l.contains("bitcoin") || l.contains("btc") || l.contains("blockchain")
}

pub fn parse_eu(data: &[u8]) -> Result<ParsedList> {
    let data = data.strip_prefix("\u{feff}".as_bytes()).unwrap_or(data);
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b';')
        .flexible(true)
        .from_reader(data);
    let headers = reader.headers().context("reading EU headers")?.clone();
    let col = |name: &str| headers.iter().position(|h| h == name);
    let (Some(id_col), Some(name_col)) = (col("Entity_LogicalId"), col("NameAlias_WholeName"))
    else {
        bail!("EU list is missing Entity_LogicalId or NameAlias_WholeName");
    };
    let kind_col = col("Entity_SubjectType_ClassificationCode");
    let date_col = col("fileGenerationDate");
    let mut published = None;
    let mut entries: BTreeMap<String, ListEntry> = BTreeMap::new();
    for row in reader.records() {
        let row = row.context("reading EU list")?;
        let Some(id) = row.get(id_col).map(str::trim).filter(|s| !s.is_empty()) else {
            continue;
        };
        if published.is_none() {
            published = date_col
                .and_then(|c| row.get(c))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
        }
        let entry = entries.entry(id.to_string()).or_insert_with(|| ListEntry {
            id: id.to_string(),
            kind: match kind_col.and_then(|c| row.get(c)).map(str::trim) {
                Some("person") => PartyKind::Individual,
                Some("enterprise") => PartyKind::Entity,
                _ => PartyKind::Unknown,
            },
            ..Default::default()
        });
        if let Some(name) = row.get(name_col).map(str::trim).filter(|s| !s.is_empty()) {
            push_unique(&mut entry.names, name.to_string());
        }
        for raw in row.iter() {
            let cell = raw.replace("\\n", "\n");
            let cell = cell.as_str();
            if cell.contains('@') {
                for m in EMAIL.find_iter(cell) {
                    push_unique(&mut entry.emails, normalize_email(m.as_str()));
                }
            }
            if wallet_context(cell) {
                for m in BTC_ADDRESS.find_iter(cell) {
                    push_unique(
                        &mut entry.addresses,
                        CryptoAddress {
                            asset: "XBT".to_string(),
                            address: normalize_address(m.as_str()),
                        },
                    );
                }
            }
        }
    }
    entries.retain(|_, e| !e.names.is_empty());
    if entries.is_empty() {
        bail!("EU consolidated list has no entries");
    }
    Ok(ParsedList {
        source: SOURCE_EU_FSF.to_string(),
        published,
        entries: entries.into_values().collect(),
    })
}

pub fn encode_entries(entries: &[ListEntry]) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(entries)?;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&json)?;
    Ok(enc.finish()?)
}

pub fn decode_entries(blob: &[u8]) -> Result<Vec<ListEntry>> {
    let mut json = Vec::new();
    flate2::read::GzDecoder::new(blob)
        .read_to_end(&mut json)
        .context("decompressing sanctions list")?;
    Ok(serde_json::from_slice(&json)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sanctions::fixtures;

    #[test]
    fn ofac_fixture_parses_names_aliases_addresses_and_emails() {
        let list = fixtures::ofac().unwrap();
        assert_eq!(list.source, SOURCE_OFAC_SDN);
        let mesri = list.entries.iter().find(|e| e.id == "90001").unwrap();
        assert_eq!(mesri.kind, PartyKind::Individual);
        assert_eq!(mesri.names, vec!["TESTOV, Ivan Petrovich", "TESTOV, Vanya"]);
        assert_eq!(
            mesri.addresses,
            vec![
                CryptoAddress {
                    asset: "XBT".into(),
                    address: fixtures::OFAC_LISTED_ADDRESS.into()
                },
                CryptoAddress {
                    asset: "ETH".into(),
                    address: "0x00000000000000000000000000000000000f1x7e".into()
                }
            ]
        );
        assert_eq!(mesri.emails, vec!["listed.person@example.com"]);
        let continued = list.entries.iter().find(|e| e.id == "90003").unwrap();
        assert_eq!(continued.kind, PartyKind::Entity);
        assert_eq!(
            continued.addresses[0].address,
            fixtures::OFAC_CONTINUED_ADDRESS
        );
    }

    #[test]
    fn eu_fixture_groups_rows_and_extracts_wallets() {
        let list = fixtures::eu().unwrap();
        assert_eq!(list.source, SOURCE_EU_FSF);
        assert_eq!(list.published.as_deref(), Some("20/11/2026"));
        let ent = list.entries.iter().find(|e| e.id == "7001").unwrap();
        assert_eq!(ent.kind, PartyKind::Entity);
        assert_eq!(
            ent.names,
            vec!["Fixture Exchange LLC", "OOO Fixture Exchange"]
        );
        assert_eq!(ent.addresses[0].address, fixtures::EU_LISTED_ADDRESS);
        assert_eq!(
            ent.addresses[1].address,
            "3FxtrEuSecondAddr33333333333333333"
        );
        assert_eq!(ent.addresses.len(), 2);
        let person = list.entries.iter().find(|e| e.id == "7002").unwrap();
        assert_eq!(person.kind, PartyKind::Individual);
        assert!(person.addresses.is_empty());
        assert_eq!(person.emails, vec!["eu.listed@example.org"]);
    }

    #[test]
    fn entries_round_trip_through_the_stored_blob() {
        let list = fixtures::eu().unwrap();
        let blob = encode_entries(&list.entries).unwrap();
        assert_eq!(decode_entries(&blob).unwrap(), list.entries);
    }

    #[test]
    fn empty_lists_are_refused() {
        assert!(parse_ofac(b"", b"", b"").is_err());
        assert!(parse_eu(b"Entity_LogicalId;NameAlias_WholeName\n").is_err());
        assert!(parse_eu(b"a;b\n1;2\n").is_err());
    }

    #[test]
    fn addresses_normalise_bech32_case_only() {
        assert_eq!(normalize_address(" BC1QABC "), "bc1qabc");
        assert_eq!(normalize_address("1AbC"), "1AbC");
        assert_eq!(normalize_email(" X@Y.com. "), "x@y.com");
    }

    #[test]
    #[ignore = "reads downloaded official lists from LNVPS_SANCTIONS_DIR"]
    fn downloaded_lists_parse() {
        let dir = std::path::PathBuf::from(std::env::var("LNVPS_SANCTIONS_DIR").unwrap());
        let read = |f: &str| std::fs::read(dir.join(f)).unwrap();
        let ofac = parse_ofac(
            &read("SDN.CSV"),
            &read("ALT.CSV"),
            &read("SDN_COMMENTS.CSV"),
        )
        .unwrap();
        let eu = parse_eu(&read("eu.csv")).unwrap();
        let xbt = ofac
            .entries
            .iter()
            .flat_map(|e| &e.addresses)
            .filter(|a| a.asset == "XBT")
            .count();
        let eu_btc = eu.entries.iter().flat_map(|e| &e.addresses).count();
        println!(
            "ofac entries {} xbt {} eu entries {} eu btc {} published {:?}",
            ofac.entries.len(),
            xbt,
            eu.entries.len(),
            eu_btc,
            eu.published
        );
        assert!(xbt > 100);
        assert!(eu.entries.len() > 1000);
    }
}
