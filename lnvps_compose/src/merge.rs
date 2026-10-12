use anyhow::{Result, anyhow, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileFormat {
    Yaml,
    Toml,
    Json,
}

impl FileFormat {
    pub fn from_path(path: &str) -> Option<Self> {
        let (_, ext) = path.rsplit_once('.')?;
        match ext.to_ascii_lowercase().as_str() {
            "yaml" | "yml" => Some(Self::Yaml),
            "toml" => Some(Self::Toml),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Yaml => "YAML",
            Self::Toml => "TOML",
            Self::Json => "JSON",
        }
    }

    pub fn check_document(self, text: &str) -> Result<()> {
        if text.trim().is_empty() {
            return Ok(());
        }
        match self {
            Self::Yaml => yaml_map(text).map(drop),
            Self::Toml => toml_table(text).map(drop),
            Self::Json => json_map(text).map(drop),
        }
    }

    pub fn merge(self, base: &str, overlay: &str) -> Result<String> {
        if overlay.trim().is_empty() {
            return Ok(base.to_string());
        }
        match self {
            Self::Yaml => {
                let mut merged = yaml_map(base)?;
                merge_yaml(&mut merged, yaml_map(overlay)?);
                serde_yaml_ng::to_string(&serde_yaml_ng::Value::Mapping(merged))
                    .map_err(|e| anyhow!("{e}"))
            }
            Self::Toml => {
                let mut merged = toml_table(base)?;
                merge_toml(&mut merged, toml_table(overlay)?);
                toml::to_string(&merged).map_err(|e| anyhow!("{e}"))
            }
            Self::Json => {
                let mut merged = json_map(base)?;
                merge_json(&mut merged, json_map(overlay)?);
                serde_json::to_string_pretty(&serde_json::Value::Object(merged))
                    .map_err(|e| anyhow!("{e}"))
            }
        }
    }
}

fn yaml_map(text: &str) -> Result<serde_yaml_ng::Mapping> {
    match serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text).map_err(|e| anyhow!("{e}"))? {
        serde_yaml_ng::Value::Mapping(m) => Ok(m),
        serde_yaml_ng::Value::Null => Ok(serde_yaml_ng::Mapping::new()),
        _ => bail!("the top level must be a mapping of keys"),
    }
}

fn toml_table(text: &str) -> Result<toml::Table> {
    text.parse::<toml::Table>().map_err(|e| anyhow!("{e}"))
}

fn json_map(text: &str) -> Result<serde_json::Map<String, serde_json::Value>> {
    match serde_json::from_str::<serde_json::Value>(text).map_err(|e| anyhow!("{e}"))? {
        serde_json::Value::Object(m) => Ok(m),
        _ => bail!("the top level must be an object"),
    }
}

fn merge_yaml(base: &mut serde_yaml_ng::Mapping, overlay: serde_yaml_ng::Mapping) {
    use serde_yaml_ng::Value;
    for (key, value) in overlay {
        match value {
            Value::Null => {
                base.remove(&key);
            }
            Value::Mapping(inner) => match base.get_mut(&key) {
                Some(Value::Mapping(existing)) => merge_yaml(existing, inner),
                _ => {
                    base.insert(key, Value::Mapping(inner));
                }
            },
            other => {
                base.insert(key, other);
            }
        }
    }
}

fn merge_toml(base: &mut toml::Table, overlay: toml::Table) {
    for (key, value) in overlay {
        match value {
            toml::Value::Table(inner) => match base.get_mut(&key) {
                Some(toml::Value::Table(existing)) => merge_toml(existing, inner),
                _ => {
                    base.insert(key, toml::Value::Table(inner));
                }
            },
            other => {
                base.insert(key, other);
            }
        }
    }
}

fn merge_json(
    base: &mut serde_json::Map<String, serde_json::Value>,
    overlay: serde_json::Map<String, serde_json::Value>,
) {
    use serde_json::Value;
    for (key, value) in overlay {
        match value {
            Value::Null => {
                base.remove(&key);
            }
            Value::Object(inner) => match base.get_mut(&key) {
                Some(Value::Object(existing)) => merge_json(existing, inner),
                _ => {
                    base.insert(key, Value::Object(inner));
                }
            },
            other => {
                base.insert(key, other);
            }
        }
    }
}

pub fn parse_env_lines(text: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("line {}: expected KEY=VALUE", i + 1))?;
        let key = key.trim();
        if !is_env_name(key) {
            bail!(
                "line {}: '{key}' is not a valid variable name (letters, digits and _, not \
                 starting with a digit)",
                i + 1
            );
        }
        out.push((key.to_string(), unquote(value.trim()).to_string()));
    }
    Ok(out)
}

fn is_env_name(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn unquote(value: &str) -> &str {
    for q in ['"', '\''] {
        if value.len() >= 2 && value.starts_with(q) && value.ends_with(q) {
            return &value[1..value.len() - 1];
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_from_path() {
        assert_eq!(
            FileFormat::from_path("/app/config.yml"),
            Some(FileFormat::Yaml)
        );
        assert_eq!(
            FileFormat::from_path("/app/config.YAML"),
            Some(FileFormat::Yaml)
        );
        assert_eq!(
            FileFormat::from_path("/a/config.toml"),
            Some(FileFormat::Toml)
        );
        assert_eq!(FileFormat::from_path("/a/x.json"), Some(FileFormat::Json));
        assert_eq!(FileFormat::from_path("/etc/strfry.conf"), None);
        assert_eq!(FileFormat::from_path("/etc/noext"), None);
        assert_eq!(FileFormat::Toml.name(), "TOML");
        assert_eq!(FileFormat::Yaml.name(), "YAML");
        assert_eq!(FileFormat::Json.name(), "JSON");
    }

    #[test]
    fn yaml_deep_merge_overrides_and_removes() {
        let base = "a: 1\nnested:\n  keep: x\n  change: y\nlist: [1, 2]\ngone: true\n";
        let overlay = "nested:\n  change: z\n  added: 3\nlist: [9]\ngone: null\nnew: hi\n";
        let merged = FileFormat::Yaml.merge(base, overlay).unwrap();
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&merged).unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(v["nested"]["keep"], "x");
        assert_eq!(v["nested"]["change"], "z");
        assert_eq!(v["nested"]["added"], 3);
        assert_eq!(
            v["list"],
            serde_yaml_ng::from_str::<serde_yaml_ng::Value>("[9]").unwrap()
        );
        assert_eq!(v["new"], "hi");
        assert!(v.get("gone").is_none());
    }

    #[test]
    fn yaml_scalar_replaces_mapping_and_mapping_replaces_scalar() {
        let merged = FileFormat::Yaml
            .merge("a:\n  b: 1\nc: 2\n", "a: flat\nc:\n  d: 3\n")
            .unwrap();
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&merged).unwrap();
        assert_eq!(v["a"], "flat");
        assert_eq!(v["c"]["d"], 3);
    }

    #[test]
    fn toml_deep_merge() {
        let base = "[info]\nname = \"a\"\ndescription = \"d\"\n[network]\nport = 8080\n";
        let overlay = "[info]\nname = \"b\"\n[limits]\nmessages_per_sec = 5\n";
        let merged = FileFormat::Toml.merge(base, overlay).unwrap();
        let v: toml::Table = merged.parse().unwrap();
        assert_eq!(v["info"]["name"].as_str(), Some("b"));
        assert_eq!(v["info"]["description"].as_str(), Some("d"));
        assert_eq!(v["network"]["port"].as_integer(), Some(8080));
        assert_eq!(v["limits"]["messages_per_sec"].as_integer(), Some(5));
        let replaced = FileFormat::Toml
            .merge("a = 1\n[t]\nx = 1\n", "a = 2\nt = 3\n")
            .unwrap();
        let v: toml::Table = replaced.parse().unwrap();
        assert_eq!(v["a"].as_integer(), Some(2));
        assert_eq!(v["t"].as_integer(), Some(3));
        let table_over_scalar = FileFormat::Toml.merge("a = 1\n", "[a]\nb = 2\n").unwrap();
        let v: toml::Table = table_over_scalar.parse().unwrap();
        assert_eq!(v["a"]["b"].as_integer(), Some(2));
    }

    #[test]
    fn json_deep_merge() {
        let merged = FileFormat::Json
            .merge(
                r#"{"a":{"b":1,"c":2},"d":3,"e":4}"#,
                r#"{"a":{"b":9},"d":null,"e":{"f":1},"g":"x"}"#,
            )
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(v["a"]["b"], 9);
        assert_eq!(v["a"]["c"], 2);
        assert!(v.get("d").is_none());
        assert_eq!(v["e"]["f"], 1);
        assert_eq!(v["g"], "x");
    }

    #[test]
    fn blank_overlay_keeps_base_verbatim() {
        let base = "# comment\na: 1\n";
        assert_eq!(FileFormat::Yaml.merge(base, "  \n").unwrap(), base);
        assert_eq!(FileFormat::Toml.merge("x = 1", "").unwrap(), "x = 1");
    }

    #[test]
    fn check_document_rejects_bad_input() {
        assert!(FileFormat::Yaml.check_document("").is_ok());
        assert!(FileFormat::Yaml.check_document("a: 1").is_ok());
        assert!(FileFormat::Yaml.check_document("~").is_ok());
        assert!(FileFormat::Yaml.check_document("- a\n- b").is_err());
        assert!(FileFormat::Yaml.check_document("a: [").is_err());
        assert!(FileFormat::Toml.check_document("a = 1").is_ok());
        assert!(FileFormat::Toml.check_document("a = ").is_err());
        assert!(FileFormat::Json.check_document("{\"a\":1}").is_ok());
        assert!(FileFormat::Json.check_document("[1]").is_err());
        assert!(FileFormat::Json.check_document("{").is_err());
        assert!(FileFormat::Json.merge("[1]", "{\"a\":1}").is_err());
        assert!(FileFormat::Toml.merge("a =", "b = 1").is_err());
    }

    #[test]
    fn env_lines() {
        let parsed = parse_env_lines(
            "# comment\n\nFOO=bar\nexport BAZ = \"quoted value\"\nEMPTY=\nSINGLE='x=y'\n_U1=a=b\n",
        )
        .unwrap();
        assert_eq!(
            parsed,
            vec![
                ("FOO".into(), "bar".into()),
                ("BAZ".into(), "quoted value".into()),
                ("EMPTY".into(), "".into()),
                ("SINGLE".into(), "x=y".into()),
                ("_U1".into(), "a=b".into()),
            ]
        );
        assert!(parse_env_lines("NOEQUALS").is_err());
        assert!(parse_env_lines("1BAD=x").is_err());
        assert!(parse_env_lines("BAD-NAME=x").is_err());
        assert!(parse_env_lines("=x").is_err());
        assert_eq!(unquote("\""), "\"");
    }
}
