//! Parser, validator and `${…}` resolver for the app-catalog **compose-ish**
//! YAML.
//!
//! The catalog stores each app as a small compose-style document with four
//! top-level keys (no `x-*` extensions):
//!
//! - `services:` — one or more containers (image / ports / env / volumes).
//! - `secrets:` — values the operator generates **once** per deployment and
//!   injects wherever `${NAME}` is referenced (e.g. a DB password shared by two
//!   services).
//! - `config:` — fields the customer fills in (rendered as a form); their
//!   values are stored on the deployment and injected as env.
//!
//! This module only turns the YAML into a typed model, validates it, and
//! resolves `${…}` references. The Kubernetes object mapping lives elsewhere.

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::collections::HashMap;

/// A parsed app compose document.
#[derive(Debug, Clone, Deserialize)]
pub struct Compose {
    /// Named services (containers). Order is not significant; ordering hints are
    /// expressed via `depends_on` (advisory).
    pub services: HashMap<String, Service>,
    /// Operator-generated secrets, injected as env wherever referenced.
    #[serde(default)]
    pub secrets: Vec<SecretDecl>,
    /// Customer-provided configuration fields (the deploy form).
    #[serde(default)]
    pub config: Vec<ConfigField>,
}

/// A single service/container within an app.
#[derive(Debug, Clone, Deserialize)]
pub struct Service {
    /// Container image reference.
    pub image: String,
    /// Exposed/served ports.
    #[serde(default)]
    pub ports: Vec<Port>,
    /// Environment variables (values may contain `${…}` references).
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Persistent volumes → PVCs.
    #[serde(default)]
    pub volumes: Vec<Volume>,
    /// Advisory startup ordering hints (k8s has no hard ordering; apps retry).
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Optional backup method for this service's data.
    #[serde(default)]
    pub backup: Option<Backup>,
}

/// How a port is exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Expose {
    /// Internal only (ClusterIP Service). Default.
    #[default]
    None,
    /// Public HTTP(S) via nginx Ingress + cert-manager TLS (http protocol only).
    Ingress,
    /// Raw L4 TCP (ingress-controller TCP passthrough / NodePort). Not in MVP.
    Tcp,
    /// Raw L4 UDP. Not in MVP.
    Udp,
}

/// Wire protocol of a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    #[default]
    Tcp,
    Udp,
}

/// A service port.
#[derive(Debug, Clone, Deserialize)]
pub struct Port {
    /// Port name (used for the k8s Service port and ingress backend).
    pub name: String,
    /// Container port number.
    pub container: u16,
    #[serde(default)]
    pub protocol: Protocol,
    #[serde(default)]
    pub expose: Expose,
    /// Ingress path (defaults to `/`), only meaningful for `expose: ingress`.
    #[serde(default)]
    pub path: Option<String>,
}

/// A persistent volume mounted into a service → one PVC.
#[derive(Debug, Clone, Deserialize)]
pub struct Volume {
    /// Volume name (becomes the PVC name suffix; must be a slug).
    pub name: String,
    /// Absolute mount path inside the container.
    pub path: String,
    /// Requested size, e.g. `5Gi`.
    pub size: String,
}

/// An operator-generated secret.
#[derive(Debug, Clone, Deserialize)]
pub struct SecretDecl {
    /// Env var name the generated value is bound to (referenced as `${name}`).
    pub name: String,
    /// How to generate it.
    #[serde(default)]
    pub generate: Generate,
}

/// Secret generation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Generate {
    /// A random URL-safe password.
    #[default]
    Password,
    /// A random hex token.
    Token,
}

/// A customer-provided config field (rendered as a form input).
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigField {
    /// Env var name (referenced as `${name}`).
    pub name: String,
    /// Human-readable form label.
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub r#type: FieldType,
    /// Default value when the customer leaves it blank.
    #[serde(default)]
    pub default: Option<String>,
    /// Whether the field must be supplied.
    #[serde(default)]
    pub required: bool,
}

/// Config field input type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    #[default]
    String,
    Int,
    Bool,
}

/// A service's backup method.
#[derive(Debug, Clone, Deserialize)]
pub struct Backup {
    /// App-consistent dump command; stdout is captured as the artifact.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// Alternatively, raw tar of this named volume (append-only data only).
    #[serde(default)]
    pub volume: Option<String>,
    /// Suggested artifact filename.
    #[serde(default)]
    pub artifact: Option<String>,
}

impl Compose {
    /// Parse an app compose document from YAML.
    pub fn parse(yaml: &str) -> Result<Self> {
        let c: Compose =
            serde_yaml::from_str(yaml).map_err(|e| anyhow!("invalid compose YAML: {e}"))?;
        c.validate()?;
        Ok(c)
    }

    /// Validate structural + policy rules. Enforced at parse time so the
    /// operator never tries to render an unsafe or malformed app.
    pub fn validate(&self) -> Result<()> {
        if self.services.is_empty() {
            bail!("compose must define at least one service");
        }
        for (sname, svc) in &self.services {
            if svc.image.trim().is_empty() {
                bail!("service '{sname}': image is required");
            }
            for p in &svc.ports {
                // Ingress is HTTP only (WebSocket rides HTTP → wss).
                if p.expose == Expose::Ingress && p.protocol != Protocol::Http {
                    bail!(
                        "service '{sname}' port '{}': expose: ingress requires protocol: http",
                        p.name
                    );
                }
            }
            for v in &svc.volumes {
                validate_mount_path(sname, &v.name, &v.path)?;
            }
            // depends_on must reference real services.
            for dep in &svc.depends_on {
                if !self.services.contains_key(dep) {
                    bail!("service '{sname}': depends_on unknown service '{dep}'");
                }
            }
            // A backup entry is exactly one of command | volume.
            if let Some(b) = &svc.backup {
                match (&b.command, &b.volume) {
                    (Some(_), Some(_)) => {
                        bail!("service '{sname}': backup has both command and volume")
                    }
                    (None, None) => {
                        bail!("service '{sname}': backup needs either command or volume")
                    }
                    (None, Some(vol)) => {
                        if !svc.volumes.iter().any(|v| &v.name == vol) {
                            bail!("service '{sname}': backup volume '{vol}' is not declared");
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Every distinct env var name referenced as `${…}` across all services.
    pub fn referenced_vars(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for svc in self.services.values() {
            for val in svc.env.values() {
                for name in extract_refs(val) {
                    if !out.contains(&name) {
                        out.push(name);
                    }
                }
            }
        }
        out
    }

    /// Resolve every service's env by substituting `${NAME}` from `vars`.
    ///
    /// `vars` is the merged map of generated secret values, resolved config
    /// values, and operator-provided context (e.g. `HOSTNAME`). A reference with
    /// no matching entry is an error, so a misconfigured app fails loudly rather
    /// than silently shipping an empty value.
    pub fn resolve_env(
        &self,
        vars: &HashMap<String, String>,
    ) -> Result<HashMap<String, HashMap<String, String>>> {
        let mut out = HashMap::new();
        for (sname, svc) in &self.services {
            let mut resolved = HashMap::new();
            for (k, v) in &svc.env {
                resolved.insert(k.clone(), substitute(v, vars)?);
            }
            out.insert(sname.clone(), resolved);
        }
        Ok(out)
    }
}

/// Validate a volume mount path: absolute, no `..` traversal, not root.
fn validate_mount_path(service: &str, name: &str, path: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("service '{service}': volume name '{name}' must be a lowercase slug");
    }
    if !path.starts_with('/') {
        bail!("service '{service}': volume '{name}' path must be absolute");
    }
    if path == "/" {
        bail!("service '{service}': volume '{name}' cannot mount at '/'");
    }
    if path.split('/').any(|seg| seg == "..") {
        bail!("service '{service}': volume '{name}' path must not contain '..'");
    }
    Ok(())
}

/// Extract the `NAME`s referenced as `${NAME}` in a string.
fn extract_refs(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$'
            && bytes[i + 1] == b'{'
            && let Some(end) = s[i + 2..].find('}')
        {
            let name = &s[i + 2..i + 2 + end];
            if !name.is_empty() {
                out.push(name.to_string());
            }
            i = i + 2 + end + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// Substitute every `${NAME}` in `s` from `vars`, erroring on an unknown name.
fn substitute(s: &str, vars: &HashMap<String, String>) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| anyhow!("unterminated '${{' in '{s}'"))?;
        let name = &after[..end];
        let val = vars
            .get(name)
            .ok_or_else(|| anyhow!("unresolved reference '${{{name}}}'"))?;
        out.push_str(val);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE96: &str = r#"
services:
  mariadb:
    image: mariadb:11
    env:
      MARIADB_PASSWORD: ${DB_PASSWORD}
    volumes:
      - { name: db, path: /var/lib/mysql, size: 5Gi }
    backup:
      command: ["sh", "-c", "mariadb-dump"]
      artifact: dump.sql
  route96:
    image: ghcr.io/v0l/route96:latest
    depends_on: [mariadb]
    ports:
      - { name: http, container: 8000, protocol: http, expose: ingress }
    env:
      DATABASE_URL: "mysql://route96:${DB_PASSWORD}@mariadb:3306/route96"
      PUBLIC_URL: "https://${HOSTNAME}"
      MAX_UPLOAD_MB: ${max_upload_mb}
    volumes:
      - { name: blobs, path: /app/data, size: 20Gi }
    backup:
      volume: blobs

secrets:
  - { name: DB_PASSWORD, generate: password }

config:
  - { name: max_upload_mb, label: "Max upload (MB)", type: int, default: "100" }
"#;

    #[test]
    fn parses_multi_service_app() {
        let c = Compose::parse(ROUTE96).unwrap();
        assert_eq!(c.services.len(), 2);
        assert_eq!(c.secrets.len(), 1);
        assert_eq!(c.secrets[0].generate, Generate::Password);
        assert_eq!(c.config.len(), 1);

        let route96 = &c.services["route96"];
        assert_eq!(route96.depends_on, vec!["mariadb"]);
        assert_eq!(route96.ports[0].expose, Expose::Ingress);
        assert_eq!(route96.ports[0].protocol, Protocol::Http);
        assert_eq!(route96.volumes[0].name, "blobs");

        // mariadb has no ports -> internal only, and a command backup.
        let db = &c.services["mariadb"];
        assert!(db.ports.is_empty());
        assert!(db.backup.as_ref().unwrap().command.is_some());
    }

    #[test]
    fn defaults_apply() {
        let c = Compose::parse(
            "services:\n  a:\n    image: x\n    ports:\n      - { name: p, container: 80 }\n",
        )
        .unwrap();
        let p = &c.services["a"].ports[0];
        assert_eq!(p.expose, Expose::None);
        assert_eq!(p.protocol, Protocol::Tcp);
    }

    #[test]
    fn referenced_vars_collected() {
        let c = Compose::parse(ROUTE96).unwrap();
        let mut refs = c.referenced_vars();
        refs.sort();
        assert_eq!(refs, vec!["DB_PASSWORD", "HOSTNAME", "max_upload_mb"]);
    }

    #[test]
    fn resolves_env_across_services() {
        let c = Compose::parse(ROUTE96).unwrap();
        let mut vars = HashMap::new();
        vars.insert("DB_PASSWORD".to_string(), "s3cr3t".to_string());
        vars.insert(
            "HOSTNAME".to_string(),
            "my-relay.apps.example.com".to_string(),
        );
        vars.insert("max_upload_mb".to_string(), "100".to_string());

        let env = c.resolve_env(&vars).unwrap();
        assert_eq!(env["mariadb"]["MARIADB_PASSWORD"], "s3cr3t");
        assert_eq!(
            env["route96"]["DATABASE_URL"],
            "mysql://route96:s3cr3t@mariadb:3306/route96"
        );
        assert_eq!(
            env["route96"]["PUBLIC_URL"],
            "https://my-relay.apps.example.com"
        );
        assert_eq!(env["route96"]["MAX_UPLOAD_MB"], "100");
    }

    #[test]
    fn unresolved_reference_errors() {
        let c = Compose::parse(ROUTE96).unwrap();
        // Missing max_upload_mb / HOSTNAME.
        let mut vars = HashMap::new();
        vars.insert("DB_PASSWORD".to_string(), "x".to_string());
        assert!(c.resolve_env(&vars).is_err());
    }

    #[test]
    fn rejects_ingress_on_non_http() {
        let yaml = "services:\n  a:\n    image: x\n    ports:\n      - { name: p, container: 5, protocol: tcp, expose: ingress }\n";
        assert!(Compose::parse(yaml).is_err());
    }

    #[test]
    fn rejects_bad_mount_paths() {
        // relative
        assert!(
            Compose::parse(
                "services:\n  a:\n    image: x\n    volumes:\n      - { name: d, path: data, size: 1Gi }\n"
            )
            .is_err()
        );
        // traversal
        assert!(
            Compose::parse(
                "services:\n  a:\n    image: x\n    volumes:\n      - { name: d, path: /var/../etc, size: 1Gi }\n"
            )
            .is_err()
        );
        // root
        assert!(
            Compose::parse(
                "services:\n  a:\n    image: x\n    volumes:\n      - { name: d, path: /, size: 1Gi }\n"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_empty_and_bad_refs() {
        assert!(Compose::parse("services: {}\n").is_err());
        assert!(
            Compose::parse("services:\n  a:\n    image: x\n    depends_on: [ghost]\n").is_err()
        );
        // backup volume not declared
        assert!(
            Compose::parse("services:\n  a:\n    image: x\n    backup: { volume: nope }\n")
                .is_err()
        );
    }

    #[test]
    fn substitute_unterminated_errors() {
        let vars = HashMap::new();
        assert!(substitute("${oops", &vars).is_err());
    }
}
