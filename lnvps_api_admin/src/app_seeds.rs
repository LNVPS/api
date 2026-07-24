//! Predefined **launch apps** for the managed-app catalog (Nostr-native
//! services). Each ships a validated `lnvps_compose` document; [`seed_launch_apps`]
//! inserts any that are missing (disabled, so an operator reviews pricing before
//! offering them) with the resource footprint computed from the compose.

use anyhow::{Result, anyhow};
use lnvps_db::{App, IntervalType, LNVpsDbBase};

/// A catalog app definition shipped with LNVPS.
pub struct LaunchApp {
    pub name: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    pub compose: &'static str,
    /// Suggested monthly price in cents (USD). Operators adjust before enabling.
    pub amount_cents: u64,
}

// strfry has no official image; dockurr/strfry is the widely-used community
// build. It reads /etc/strfry.conf and listens on 7777 (bind must be 0.0.0.0
// inside a container). Data lives under /app/strfry-db.
const STRFRY: &str = r#"services:
  strfry:
    image: dockurr/strfry:latest
    resources: { cpu: 500m, memory: 512Mi }
    ports:
      - { name: ws, container: 7777, protocol: http, expose: ingress }
    files:
      - path: /etc/strfry.conf
        content: |
          db = "/app/strfry-db/"
          relay {
              bind = "0.0.0.0"
              port = 7777
              info {
                  name = "${relay_name}"
                  description = "${relay_description}"
              }
          }
    volumes:
      - { name: db, path: /app/strfry-db, size: 5Gi }
config:
  - { name: relay_name, label: "Relay name", type: string, default: "My strfry relay" }
  - { name: relay_description, label: "Description", type: string, default: "A personal Nostr relay" }
"#;

// route96 (voidic/route96) is a YAML-config Blossom/NIP-96 server backed by
// MySQL. Config is a file at /app/config.yaml; it reaches MariaDB via the
// in-namespace service name `db`. See route96 config.prod.yaml / docker-compose.
const ROUTE96: &str = r#"services:
  db:
    image: mariadb:11
    resources: { cpu: 500m, memory: 512Mi }
    env:
      MARIADB_ROOT_PASSWORD: ${DB_ROOT_PASSWORD}
      MARIADB_DATABASE: route96
    volumes:
      - { name: data, path: /var/lib/mysql, size: 5Gi }
    backup:
      command: ["sh", "-c", "exec mariadb-dump --all-databases -uroot -p\"$MARIADB_ROOT_PASSWORD\""]
      artifact: route96.sql
  route96:
    image: voidic/route96:latest
    resources: { cpu: 500m, memory: 512Mi }
    depends_on: [db]
    ports:
      - { name: http, container: 8000, protocol: http, expose: ingress }
    files:
      - path: /app/config.yaml
        content: |
          listen: "0.0.0.0:8000"
          database: "mysql://root:${DB_ROOT_PASSWORD}@db:3306/route96"
          storage_dir: "/app/data"
          max_upload_bytes: 104857600
          public_url: "https://${HOSTNAME}"
    volumes:
      - { name: blobs, path: /app/data, size: 20Gi }
    backup:
      volume: blobs
secrets:
  - { name: DB_ROOT_PASSWORD, generate: password }
"#;

// hzrd149/blossom-server (Deno). YAML config at /app/config.yml; listens on
// 3000; SQLite + blobs under /app/data. `publicDomain` is a BARE hostname.
const BLOSSOM: &str = r#"services:
  blossom:
    image: ghcr.io/hzrd149/blossom-server:master
    resources: { cpu: 250m, memory: 256Mi }
    ports:
      - { name: http, container: 3000, protocol: http, expose: ingress }
    files:
      - path: /app/config.yml
        content: |
          port: 3000
          host: 0.0.0.0
          publicDomain: "${HOSTNAME}"
          database:
            path: /app/data/sqlite.db
          storage:
            backend: local
            local:
              dir: /app/data/blobs
            rules:
              - { type: "*", expiration: "1 month" }
          upload:
            enabled: true
            requireAuth: true
    volumes:
      - { name: data, path: /app/data, size: 20Gi }
"#;

/// The catalog of launch apps shipped with LNVPS.
pub fn launch_apps() -> Vec<LaunchApp> {
    vec![
        LaunchApp {
            name: "strfry",
            display_name: "strfry Relay",
            description: "A high-performance personal Nostr relay (C++/LMDB). Uses the community dockurr/strfry image.",
            compose: STRFRY,
            amount_cents: 500,
        },
        LaunchApp {
            name: "route96",
            display_name: "route96 (Blossom + NIP-96)",
            description: "A Blossom / NIP-96 media server (voidic/route96) backed by MariaDB.",
            compose: ROUTE96,
            amount_cents: 1000,
        },
        LaunchApp {
            name: "blossom",
            display_name: "Blossom Server",
            description: "A simple Blossom blob/media server (hzrd149/blossom-server) with local storage.",
            compose: BLOSSOM,
            amount_cents: 500,
        },
    ]
}

/// Insert any launch apps not already present (matched by name), **disabled**
/// with the footprint computed from their compose. Returns the number inserted.
/// Idempotent: existing apps are left untouched.
pub async fn seed_launch_apps<D: LNVpsDbBase + ?Sized>(db: &D) -> Result<usize> {
    let mut inserted = 0;
    for a in launch_apps() {
        if db.get_app_by_name(a.name).await.is_ok() {
            continue;
        }
        let compose = lnvps_compose::Compose::parse(a.compose)
            .map_err(|e| anyhow!("launch app '{}' compose invalid: {e}", a.name))?;
        let fp = compose.footprint()?;
        let app = App {
            id: 0,
            name: a.name.to_string(),
            display_name: a.display_name.to_string(),
            description: Some(a.description.to_string()),
            icon: None,
            compose: a.compose.to_string(),
            amount: a.amount_cents,
            currency: "USD".to_string(),
            interval_amount: 1,
            interval_type: IntervalType::Month,
            setup_amount: 0,
            // Disabled: an operator reviews/prices before offering it.
            enabled: false,
            cpu_milli: fp.cpu_milli,
            memory_bytes: fp.memory_bytes,
            storage_bytes: fp.storage_bytes,
            created: chrono::Utc::now(),
        };
        db.insert_app(&app).await?;
        inserted += 1;
    }
    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_launch_apps_parse_and_have_footprint() {
        let apps = launch_apps();
        assert!(!apps.is_empty());
        let mut names = std::collections::HashSet::new();
        for a in &apps {
            assert!(
                names.insert(a.name),
                "duplicate launch app name '{}'",
                a.name
            );
            let compose = lnvps_compose::Compose::parse(a.compose)
                .unwrap_or_else(|e| panic!("'{}' compose invalid: {e}", a.name));
            let fp = compose.footprint().unwrap();
            assert!(fp.cpu_milli > 0, "'{}' has no cpu footprint", a.name);
            assert!(fp.memory_bytes > 0, "'{}' has no memory footprint", a.name);
        }
    }

    #[tokio::test]
    async fn seed_is_idempotent() {
        let db = lnvps_api_common::MockDb::default();
        let n1 = seed_launch_apps(&db).await.unwrap();
        assert_eq!(n1, launch_apps().len());
        // Seeded apps are disabled and carry a computed footprint.
        let strfry = db.get_app_by_name("strfry").await.unwrap();
        assert!(!strfry.enabled);
        assert!(strfry.cpu_milli > 0);
        // Running again inserts nothing.
        let n2 = seed_launch_apps(&db).await.unwrap();
        assert_eq!(n2, 0);
    }
}
