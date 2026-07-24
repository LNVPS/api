# Managed App — catalog examples

Reference `compose` documents for adding **managed apps** to the catalog via the
admin API. These are **not** auto-seeded; create them manually and set your own
pricing / enable them when ready.

## How to add one

`POST /api/admin/v1/apps` (permission `app::create`). The server parses and
validates the `compose`, computes the resource footprint from it, and returns
the created app (create it disabled, then `PATCH .../apps/{id}` with
`"enabled": true` once you've reviewed pricing):

```jsonc
{
  "name": "strfry",                 // DNS-safe slug, unique
  "display_name": "strfry Relay",
  "description": "A high-performance personal Nostr relay.",
  "compose": "<the YAML below, as a string>",
  "amount": 500,                    // price in the smallest currency unit (e.g. cents)
  "currency": "USD",
  "interval_amount": 1,
  "interval_type": "month",
  "setup_amount": 0,
  "enabled": false
}
```

You also need at least one **app cluster** with capacity in a region
(`POST /api/admin/v1/app_clusters`), and the operator for that cluster must run
with the matching `app_cluster_id`.

## Compose grammar recap

Top-level keys: `services`, `secrets` (operator-generated, injected as
`${NAME}`), `config` (customer form fields, injected as `${name}`). Per service:
`image`, `resources: { cpu, memory }`, `ports` (`expose: none|ingress`, ingress
is HTTP only), `env`, `volumes` (PVCs, read-write), `files` (ConfigMap/Secret,
read-only, mounted via subPath), `depends_on`, `backup`. `${HOSTNAME}` resolves
to `{deployment-name}.{cluster-ingress-domain}`; a service name resolves to its
in-namespace DNS (e.g. `db:3306`).

---

## strfry — Nostr relay

- **Image:** `dockurr/strfry` (community; strfry has no official image).
- **Docs:** <https://github.com/hoytech/strfry> — config file, `bind` defaults
  to `127.0.0.1` (must be `0.0.0.0` in a container), port `7777`, data in
  `./strfry-db/`. The `dockurr/strfry` image reads `/etc/strfry.conf`.

```yaml
services:
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
```

---

## route96 — Blossom / NIP-96 media server (+ MariaDB)

- **Image:** `voidic/route96` (Docker Hub) + `mariadb:11`.
- **Docs:** <https://github.com/v0l/route96> — YAML config file at
  `/app/config.yaml`; MySQL/MariaDB backend; blobs under `storage_dir`; port
  `8000`. Mirrors route96's `config.prod.yaml` + `docker-compose.prod.yml`
  (app reaches the DB via the service name `db`).

```yaml
services:
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
```

---

## Blossom Server (hzrd149)

- **Image:** `ghcr.io/hzrd149/blossom-server`.
- **Docs:** <https://github.com/hzrd149/blossom-server> — YAML config at
  `/app/config.yml`; listens on `3000`; SQLite + blobs under `/app/data`.
  `publicDomain` is a **bare** hostname (no scheme).

```yaml
services:
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
```

---

## Notes on other apps

- **HAVEN** (<https://github.com/barrydeen/haven>) — no official image; the
  community `holgerhatgarkeinenode/haven-docker` image requires a mounted
  `templates/` directory of binary web assets plus several JSON list files
  (`relays_import.json`, `relays_blastr.json`, whitelist/blacklist). The
  `files:` mechanism only injects individual text files, so HAVEN isn't cleanly
  deployable here yet — it would need a self-contained image that bundles the
  templates.
- **zap-stream-core** — needs raw TCP/UDP ingest (RTMP `1935/tcp`, SRT), i.e.
  the not-yet-implemented `expose: tcp|udp` path.
