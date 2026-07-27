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
`${NAME}`; `bytes:` sets the generated length, default 24, range 16–64, always
hex-encoded so the value is twice that many characters), `config` (customer
form fields, injected as `${name}`). Per service:
`image`, `resources: { cpu, memory }`, `ports` (`expose: none|ingress`, ingress
is HTTP only), `env`, `volumes` (PVCs, read-write), `files` (ConfigMap/Secret,
read-only, mounted via subPath), `depends_on`, `backup`, `user`. `${HOSTNAME}`
resolves to `{deployment-name}.{cluster-ingress-domain}`; a service name
resolves to its in-namespace DNS (e.g. `db:3306`).

**`user`** — by default every service runs under the restricted Pod Security
Standard with `runAsNonRoot: true`. Set `user: root` (or `"0"`) on a service
whose image entrypoint must *start* as root and drop privileges itself —
`mariadb`, `postgres`, `redis`, etc. That container gets `runAsNonRoot: false`
and the deployment's namespace drops to the baseline Pod Security Standard
(still blocking privileged pods, host namespaces/ports/PID/IPC and hostPath);
all other hardening (no privilege escalation, drop ALL capabilities, read-only
root filesystem) stays in force. Only set it where the image genuinely needs
it.

**Read-only root filesystem** — this applies to *every* service, `user: root`
included, and only declared `volumes` are writable. An image that writes
outside its data directory needs either a small volume for that path or an env
var redirecting it: `postgres` wants `/var/run/postgresql` (postmaster lock +
unix socket), `redis` wants `/data` (otherwise its bgsave fails and it starts
refusing writes with `MISCONF`), and an image that logs to a file needs to be
pointed at stdout. This is not caught at validation time — it shows up as a
crash loop on first boot.

`user` also accepts a **numeric UID** (e.g. `user: "1000"`), which is required
when the image's Dockerfile sets `USER` to a *name* rather than a number (e.g.
`USER nonroot`). The kubelet enforces `runAsNonRoot` by reading the image
config's user field and cannot resolve a name to a UID, so such an image is
refused at startup with:

```
container has runAsNonRoot and image has non-numeric user (nonroot),
cannot verify user is non-root
```

Setting the numeric UID supplies `runAsUser` explicitly, which satisfies the
check. The same value is used as the pod's `fsGroup`, so mounted volumes are
chowned to that group and the non-root process can write to them (a fresh PVC
is otherwise root-owned `0755`). Find the UID in the image's `/etc/passwd` —
for an Alpine `adduser -D nonroot` that is `1000`; for distroless `nonroot`
it is `65532`. A `user:` that is neither `root`/`0` nor a positive integer is
rejected when the compose is validated.

**Variable references** — every `${NAME}` in `env`, `files[].content` or a
`content_from` must be declared, either as a `config:` field, a `secrets:` entry,
or the built-in `HOSTNAME`. This is enforced when an app is created or updated
(and by `compose-validate`), so adding a reference without declaring it is
rejected up front.

It is deliberately *not* enforced when the operator renders a deployment. A
deployment stores the config values the customer supplied at order time, so if
the catalog compose later gains a new `config:` field, existing deployments have
no value for it. Rather than failing the reconcile — which would take a running
workload offline over a value the customer never had the chance to supply — the
operator resolves such a reference to the field's **default**, or to an empty
string if it has none, and logs a warning. So a compose change is safe to roll
out to already-deployed instances; give any new field a sensible `default` if a
blank would break the app.

## Validating a compose document

Before pasting a `compose` into the admin API, validate it locally with the
`compose-validate` CLI (runs the exact parser + checks the API and operator
use, and prints the resource footprint):

```sh
cargo run -p lnvps_compose --bin compose-validate -- app.yaml
# or pipe one doc via stdin:
cat app.yaml | cargo run -q -p lnvps_compose --bin compose-validate
# → OK   app.yaml: 2 service(s), cpu=1000m memory=1.00 GiB storage=25.00 GiB; vars: DB_ROOT_PASSWORD
```

Exits non-zero if any document fails to parse or validate.

---

## strfry — Nostr relay

- **Image:** `dockurr/strfry` — <https://hub.docker.com/r/dockurr/strfry>
  (community; strfry has no official image; image source
  <https://github.com/dockur/strfry>).
- **Repo:** <https://github.com/hoytech/strfry> — config file, `bind` defaults
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

- **Image:** `voidic/route96` — <https://hub.docker.com/r/voidic/route96> +
  `mariadb:11` — <https://hub.docker.com/_/mariadb>.
- **Repo:** <https://github.com/v0l/route96> — YAML config file at
  `/app/config.yaml`; MySQL/MariaDB backend; blobs under `storage_dir`; port
  `8000`. Mirrors route96's `config.prod.yaml` + `docker-compose.prod.yml`
  (app reaches the DB via the service name `db`).

```yaml
services:
  db:
    image: mariadb:11
    user: root    # mariadb's entrypoint starts as root, then drops to `mysql`
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

- **Image:** `ghcr.io/hzrd149/blossom-server` —
  <https://github.com/hzrd149/blossom-server/pkgs/container/blossom-server>.
- **Repo:** <https://github.com/hzrd149/blossom-server> — YAML config at
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

## nostr-rs-relay

- **Image:** `scsibug/nostr-rs-relay` (official pre-built) —
  <https://hub.docker.com/r/scsibug/nostr-rs-relay>.
- **Repo:** <https://github.com/scsibug/nostr-rs-relay> — optional TOML config
  at `/usr/src/app/config.toml`; listens on `8080`; SQLite DB under
  `/usr/src/app/db`. Set `network.address = "0.0.0.0"` so it's reachable in the
  pod.

```yaml
services:
  relay:
    image: scsibug/nostr-rs-relay:latest
    resources: { cpu: 250m, memory: 256Mi }
    ports:
      - { name: ws, container: 8080, protocol: http, expose: ingress }
    files:
      - path: /usr/src/app/config.toml
        content: |
          [info]
          relay_url = "wss://${HOSTNAME}/"
          name = "${relay_name}"
          description = "${relay_description}"
          [database]
          data_directory = "/usr/src/app/db"
          [network]
          address = "0.0.0.0"
          port = 8080
    volumes:
      - { name: db, path: /usr/src/app/db, size: 10Gi }
config:
  - { name: relay_name, label: "Relay name", type: string, default: "My nostr-rs-relay" }
  - { name: relay_description, label: "Description", type: string, default: "A personal Nostr relay" }
```

---

## Pyramid — community relay (fiatjaf)

- **Image:** `ghcr.io/fiatjaf/pyramid` (official, published from the repo) —
  <https://github.com/fiatjaf/pyramid/pkgs/container/pyramid>.
- **Repo:** <https://github.com/fiatjaf/pyramid> — a feature-rich hierarchical
  community relay (invite tree, sub-relays, NIP-29 groups, Blossom, search).
  Env-configured with sensible defaults baked into the image (`HOST`, `PORT`
  `3334`, `DATA_PATH` `./data`, `NO_AUTO_UPDATES`); a single LMDB store + the
  settings JSON live under `/app/data`. The **relay domain and root member are
  set through a one-time web setup flow** the first time you open the
  deployment's hostname and sign in with a Nostr signer — nothing to configure
  here.
- **Notes:** keep `NO_AUTO_UPDATES=true` (the operator manages the image; the
  in-app self-update writes to a read-only rootfs and would fail anyway). TLS is
  terminated at the ingress, so run plain HTTP on `3334` (don't enable the
  built-in autocert/`443`). Optional extras that need raw TCP — the SFTP blob
  manager (`2222`) and audio/video via embedded LiveKit — aren't reachable
  until the `expose: tcp/udp` path exists.

```yaml
services:
  pyramid:
    image: ghcr.io/fiatjaf/pyramid:latest
    resources: { cpu: 500m, memory: 512Mi }
    ports:
      - { name: http, container: 3334, protocol: http, expose: ingress }
    env:
      HOST: "0.0.0.0"
      PORT: "3334"
      DATA_PATH: "/app/data"
      NO_AUTO_UPDATES: "true"
    volumes:
      - { name: data, path: /app/data, size: 20Gi }
```

---

## HAVEN — sovereign personal relay (+ Blossom)

- **Image:** `holgerhatgarkeinenode/haven-docker` —
  <https://hub.docker.com/r/holgerhatgarkeinenode/haven-docker> (community;
  barrydeen ships binaries, not an image; image source
  <https://github.com/HolgerHatGarKeineNode/haven-docker>). Workdir `/app`.
- **Repo:** <https://github.com/barrydeen/haven> — configured entirely by env
  vars; listens on `RELAY_PORT` (default `3355`), `RELAY_BIND_ADDRESS` must be
  `0.0.0.0`. Databases (badger) live under `/app/db`, Blossom media under
  `/app/blossom`. It **fatally requires** the two relay-list files
  `relays_import.json` and `relays_blastr.json` at startup (provided below via
  `files:`); the whitelist/blacklist files are optional and disabled by setting
  their env vars to `""` (owner-only).
- **Caveat:** current published community images do **not** bundle HAVEN's
  `templates/` directory, so the web landing page at `/` won't render — but the
  relay itself works fully over WebSocket (which is what the ingress serves as
  `wss://`). A fix to bake the templates into the image is proposed upstream
  (<https://github.com/HolgerHatGarKeineNode/haven-docker/pull/8>); once merged
  and released the dashboard works out of the box.

```yaml
services:
  haven:
    image: holgerhatgarkeinenode/haven-docker:v1.2.2
    # The image sets `USER nonroot` (a name), which the kubelet cannot verify
    # under runAsNonRoot. `nonroot` is uid 1000 in this image (Alpine
    # `adduser -D nonroot`), and 1000 also becomes the fsGroup so the db and
    # blossom volumes are writable.
    user: "1000"
    resources: { cpu: 500m, memory: 512Mi }
    ports:
      - { name: ws, container: 3355, protocol: http, expose: ingress }
    env:
      OWNER_NPUB: "${owner_npub}"
      RELAY_URL: "${HOSTNAME}"
      RELAY_PORT: "3355"
      RELAY_BIND_ADDRESS: "0.0.0.0"
      DB_ENGINE: "badger"
      BLOSSOM_PATH: "blossom/"
      PRIVATE_RELAY_NPUB: "${owner_npub}"
      CHAT_RELAY_NPUB: "${owner_npub}"
      OUTBOX_RELAY_NPUB: "${owner_npub}"
      INBOX_RELAY_NPUB: "${owner_npub}"
      IMPORT_SEED_RELAYS_FILE: "relays_import.json"
      BLASTR_RELAYS_FILE: "relays_blastr.json"
      WHITELISTED_NPUBS_FILE: ""
      BLACKLISTED_NPUBS_FILE: ""
      BACKUP_PROVIDER: "none"
    files:
      - path: /app/relays_import.json
        content: |
          ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"]
      - path: /app/relays_blastr.json
        content: |
          ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"]
    volumes:
      - { name: db, path: /app/db, size: 10Gi }
      - { name: blossom, path: /app/blossom, size: 20Gi }
config:
  - { name: owner_npub, label: "Owner npub", type: string, required: true }
```

---

## Buzz — team relay + web UI (+ Postgres, Redis, RustFS)

- **Image:** `ghcr.io/block/buzz` (official, published from the repo by
  `relay-v*` tags) — <https://github.com/block/buzz/pkgs/container/buzz>, plus
  `postgres:17-alpine`, `redis:7-alpine` and `rustfs/rustfs`
  (<https://hub.docker.com/r/rustfs/rustfs>) for object storage.
- **Repo:** <https://github.com/block/buzz> — a Nostr relay (NIP-29 groups,
  NIP-42 auth, NIP-17 DMs, NIP-34 git) that also serves the web UI from the
  same port, so one `expose: ingress` port covers `wss://`, the REST API,
  media and the browser client. It is *not* a plain relay: it hard-requires
  Postgres (event store), Redis (pub/sub fan-out, presence, rate limits,
  NIP-98 replay set) and an S3-compatible bucket (media blobs + git objects).
  Schema migrations are embedded in the binary and run at startup under a
  Postgres advisory lock (`BUZZ_AUTO_MIGRATE`).
- **Identity:** `RELAY_OWNER_PUBKEY` bootstraps the owner into `relay_members`
  and, with `BUZZ_REQUIRE_RELAY_MEMBERSHIP=true`, is the only pubkey that can
  use the relay until it adds more members. `BUZZ_RELAY_PRIVATE_KEY` is the
  relay's own signing key — it signs NIP-29 discovery (39000/39001/39002),
  membership rosters (13534), membership notifications (44100/44101) and
  system messages. It must be stable: rotating it is a new relay identity.
- **Notes:**
  - `RELAY_URL` is used verbatim in NIP-42 auth challenges, so it must be the
    public `wss://` URL — `wss://${HOSTNAME}`, not the in-namespace name.
  - The relay runs a startup **A3 conformance probe** against the object store
    (a linearizable conditional-write race backing git pointer CAS) and
    *exits* if it fails. RustFS answers the default 32-way race with HTTP 503;
    a 4-way single-round race passes. Hence `BUZZ_GIT_PROBE_WRITERS=4` /
    `BUZZ_GIT_PROBE_ROUNDS=1` above — do not remove them, and do not paper
    over a failure with `BUZZ_GIT_CONFORMANCE_PROBE=false` (that disables the
    gate, not the requirement).
  - Every container runs with `readOnlyRootFilesystem`, which is why `db`
    mounts a small volume at `/var/run/postgresql` (lock file + unix socket)
    and `s3` overrides `RUSTFS_OBS_LOG_DIRECTORY` (the image logs to `/logs`).
  - `PGDATA` points at a *subdirectory* of the volume: `initdb` refuses a
    non-empty directory and a fresh ext4 PVC contains `lost+found`.
  - Search is Postgres FTS; no Typesense service is needed. Huddle
    audio/video and the pairing relay are not wired up here (they need raw
    TCP/UDP).
  - The ACP agent harness (`buzz-acp`) is a *client* of the relay, not part of
    this deployment — it runs wherever the customer's agent runs and connects
    over `wss://` with its own key.

```yaml
services:
  db:
    image: postgres:17-alpine
    user: root    # postgres' entrypoint starts as root, then drops to `postgres`
    resources: { cpu: 500m, memory: 1Gi }
    env:
      POSTGRES_DB: buzz
      POSTGRES_USER: buzz
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      # initdb refuses a non-empty directory, and a fresh ext4 PVC has lost+found
      PGDATA: /var/lib/postgresql/data/pgdata
    volumes:
      - { name: data, path: /var/lib/postgresql/data, size: 20Gi }
      # readOnlyRootFilesystem: the postmaster lock + unix socket need a writable dir
      - { name: run, path: /var/run/postgresql, size: 1Gi }
    backup:
      command: ["sh", "-c", "exec pg_dumpall -U buzz"]
      artifact: buzz.sql
  redis:
    image: redis:7-alpine
    user: root    # redis' entrypoint starts as root, then drops to `redis`
    resources: { cpu: 250m, memory: 512Mi }
    volumes:
      # RDB snapshots; without a writable /data redis fails its bgsave and then
      # refuses writes with MISCONF
      - { name: data, path: /data, size: 2Gi }
  s3:
    image: rustfs/rustfs:1.0.0-beta.11
    user: "10001"    # image sets `USER rustfs` (a name); uid 10001 per its Dockerfile
    resources: { cpu: 500m, memory: 1Gi }
    ports:
      - { name: s3, container: 9000, protocol: http, expose: none }
    env:
      RUSTFS_ACCESS_KEY: ${S3_ACCESS_KEY}
      RUSTFS_SECRET_KEY: ${S3_SECRET_KEY}
      RUSTFS_VOLUMES: /data
      RUSTFS_ADDRESS: ":9000"
      RUSTFS_CONSOLE_ENABLE: "false"
      # image default is RUSTFS_OBS_LOG_DIRECTORY=/logs, which is unwritable
      # under readOnlyRootFilesystem — log to stdout instead
      RUSTFS_OBS_LOG_DIRECTORY: ""
      RUSTFS_OBS_USE_STDOUT: "true"
      RUSTFS_OBS_LOGGER_LEVEL: warn
    volumes:
      - { name: blobs, path: /data, size: 50Gi }
    backup:
      volume: blobs
  relay:
    image: ghcr.io/block/buzz:latest
    user: "1000"    # image sets `USER buzz:buzz` (a name); uid 1000 per its Dockerfile
    resources: { cpu: 1, memory: 2Gi }
    depends_on: [db, redis, s3]
    ports:
      - { name: http, container: 3000, protocol: http, expose: ingress }
    env:
      # --- identity / public URL ---
      RELAY_URL: "wss://${HOSTNAME}"
      BUZZ_MEDIA_BASE_URL: "https://${HOSTNAME}"
      BUZZ_BIND_ADDR: "0.0.0.0:3000"
      BUZZ_RELAY_PRIVATE_KEY: "${BUZZ_RELAY_PRIVATE_KEY}"
      RELAY_OWNER_PUBKEY: "${owner_pubkey}"
      # --- backing services (in-namespace DNS) ---
      DATABASE_URL: "postgres://buzz:${DB_PASSWORD}@db:5432/buzz"
      REDIS_URL: "redis://redis:6379"
      BUZZ_AUTO_MIGRATE: "true"
      # --- object storage ---
      BUZZ_S3_ENDPOINT: "http://s3:9000"
      BUZZ_S3_BUCKET: "buzz-media"
      BUZZ_S3_REGION: "us-east-1"
      BUZZ_S3_ACCESS_KEY: "${S3_ACCESS_KEY}"
      BUZZ_S3_SECRET_KEY: "${S3_SECRET_KEY}"
      # --- access control ---
      BUZZ_REQUIRE_AUTH_TOKEN: "true"
      BUZZ_REQUIRE_RELAY_MEMBERSHIP: "true"
      BUZZ_ALLOW_NIP_OA_AUTH: "true"
      BUZZ_PUBKEY_ALLOWLIST: "false"
      BUZZ_REQUIRE_MEDIA_GET_AUTH: "false"
      # --- git on object storage ---
      BUZZ_GIT_REPO_PATH: "/var/lib/buzz/git"
      BUZZ_GIT_PACK_CACHE_PATH: "/var/cache/buzz/git-packs"
      BUZZ_GIT_HOOK_HMAC_SECRET: "${GIT_HOOK_HMAC_SECRET}"
      # RustFS serves 503 under the default 32-way conditional-PUT race; the A3
      # probe is startup-fatal, so keep the race narrow (verified: 4x1 passes)
      BUZZ_GIT_PROBE_WRITERS: "4"
      BUZZ_GIT_PROBE_ROUNDS: "1"
      # --- capacity / logging ---
      BUZZ_MAX_CONNECTIONS: "2000"
      RUST_LOG: "info"
    volumes:
      - { name: git, path: /var/lib/buzz/git, size: 20Gi }
      - { name: packs, path: /var/cache/buzz/git-packs, size: 5Gi }
secrets:
  - { name: DB_PASSWORD, generate: password }
  - { name: S3_ACCESS_KEY, generate: token }
  - { name: S3_SECRET_KEY, generate: password }
  - { name: GIT_HOOK_HMAC_SECRET, generate: token }
  # 32 bytes exactly: this is the relay's Nostr secret key, and the default 24
  # is rejected at startup as an invalid secret key.
  - { name: BUZZ_RELAY_PRIVATE_KEY, generate: token, bytes: 32 }
config:
  - { name: owner_pubkey, label: "Owner pubkey (64-char hex)", type: string, required: true }
```

### Before this one can be enabled

One thing in the compose grammar is still missing for this app to deploy
end-to-end; until it lands, this entry is documentation, not a shippable
catalog item.

(The 32-byte generated secret it also needed landed in #243: `bytes:` on a
secret declaration, used above for `BUZZ_RELAY_PRIVATE_KEY`. The customer no
longer pastes the relay's identity key into the order form.)

1. **One-shot bucket creation.** The relay never issues `CreateBucket`; it
   expects `BUZZ_S3_BUCKET` to exist and dies with `NoSuchBucket` in the A3
   probe otherwise (upstream's Helm chart runs an `mc mb` Job plus a
   wait-for-bucket init container). RustFS has no "default buckets" env var,
   and a compose service has no `command`, so nothing in a deployment can
   create it. Mounting a second volume at `/data/<bucket>` makes RustFS *list*
   the bucket but writes then fail with `Cross-device link` on its rename out
   of the drive-root temp area, so that is not a workaround. This needs
   either an init/`command` hook in the grammar, or an operator-side bucket
   bootstrap for services that declare one.

Everything else was verified end-to-end against these images (relay reaches
`buzz-relay TCP listening`, `/_readiness` 200, NIP-11 served, A3 probe
admitted) with all four containers running read-only-rootfs and non-root
where the image allows it.

---

## Notes on other apps

- **zap-stream-core** — needs raw TCP/UDP ingest (RTMP `1935/tcp`, SRT), i.e.
  the not-yet-implemented `expose: tcp|udp` path.
