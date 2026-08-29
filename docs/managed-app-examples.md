# Managed App — catalog examples

Reference `compose` documents for adding **managed apps** to the catalog via the
admin API. Each one lives as a standalone document in [`catalog/`](../catalog),
so it can be validated, started and shipped without being pasted out of a
Markdown fence. They are **not** auto-seeded; create them manually and set your
own pricing / enable them when ready.

CI starts every `catalog/*.yaml` one at a time on each change to the directory,
the grammar or the renderer (`.github/workflows/app-catalog.yml`), so an entry
that can no longer start fails the build rather than a customer's order.

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
  "compose": "<the document from catalog/strfry.yaml, as a string>",
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

**Validation cannot tell you the app will start.** It checks the document's own
grammar and computes a footprint; it has no way to know what a third-party image
requires, so an entry can validate cleanly, price correctly and still be
incapable of booting. Before enabling one, read the image's config loader for
values that are required *without a default* and confirm the compose supplies
every one — HAVEN shipped enabled with 11 of its 21 required env vars absent
(#248), and because it aborts on the first missing one it reports them a single
variable at a time.

## Compose grammar recap

Top-level keys: `services`, `secrets` (operator-generated, injected as
`${NAME}`; `bytes:` sets the generated length, default 24, range 16–64, always
hex-encoded so the value is twice that many characters), `config` (customer
form fields, injected as `${name}`). Per service:
`image`, `resources: { cpu, memory }`, `ports` (`expose: none|ingress`, ingress
is HTTP only), `env`, `volumes` (PVCs, read-write), `files` (ConfigMap/Secret,
read-only, mounted via subPath), `depends_on`, `backup`, `user`,
`init`. Volumes take an optional `label` (see below). `${HOSTNAME}`
resolves to `{deployment-name}.{cluster-ingress-domain}`; a service name
resolves to its in-namespace DNS (e.g. `db:3306`).

**`volumes[].label`** — optional, and what a **buyer** gets from that volume:
`events`, `media`, `database`, `files`. Surfaced per volume on
`GET /api/v1/apps`, so a listing can say "10 GB events + 20 GB media" instead of
a flat "30 GB" that reads as 30 GB of events (issue #260):

```yaml
services:
  haven:
    image: holgerhatgarkeinenode/haven-docker:v1.2.2
    user: "1000"
    ports:
      - { name: ws, container: 3355, protocol: http, expose: ingress }
    volumes:
      - { name: db,      path: /app/db,      size: 10Gi, label: events }
      - { name: blossom, path: /app/blossom, size: 20Gi, label: media }
```

Write it here because **only the app definition knows what a volume is for**.
The names do not generalise: `db` is HAVEN's event store and route96's MySQL,
`data` is Pyramid's events and Buzz's Postgres, and Buzz declares two different
volumes both called `data`. Any client-side mapping is right for today's apps
and wrong for the next one.

Leave it off for volumes nobody shops for — Buzz's `run` (a Postgres socket
dir), `packs` (a cache), redis' RDB snapshots. An unlabelled volume is still
reported with its size, and an app with no labels at all just reports its total,
so no existing entry has to be backfilled. Keep it a lower-case noun, at most 40
characters; it renders next to a size, not as a sentence.

**`user`** — by default every service runs under the restricted Pod Security
Standard with `runAsNonRoot: true`. Set `user: root` (or `"0"`) on a service
whose image entrypoint must *start* as root and drop privileges itself —
`mariadb`, `postgres`, `redis`, etc. That container gets `runAsNonRoot: false`
and the deployment's namespace drops to the baseline Pod Security Standard
(still blocking privileged pods, host namespaces/ports/PID/IPC and hostPath).
Such a container also gets `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID` and
`SETUID` added back on top of `drop: ALL` — the chown of a fresh, root-owned
data directory and the `gosu`/`su-exec` drop that follows it. That is the whole
grant: no privilege escalation and the read-only root filesystem stay in force,
and every other capability stays dropped. Only set it where the image genuinely
needs it.

**`init`** — one-shot setup steps that must succeed before the service's own
container starts. They render as Kubernetes init containers in that service's
pod, run to completion in declaration order, and the kubelet restarts a failed
one — so a service whose setup has not succeeded never runs. The canonical case
is an S3 bucket a consumer needs to already exist (`NoSuchBucket` at startup is
otherwise fatal):

```yaml
services:
  s3:
    image: rustfs/rustfs:1.0.0-beta.11
    user: "10001"                     # image sets `USER rustfs`; see `user` above
    ports:
      - { name: s3, container: 9000, protocol: http, expose: none }
  app:
    image: example/app:latest
    user: "1000"                      # every service needs one — see `user` above
    depends_on: [s3]
    ports:
      - { name: http, container: 3000, protocol: http, expose: ingress }
    init:
      - name: create-bucket           # DNS label, unique within the service
        image: minio/mc:latest
        env:                          # ${…} is resolved here, and only here
          MC_HOST_s3: http://${S3_ACCESS_KEY}:${S3_SECRET_KEY}@s3:9000
          MC_CONFIG_DIR: /tmp/mc
        command:
          - sh
          - -c
          - |
            set -e
            until mc --quiet ls s3 >/dev/null 2>&1; do sleep 2; done
            mc mb -p s3/media
        # resources: { cpu: 50m, memory: 64Mi }   # the default
        # user: "65534"                           # defaults to the service's
secrets:
  - { name: S3_ACCESS_KEY, generate: token }
  - { name: S3_SECRET_KEY, generate: password }
```

Rules worth knowing:

- **Put the step on the service that needs it**, not on the one it prepares. A
  bucket cannot be created in a server that has not started, and it is the
  consumer that must not run without it — so the wait loop above belongs in
  `app`, whose container the kubelet holds back. `depends_on` alone is advisory.
- **`${…}` is not substituted in `command`/`args`** and a reference there is
  rejected at validation: a customer-supplied `config` value interpolated into a
  shell string is an injection. Pass values through the step's `env` and read
  them as shell variables.
- **A step sees what the service container sees** — the same `volumes` and
  `files` at the same paths, so it can seed a data directory — plus a writable
  `/tmp`. Everything else is read-only, exactly as for the service.
- **Same hardening**, and the step inherits the service's `user:` unless it
  names its own.
- **Resources default to `50m`/`64Mi`.** A pod reserves
  `max(largest init container, sum of containers)`, so a small step adds nothing
  to the app's footprint; a step asking for more than its service does raises
  it, and the capacity accounting says so.
- **Make it idempotent.** It re-runs on every restart and redeploy (`mc mb -p`,
  `CREATE ... IF NOT EXISTS`).
- Generated `secrets:` are hex, so embedding one in a URL (the `MC_HOST_s3`
  above) is safe. A customer-supplied `config:` value is arbitrary text — don't
  build a URL out of one.

**Read-only root filesystem** — this applies to *every* service, `user: root`
included. Only declared `volumes` and `scratch:` paths are writable. An image
that writes outside its data directory needs one of those, or an env var
redirecting it: `redis` wants `/data` (otherwise its bgsave fails and it starts
refusing writes with `MISCONF`), and an image that logs to a file needs to be
pointed at stdout. This is not caught at validation time — it shows up as a
crash loop on first boot.

**`scratch`** — writable paths the app does *not* keep, one `emptyDir` each:
created empty with the pod, discarded with it (issue #264).

```yaml
services:
  db:
    image: mariadb:11
    user: root                        # see `user` above
    volumes:
      - { name: data, path: /var/lib/mysql, size: 5Gi, label: database }
    scratch:
      - { path: /tmp }                # size defaults to 256Mi
      - { path: /run/mysqld, size: 32Mi }
  app:
    image: example/app:latest
    user: "1000"
    depends_on: [db]
    ports:
      - { name: http, container: 3000, protocol: http, expose: ingress }
```

Every database image needs at least one. `mariadb` writes InnoDB's temporary
files under `/tmp` and its pid file and unix socket under `/run/mysqld`;
`postgres` writes its postmaster lock and socket under `/var/run/postgresql`.
Without a writable path for those the process exits during startup — with
`Can't create/write to file '/tmp/…' (Errcode: 30 "Read-only file system")` or
`could not create lock file "/var/run/postgresql/.s.PGSQL.5432.lock"`.

Use it, not a `volume`, for anything the app would be happy to lose: a volume
is billed, backed up, counted in the storage the buyer is shown, and it hands
the app back a stale pid file after a restart. Conversely, do not put data in
scratch — it is gone on every restart, and validation rejects a `scratch:` that
sits inside a volume (or a volume inside a scratch) for that reason.

`size` defaults to `256Mi` and may not exceed `1Gi`: this is the node's own
disk, shared with every other tenant, and the kubelet evicts a pod that writes
past its limit. Something that needs more than that is storage — declare a
`volume`.

An `init:` step already gets a writable `/tmp`. If the service declares
`scratch:` at `/tmp` the step shares that one instead.

**A service with `volumes:` must declare `user:`** (issue #277), and app
create/update refuses one that does not. Kubernetes chowns a freshly
provisioned PVC to the pod's `fsGroup`, the operator takes that from the numeric
`user:`, and without one the volume mounts root-owned `0755` while the kubelet
starts the container as whatever non-root UID the image names — so the app comes
up and fails on its first write, on a fresh volume, every time. `user: root` is
a valid answer: a root process can write to a root-owned volume.

**A volume's `size` can be raised later but never lowered, and a volume can
never be removed or renamed** (issue #292) — app update refuses all three,
matched on `(service, volume name)` against the stored compose. Kubernetes
permits PVC expansion only, so a smaller size makes every existing deployment
of the app fail to reconcile with a `422` until the size is put back; and
because the operator cannot prune a PVC it merely stops applying, dropping or
renaming a volume leaves the old one behind holding the customer's data,
unmounted. Pick names and sizes on the assumption that the first deployment
freezes both.

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

**An image that declares no `USER` at all runs as root, and is refused the same
way** (issue #256):

```
container has runAsNonRoot and image will run as root
```

Omitting `user:` is therefore not a neutral default — it is a bet that the image
declares a numeric non-root `USER`, and most public images do not. Three of the
five apps in this file shipped enabled and priced without one and could never
have started. **Check the image before writing the entry, and check it again
when the tag moves.** Nothing in validation can catch this: the compose is
well-formed, and the operator only learns the image's `USER` when the kubelet
refuses the pod.

### Checking an image, and proving the choice works

```bash
docker pull <image>
# What the kubelet will read. Empty means root.
docker inspect -f 'USER={{.Config.User}}' <image>
# A name (e.g. `appuser`) still needs its number:
docker run --rm --entrypoint sh <image> -c 'getent passwd appuser'
```

Then run it the way the operator will — read-only root filesystem, all
capabilities dropped, as that UID, with only the declared volume writable and
pre-chowned (standing in for `fsGroup`) and any `files:` mounted read-only:

```bash
docker volume create smoke && docker run --rm -u 0 -v smoke:/d busybox chown -R 1000:1000 /d
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --ulimit nofile=1048576:1048576 --user 1000:1000 \
  -v smoke:/app/data -v "$PWD/config.yaml:/app/config.yaml:ro" <image>
```

It has to still be running after ~10s **and** have written into the volume
(`docker run --rm -u 1000 -v smoke:/d busybox ls -la /d`) — an app that starts
but cannot write its database only crash-loops later. Set the `nofile` limit:
containerd's default is 1048576 and Docker's is lower, so an app that raises its
own limit (strfry asks for 1000000) fails locally for a reason that would not
apply on the cluster.

This is not a substitute for a real reconcile — it does not exercise the
ingress, the PVC provisioner or `depends_on` ordering — but it does exercise the
exact check that refuses these pods.

**A service another service talks to must declare `ports:`** (issue #281). The
operator creates a Kubernetes Service — the only thing that gives a compose
service a DNS name inside the namespace — only for a service with declared
ports. So this does not resolve, and the app fails at its first connection with
`Name or service not known`:

```yaml
services:
  db:
    image: postgres:17-alpine
    user: root
    # Drop this block and `db:5432` below stops resolving: no ports, no
    # Service, no DNS name. `expose: none` keeps it in-namespace — only
    # `expose: ingress` ports reach the Ingress.
    ports:
      - { name: postgres, container: 5432, protocol: tcp, expose: none }
  relay:
    image: example/relay:latest
    user: "1000"
    ports:
      - { name: http, container: 3000, protocol: http, expose: ingress }
    env:
      DATABASE_URL: "postgres://buzz:pw@db:5432/buzz"
```

App create/update refuses a compose that addresses a portless peer as
`name:port`, and so do `compose-validate` and `compose-to-docker`. **A local
`docker compose up` will not catch this on its own** — docker gives every
service a DNS alias whether or not it declares ports, which is exactly why the
rule is enforced at authoring time.

**`config[].pattern`** — a regex a submitted value must match, checked at
order time (issue #271):

```yaml
services:
  haven:
    image: holgerhatgarkeinenode/haven-docker:v1.2.2
    user: "1000"
    ports:
      - { name: ws, container: 3355, protocol: http, expose: ingress }
    env:
      OWNER_NPUB: "${owner_npub}"
config:
  - { name: owner_npub, label: "Owner npub", type: string, required: true,
      pattern: "npub1[02-9ac-hj-np-z]{58}" }
```

`type:` only covers what a form input can check — a whole number, a boolean —
and both are now enforced too: an order submitting `abc` for an `int` field is
refused with the field's label. But most catalog fields are a `string` whose
*shape* the app depends on, and an app that is strict about it is strict in the
worst way: HAVEN panics on an `owner_npub` that is not an npub, so before this
a mistyped character was accepted, charged for, and turned into a deployment
that restarted forever with nothing on screen naming the field.

The pattern is **anchored automatically** — it must match the whole value, so
`npub1…` cannot admit a value with junk on the end. It is compiled when the app
is created or updated, so a pattern that does not compile is the author's error
rather than a customer's failed order, and a declared `default` is checked
against its own field there too. Not applied to `type: file`, whose content is
arbitrary. Keep it under 200 characters.

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

## Running a compose document locally

Validation is a static check on the document. It cannot tell you that the
image's entrypoint wants to write to `/run`, or that the app exits because
`RELAY_URL` resolved to an empty string. Those only surface when a container
starts — which is how every managed-app outage so far was eventually found
(#248, #256, #263, #264), long after the app shipped priced and enabled.

`compose-to-docker` renders the document as a `docker-compose.yaml` you can run
(issue #268):

```sh
cargo run -q -p lnvps_compose --bin compose-to-docker -- app.yaml \
    --out-dir .local/haven --config owner_npub=npub1… --hostname localhost

# Then what it prints: create the volumes, chown them (the fsGroup stand-in),
# and start.
docker compose -f .local/haven/docker-compose.yaml up --no-start
docker run --rm -u 0 -v haven_haven-db:/d busybox chown -R 1000:1000 /d
docker compose -f .local/haven/docker-compose.yaml up
```

It resolves config, secrets, `env`, `files` and `init` through the same
functions the operator calls, so what starts locally is what the cluster would
start. The out-dir holds the compose file, the rendered `files[]` (bind-mounted
read-only) and `secrets.env` — generated once and reused, so a second run does
not rotate the password the first run's database was initialised with.

**The hardening is the point.** Every emitted service carries what
`container_security_context_for` sets: `read_only: true`, `cap_drop: [ALL]`,
`security_opt: [no-new-privileges:true]`, the declared `user:`, and — for a
`user: root` service — the five capabilities a root entrypoint gets back
(#263). `scratch:` becomes `tmpfs` at the same byte limit, `volumes[]` become
named volumes, `init:` steps become one-shot services the service waits on with
`condition: service_completed_successfully`. Take any of that out and the run
stops meaning anything: a permissive docker-compose starts all four historically
broken apps cleanly.

A green `docker compose up` means the image starts and the app's own startup
checks pass under our security context. **It is not a deployment test.**

### One command, and the same one CI runs

`scripts/app-catalog-test.sh catalog/<app>.yaml` does the whole loop: render,
create and chown the volumes, `up --wait`, then re-read the state after a settle
period and check every ingress port is listening. It fails if a service exits
non-zero, restarts, or never binds — the three shapes a broken image takes.

```sh
scripts/app-catalog-test.sh catalog/strfry.yaml
```

Ingress ports are published on loopback at the container number, so the script
stops early if one is already taken on your machine rather than reporting it as
the app's fault. Config fields the customer supplies at order time come from
`app_config()` in that script; an entry with a required field and no value there
fails the render loudly.

### Known non-equivalences

- **Volume ownership.** Kubernetes sets `fsGroup` from `user:` so a fresh PVC is
  writable by a non-root container. Docker has no equivalent: a fresh named
  volume is root-owned `0755` and a non-root service cannot write to it. The
  tool prints the `docker volume create … && chown` that stands in for it rather
  than performing it — the failure it produces is local-only, and silently
  fixing it would hide the difference.
- **File-descriptor limits.** The tool sets `nofile` to containerd's default
  (1048576) because dockerd's is lower — without it strfry aborts locally with
  `Unable to set NOFILES limit to 1000000, exceeds max of 524288` while
  starting fine in the cluster.
- **Host ports.** Only `expose: ingress` ports are published, on loopback at the
  same number. If that port is already taken on your machine, pass
  `--no-publish`; services still reach each other by name.
- **`scratch:` is `tmpfs` here, an `emptyDir` there** — memory-backed locally,
  node disk in the cluster. The size limit is the same; the failure mode when an
  app writes far more than it declared is not.
- **No ingress, TLS or cert-manager.** `${HOSTNAME}` is whatever `--hostname`
  says.
- **No `Recreate` strategy, RWO PVC semantics, scheduler or capacity
  accounting**, and `depends_on` is enforced locally where Kubernetes treats it
  as advisory.

---

## strfry — Nostr relay

- **Image:** `dockurr/strfry` — <https://hub.docker.com/r/dockurr/strfry>
  (community; strfry has no official image; image source
  <https://github.com/dockur/strfry>).
- **Repo:** <https://github.com/hoytech/strfry> — config file, `bind` defaults
  to `127.0.0.1` (must be `0.0.0.0` in a container), port `7777`, data in
  `./strfry-db/`. The `dockurr/strfry` image reads `/etc/strfry.conf`.

**Document:** [`catalog/strfry.yaml`](../catalog/strfry.yaml) —
`scripts/app-catalog-test.sh catalog/strfry.yaml` starts it locally.

---

## route96 — Blossom / NIP-96 media server (+ MariaDB)

- **Image:** `voidic/route96` — <https://hub.docker.com/r/voidic/route96> +
  `mariadb:11` — <https://hub.docker.com/_/mariadb>.
- **Repo:** <https://github.com/v0l/route96> — YAML config file at
  `/app/config.yaml`; MySQL/MariaDB backend; blobs under `storage_dir`; port
  `8000`. Mirrors route96's `config.prod.yaml` + `docker-compose.prod.yml`
  (app reaches the DB via the service name `db`).

**Document:** [`catalog/route96.yaml`](../catalog/route96.yaml) —
`scripts/app-catalog-test.sh catalog/route96.yaml` starts it locally.

---

## Blossom Server (hzrd149)

- **Image:** `ghcr.io/hzrd149/blossom-server` —
  <https://github.com/hzrd149/blossom-server/pkgs/container/blossom-server>.
- **Repo:** <https://github.com/hzrd149/blossom-server> — YAML config at
  `/app/config.yml`; listens on `3000`; SQLite + blobs under `/app/data`.
  `publicDomain` is a **bare** hostname (no scheme).

**Document:** [`catalog/blossom-server.yaml`](../catalog/blossom-server.yaml) —
`scripts/app-catalog-test.sh catalog/blossom-server.yaml` starts it locally.

---

## nostr-rs-relay

- **Image:** `scsibug/nostr-rs-relay` (official pre-built) —
  <https://hub.docker.com/r/scsibug/nostr-rs-relay>.
- **Repo:** <https://github.com/scsibug/nostr-rs-relay> — optional TOML config
  at `/usr/src/app/config.toml`; listens on `8080`; SQLite DB under
  `/usr/src/app/db`. Set `network.address = "0.0.0.0"` so it's reachable in the
  pod.

**Document:** [`catalog/nostr-rs-relay.yaml`](../catalog/nostr-rs-relay.yaml) —
`scripts/app-catalog-test.sh catalog/nostr-rs-relay.yaml` starts it locally.

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

**Document:** [`catalog/pyramid.yaml`](../catalog/pyramid.yaml) —
`scripts/app-catalog-test.sh catalog/pyramid.yaml` starts it locally.

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
  `relays_import.json` and `relays_blastr.json` at startup (provided via
  `files:`); the whitelist/blacklist files are optional and disabled by setting
  their env vars to `""` (owner-only).
- **Caveat:** current published community images do **not** bundle HAVEN's
  `templates/` directory, so the web landing page at `/` won't render — but the
  relay itself works fully over WebSocket (which is what the ingress serves as
  `wss://`). A fix to bake the templates into the image is proposed upstream
  (<https://github.com/HolgerHatGarKeineNode/haven-docker/pull/8>); once merged
  and released the dashboard works out of the box.

**Document:** [`catalog/haven.yaml`](../catalog/haven.yaml) —
`scripts/app-catalog-test.sh catalog/haven.yaml` starts it locally.

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
    `BUZZ_GIT_PROBE_ROUNDS=1` in the document — do not remove them, and do not paper
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

**Document:** [`catalog/buzz.yaml`](../catalog/buzz.yaml) —
`scripts/app-catalog-test.sh catalog/buzz.yaml` starts it locally.

### Before this one can be enabled

Both compose-grammar gaps this entry was blocked on have landed: the 32-byte
generated secret (#243, `bytes:` on a secret declaration, used in the document for
`BUZZ_RELAY_PRIVATE_KEY`) and bucket creation (#244, `init:` on the `relay`
service). The customer no longer pastes the relay's identity key into the
order form, and nothing in the deployment has to pre-exist.

What is **not** yet done is a run of this exact compose through the operator
against a live cluster — the composition has never been reconciled end to
end with the init step in place. Do that before enabling it in the catalog:
validation checks the document, not whether the app starts.

Everything else was verified end-to-end against these images (relay reaches
`buzz-relay TCP listening`, `/_readiness` 200, NIP-11 served, A3 probe
admitted) with all four containers running read-only-rootfs and non-root
where the image allows it.

---

## AppWeaver — AI-powered app hub

- **Image:** `ghcr.io/getappweaver/core:alpine` — published from
  <https://github.com/getappweaver/core>. The Alpine runtime includes Bun,
  OpenCode, ngit and Piper, but deliberately excludes Chromium, Playwright
  browsers, Cursor Agent and VNC.
- **Repo:** <https://github.com/getappweaver/core> — the entrypoint clones the
  core repository into the persistent workspace on first boot, installs its
  locked dependencies and starts the setup web UI on port `5551`. The workspace
  volume retains configuration, credentials, installed apps and app data across
  image upgrades.
- **Authentication:** API-key and device-code OpenCode providers work through
  the setup web UI. A provider that requires a callback to the user's localhost
  cannot be authenticated without a separate tunnel and should not be selected
  for a managed deployment.
- **Setup access:** the order form requires the owner's 64-character lowercase
  hex Nostr pubkey. AppWeaver receives it as `BOT_MASTER_PUBKEY`; `/setup`
  requires a matching NIP-98 signature before issuing an in-memory setup
  session, so the customer does not need access to container logs.

**Document:** [`catalog/appweaver.yaml`](../catalog/appweaver.yaml) —
`scripts/app-catalog-test.sh catalog/appweaver.yaml` starts it locally.

---

## Notes on other apps

- **zap-stream-core** — needs raw TCP/UDP ingest (RTMP `1935/tcp`, SRT), i.e.
  the not-yet-implemented `expose: tcp|udp` path.
