# lnvps_fw dashboard

The daemon's internal control dashboard — a **Vite + TypeScript + Preact** app
built into a single self-contained `dist/index.html` (JS + CSS inlined, no
external requests) which the service embeds via `include_str!` and serves
same-origin under a strict CSP.

## Develop

```sh
# Point the dev server's /api proxy at a running daemon (self-signed cert ok):
VITE_API_TARGET=https://127.0.0.1:8888 bun run dev
```

The dev server serves the UI with hot-reload and proxies `/api/*` to the
daemon, so the app's relative fetch paths work in both dev and production.

## Build

```sh
bun install
bun run build        # -> dist/index.html  (commit this)
bun run check        # tsc --noEmit
```

`dist/index.html` is committed so a plain `cargo build` needs no Node toolchain;
CI (`lnvps_fw-deb.yml`) also rebuilds it before packaging. **After changing
anything under `src/`, run `bun run build` and commit the updated `dist/`.**
