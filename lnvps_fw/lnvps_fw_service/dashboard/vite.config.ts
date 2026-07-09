import { defineConfig } from "vite";
import preact from "@preact/preset-vite";
import { viteSingleFile } from "vite-plugin-singlefile";

// Build the dashboard into a single self-contained index.html (JS + CSS
// inlined, no external requests) so the daemon can `include_str!` it and serve
// it same-origin under a strict CSP.
//
// In production the bundle is served by the daemon, so `/api/*` is same-origin.
// The dev server (`bun run dev`) runs on its own port, so it proxies `/api/*`
// to a running daemon. Point it at yours with:
//   VITE_API_TARGET=https://host:8888 bun run dev
// (`secure: false` accepts the daemon's self-signed API cert.)
const API_TARGET = process.env.VITE_API_TARGET || "https://127.0.0.1:8888";

export default defineConfig({
  plugins: [preact(), viteSingleFile()],
  server: {
    proxy: {
      "/api": { target: API_TARGET, changeOrigin: true, secure: false },
    },
  },
  build: {
    target: "es2020",
    outDir: "dist",
    emptyOutDir: true,
    cssCodeSplit: false,
    assetsInlineLimit: 100_000_000,
    chunkSizeWarningLimit: 100_000_000,
  },
});
