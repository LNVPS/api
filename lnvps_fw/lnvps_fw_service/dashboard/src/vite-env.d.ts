/// <reference types="vite/client" />

interface ImportMetaEnv {
  // Optional token baked into the demo image build so the dashboard
  // auto-connects without a manual login. Unset in normal release builds.
  readonly VITE_DEMO_TOKEN?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
