/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_OPENCLAW_GATEWAY_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
