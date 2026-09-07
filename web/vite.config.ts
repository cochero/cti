import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Dev: the SPA proxies /api to the Django core (session cookie + CSRF
// flow through unchanged). Prod: Caddy serves the built assets and routes
// /api to the core — same origin either way, no CORS surface.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.TRUVO_CORE_URL || "http://localhost:8000",
        changeOrigin: false,
      },
      "/oidc": {
        target: process.env.TRUVO_CORE_URL || "http://localhost:8000",
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
