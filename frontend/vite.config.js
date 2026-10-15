import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"

const backend = process.env.BACKEND_URL || "http://localhost:8000"
const warden = process.env.WARDEN_URL || "http://localhost:8001"

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (
            id.includes("/node_modules/recharts/") ||
            id.includes("/node_modules/victory-vendor/") ||
            id.includes("/node_modules/d3-")
          ) {
            return "charts"
          }
          if (id.includes("/node_modules/")) return "vendor"
        },
      },
    },
  },
  server: {
    host: "0.0.0.0",
    proxy: {
      "/api": backend,
      "/health": backend,
      "/gateway": warden,
    },
  },
})
