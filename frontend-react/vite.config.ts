import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // The backend runs the C++ engine and stores what n8n sends back. Proxying
    // means the browser sees a same-origin /api, so there is no CORS setup for
    // whoever builds the backend to get wrong.
    proxy: {
      "/api": {
        target: "http://localhost:3000",
        changeOrigin: true,
      },
    },
  },
  build: { outDir: "dist", sourcemap: true },
});
