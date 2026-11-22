import vueSfc from "@vitejs/plugin-vue";
import vueJsx from "@vitejs/plugin-vue-jsx";
import { defineConfig } from "vite";

// Build-only config (family convention: no dev server, no HMR, no proxy —
// rebuilds are driven externally and the dist is embedded into the binary).
export default defineConfig({
  plugins: [vueSfc(), vueJsx()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
  },
  server: { hmr: false },
});