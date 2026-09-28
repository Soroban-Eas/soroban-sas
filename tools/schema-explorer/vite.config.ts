/// <reference types="vitest" />
import { defineConfig } from "vite";

export default defineConfig({
  // Relative asset URLs so `dist/` can be served from any sub-path or opened
  // from a static file host without rewriting.
  base: "./",
  define: {
    // @stellar/stellar-sdk reads `global` in a few code paths.
    global: "globalThis",
  },
  build: {
    target: "es2022",
    // The Stellar SDK dominates the bundle; don't warn about it.
    chunkSizeWarningLimit: 2048,
  },
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
  },
});
