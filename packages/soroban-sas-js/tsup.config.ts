import { defineConfig } from "tsup";

const common = { sourcemap: true, target: "es2022" as const };

export default [
  defineConfig({
    ...common,
    entry: {
      index: "src/index.ts",
      node: "src/node.ts",
      client: "src/client-entry.ts",
      cli: "src/cli.ts",
      testing: "src/testing.ts",
      schema: "src/schema.ts",
      typegen: "src/typegen.ts",
    },
    format: ["esm", "cjs"],
    dts: true,
    clean: true,
  }),
  defineConfig({
    ...common,
    entry: { browser: "src/index.ts" },
    platform: "browser",
    format: ["esm"],
    bundle: true,
    noExternal: ["@noble/curves", "@noble/hashes", "buffer"],
    esbuildOptions(options) {
      options.banner = {
        ...(options.banner ?? {}),
        js: "var self = globalThis;",
      };
    },
  }),
];
