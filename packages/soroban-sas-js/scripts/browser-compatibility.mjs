import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const packageDir = new URL("..", import.meta.url).pathname;
const packageJson = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8"));
const run = (command, args, cwd) => execFileSync(command, args, { cwd, stdio: "inherit" });

run("npm", ["run", "build"], packageDir);

const browser = readFileSync(join(packageDir, "dist/browser.js"), "utf8");
const esm = readFileSync(join(packageDir, "dist/index.js"), "utf8");
const cjs = readFileSync(join(packageDir, "dist/index.cjs"), "utf8");
const forbidden = /(?:["']node:|require\(["'](?:crypto|fs|path|stream|util)["']\)|from ["'](?:crypto|fs|path|stream|util)["'])/;
if (forbidden.test(browser) || forbidden.test(esm) || forbidden.test(cjs)) {
  throw new Error("Node.js built-in module reference found in SDK distribution");
}

for (const file of ["index.d.ts", "index.d.cts", "index.d.ts.map", "index.d.cts.map"]) {
  try {
    readFileSync(join(packageDir, "dist", file));
  } catch {
    throw new Error(`Missing declaration artifact: dist/${file}`);
  }
}

const gzipBytes = Number(execFileSync("gzip", ["-c", join(packageDir, "dist/browser.js")]).length);
console.log(`SDK browser artifact: ${gzipBytes} bytes gzipped (dependency-inclusive consumer size is reported by Vite below)`);

const temp = mkdtempSync(join(tmpdir(), "soroban-sas-browser-"));
process.on("exit", () => rmSync(temp, { recursive: true, force: true }));
const packed = JSON.parse(execFileSync("npm", ["pack", "--json", "--pack-destination", temp], { cwd: packageDir }))[0].filename;
const tarball = join(temp, packed);
const tarContents = execFileSync("tar", ["-tzf", tarball], { encoding: "utf8" });
for (const required of ["package/src/index.ts", "package/dist/index.d.ts.map", "package/dist/index.d.cts.map"]) {
  if (!tarContents.split("\n").includes(required)) throw new Error(`Packed package is missing ${required}`);
}
const fixture = join(temp, "fixture");
mkdirSync(join(fixture, "src"), { recursive: true });
const fixturePackage = {
  private: true,
  type: "module",
  dependencies: {
    "@soroban-sas/sdk": `file:${tarball}`,
  },
};
writeFileSync(join(fixture, "package.json"), JSON.stringify(fixturePackage));
run("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--prefix", fixture, "--package-lock=false"], temp);
for (const dependency of ["vite", "next", "react", "react-dom"]) {
  symlinkSync(join(packageDir, "node_modules", dependency), join(fixture, "node_modules", dependency), "junction");
}

writeFileSync(join(fixture, "index.html"), '<div id="app"></div><script type="module" src="/src/main.js"></script>');
writeFileSync(join(fixture, "src/main.js"), `window.addEventListener("error", (event) => { document.querySelector("#app").textContent = "ERROR: " + event.error?.stack; });\nimport { computeSchemaUid } from "@soroban-sas/sdk";\ndocument.querySelector("#app").textContent = computeSchemaUid("browser", "GA5WUJ54Z23KILLCUOUNAKTPBVZWKMQVO4O6EQ5GHLAERIMLLHNCSKYH", true);`);
run(join(packageDir, "node_modules/.bin/vite"), ["build"], fixture);
const viteAssets = readdirSync(join(fixture, "dist", "assets"))
  .filter((file) => file.endsWith(".js"))
  .map((file) => join(fixture, "dist", "assets", file));
const viteBytes = viteAssets.reduce((total, file) => total + statSync(file).size, 0);
const viteGzipBytes = viteAssets.reduce(
  (total, file) => total + Number(execFileSync("gzip", ["-c", file]).length),
  0,
);
const browserDependencyLeak = /(?:["']node:|(?:__require|require)\(["'](?:crypto|fs|path|stream|util|http|https|net|tls|url|assert)["']\)|require-addon\/|from ["'](?:crypto|fs|path|stream|util|http|https|net|tls|url|assert)["'])/;
if (viteAssets.some((file) => browserDependencyLeak.test(readFileSync(file, "utf8")))) {
  throw new Error("Vite browser output contains a Node.js built-in or native signing dependency");
}
console.log(`Vite consumer JavaScript: ${viteBytes} bytes, ${viteGzipBytes} bytes gzipped`);
const sizeFailure = viteGzipBytes >= 50 * 1024;

writeFileSync(join(fixture, "src/client-main.js"), `import { SASClient } from "@soroban-sas/sdk/client";\ndocument.querySelector("#app").textContent = typeof SASClient;`);
writeFileSync(join(fixture, "client.html"), '<div id="app"></div><script type="module" src="/src/client-main.js"></script>');
writeFileSync(join(fixture, "vite.client.config.mjs"), 'export default { build: { rollupOptions: { input: "client.html" } } };\n');
run(join(packageDir, "node_modules/.bin/vite"), ["build", "--config", "vite.client.config.mjs", "--outDir", "client-dist"], fixture);
const clientAssets = readdirSync(join(fixture, "client-dist", "assets"))
  .filter((file) => file.endsWith(".js"))
  .map((file) => join(fixture, "client-dist", "assets", file));
const clientBytes = clientAssets.reduce((total, file) => total + statSync(file).size, 0);
const clientGzipBytes = clientAssets.reduce(
  (total, file) => total + Number(execFileSync("gzip", ["-c", file]).length),
  0,
);
console.log(`Vite full /client JavaScript: ${clientBytes} bytes, ${clientGzipBytes} bytes gzipped (optional, not part of the core budget)`);

const chrome = ["google-chrome", "chromium", "chromium-browser"].find((candidate) => {
  try {
    execFileSync("which", [candidate], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
});
if (chrome) {
  const preview = spawn(join(packageDir, "node_modules/.bin/vite"), ["preview", "--host", "127.0.0.1", "--port", "4179"], { cwd: fixture, stdio: "ignore" });
  const clientPreview = spawn(join(packageDir, "node_modules/.bin/vite"), ["preview", "--host", "127.0.0.1", "--port", "4180", "--outDir", "client-dist"], { cwd: fixture, stdio: "ignore" });
  try {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      try {
        if ((await fetch("http://127.0.0.1:4179/")).ok) break;
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    const dom = execFileSync(chrome, ["--headless", "--no-sandbox", "--disable-gpu", "--dump-dom", "http://127.0.0.1:4179/"], { encoding: "utf8" });
    if (!dom.includes("8658b775c3eaff1bdae4855a96911bab8348f9d664995a5248aebca41d819907")) {
      throw new Error(`Packed SDK browser runtime produced an unexpected UID: ${dom}`);
    }
    console.log(`Browser runtime check passed with ${chrome}`);
    for (let attempt = 0; attempt < 30; attempt += 1) {
      try {
        if ((await fetch("http://127.0.0.1:4180/")).ok) break;
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    const clientDom = execFileSync(chrome, ["--headless", "--no-sandbox", "--disable-gpu", "--dump-dom", "http://127.0.0.1:4180/client.html"], { encoding: "utf8" });
    if (!clientDom.includes("function")) throw new Error("Packed /client browser runtime import failed");
    console.log("Full /client browser import runtime check passed");
  } finally {
    preview.kill();
    clientPreview.kill();
  }
} else {
  throw new Error("Browser runtime check requires Chromium; install google-chrome or chromium");
}

writeFileSync(join(fixture, "next.config.mjs"), "export default {};\n");
mkdirSync(join(fixture, "app"), { recursive: true });
writeFileSync(join(fixture, "app/layout.jsx"), "export default function Layout({ children }) { return <html><body>{children}</body></html>; }\n");
writeFileSync(join(fixture, "app/page.jsx"), '"use client";\nimport { computeSchemaUid } from "@soroban-sas/sdk";\nexport default function Page() { return <main>{computeSchemaUid("next", "GA5WUJ54Z23KILLCUOUNAKTPBVZWKMQVO4O6EQ5GHLAERIMLLHNCSKYH", true)}</main>; }\n');
run(join(packageDir, "node_modules/.bin/next"), ["build"], fixture);

rmSync(temp, { recursive: true, force: true });
if (sizeFailure) {
  throw new Error(`Dependency-inclusive Vite browser output is ${viteGzipBytes} bytes gzipped; the <50 KiB requirement remains unmet`);
}
console.log("Browser compatibility checks passed: Vite build, Next App Router build, exports, declarations, Node built-in scan, and gzip budget.");
