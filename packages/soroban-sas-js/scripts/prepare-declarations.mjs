import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dist = new URL("../dist/", import.meta.url).pathname;
const map = JSON.parse(readFileSync(join(dist, "index.d.ts.map"), "utf8"));
map.file = "index.d.cts";
writeFileSync(join(dist, "index.d.cts.map"), `${JSON.stringify(map)}\n`);
copyFileSync(join(dist, "index.d.ts"), join(dist, "index.d.cts"));
