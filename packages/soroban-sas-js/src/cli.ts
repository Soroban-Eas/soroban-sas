#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { generateTypeScript } from "./typegen.js";

function usage(): never {
  throw new Error("Usage: sas-typegen <schema|--schema-file path> [--name InterfaceName] [--out file]");
}

async function main(args: string[]): Promise<void> {
  let schema: string | undefined;
  let name = "AttestationPayload";
  let output: string | undefined;
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--schema-file": {
        const path = args[++i];
        if (!path || schema !== undefined) usage();
        schema = await readFile(path, "utf8");
        break;
      }
      case "--name": name = args[++i] ?? usage(); break;
      case "--out": output = args[++i] ?? usage(); break;
      case "--help":
      case "-h":
        process.stdout.write("Usage: sas-typegen <schema|--schema-file path> [--name InterfaceName] [--out file]\n");
        return;
      default:
        if (args[i].startsWith("-" ) || schema !== undefined) usage();
        schema = args[i];
    }
  }
  if (schema === undefined) usage();
  const generated = `${generateTypeScript(schema, name)}\n`;
  if (output) await writeFile(output, generated, "utf8");
  else process.stdout.write(generated);
}

main(process.argv.slice(2)).catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
