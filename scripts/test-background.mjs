import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const tempDir = mkdtempSync(join(tmpdir(), "sshkey-web-auth-tests-"));
const outfile = join(tempDir, "background-policy.test.mjs");

const srcPath = fileURLToPath(new URL("../src", import.meta.url));

try {
  await build({
    entryPoints: ["tests/background-policy.test.ts"],
    outfile,
    format: "esm",
    platform: "node",
    target: ["node20"],
    bundle: true,
    sourcemap: false,
    alias: {
      "@": srcPath
    }
  });

  const testRun = spawnSync(process.execPath, ["--test", outfile], {
    stdio: "inherit"
  });
  process.exit(testRun.status ?? 1);
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}
