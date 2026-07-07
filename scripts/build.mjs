import { build, context } from "esbuild";
import { cpSync, existsSync, mkdirSync, rmSync, watch } from "node:fs";
import { resolve } from "node:path";
import { readFile } from "node:fs/promises";

const argTarget = process.argv.find((v) => v.startsWith("--target="));
const target = (argTarget ? argTarget.split("=")[1] : "all").toLowerCase();
const watchMode = process.argv.includes("--watch");

const validTargets = ["chrome", "firefox"];
const targets = target === "all" ? validTargets : [target];
for (const t of targets) {
  if (!validTargets.includes(t)) {
    throw new Error(`Unsupported target: ${t}`);
  }
}

const root = process.cwd();
const distRoot = resolve(root, "dist");

async function validateManifestParity() {
  const chromeManifest = JSON.parse(await readFile(resolve(root, "manifests", "manifest.chrome.json"), "utf8"));
  const firefoxManifest = JSON.parse(await readFile(resolve(root, "manifests", "manifest.firefox.json"), "utf8"));

  const keysToMatch = ["name", "version", "description"];
  for (const key of keysToMatch) {
    if (chromeManifest[key] !== firefoxManifest[key]) {
      throw new Error(`Manifest mismatch for '${key}': chrome='${chromeManifest[key]}' firefox='${firefoxManifest[key]}'`);
    }
  }
}

function copyManifest(targetName) {
  const src = resolve(root, "manifests", `manifest.${targetName}.json`);
  const outDir = resolve(distRoot, targetName);
  mkdirSync(outDir, { recursive: true });
  cpSync(src, resolve(outDir, "manifest.json"));
}

function copyPopup(targetName) {
  const outDir = resolve(distRoot, targetName);
  cpSync(resolve(root, "src", "popup", "popup.html"), resolve(outDir, "popup.html"));
  cpSync(resolve(root, "src", "popup", "popup.css"), resolve(outDir, "popup.css"));
}

function copyOptions(targetName) {
  const outDir = resolve(distRoot, targetName);
  cpSync(resolve(root, "src", "options", "options.html"), resolve(outDir, "options.html"));
  cpSync(resolve(root, "src", "options", "options.css"), resolve(outDir, "options.css"));
}

function copyOnboarding(targetName) {
  const outDir = resolve(distRoot, targetName);
  cpSync(resolve(root, "src", "onboarding", "onboarding.html"), resolve(outDir, "onboarding.html"));
  cpSync(resolve(root, "src", "onboarding", "onboarding.css"), resolve(outDir, "onboarding.css"));
}

function copyIcons(targetName) {
  const outDir = resolve(distRoot, targetName);
  cpSync(resolve(root, "assets", "icons"), resolve(outDir, "icons"), { recursive: true });
}

function copyStaticAssets(targetName) {
  copyManifest(targetName);
  copyPopup(targetName);
  copyOptions(targetName);
  copyOnboarding(targetName);
  copyIcons(targetName);
}

function watchStaticAssets(targetName) {
  const outDir = resolve(distRoot, targetName);
  const staticFiles = [
    { src: resolve(root, "manifests", `manifest.${targetName}.json`), dest: resolve(outDir, "manifest.json") },
    { src: resolve(root, "src", "popup", "popup.html"), dest: resolve(outDir, "popup.html") },
    { src: resolve(root, "src", "popup", "popup.css"), dest: resolve(outDir, "popup.css") },
    { src: resolve(root, "src", "options", "options.html"), dest: resolve(outDir, "options.html") },
    { src: resolve(root, "src", "options", "options.css"), dest: resolve(outDir, "options.css") },
    { src: resolve(root, "src", "onboarding", "onboarding.html"), dest: resolve(outDir, "onboarding.html") },
    { src: resolve(root, "src", "onboarding", "onboarding.css"), dest: resolve(outDir, "onboarding.css") }
  ];
  const iconsDir = resolve(root, "assets", "icons");
  const iconsOutDir = resolve(outDir, "icons");

  for (const file of staticFiles) {
    watch(file.src, { persistent: true }, () => {
      cpSync(file.src, file.dest);
      console.log(`[watch] ${targetName} copied ${file.src}`);
    });
  }

  watch(iconsDir, { persistent: true }, () => {
    cpSync(iconsDir, iconsOutDir, { recursive: true });
    console.log(`[watch] ${targetName} copied icons`);
  });
}

async function buildTarget(targetName) {
  const outDir = resolve(distRoot, targetName);
  mkdirSync(outDir, { recursive: true });

  const common = {
    bundle: true,
    format: "iife",
    target: ["chrome121", "firefox121", "safari17", "edge121"],
    sourcemap: true,
    logLevel: "info",
    define: {
      __DEBUG__: JSON.stringify(process.env.DEBUG === "true")
    },
    alias: {
      "@": resolve(root, "src")
    }
  };

  const entries = [
    { in: resolve(root, "src", "background", "index.ts"), out: resolve(outDir, "background.js") },
    { in: resolve(root, "src", "content", "index.ts"), out: resolve(outDir, "content.js") },
    { in: resolve(root, "src", "popup", "index.ts"), out: resolve(outDir, "popup.js") },
    { in: resolve(root, "src", "options", "index.ts"), out: resolve(outDir, "options.js") },
    { in: resolve(root, "src", "onboarding", "index.ts"), out: resolve(outDir, "onboarding.js") }
  ];

  if (watchMode) {
    const contexts = [];
    for (const entry of entries) {
      const ctx = await context({
        ...common,
        entryPoints: [entry.in],
        outfile: entry.out
      });
      await ctx.watch();
      contexts.push(ctx);
    }
    copyStaticAssets(targetName);
    watchStaticAssets(targetName);
    console.log(`[watch] ${targetName} extension watching...`);
    return contexts;
  }

  for (const entry of entries) {
    await build({
      ...common,
      entryPoints: [entry.in],
      outfile: entry.out
    });
  }

  copyStaticAssets(targetName);
}

async function main() {
  await validateManifestParity();
  if (!watchMode && existsSync(distRoot)) {
    rmSync(distRoot, { recursive: true, force: true });
  }
  for (const t of targets) {
    await buildTarget(t);
    console.log(`[build] completed target: ${t}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
