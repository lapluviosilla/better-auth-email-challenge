#!/usr/bin/env node
// Runs typecheck + tests against each `better-auth` version in the matrix.
// Restores `better-auth@latest` at the end so the working tree matches what CI does.

import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const VERSIONS = process.env.MATRIX_VERSIONS?.split(",") ?? [
  "1.5.0", // declared floor
  "latest",
];

const pkgPath = resolve("package.json");
const originalPkg = readFileSync(pkgPath, "utf8");

const sh = (cmd) => execSync(cmd, { stdio: "inherit" });
const shQuiet = (cmd) =>
  execSync(cmd, { stdio: ["ignore", "pipe", "pipe"] })
    .toString()
    .trim();

const installed = () => {
  const v = JSON.parse(
    readFileSync("node_modules/better-auth/package.json", "utf8"),
  ).version;
  return v;
};

const results = [];

for (const version of VERSIONS) {
  console.log(`\n━━━ better-auth@${version} ━━━`);
  try {
    sh(`npm install better-auth@${version} --save-dev --legacy-peer-deps`);
    console.log(`installed: ${installed()}`);
    sh("npx tsc --noEmit");
    sh("npx vitest run");
    results.push({ version, installed: installed(), status: "pass" });
  } catch {
    results.push({
      version,
      installed: (() => {
        try {
          return installed();
        } catch {
          return "n/a";
        }
      })(),
      status: "fail",
    });
  }
}

// Restore the original package.json so the working tree matches what was checked in.
writeFileSync(pkgPath, originalPkg);
console.log("\nRestoring devDependency range from package.json…");
sh("npm install --legacy-peer-deps");

console.log("\n━━━ Matrix summary ━━━");
for (const r of results) {
  const mark = r.status === "pass" ? "✓" : "✗";
  console.log(
    `${mark} better-auth@${r.version} → ${r.installed} → ${r.status}`,
  );
}

if (results.some((r) => r.status === "fail")) process.exit(1);
