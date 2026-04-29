import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

type BumpKind = "major" | "minor" | "patch" | "prerelease";

interface PackageJson {
  version: string;
  [key: string]: unknown;
}

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function main(): Promise<void> {
  const requested = process.argv[2];
  if (!requested) {
    throw new Error("Usage: bun run version:bump -- <major|minor|patch|prerelease|x.y.z[-tag.n]>");
  }

  const packagePath = path.join(rootDir, "package.json");
  const pkg = JSON.parse(await fs.readFile(packagePath, "utf8")) as PackageJson;
  const nextVersion = isBumpKind(requested)
    ? bumpVersion(pkg.version, requested)
    : normalizeVersion(requested);

  pkg.version = nextVersion;
  await fs.writeFile(packagePath, `${JSON.stringify(pkg, null, 2)}\n`, "utf8");
  console.log(`${nextVersion}`);
}

function isBumpKind(value: string): value is BumpKind {
  return value === "major" || value === "minor" || value === "patch" || value === "prerelease";
}

function bumpVersion(current: string, kind: BumpKind): string {
  const parsed = parseVersion(current);
  if (kind === "major") return `${parsed.major + 1}.0.0`;
  if (kind === "minor") return `${parsed.major}.${parsed.minor + 1}.0`;
  if (kind === "patch") return `${parsed.major}.${parsed.minor}.${parsed.patch + 1}`;

  const prerelease = parsed.prerelease ?? "alpha.0";
  const match = /^(.*?)(\d+)$/.exec(prerelease);
  if (!match) return `${parsed.major}.${parsed.minor}.${parsed.patch}-${prerelease}.1`;
  const label = match[1];
  const number = Number(match[2]);
  return `${parsed.major}.${parsed.minor}.${parsed.patch}-${label}${number + 1}`;
}

function normalizeVersion(value: string): string {
  parseVersion(value);
  return value;
}

function parseVersion(value: string): { major: number; minor: number; patch: number; prerelease?: string } {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(value);
  if (!match) throw new Error(`Invalid semver version: ${value}`);
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4],
  };
}

main().catch((error) => {
  console.error("Version bump failed:", error);
  process.exit(1);
});
