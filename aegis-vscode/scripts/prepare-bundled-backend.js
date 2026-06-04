const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

const extensionRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(extensionRoot, "..");
const coreRoot = path.join(repoRoot, "aegis-ai-core");
const targetRoot = path.join(extensionRoot, "resources", "aegis-ai-core");
const manifestName = "backend-manifest.json";

const excludedDirectories = new Set([
  ".aegis-cache",
  ".cache",
  ".mypy_cache",
  ".pytest_cache",
  ".ruff_cache",
  "__pycache__",
  "aegis_db",
  "data",
  "htmlcov",
  "real_world_targets",
  "reports",
  "tests",
]);

const excludedExtensions = new Set([".pyc", ".pyd", ".pyo"]);

function assertExists(candidate, description) {
  if (!fs.existsSync(candidate)) {
    throw new Error(`${description} not found: ${candidate}`);
  }
}

function shouldSkip(sourcePath) {
  const name = path.basename(sourcePath);
  if (excludedDirectories.has(name)) {
    return true;
  }
  return excludedExtensions.has(path.extname(name));
}

function copyRecursive(sourcePath, targetPath) {
  if (shouldSkip(sourcePath)) {
    return;
  }

  const stat = fs.statSync(sourcePath);
  if (stat.isDirectory()) {
    fs.mkdirSync(targetPath, { recursive: true });
    for (const entry of fs.readdirSync(sourcePath)) {
      copyRecursive(path.join(sourcePath, entry), path.join(targetPath, entry));
    }
    return;
  }

  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.copyFileSync(sourcePath, targetPath);
}

function listFiles(root, current = root) {
  const entries = fs.readdirSync(current, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(current, entry.name);
    if (entry.isDirectory()) {
      files.push(...listFiles(root, fullPath));
    } else if (entry.isFile() && entry.name !== manifestName) {
      files.push(path.relative(root, fullPath).replace(/\\/g, "/"));
    }
  }
  return files.sort();
}

function writeBackendManifest() {
  const files = listFiles(targetRoot);
  const hash = crypto.createHash("sha256");
  for (const rel of files) {
    const fullPath = path.join(targetRoot, rel);
    hash.update(rel);
    hash.update("\0");
    hash.update(fs.readFileSync(fullPath));
    hash.update("\0");
  }
  fs.writeFileSync(
    path.join(targetRoot, manifestName),
    JSON.stringify(
      {
        manifestVersion: 1,
        fingerprint: hash.digest("hex"),
        files: files.length,
      },
      null,
      2,
    ),
    "utf8",
  );
}

function main() {
  assertExists(path.join(coreRoot, "pyproject.toml"), "aegis-ai-core pyproject.toml");
  assertExists(path.join(coreRoot, "src", "lsp", "__main__.py"), "Aegis LSP entry point");

  fs.rmSync(targetRoot, { recursive: true, force: true });
  fs.mkdirSync(targetRoot, { recursive: true });

  fs.copyFileSync(path.join(coreRoot, "pyproject.toml"), path.join(targetRoot, "pyproject.toml"));
  copyRecursive(path.join(coreRoot, "src"), path.join(targetRoot, "src"));
  writeBackendManifest();

  console.log(`[Aegis] Prepared bundled backend at ${targetRoot}`);
}

main();
