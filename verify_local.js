// Verify the scanner against a local checkout (so we don't hit GitHub rate
// limits). Walks a directory, filters to relevant files, runs the scanner.

"use strict";
const fs = require("fs");
const path = require("path");

const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
const scriptMatch = html.match(/<script>\s*"use strict";([\s\S]*?)<\/script>/);
const fullJs = scriptMatch[1];
const cutAt = fullJs.indexOf("// Renderer");
const scannerJs = fullJs.slice(0, cutAt);
const ctx = {};
new Function("module", "exports", scannerJs + "\nmodule.exports = { RULES, scanFile };")(ctx, ctx);
const { scanFile } = ctx.exports;

function walk(dir, base = "") {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith(".git") || entry.name === "node_modules" || entry.name === "__pycache__") continue;
    const full = path.join(dir, entry.name);
    const rel = base ? `${base}/${entry.name}` : entry.name;
    if (entry.isDirectory()) out.push(...walk(full, rel));
    else if (entry.isFile()) out.push({ full, rel });
  }
  return out;
}

function isRelevant(p) {
  return /\.py$/i.test(p) ||
    /(^|\/)(setup\.cfg|setup\.py|pyproject\.toml)$/i.test(p) ||
    /(^|\/)requirements[^\/]*\.txt$/i.test(p);
}

const target = process.argv[2];
if (!target) {
  console.log("Usage: node verify_local.js <path/to/repo>");
  process.exit(1);
}

const files = walk(target).filter((f) => isRelevant(f.rel));
console.log(`\n=== ${target} : ${files.length} relevant files ===`);

let totalLines = 0;
const counts = { crit: 0, high: 0, warn: 0, info: 0 };
const byRule = {};

for (const { full, rel } of files) {
  const src = fs.readFileSync(full, "utf8");
  totalLines += (src.match(/\n/g) || []).length + 1;
  const findings = scanFile(rel, src);
  for (const f of findings) {
    counts[f.severity]++;
    byRule[f.ruleId] = (byRule[f.ruleId] || 0) + 1;
  }
}

console.log(`  ${totalLines} lines analysed`);
console.log(`  crit=${counts.crit}  high=${counts.high}  warn=${counts.warn}  info=${counts.info}`);
console.log(`  fired rules:`);
for (const [rule, n] of Object.entries(byRule).sort((a, b) => b[1] - a[1])) {
  console.log(`    ${n.toString().padStart(3)} × ${rule}`);
}
