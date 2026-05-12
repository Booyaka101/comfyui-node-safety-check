#!/usr/bin/env node
/**
 * Sweep — runs the same rule engine that powers the live page against every
 * custom node listed in ComfyUI-Manager's custom-node-list.json. Outputs a
 * machine-readable JSON dump and a human triage markdown locally — nothing
 * is uploaded, committed, or transmitted anywhere outside GitHub's public
 * read endpoints.
 *
 * Usage:
 *   GITHUB_TOKEN=ghp_xxx node tools/sweep.js
 *
 *     --limit N       Only scan first N repos (handy for a smoke test)
 *     --resume        Continue from sweep-progress.json (default behaviour
 *                     if the file exists)
 *     --restart       Start over even if progress exists
 *     --out DIR       Output directory (default: ./sweep-output)
 *
 * Outputs:
 *   sweep-output/sweep-results.json   full findings, JSON
 *   sweep-output/sweep-triage.md      human-readable manual review queue
 *   sweep-output/sweep-progress.json  resume state (delete to start over)
 *
 * Hard rules:
 *   - PAT is read from process.env.GITHUB_TOKEN only. Never written to disk.
 *   - All output is local. The script does no git commits, no network egress
 *     beyond api.github.com and raw.githubusercontent.com.
 *   - Critical findings are not published. They go to triage, then if
 *     confirmed get reported privately to Comfy-Org's security-review-council.
 *
 * Etiquette:
 *   - 200 ms delay between API calls even with PAT (still hits rate limit
 *     occasionally for unrelated reasons — be a good citizen).
 *   - 30 s back-off on 403, retry once.
 *   - Pauses if rate-limit remaining drops below 50.
 */

"use strict";
const fs = require("fs");
const path = require("path");
const https = require("https");
const { URL } = require("url");

// ----- Args -----
const ARGS = (() => {
  const a = process.argv.slice(2);
  const opts = { limit: Infinity, resume: true, out: "sweep-output" };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === "--limit") opts.limit = parseInt(a[++i], 10);
    else if (a[i] === "--restart") opts.resume = false;
    else if (a[i] === "--resume") opts.resume = true;
    else if (a[i] === "--out") opts.out = a[++i];
  }
  return opts;
})();

const TOKEN = process.env.GITHUB_TOKEN || "";
if (!TOKEN) {
  console.error("FATAL: set GITHUB_TOKEN env var to a GitHub Personal Access Token before running.");
  console.error("       Create one at https://github.com/settings/tokens with no scopes (fine-grained)");
  console.error("       or 'public_repo' read (classic). Token stays in env only — never written to disk.");
  process.exit(2);
}

const OUT_DIR = path.resolve(ARGS.out);
fs.mkdirSync(OUT_DIR, { recursive: true });
const RESULTS_FILE = path.join(OUT_DIR, "sweep-results.json");
const TRIAGE_FILE  = path.join(OUT_DIR, "sweep-triage.md");
const PROGRESS_FILE = path.join(OUT_DIR, "sweep-progress.json");

// ----- Load rule engine straight out of index.html so there's one source of truth -----
const html = fs.readFileSync(path.resolve(__dirname, "..", "index.html"), "utf8");
const scriptMatch = html.match(/<script>\s*"use strict";([\s\S]*?)<\/script>/);
if (!scriptMatch) { console.error("FATAL: couldn't find <script> in index.html"); process.exit(2); }
const fullJs = scriptMatch[1];
const cutAt = fullJs.indexOf("// Renderer");
const scannerJs = fullJs.slice(0, cutAt);
const scannerCtx = {};
new Function("module", "exports", scannerJs + "\nmodule.exports = { RULES, scanFile };")(scannerCtx, scannerCtx);
const { RULES, scanFile } = scannerCtx.exports;
console.log(`Loaded ${RULES.length} rules from index.html`);

// ----- Tiny HTTP helper -----
function httpGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const opts = {
      headers: { "User-Agent": "comfyui-node-safety-sweep", Accept: "application/vnd.github+json", ...headers }
    };
    https.get(url, opts, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        httpGet(res.headers.location, headers).then(resolve, reject); return;
      }
      let body = "";
      res.on("data", (c) => body += c);
      res.on("end", () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body
      }));
    }).on("error", reject);
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ----- Rate-limit-aware API fetch -----
async function githubApi(url) {
  await sleep(200);
  for (let attempt = 0; attempt < 2; attempt++) {
    const res = await httpGet(url, { Authorization: `Bearer ${TOKEN}` });
    const remaining = parseInt(res.headers["x-ratelimit-remaining"] || "5000", 10);
    if (remaining < 50) {
      const reset = parseInt(res.headers["x-ratelimit-reset"] || "0", 10) * 1000;
      const wait = Math.max(reset - Date.now() + 1000, 5000);
      console.log(`  rate limit low (${remaining}/5000) — sleeping ${Math.ceil(wait / 1000)}s`);
      await sleep(wait);
    }
    if (res.status === 403) { await sleep(30_000); continue; }
    if (res.status === 200) return JSON.parse(res.body);
    if (res.status === 404) return null;
    if (res.status === 451) return null; // dmca
    if (res.status >= 500) { await sleep(5_000); continue; }
    return null;
  }
  return null;
}

async function fetchRaw(owner, repo, branch, p) {
  const res = await httpGet(`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${encodeURI(p)}`);
  return res.status === 200 ? res.body : null;
}

function isRelevant(p) {
  return /\.py$/i.test(p) ||
    /(^|\/)(setup\.cfg|setup\.py|pyproject\.toml)$/i.test(p) ||
    /(^|\/)requirements[^\/]*\.txt$/i.test(p);
}

function parseRepo(url) {
  if (!url || typeof url !== "string") return null;
  const m = url.match(/^https?:\/\/github\.com\/([^\/\s]+)\/([^\/\s#?]+?)(?:\.git)?(?:\/.*)?$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2].replace(/\.git$/, "") };
}

// ----- One repo's worth of work -----
async function scanRepo(repoUrl) {
  const parsed = parseRepo(repoUrl);
  if (!parsed) return { repoUrl, error: "couldn't parse URL", skipped: true };
  const { owner, repo } = parsed;

  const meta = await githubApi(`https://api.github.com/repos/${owner}/${repo}`);
  if (!meta) return { repoUrl, owner, repo, error: "meta fetch failed", skipped: true };
  if (meta.archived) return { repoUrl, owner, repo, archived: true, skipped: true };

  const branch = meta.default_branch;
  const tree = await githubApi(`https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`);
  if (!tree || !tree.tree) return { repoUrl, owner, repo, error: "tree fetch failed", skipped: true };
  if (tree.truncated) {
    // Repo too big — skip with a note. The big nodes are usually well-known and
    // less likely to be malicious, but record for completeness.
    return { repoUrl, owner, repo, error: "tree truncated (repo too large)", skipped: true };
  }

  const files = tree.tree.filter((n) => n.type === "blob" && isRelevant(n.path));
  if (files.length === 0) return { repoUrl, owner, repo, branch, skipped: true, error: "no python files" };

  let totalLines = 0;
  const findings = [];
  const ruleBreakdown = {};
  for (const f of files) {
    // raw.githubusercontent.com isn't rate-limited but throttle anyway.
    await sleep(50);
    const content = await fetchRaw(owner, repo, branch, f.path);
    if (!content) continue;
    totalLines += (content.match(/\n/g) || []).length + 1;
    const fileFindings = scanFile(f.path, content);
    for (const fd of fileFindings) {
      ruleBreakdown[fd.ruleId] = (ruleBreakdown[fd.ruleId] || 0) + 1;
      findings.push(fd);
    }
  }

  const counts = findings.reduce((acc, f) => { acc[f.severity]++; return acc; },
    { crit: 0, high: 0, warn: 0, info: 0 });
  const verdict =
    counts.crit > 0 ? "crit" :
    counts.high > 0 ? "high" :
    counts.warn > 0 ? "warn" : "ok";

  return {
    repoUrl, owner, repo, branch,
    stars: meta.stargazers_count,
    pushed_at: meta.pushed_at,
    files_scanned: files.length,
    lines: totalLines,
    verdict,
    counts,
    ruleBreakdown,
    findings
  };
}

// ----- Corpus fetch -----
async function fetchCorpus() {
  console.log("Fetching ComfyUI-Manager custom-node-list.json …");
  const res = await httpGet("https://raw.githubusercontent.com/Comfy-Org/ComfyUI-Manager/main/custom-node-list.json");
  if (res.status !== 200) {
    console.error("FATAL: couldn't fetch custom-node-list.json:", res.status);
    process.exit(2);
  }
  const data = JSON.parse(res.body);
  const nodes = data.custom_nodes || [];
  const seen = new Set();
  const urls = [];
  for (const n of nodes) {
    if (!n.reference) continue;
    const parsed = parseRepo(n.reference);
    if (!parsed) continue;
    const key = `${parsed.owner}/${parsed.repo}`.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    urls.push(n.reference);
  }
  console.log(`Corpus: ${urls.length} unique GitHub repos`);
  return urls;
}

// ----- Triage markdown emission -----
function writeTriage(allResults) {
  const lines = [];
  lines.push(`# ComfyUI Custom Node Safety Sweep — Triage Queue\n`);
  lines.push(`Generated: ${new Date().toISOString()}\n`);
  lines.push(`Scanner rules: ${RULES.length} (loaded from comfyui-node-safety-check/index.html)\n`);

  const scanned = allResults.filter((r) => !r.skipped);
  const skipped = allResults.filter((r) => r.skipped);
  const byVerdict = {
    crit: scanned.filter((r) => r.verdict === "crit"),
    high: scanned.filter((r) => r.verdict === "high"),
    warn: scanned.filter((r) => r.verdict === "warn"),
    ok:   scanned.filter((r) => r.verdict === "ok")
  };

  lines.push(`## Summary\n`);
  lines.push(`- Scanned: **${scanned.length}** repos`);
  lines.push(`- Skipped: ${skipped.length} (archived / too-large / no python / fetch failed)`);
  lines.push(`- **Critical:** ${byVerdict.crit.length}`);
  lines.push(`- High:     ${byVerdict.high.length}`);
  lines.push(`- Medium:   ${byVerdict.warn.length}`);
  lines.push(`- Clean:    ${byVerdict.ok.length}\n`);
  lines.push(`---\n`);
  lines.push(`> **Triage rule:** every entry below requires manual confirmation before any public statement or contact. Static analysis catches patterns, not intent. False positives are unavoidable at scale.\n`);

  if (byVerdict.crit.length) {
    lines.push(`\n## 🟥 Critical — manual review needed\n`);
    for (const r of byVerdict.crit.sort((a, b) => (b.stars || 0) - (a.stars || 0))) {
      lines.push(`### [${r.owner}/${r.repo}](${r.repoUrl}) · ★ ${r.stars || 0} · last push ${(r.pushed_at || "").slice(0,10)}\n`);
      lines.push(`Findings: ${r.counts.crit} critical, ${r.counts.high} high, ${r.counts.warn} medium\n`);
      const crits = r.findings.filter((f) => f.severity === "crit");
      for (const c of crits.slice(0, 10)) {
        lines.push(`- **${c.ruleId}** [\`${c.filename}:${c.line}\`](https://github.com/${r.owner}/${r.repo}/blob/${r.branch}/${c.filename}#L${c.line})  \n  \`${c.excerpt.slice(0, 140).replace(/`/g, "")}\``);
      }
      if (crits.length > 10) lines.push(`- … ${crits.length - 10} more critical findings`);
      lines.push("");
    }
  }

  if (byVerdict.high.length) {
    lines.push(`\n## 🟧 High — review (usually legit — pip-runtime, ctypes, etc.)\n`);
    lines.push(`| Repo | ★ | High | Medium | Top rule |`);
    lines.push(`|---|---|---|---|---|`);
    for (const r of byVerdict.high.sort((a, b) => b.counts.high - a.counts.high).slice(0, 60)) {
      const topRule = Object.entries(r.ruleBreakdown).sort((a, b) => b[1] - a[1])[0];
      lines.push(`| [${r.owner}/${r.repo}](${r.repoUrl}) | ${r.stars || 0} | ${r.counts.high} | ${r.counts.warn} | ${topRule ? topRule[0] : "—"} (×${topRule ? topRule[1] : 0}) |`);
    }
    if (byVerdict.high.length > 60) lines.push(`\n_+ ${byVerdict.high.length - 60} more — see sweep-results.json_`);
  }

  fs.writeFileSync(TRIAGE_FILE, lines.join("\n"));
}

// ----- Main -----
(async () => {
  console.log(`Output dir: ${OUT_DIR}`);

  const corpus = await fetchCorpus();
  const limited = corpus.slice(0, ARGS.limit);
  console.log(`Will scan: ${limited.length} repos${ARGS.limit !== Infinity ? ` (limit ${ARGS.limit})` : ""}`);

  let results = [];
  let startAt = 0;
  if (ARGS.resume && fs.existsSync(PROGRESS_FILE)) {
    const prog = JSON.parse(fs.readFileSync(PROGRESS_FILE, "utf8"));
    results = prog.results || [];
    startAt = results.length;
    console.log(`Resuming from progress file: ${startAt}/${limited.length} already done`);
  }

  for (let i = startAt; i < limited.length; i++) {
    const url = limited[i];
    process.stdout.write(`[${i + 1}/${limited.length}] ${url.padEnd(70).slice(0, 70)} `);
    const t0 = Date.now();
    try {
      const r = await scanRepo(url);
      results.push(r);
      const dt = ((Date.now() - t0) / 1000).toFixed(1);
      if (r.skipped) process.stdout.write(`skip (${r.error || "—"}) ${dt}s\n`);
      else process.stdout.write(`${r.verdict.toUpperCase().padEnd(4)} c${r.counts.crit} h${r.counts.high} w${r.counts.warn} (${r.files_scanned}f, ${dt}s)\n`);
    } catch (e) {
      results.push({ repoUrl: url, error: e.message, skipped: true });
      process.stdout.write(`ERROR ${e.message}\n`);
    }

    // Checkpoint every 25 repos
    if ((i + 1) % 25 === 0 || i === limited.length - 1) {
      fs.writeFileSync(PROGRESS_FILE, JSON.stringify({ results }, null, 0));
      fs.writeFileSync(RESULTS_FILE, JSON.stringify(results, null, 2));
      writeTriage(results);
    }
  }

  console.log(`\nDone. Triage queue: ${TRIAGE_FILE}`);
  console.log(`Full results: ${RESULTS_FILE}`);
  console.log(`To re-run from scratch: delete ${PROGRESS_FILE} or pass --restart`);
})();
