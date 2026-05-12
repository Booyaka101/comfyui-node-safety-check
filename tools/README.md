# Sweep tooling

`sweep.js` runs the same rule engine that powers the live page against every
ComfyUI custom node listed in [ComfyUI-Manager's `custom-node-list.json`](https://github.com/Comfy-Org/ComfyUI-Manager/blob/main/custom-node-list.json).

## What it does

1. Pulls the registry of ~1,300 custom-node GitHub URLs.
2. For each: fetches metadata + recursive tree (2 GitHub API calls), then pulls each Python / dependency file's raw content.
3. Runs the rule engine (`RULES` table from `index.html` — single source of truth).
4. Writes results to `sweep-output/` locally:
    - `sweep-results.json` — machine-readable findings per repo
    - `sweep-triage.md` — human-readable manual review queue
    - `sweep-progress.json` — resume state for interrupted runs

## What it does **not** do

- **Never writes the PAT anywhere.** Token is read from `process.env.GITHUB_TOKEN` only.
- **Never commits results.** All output is local.
- **Never transmits results.** No HTTP egress beyond `api.github.com` and `raw.githubusercontent.com` (both read-only public endpoints).
- **Never makes a public claim.** Critical findings go to a triage queue. Manual confirmation is required before any contact. Confirmed real concerns get reported **privately** to Comfy-Org's `#security-review-council`, not published.

## Usage

```bash
# Create a PAT first (fine-grained, no scopes / classic with public_repo).
# Set it in your shell session:
export GITHUB_TOKEN=ghp_your_token_here   # bash / zsh
$env:GITHUB_TOKEN = "ghp_your_token_here" # PowerShell

# Smoke test with 5 repos first:
node tools/sweep.js --limit 5

# Full sweep (~2-3 hours with PAT, ~30+ hours without):
node tools/sweep.js

# Resume an interrupted run (default behaviour if sweep-progress.json exists):
node tools/sweep.js

# Force restart:
node tools/sweep.js --restart
```

## Etiquette built into the script

- 200 ms minimum gap between GitHub API calls — be a good citizen even with rate-limit headroom.
- 30 s back-off + single retry on 403.
- Pause-until-reset if remaining API calls drop below 50.
- Skips archived repos.
- Skips truncated trees (huge repos).

## After the sweep — what to do with the triage

The script's job ends at producing `sweep-triage.md`. The next step is **human review**, in this exact order:

1. Open each repo in the Critical list. Look at the flagged file / line. Confirm the pattern is what the scanner thinks it is.
2. If confirmed real: **do not post publicly.** Submit a private security advisory via the affected repo, or report to Comfy-Org's `#security-review-council` via their documented channel.
3. If false positive (e.g., a research repo intentionally containing patterns, a legitimate use of `ctypes.CDLL` for CUDA, etc.): note the rule for tightening in a future iteration. No further action.
4. Never publish a list of "suspicious repos" by name. False positives at scale damage innocent maintainers; even one wrong entry has real cost.
