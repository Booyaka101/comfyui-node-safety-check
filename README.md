# ComfyUI Node Safety Check

Static-analysis safety check for ComfyUI custom-node repos. Paste a GitHub URL — or upload Python files — and get a line-level risk report before you `pip install` something you found on the internet.

**Live:** https://booyaka101.github.io/comfyui-node-safety-check/

Runs entirely in the browser. No source code or URLs leave your machine.

## Why this exists

ComfyUI has been the target of multiple real-world custom-node attacks:

- **LLMVISION** (May 2024) — stole browser passwords, credit cards, history.
- **Upscaler_4K / Akira stealer** (2025) — Golang-based credential stealer staged through a fake "image enhancement" node on Comfy Registry.
- **Cryptominer botnet** (April 2026) — 1,000+ exposed ComfyUI instances turned into a Monero-mining proxy network.

The official response is private: ComfyUI's security review happens in a maintainer-only Discord channel and surfaces alerts via the Registry. End users have no quick way to check a custom node themselves before installing it. The [Comfy-Spaces safety-scanner proposal](https://github.com/ashish-aesthisia/Comfy-Spaces/discussions/6) (January 2026) has sat unbuilt; the only public tool ([christian-byrne/custom-nodes-security-scan](https://github.com/christian-byrne/custom-nodes-security-scan)) is CLI-only and Linux-only.

This page fills that gap. Paste, scan, decide.

## What it checks

~28 curated rules across four severities:

- **Critical** — obfuscated `exec`/`eval` chains (base64 → exec, chr-assembled), `pickle.loads`, browser-profile / SSH-key paths, OS autostart writes, Discord webhooks, hardcoded crypto-wallet addresses.
- **High** — `os.system`, `subprocess` with `shell=True`, `ctypes` native DLL loading, `importlib` with computed module names, runtime `pip install`, raw-IP URLs, pastebin URLs.
- **Medium** — `subprocess` without shell, raw `socket`, network/subprocess use in `setup.py`, long base64 literals.
- **Info** — git-URL dependencies (rug-pull risk), unpinned dependencies.

Each finding gives you the file, line number, the matched code excerpt, and a one-sentence rationale.

## Limits — read these

Static analysis cannot:

- Detect threats that fetch and execute a payload at runtime (the payload bytes aren't in the repo).
- See through deep obfuscation (encrypted strings reassembled by arithmetic, etc.).
- Evaluate `.pyc` bundled with the repo (compiled bytecode isn't scanned).
- Understand semantic intent — `subprocess` is flagged regardless of whether the called command is benign.

A clean result here is a **first checkpoint, not a guarantee**. For high-stakes installs:

1. Read the source yourself.
2. Check the maintainer's track record and other repos.
3. Pin the version after install (commit hash in `requirements.txt`).
4. Sandbox the install (Docker, separate venv, disposable VM).

The official ComfyUI security review and manual code review remain the gold standards.

## How it works

- **Input:** GitHub URL, pasted Python source, or drag-dropped files.
- **Fetch:** 2 GitHub API calls for URL inputs (repo meta + recursive tree). File contents pulled from `raw.githubusercontent.com`, which is CORS-friendly and doesn't count against the rate limit. Anonymous API limit is 60 req/hour — plenty for typical use.
- **Scan:** rules run client-side against each file. Source is preprocessed to strip string contents and comments (so `# subprocess` in a comment doesn't trip a rule), while preserving line numbers.
- **Output:** verdict + grouped findings with code excerpts and per-finding GitHub permalinks.

## Privacy

Zero analytics. Zero backend. Zero uploads. URLs are fetched only against GitHub's public CDN. If you paste source, the text never leaves your tab.

The page is one HTML file. You can `view-source` it any time, or read [index.html on GitHub](https://github.com/Booyaka101/comfyui-node-safety-check/blob/main/index.html) to audit the ~30 KB of code yourself.

## License

MIT. PRs welcome — especially for rules covering new attack patterns.
