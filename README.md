# pkgscan: malicious npm / PyPI package scanner

pkgscan downloads package versions without installing or executing them. It runs the signal producers from
`Signal Producers (1).pdf` in parallel, writes each producer's findings to a markdown file, runs Semgrep and
YARA (SARIF output), and has `claude -p` correlate everything into a score, a verdict and a reason of at most
400 characters. In CI, a **high** or **critical** verdict fails the required check and blocks the PR.

```
PR opened/updated ──► pkgscan repo . --base-ref origin/main
                        │  package.json / package-lock.json / requirements*.txt / pyproject.toml / uv|poetry.lock
                        │  vs .pkgscan/state.json read from the BASE branch (PR can't tamper with it)
                        ├─ state missing        → full scan of every dependency (first scan of the repo)
                        ├─ new dependency       → full scan
                        ├─ version changed      → fetch new + previously recorded version, diff, scan both versions
                        └─ URL/git dependency   → HIGH (remote dynamic dependency, can't be scanned)
                      for each package (parallel), producers run in parallel:
                        1 metadata · 2 files(+VirusTotal) · 3 publisher · 4 lifecycle hooks
                        5 Semgrep (5.1–5.7) · 5/7 YARA · 5.1 obfuscation metrics · 5.2 network IOCs
                        6 code diff (+ rescan: which rule hits are NEW) · 8 typosquatting · known IOCs
                      → output/<run>/<pkg@ver>/signals/*.md, sarif/*.sarif
                      → heuristic score + deterministic floors
                      → claude -p (no tools, JSON schema) → verdict.json / verdict.md
                      → exit 1 if any verdict ∈ verdict.block_on
merge to main ──────► pkgscan update-state . → commits .pkgscan/state.json
```

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]' semgrep
npm install -g --ignore-scripts @anthropic-ai/claude-code   # provides `claude -p`
claude                              # sign in with your Claude account on first run
export VT_API_KEY=...               # optional: VirusTotal hash/domain lookups (nothing is uploaded)
export GITHUB_TOKEN=...             # optional: higher rate limit for repository checks
```

The scanner sends LLM verdict requests through the Claude Code CLI, using its saved Claude account login; no
Anthropic API key is needed. For GitHub Actions, run `claude setup-token` and save the resulting subscription
token as the `CLAUDE_CODE_OAUTH_TOKEN` repository secret. This requires a Claude Pro, Max, Team or Enterprise plan.

## Usage

```bash
# Standalone: full scan of an entire package version
pkgscan package npm lodash 4.17.21
pkgscan package pypi requests 2.32.3

# Diff against the previous published version, or a specific one
pkgscan package npm axios 1.7.9 --diff-previous
pkgscan package npm axios 1.7.9 --previous 1.7.7

# Project/repo mode (what CI runs)
pkgscan repo . --base-ref origin/main
pkgscan repo . --write-state            # local use: also record versions + verdicts

# Record approved versions without scanning (post-merge job)
pkgscan update-state .

# Already-extracted directory, no registry lookups
pkgscan local ./suspicious-pkg --ecosystem npm --name foo --version 1.0.0

# Common flags: --out DIR (default ./output), --no-llm (heuristic only), --config my.yaml, -v
```

Exit codes: `0` passed, `1` at least one blocking verdict, `2` error or interrupted.

## Output

```
output/20261022T073607Z/
  summary.json, summary.md            # also appended to $GITHUB_STEP_SUMMARY
  npm__left-pad@1.3.0/
    signals/<producer>.md             # one per signal producer: the prompt fragments sent to the LLM
    sarif/semgrep.sarif, semgrep-baseline.sarif (diff mode), yara.sarif
    files.json                        # every file: path, size, sha256, md5
    diff.patch                        # diff mode: truncated unified diff given to the LLM
    prompt.md, llm_raw.json           # exactly what Claude saw and returned
    verdict.json, verdict.md          # verdict, score, reasoning (≤400 chars), key signals, blocked
```

## Verdict logic

| Score | 0–19 | 20–39 | 40–59 | 60–79 | 80–100 |
|---|---|---|---|---|---|
| Verdict | benign | low | medium | **high** | **critical** |

1. Each producer emits signals with a severity, category and file context (`install-hook`, `entrypoint`,
   `source`, `test`, `bundled`). In diff mode, each signal is also marked as new in this version or present
   before. A deterministic **heuristic score** weights combinations, such as credential access plus network
   egress, or an install hook plus exec.
2. **Floors.** Rule hits that set a minimum verdict the LLM cannot go below:
   - any YARA rule tagged `high_confidence` (doc section 7) → at least `high`
   - known IOCs (`data/iocs.json`) → `critical`
   - the npm `-security` holding package → `critical`
   - a VirusTotal detection → `high`
3. **Claude** (`claude -p --tools "" --json-schema …`) receives every producer's markdown, the condensed
   SARIF findings and the diff. Package content is fenced as untrusted data. The LLM verdict is used,
   with two limits:
   - it is never below a floor
   - it is at most **one band below** the heuristic verdict (`llm.max_downgrade_bands`), so a
     prompt-injected or mistaken LLM can't clear a package the rules rate critical.
     `llm.trusted_override_packages` lifts this cap for known-noisy legitimate packages.
4. If `claude -p` fails (authentication or usage limit, timeout, bad JSON) and `llm.fail_closed: true`, the package is
   **blocked**. The LLM is skipped when no producer reports anything above `info` (`llm.skip_when_clean`).

## Configuration

Settings live in `pkgscan/default_config.yaml`. Override them with `--config` or `PKGSCAN_CONFIG`.

- **Registries and mirrors.** npm uses `registry.npmmirror.com` and PyPI uses `pypi.tuna.tsinghua.edu.cn`
  as fallbacks when a package or version is missing upstream. Add Artifactory, Verdaccio or devpi URLs
  under `registries.*.mirrors`. Tarball integrity (npm sha512, PyPI sha256) is verified for every source.
- **`scan.include_transitive`** defaults to `false`: only direct dependencies are scanned, with versions
  pinned from the lockfile.
- **`scan.allow_url_deps`** lists git/URL dependencies you accept.
- **`thresholds.*`** holds every number from the signals document.
- **`verdict.block_on`** sets which verdicts block. The default is `[high, critical]`.

## Rules

- `pkgscan/rules/semgrep/`: `obfuscation`, `network`, `credentials`, `dynamic_exec` (including taint rules
  for network→eval, decode→eval and credential→HTTP-POST flows), `crypto_wallet`, `process_exec` and `persistence`.
  Lifecycle analysis also detects obfuscated install-time npm publishing, and native binaries are inspected for
  combined network, execution and credential indicators. These cover sections 5.1–5.7.
- `pkgscan/rules/yara/`: `obfuscation.yar` (5.1) and `high_confidence.yar` (section 7: invisible-Unicode
  runs, hex blobs over 500 characters, obfuscator.io, reverse shells, miners, Shai-Hulud, webhook exfil,
  embedded executables).
- `pkgscan/data/`: the IOC list, disposable-email domains and the top-package lists for typosquatting.
  These are seed lists, so extend them from your threat-intel feeds.

## CI hardening notes

- Use `pull_request`, never `pull_request_target`. Make the check **required**, and preferably enforce it
  as an org-level required workflow so a PR can't edit the workflow to skip it.
- State is always read from the base branch. In Actions, `--base-ref` defaults to
  `origin/$GITHUB_BASE_REF`.
- Packages are never installed, and nothing extracted is executed. `setup.py` is analysed with `ast` only.
  Archive extraction rejects path traversal, links, setuid bits and archives over the size or file-count
  limits.

## Not implemented / known gaps

- Dependents count, which has no public npm API. Weekly downloads are used instead.
- The "dead code ratio" is a proxy: it counts constant-false branches.
- The PyPI publisher account age isn't exposed by any PyPI API, so the project age is used instead.
- yarn.lock and pnpm-lock.yaml are not parsed yet. Their direct dependencies are resolved from
  package.json ranges.


