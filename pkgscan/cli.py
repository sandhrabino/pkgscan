"""pkgscan CLI.

  pkgscan package npm lodash 4.17.21               # full scan of a single package version
  pkgscan package npm lodash 4.17.21 --diff-previous   # diff against the previous published version
  pkgscan repo . --base-ref origin/main            # CI: scan dependency changes vs. recorded state
  pkgscan update-state .                           # record current dependency versions (post-merge)
  pkgscan local ./extracted-pkg --ecosystem npm --name x --version 1.0.0
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from pkgscan.config import load_config
from pkgscan.http import Http
from pkgscan.manifest import collect_dependencies
from pkgscan.models import Verdict
from pkgscan.orchestrator import scan_local, scan_package, write_verdict
from pkgscan.registry import NotFound, client_for
from pkgscan.state import load_state, plan_scans, record_dependencies, record_verdict, save_state

EXIT_OK, EXIT_BLOCKED, EXIT_ERROR = 0, 1, 2


def _run_dir(out: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    d = Path(out) / stamp
    d.mkdir(parents=True, exist_ok=True)
    return d


def _print_verdict(v: Verdict) -> None:
    flag = "BLOCK" if v.blocked else "pass "
    prev = f" (diff vs {v.previous_version})" if v.previous_version else ""
    print(f"[{flag}] {v.ecosystem}:{v.package}@{v.version}{prev}: {v.verdict.upper()} {v.score}/100 [{v.source}]")
    print(f"        {v.reasoning}")


def write_summary(run_dir: Path, verdicts: list[Verdict], extra: dict) -> None:
    blocked = [v for v in verdicts if v.blocked]
    data = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), **extra,
            "blocked": bool(blocked), "results": [v.to_dict() for v in verdicts]}
    (run_dir / "summary.json").write_text(json.dumps(data, indent=2))
    rows = ["| Package | Version | Prev | Verdict | Score | Blocked | Reasoning |", "|---|---|---|---|---|---|---|"]
    for v in sorted(verdicts, key=lambda v: (-v.score, v.package)):
        rows.append(f"| {v.ecosystem}:{v.package} | {v.version} | {v.previous_version or '-'} | **{v.verdict}** "
                    f"| {v.score} | {'⛔' if v.blocked else '✅'} | {v.reasoning.replace('|', '/')} |")
    md = (f"## pkgscan: {'⛔ BLOCKED' if blocked else '✅ passed'}\n\n"
          + (f"{len(verdicts)} package(s) scanned.\n\n" + "\n".join(rows) if verdicts else "No dependency changes to scan.")
          + "\n")
    (run_dir / "summary.md").write_text(md)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(md)


def cmd_package(args, cfg) -> int:
    run_dir = _run_dir(args.out)
    v = scan_package(cfg, args.ecosystem, args.name, args.version, run_dir, previous=args.previous,
                     diff_previous=args.diff_previous, use_llm=not args.no_llm, keep_workdir=args.keep_workdir)
    _print_verdict(v)
    write_summary(run_dir, [v], {"mode": "package"})
    print(f"\nOutput: {run_dir}")
    return EXIT_BLOCKED if v.blocked else EXIT_OK


def cmd_local(args, cfg) -> int:
    run_dir = _run_dir(args.out)
    v = scan_local(cfg, Path(args.path), args.ecosystem, args.name, args.version, run_dir, use_llm=not args.no_llm)
    _print_verdict(v)
    write_summary(run_dir, [v], {"mode": "local"})
    print(f"\nOutput: {run_dir}")
    return EXIT_BLOCKED if v.blocked else EXIT_OK


def _resolver(cfg, http):
    clients = {}

    def resolve(eco: str, name: str, spec: str):
        clients.setdefault(eco, client_for(eco, http, cfg))
        try:
            return clients[eco].resolve(name, spec)
        except NotFound:
            return None
    return resolve


def cmd_repo(args, cfg) -> int:
    repo = Path(args.path).resolve()
    http = Http(cfg["limits"]["http_timeout"])
    include_transitive = args.include_transitive or cfg["scan"]["include_transitive"]
    deps = collect_dependencies(repo, _resolver(cfg, http), include_transitive)
    state_path = args.state_file or cfg["scan"]["state_file"]
    if not args.base_ref and os.environ.get("GITHUB_BASE_REF"):
        # never trust the PR head's copy of the state file
        args.base_ref = f"origin/{os.environ['GITHUB_BASE_REF']}"
    state, existed = load_state(repo, state_path, args.base_ref)
    run_dir = _run_dir(args.out)
    print(f"{len(deps)} dependencies found; state {'loaded' if existed else 'missing -> first scan (full)'}"
          + (f" from {args.base_ref}" if args.base_ref and existed else ""))

    verdicts: list[Verdict] = []
    allow = set(cfg["scan"]["allow_url_deps"])
    for d in deps:
        if d.problem == "url-spec" and d.key not in allow:
            v = Verdict(d.name, d.ecosystem, d.spec, None, "unscannable", "high", 65,
                        f"{d.source}: `{d.name}` is installed from a URL/git spec ({d.spec[:120]}), bypassing registry "
                        "scanning (remote dynamic dependency). Pin a registry version or add to scan.allow_url_deps.",
                        ["lifecycle_hooks:remote-dynamic-dependency"], "heuristic", "high", None, True, "")
            verdicts.append(v)
        elif d.problem == "unresolved":
            verdicts.append(Verdict(d.name, d.ecosystem, d.spec, None, "unscannable", "medium", 45,
                                    f"Could not resolve `{d.name}{' ' + d.spec if d.spec else ''}` in any registry/mirror"
                                    " - possible dependency confusion or removed package.", [], "heuristic",
                                    None, None, "medium" in cfg["verdict"]["block_on"], ""))

    plan = plan_scans(state, existed, deps)
    todo = []
    for dep, prev, reason in plan:
        ref = f"{dep.key}@{dep.version}"
        cached = state["verdicts"].get(ref) if cfg["scan"]["reuse_cached_verdicts"] else None
        if cached:
            v = Verdict(dep.name, dep.ecosystem, dep.version, prev, "cached", cached["verdict"], cached["score"],
                        cached.get("reasoning", ""), [], "cached")
            v.blocked = v.verdict in cfg["verdict"]["block_on"]
            verdicts.append(v)
        else:
            todo.append((dep, prev, reason))
    print(f"{len(todo)} package version(s) to scan, {len(plan) - len(todo)} cached")

    def one(item):
        dep, prev, reason = item
        try:
            return scan_package(cfg, dep.ecosystem, dep.name, dep.version, run_dir, previous=prev,
                                use_llm=not args.no_llm, http=http)
        except Exception as e:
            out = run_dir / f"{dep.ecosystem}__{dep.name.replace('/', '_')}@{dep.version}"
            out.mkdir(parents=True, exist_ok=True)
            v = Verdict(dep.name, dep.ecosystem, dep.version, prev, "error", "medium", 40,
                        f"Scan failed: {type(e).__name__}: {str(e)[:300]}", [], "error", None, None,
                        cfg["llm"]["fail_closed"], str(out))
            write_verdict(out, v)
            return v

    with ThreadPoolExecutor(max_workers=cfg["scan"]["max_parallel_packages"]) as pool:
        for v in pool.map(one, todo):
            verdicts.append(v)
            _print_verdict(v)

    if args.write_state:
        record_dependencies(state, deps)
        for v in verdicts:
            if v.source in ("llm", "heuristic") and v.mode in ("full", "diff"):
                record_verdict(state, f"{v.ecosystem}:{v.package}@{v.version}", v.to_dict())
        print(f"State written: {save_state(repo, state_path, state)}")

    write_summary(run_dir, verdicts, {"mode": "repo", "repo": str(repo), "base_ref": args.base_ref,
                                      "first_scan": not existed})
    blocked = [v for v in verdicts if v.blocked]
    print(f"\n{'BLOCKED' if blocked else 'PASSED'}: {len(blocked)} blocking result(s). Output: {run_dir}")
    return EXIT_BLOCKED if blocked else EXIT_OK


def cmd_update_state(args, cfg) -> int:
    repo = Path(args.path).resolve()
    http = Http(cfg["limits"]["http_timeout"])
    deps = collect_dependencies(repo, _resolver(cfg, http), args.include_transitive or cfg["scan"]["include_transitive"])
    path = args.state_file or cfg["scan"]["state_file"]
    state, _ = load_state(repo, path)
    record_dependencies(state, deps)
    print(f"Recorded {len(state['dependencies'])} dependencies -> {save_state(repo, path, state)}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pkgscan", description="Malicious npm/PyPI package scanner")
    ap.add_argument("--config", help="YAML overriding default_config.yaml")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--out", default="output", help="output root folder (default: ./output)")
        p.add_argument("--no-llm", action="store_true", help="heuristic verdict only, do not call claude -p")

    p = sub.add_parser("package", help="scan one package version from the registry")
    p.add_argument("ecosystem", choices=["npm", "pypi"])
    p.add_argument("name")
    p.add_argument("version")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--previous", help="diff against this version instead of a full scan")
    g.add_argument("--diff-previous", action="store_true", help="diff against the previous published version")
    p.add_argument("--keep-workdir", action="store_true", help="keep extracted sources (debugging)")
    common(p)
    p.set_defaults(fn=cmd_package)

    p = sub.add_parser("repo", help="scan dependency changes of a project checkout")
    p.add_argument("path")
    p.add_argument("--base-ref", help="git ref to read the state file from (e.g. origin/main) - use in CI")
    p.add_argument("--state-file")
    p.add_argument("--include-transitive", action="store_true")
    p.add_argument("--write-state", action="store_true", help="write state + verdicts after scanning (local use)")
    common(p)
    p.set_defaults(fn=cmd_repo)

    p = sub.add_parser("update-state", help="record current dependency versions without scanning")
    p.add_argument("path")
    p.add_argument("--state-file")
    p.add_argument("--include-transitive", action="store_true")
    p.set_defaults(fn=cmd_update_state)

    p = sub.add_parser("local", help="scan an extracted package directory (no registry lookups)")
    p.add_argument("path")
    p.add_argument("--ecosystem", choices=["npm", "pypi"], required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--version", default="0.0.0-local")
    common(p)
    p.set_defaults(fn=cmd_local)

    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    cfg = load_config(args.config)
    try:
        return args.fn(args, cfg)
    except KeyboardInterrupt:
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
