"""Per-repo scan state (.pkgscan/state.json): last scanned dependency versions + cached verdicts.

In CI the state is read from the *base* branch (git show <ref>:<path>) so a pull request
cannot edit the state file to hide a version change.
"""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from pkgscan.manifest import Dependency

SCHEMA = 1


def empty_state() -> dict:
    return {"schema": SCHEMA, "updated_at": None, "dependencies": {}, "verdicts": {}}


def load_state(repo: Path, rel_path: str, base_ref: str | None = None) -> tuple[dict, bool]:
    """Returns (state, existed)."""
    raw = None
    if base_ref:
        r = subprocess.run(["git", "-C", str(repo), "show", f"{base_ref}:{rel_path}"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            raw = r.stdout
    else:
        p = repo / rel_path
        if p.exists():
            raw = p.read_text()
    if not raw:
        return empty_state(), False
    try:
        data = json.loads(raw)
    except ValueError:
        return empty_state(), False
    base = empty_state()
    base.update({k: v for k, v in data.items() if k in base})
    return base, True


def save_state(repo: Path, rel_path: str, state: dict) -> Path:
    state["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    p = repo / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    return p


def record_dependencies(state: dict, deps: list[Dependency]) -> None:
    current: dict[str, list[str]] = {}
    for d in deps:
        if d.version:
            current.setdefault(d.key, [])
            if d.version not in current[d.key]:
                current[d.key].append(d.version)
    state["dependencies"] = {k: sorted(v) for k, v in sorted(current.items())}


def record_verdict(state: dict, ref: str, verdict: dict) -> None:
    state["verdicts"][ref] = {k: verdict[k] for k in ("verdict", "score", "reasoning", "source") if k in verdict}
    state["verdicts"][ref]["scanned_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")


def plan_scans(state: dict, existed: bool, deps: list[Dependency]) -> list[tuple[Dependency, str | None, str]]:
    """Decide what to scan: [(dep, previous_version_or_None, reason)].

    - state missing           -> full scan of every dependency (first scan of this repo)
    - name seen, version new  -> diff scan against the previously recorded version
    - name never seen         -> full scan
    - unchanged               -> skipped
    """
    plan = []
    prev_map: dict[str, list[str]] = state.get("dependencies", {})
    for d in deps:
        if d.version is None:
            continue
        if not existed:
            plan.append((d, None, "first-scan"))
            continue
        prev_versions = prev_map.get(d.key, [])
        if d.version in prev_versions:
            continue
        if prev_versions:
            plan.append((d, prev_versions[-1] if len(prev_versions) == 1 else _closest(prev_versions, d), "version-changed"))
        else:
            plan.append((d, None, "new-dependency"))
    return plan


def _closest(prev_versions: list[str], dep: Dependency) -> str:
    """Pick the previously-recorded version just below the new one (fallback: last)."""
    try:
        if dep.ecosystem == "pypi":
            from packaging.version import Version
            key = Version
        else:
            import semantic_version
            key = semantic_version.Version
        new = key(dep.version)
        below = sorted((key(v), v) for v in prev_versions if key(v) < new)
        if below:
            return below[-1][1]
    except Exception:
        pass
    return prev_versions[-1]
