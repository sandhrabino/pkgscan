"""Signal 6 - Code diff between the scanned version and the previous one (files + metadata)."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from email.parser import Parser
from pathlib import Path

from pkgscan.context import CODE_EXT, ScanContext, code_replacement_ratio
from pkgscan.models import ProducerOutput
from pkgscan.producers.base import Producer, clip
from pkgscan.producers.lifecycle import AUTO_RUN
from pkgscan.producers.metadata import _dt


def bump_kind(old: str, new: str) -> str:
    a = [int(x) for x in re.findall(r"\d+", old)[:3]] + [0, 0, 0]
    b = [int(x) for x in re.findall(r"\d+", new)[:3]] + [0, 0, 0]
    if b[0] != a[0]:
        return "major"
    if b[1] != a[1]:
        return "minor"
    return "patch"


def _deps(root: Path, ecosystem: str) -> dict[str, str]:
    if ecosystem == "npm":
        try:
            pkg = json.loads((root / "package.json").read_text())
        except (OSError, ValueError):
            return {}
        out = {}
        for f in ("dependencies", "optionalDependencies", "peerDependencies"):
            out.update({k: str(v) for k, v in (pkg.get(f) or {}).items()})
        return out
    out = {}
    for pkg_info in [root / "PKG-INFO"] + sorted(root.glob("*.egg-info/PKG-INFO")) + sorted(root.glob("*.dist-info/METADATA")):
        if pkg_info.exists():
            msg = Parser().parsestr(pkg_info.read_text(errors="replace"))
            for req in msg.get_all("Requires-Dist") or []:
                m = re.match(r"^\s*([A-Za-z0-9._-]+)\s*(.*)$", req)
                if m:
                    out[m.group(1).lower()] = m.group(2)
            if out:
                break
    return out


def _scripts(root: Path) -> dict:
    try:
        return json.loads((root / "package.json").read_text()).get("scripts") or {}
    except (OSError, ValueError):
        return {}


class CodeDiff(Producer):
    name = "code_diff"
    title = "Code Diff"
    signal_ref = "6"
    needs_prev = True

    def run(self, ctx: ScanContext) -> ProducerOutput:
        out = ProducerOutput()
        th = ctx.cfg["thresholds"]
        old, new = ctx.prev_src_dir, ctx.src_dir
        added = [r for r, s in ctx.changed.items() if s == "added"]
        modified = [r for r, s in ctx.changed.items() if s == "modified"]
        deleted = [r for r, s in ctx.changed.items() if s == "deleted"]
        bump = bump_kind(ctx.prev_version, ctx.pkg.version)
        out.facts.update({"previous_version": ctx.prev_version, "bump": bump, "added": len(added),
                          "modified": len(modified), "deleted": len(deleted),
                          "added_files": sorted(added)[:40], "modified_files": sorted(modified)[:40],
                          "deleted_files": sorted(deleted)[:20]})
        ratio = code_replacement_ratio(old, new)
        out.facts["code_replacement_ratio"] = None if ratio is None else round(ratio, 3)
        if ratio is not None and ratio >= th["code_replacement_ratio"] and bump != "major":
            out.signals.append(self.sig("code-replaced", "high",
                                        f"{ratio:.0%} of code replaced in a {bump} release (takeover/hijack?)",
                                        category="diff"))
        new_code = [r for r in added if Path(r).suffix in CODE_EXT]
        if not new_code and not modified and added:
            out.signals.append(self.sig("non-code-change", "info", "Only non-code files changed", category="diff",
                                        benign=True))

        # install hooks added / changed
        os_, ns = _scripts(old), _scripts(new)
        for hook in AUTO_RUN:
            if hook in ns and hook not in os_:
                out.signals.append(self.sig("new-install-hook", "high", f"New `{hook}` script added in this version",
                                            category="install_hook", introduced=True, evidence=[clip(ns[hook])]))
            elif hook in ns and os_.get(hook) != ns[hook]:
                out.signals.append(self.sig("changed-install-hook", "medium", f"`{hook}` script changed",
                                            category="install_hook", introduced=True,
                                            evidence=[clip(f"{os_.get(hook)} -> {ns[hook]}")]))
        if ctx.pkg.ecosystem == "pypi" and "setup.py" in ctx.changed:
            out.signals.append(self.sig("setup-py-changed", "low", f"setup.py {ctx.changed['setup.py']}",
                                        category="install_hook", introduced=True))

        # dependency diff
        od, nd = _deps(old, ctx.pkg.ecosystem), _deps(new, ctx.pkg.ecosystem)
        new_deps = sorted(set(nd) - set(od))
        removed = sorted(set(od) - set(nd))
        changed = sorted(k for k in set(od) & set(nd) if od[k] != nd[k])
        out.facts.update({"deps_added": {k: nd[k] for k in new_deps}, "deps_removed": removed,
                          "deps_changed": {k: f"{od[k]} -> {nd[k]}" for k in changed}})
        if len(new_deps) > th["many_new_deps"] and bump != "major":
            out.signals.append(self.sig("many-new-deps", "medium",
                                        f"{len(new_deps)} dependencies added in a {bump} release",
                                        category="diff", evidence=new_deps[:10]))
        dep_meta = {}
        for name in new_deps[:10]:
            dep_meta[name] = m = self._dep_meta(ctx, name)
            self._judge_new_dep(name, nd[name], m, out, th)
        out.facts["new_dep_metadata"] = dep_meta
        return out

    def _dep_meta(self, ctx: ScanContext, name: str) -> dict:
        if not ctx.client or not ctx.http:
            return {}
        m: dict = {}
        try:
            if ctx.pkg.ecosystem == "npm":
                pack = ctx.client.primary_packument(name)
                if not pack:
                    return {"exists": False}
                created = _dt((pack.get("time") or {}).get("created"))
                m["maintainers"] = len(pack.get("maintainers") or [])
                m["last_modified"] = (pack.get("time") or {}).get("modified")
            else:
                proj = ctx.client.primary_project(name)
                if not proj:
                    return {"exists": False}
                times = [_dt(f.get("upload_time_iso_8601")) for fs in (proj.get("releases") or {}).values() for f in fs]
                times = [t for t in times if t]
                created = min(times) if times else None
            m["exists"] = True
            m["age_days"] = (datetime.now(timezone.utc) - created).days if created else None
            m["weekly_downloads"] = ctx.client.weekly_downloads(name)
        except Exception as e:  # enrichment must never break the scan
            m["error"] = str(e)[:100]
        return m

    def _judge_new_dep(self, name: str, spec: str, m: dict, out: ProducerOutput, th: dict) -> None:
        if m.get("exists") is False:
            out.signals.append(self.sig("new-dep-missing", "high",
                                        f"New dependency `{name}` does not exist on the registry "
                                        "(dependency confusion / removed malware?)", category="diff"))
            return
        dl, age = m.get("weekly_downloads"), m.get("age_days")
        if dl is not None and age is not None and dl < th["new_dep_min_weekly_downloads"] and age < th["new_dep_min_age_days"]:
            out.signals.append(self.sig("new-dep-low-reputation", "high",
                                        f"New dependency `{name}` is {age} days old with {dl} weekly downloads",
                                        category="diff", evidence=[f"{name}@{spec}"]))
        elif m.get("maintainers") == 0:
            out.signals.append(self.sig("new-dep-no-maintainer", "medium",
                                        f"New dependency `{name}` has no maintainers", category="diff"))
        elif dl is not None and dl >= th["popular_dep_weekly_downloads"] and (age or 0) > 365:
            out.signals.append(self.sig("new-dep-popular", "info", f"New dependency `{name}` is popular/established",
                                        category="diff", benign=True))
