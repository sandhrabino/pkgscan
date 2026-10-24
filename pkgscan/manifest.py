"""Extract (ecosystem, name, version) dependencies from a project checkout."""
from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

URL_SPEC = re.compile(r"^(?:https?:|git(?:\+[a-z]+)?:|git@|github:|gitlab:|bitbucket:|file:|link:|[\w.-]+/[\w.-]+(?:#.*)?$)",
                      re.I)
NPM_DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies")


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str | None  # None when it could not be resolved to a registry version
    spec: str
    source: str  # manifest file it came from
    direct: bool = True
    problem: str | None = None  # e.g. "url-spec"

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}"


Resolver = Callable[[str, str, str], "str | None"]  # (ecosystem, name, spec) -> exact version


def _load_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {}


def npm_dependencies(repo: Path, resolver: Resolver | None, include_transitive: bool) -> list[Dependency]:
    pkg_json = repo / "package.json"
    if not pkg_json.exists():
        return []
    pkg = _load_json(pkg_json)
    direct: dict[str, str] = {}
    for f in NPM_DEP_FIELDS:
        direct.update({k: str(v) for k, v in (pkg.get(f) or {}).items()})

    lock = _load_json(repo / "package-lock.json") or _load_json(repo / "npm-shrinkwrap.json")
    locked: dict[str, set[str]] = {}
    top_level: dict[str, str] = {}
    if lock.get("packages"):  # lockfileVersion 2/3
        for path, meta in lock["packages"].items():
            if not path or meta.get("link") or "version" not in meta:
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            locked.setdefault(name, set()).add(meta["version"])
            if path == f"node_modules/{name}":
                top_level[name] = meta["version"]
    elif lock.get("dependencies"):  # lockfileVersion 1
        def walk(deps: dict, depth: int):
            for name, meta in deps.items():
                if "version" in meta:
                    locked.setdefault(name, set()).add(meta["version"])
                    if depth == 0:
                        top_level[name] = meta["version"]
                walk(meta.get("dependencies") or {}, depth + 1)
        walk(lock["dependencies"], 0)

    out: list[Dependency] = []
    for name, spec in sorted(direct.items()):
        if spec.startswith("npm:"):  # alias: "foo": "npm:bar@^1"
            real, _, spec = spec[4:].rpartition("@")
            name = real or name
        if URL_SPEC.match(spec) and not re.match(r"^[\^~<>=*\d]", spec):
            out.append(Dependency("npm", name, None, spec, "package.json", True, "url-spec"))
            continue
        locked_v = top_level.get(name)
        if locked_v and URL_SPEC.match(locked_v):
            out.append(Dependency("npm", name, None, locked_v, "package-lock.json", True, "url-spec"))
            continue
        version = locked_v or (resolver("npm", name, spec) if resolver else None)
        src = "package-lock.json" if locked_v else "package.json"
        out.append(Dependency("npm", name, version, spec, src, True, None if version else "unresolved"))
    if include_transitive:
        seen = {(d.name, d.version) for d in out}
        for name, versions in sorted(locked.items()):
            for v in sorted(versions):
                if (name, v) not in seen and not URL_SPEC.match(v):
                    out.append(Dependency("npm", name, v, v, "package-lock.json", False))
    return out


_PIN = re.compile(r"^==\s*([^,;\s]+)$")


def _req_to_dep(line: str, source: str, locked: dict[str, str], resolver: Resolver | None) -> Dependency | None:
    line = line.split(" #", 1)[0].strip()
    if not line or line.startswith(("#", "-")):
        return None
    try:
        req = Requirement(line)
    except InvalidRequirement:
        if URL_SPEC.match(line) or "://" in line:
            return Dependency("pypi", line, None, line, source, True, "url-spec")
        return None
    name = canonicalize_name(req.name)
    if req.url:
        return Dependency("pypi", name, None, req.url, source, True, "url-spec")
    spec = str(req.specifier)
    pin = _PIN.match(spec)
    version = locked.get(name) or (pin.group(1) if pin else None)
    if version is None and resolver:
        version = resolver("pypi", name, spec)
    return Dependency("pypi", name, version, spec, source, True, None if version else "unresolved")


def pypi_dependencies(repo: Path, resolver: Resolver | None, include_transitive: bool) -> list[Dependency]:
    locked: dict[str, str] = {}
    lock_src = None
    for lock_name in ("uv.lock", "poetry.lock", "pdm.lock"):
        p = repo / lock_name
        if p.exists():
            try:
                data = tomllib.loads(p.read_text())
            except (OSError, tomllib.TOMLDecodeError):
                continue
            for pkg in data.get("package", []):
                src = pkg.get("source") or {}
                if isinstance(src, dict) and (src.get("virtual") or src.get("editable")):
                    continue
                if "name" in pkg and "version" in pkg:
                    locked[canonicalize_name(pkg["name"])] = str(pkg["version"])
            lock_src = lock_name
            break

    deps: dict[str, Dependency] = {}
    for req_file in sorted(repo.glob("requirements*.txt")):
        for line in req_file.read_text(errors="replace").splitlines():
            d = _req_to_dep(line, req_file.name, locked, resolver)
            if d:
                deps.setdefault(d.name, d)

    pyproject = repo / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text())
        except tomllib.TOMLDecodeError:
            data = {}
        project = data.get("project", {})
        lines = list(project.get("dependencies", []))
        for extra in (project.get("optional-dependencies") or {}).values():
            lines.extend(extra)
        for group in (data.get("dependency-groups") or {}).values():
            lines.extend(x for x in group if isinstance(x, str))
        poetry = data.get("tool", {}).get("poetry", {})
        for section in [poetry.get("dependencies", {})] + \
                       [g.get("dependencies", {}) for g in (poetry.get("group") or {}).values()]:
            for n, v in section.items():
                if n.lower() == "python":
                    continue
                if isinstance(v, dict) and any(k in v for k in ("git", "url", "path")):
                    deps.setdefault(canonicalize_name(n), Dependency(
                        "pypi", canonicalize_name(n), None, json.dumps(v), "pyproject.toml", True, "url-spec"))
                    continue
                ver = v.get("version", "") if isinstance(v, dict) else str(v)
                lines.append(f"{n}{_poetry_to_pep440(ver)}")
        for line in lines:
            d = _req_to_dep(line, "pyproject.toml", locked, resolver)
            if d:
                deps.setdefault(d.name, d)

    out = sorted(deps.values(), key=lambda d: d.name)
    if include_transitive and locked:
        have = {d.name for d in out}
        out += [Dependency("pypi", n, v, f"=={v}", lock_src or "lock", False)
                for n, v in sorted(locked.items()) if n not in have]
    return out


def _poetry_to_pep440(v: str) -> str:
    v = v.strip()
    if not v or v == "*":
        return ""
    if v[0] == "^":
        base = v[1:]
        parts = base.split(".")
        major = int(parts[0]) if parts[0].isdigit() else 0
        upper = f"{major + 1}" if major > 0 else f"0.{int(parts[1]) + 1 if len(parts) > 1 and parts[1].isdigit() else 1}"
        return f">={base},<{upper}"
    if v[0] == "~" and v[1:2] != "=":
        return f"~={v[1:]}" if v.count(".") >= 1 else f">={v[1:]}"
    if v[0].isdigit():
        return f"=={v}"
    return v


def collect_dependencies(repo: Path, resolver: Resolver | None, include_transitive: bool = False) -> list[Dependency]:
    return npm_dependencies(repo, resolver, include_transitive) + pypi_dependencies(repo, resolver, include_transitive)
