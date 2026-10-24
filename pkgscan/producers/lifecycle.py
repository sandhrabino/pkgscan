"""Signal 4 - Lifecycle hooks (npm scripts, setup.py, .pth files, URL dependencies)."""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from pkgscan.context import ScanContext, iter_files
from pkgscan.manifest import URL_SPEC
from pkgscan.models import ProducerOutput
from pkgscan.producers.base import Producer, clip

NPM_HOOKS = ["preinstall", "install", "postinstall", "preuninstall", "postuninstall", "prepare", "prepublish",
             "postpublish", "prepack", "postpack", "test"]
# Hooks that run automatically when a consumer installs the package.
AUTO_RUN = {"preinstall", "install", "postinstall", "prepare"}

BENIGN_CMD = re.compile(
    r"^\s*(?:node-gyp(?:-build)?\s+rebuild|node-gyp-build|prebuild-install(?:\s+\S+)*(?:\s*\|\|\s*node-gyp rebuild)?|"
    r"node-pre-gyp\s+install(?:\s+--fallback-to-build)?|cmake-js\s+\w+|husky(?:\s+install)?|is-ci\s*\|\|\s*husky(?:\s+install)?|"
    r"patch-package|tsc(?:\s+-p\s+\S+)?|npm\s+run\s+build|ngcc|opencollective(?:-postinstall)?(?:\s*\|\|\s*exit 0)?|"
    r"echo\s+[^|;&]*|exit 0)\s*$", re.I)
SUSPICIOUS_CMD = [
    (re.compile(r"\b(?:curl|wget|iwr|Invoke-WebRequest)\b", re.I), "network", "downloads content"),
    (re.compile(r"https?://", re.I), "network", "contains a URL"),
    (re.compile(r"\|\s*(?:ba|z)?sh\b|\bsh\s+-c\b|\bbash\s+-c\b", re.I), "process_exec", "pipes/execs a shell"),
    (re.compile(r"base64|atob|Buffer\.from|\\x[0-9a-f]{2}", re.I), "obfuscation", "encoded content"),
    (re.compile(r"\bnode\s+-e\b|\bpython\d?\s+-c\b|\beval\b", re.I), "dynamic_exec", "inline code execution"),
    (re.compile(r"\.ssh|\.aws|\.npmrc|\.env\b|/etc/passwd|process\.env|\$\{?[A-Z_]*(TOKEN|SECRET|KEY)", re.I),
     "credential_access", "touches credentials/environment"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "network", "raw IP address"),
    (re.compile(r"bit\.ly|tinyurl|goo\.gl|is\.gd|cutt\.ly", re.I), "network", "URL shortener"),
    (re.compile(r"/dev/tcp|nc\s+-e|chmod\s+\+x", re.I), "process_exec", "shell/backdoor primitive"),
]
# Commands a package must not silently take over via `bin` (the real providers are allowlisted by package name).
SYSTEM_BINS = {"tsc", "tsserver", "node", "npm", "npx", "yarn", "pnpm", "git", "python", "python3", "pip", "pip3",
               "curl", "wget", "ssh", "sudo", "sh", "bash", "docker"}
SYSTEM_BIN_OWNERS = {"typescript", "node", "npm", "npx", "yarn", "pnpm", "@yarnpkg/cli", "corepack", "docker"}
SCRIPT_FILE = re.compile(r"(?:^|[\s;&|'\"])(?:node|bun|deno|sh|bash|python\d?|ts-node)?\s*([\w./@-]+\.(?:c?js|mjs|ts|sh|py))\b")
NODE_RUN = re.compile(r"\b(?:node|bun)\s+(?:--?\S+\s+)*([\w./@-]+)")


def _registry_publish_hook(script: str) -> bool:
    compact = re.sub(r"[\s\"'`\\]+", "", script).lower()
    has_publish = "npmpublish" in compact or "npmversionpatch" in compact
    handles_auth = any(token in compact for token in (".npmrc", "_authtoken", "npm_token"))
    return has_publish and handles_auth


def _resolve(src: Path, token: str) -> str | None:
    token = token.lstrip("./")
    for cand in (token, f"{token}.js", f"{token}/index.js", f"{token}.cjs", f"{token}.mjs"):
        p = src / cand
        if p.is_file():
            return p.relative_to(src).as_posix()
    return None


def discover_entrypoints(ctx: ScanContext) -> None:
    """Populate ctx.install_hooks / install_hook_files / entry_files (runs before producers)."""
    src = ctx.src_dir
    if ctx.pkg.ecosystem == "npm":
        pkg = _load(src / "package.json")
        scripts = pkg.get("scripts") or {}
        for hook in NPM_HOOKS:
            if hook in scripts and isinstance(scripts[hook], str):
                ctx.install_hooks[hook] = scripts[hook]
                if hook in AUTO_RUN:
                    for m in list(SCRIPT_FILE.finditer(scripts[hook])) + list(NODE_RUN.finditer(scripts[hook])):
                        rel = _resolve(src, m.group(1))
                        if rel:
                            ctx.install_hook_files.add(rel)
        if (src / "binding.gyp").exists() and "install" not in scripts and "preinstall" not in scripts:
            ctx.install_hooks["install(implicit)"] = "node-gyp rebuild"
        for key in ("main", "module", "browser"):
            if isinstance(pkg.get(key), str):
                rel = _resolve(src, pkg[key])
                if rel:
                    ctx.entry_files.add(rel)
        if isinstance(pkg.get("bin"), (str, dict)):
            for b in ([pkg["bin"]] if isinstance(pkg["bin"], str) else pkg["bin"].values()):
                rel = _resolve(src, str(b))
                if rel:
                    ctx.entry_files.add(rel)
        if not ctx.entry_files and (src / "index.js").exists():
            ctx.entry_files.add("index.js")
    else:
        for name in ("setup.py",):
            if (src / name).exists():
                ctx.install_hooks["setup.py"] = "python setup.py (executed on sdist install/build)"
                ctx.install_hook_files.add(name)
        for p in iter_files(src):
            rel = p.relative_to(src).as_posix()
            if p.suffix == ".pth":
                ctx.install_hook_files.add(rel)
            elif p.name == "__init__.py" and rel.count("/") <= 2:
                ctx.entry_files.add(rel)


def _load(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {}


class LifecycleHooks(Producer):
    name = "lifecycle_hooks"
    title = "Lifecycle Hooks"
    signal_ref = "4"

    def run(self, ctx: ScanContext) -> ProducerOutput:
        out = ProducerOutput()
        out.facts["hooks"] = dict(ctx.install_hooks)
        out.facts["install_time_files"] = sorted(ctx.install_hook_files)
        out.facts["entry_files"] = sorted(ctx.entry_files)
        if ctx.pkg.ecosystem == "npm":
            self._npm(ctx, out)
        else:
            self._pypi(ctx, out)
        return out

    def _npm(self, ctx: ScanContext, out: ProducerOutput) -> None:
        for hook, cmd in ctx.install_hooks.items():
            auto = hook.split("(")[0] in AUTO_RUN
            if not auto:
                continue
            reasons = [(cat, why) for rx, cat, why in SUSPICIOUS_CMD if rx.search(cmd)]
            if _registry_publish_hook(cmd):
                out.signals.append(self.sig(
                    "install-registry-publish", "high",
                    f"Auto-run `{hook}` constructs a package publish command while handling npm credentials",
                    category="process_exec", context="install-hook", floor="high", evidence=[clip(cmd, 400)]))
            if BENIGN_CMD.match(cmd) and not reasons:
                out.signals.append(self.sig("hook-build-task", "info", f"`{hook}` runs a common build task",
                                            category="install_hook", evidence=[clip(cmd)], benign=True,
                                            context="install-hook"))
                continue
            sev = "high" if reasons else "medium"
            out.signals.append(self.sig(
                "install-hook-present", sev, f"Auto-run `{hook}` script",
                category="install_hook", context="install-hook",
                detail="; ".join(sorted({w for _, w in reasons})) or "runs custom code at install time",
                evidence=[clip(cmd, 400)]))
            if any(c == "network" for c, _ in reasons) and any(c in ("process_exec", "dynamic_exec") for c, _ in reasons):
                out.signals.append(self.sig("hook-download-exec", "critical", f"`{hook}` downloads and executes code",
                                            category="install_hook", context="install-hook", evidence=[clip(cmd, 400)]))
        pkg = _load(ctx.src_dir / "package.json")
        bins = pkg.get("bin")
        bin_names = [bins] if isinstance(bins, str) else list(bins) if isinstance(bins, dict) else []
        shadowed = sorted({b for b in bin_names if b in SYSTEM_BINS})
        if shadowed and ctx.pkg.name not in SYSTEM_BIN_OWNERS:
            out.signals.append(self.sig(
                "bin-shadows-system-tool", "medium",
                f"Package registers bin entries that shadow well-known commands: {', '.join(shadowed)}",
                category="install_hook", context="metadata",
                detail="Installing this package can make `tsc`/`node`/`git`-style commands run package code instead.",
                evidence=[clip(json.dumps(bins), 200)]))
        for field in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
            for name, spec in (pkg.get(field) or {}).items():
                spec = str(spec)
                if URL_SPEC.match(spec) and not re.match(r"^[\^~<>=*\d]", spec):
                    is_http = spec.lower().startswith(("http:", "https:"))
                    out.signals.append(self.sig(
                        "remote-dynamic-dependency", "high" if is_http else "medium",
                        f"{field}.{name} is fetched from a URL/git spec instead of the registry",
                        category="install_hook", context="metadata",
                        detail="Remote dynamic dependencies (PhantomRaven) are invisible to registry scanning"
                               " and can change after review.",
                        evidence=[clip(f"{name}: {spec}")]))
        if (ctx.src_dir / ".npmrc").exists():
            txt = (ctx.src_dir / ".npmrc").read_text(errors="replace")
            if re.search(r"ignore-scripts\s*=\s*false|registry\s*=", txt):
                out.signals.append(self.sig("bundled-npmrc", "medium", "Package ships an .npmrc overriding registry/scripts",
                                            category="install_hook", evidence=[clip(txt, 200)]))

    def _pypi(self, ctx: ScanContext, out: ProducerOutput) -> None:
        setup = ctx.src_dir / "setup.py"
        if setup.exists():
            for s in _analyze_setup_py(setup.read_text(errors="replace")):
                out.signals.append(self.sig(**s, category="install_hook", context="install-hook",
                                            locations=["setup.py"]))
        for p in iter_files(ctx.src_dir):
            if p.suffix != ".pth":
                continue
            txt = p.read_text(errors="replace")
            exec_lines = [ln for ln in txt.splitlines() if ln.lstrip().startswith("import ")]
            if exec_lines:
                out.signals.append(self.sig(
                    "pth-exec", "high", f"{p.name}: .pth file executes code on every Python start-up",
                    category="persistence", context="install-hook",
                    locations=[ctx.rel(p)], evidence=[clip(ln) for ln in exec_lines[:3]]))
        pyproject = ctx.src_dir / "pyproject.toml"
        if pyproject.exists() and re.search(r"backend-path\s*=", pyproject.read_text(errors="replace")):
            out.signals.append(self.sig("in-tree-build-backend", "medium",
                                        "Custom in-tree build backend executes package code at build/install",
                                        category="install_hook", locations=["pyproject.toml"]))


_DANGEROUS_CALLS = {
    "os.system": "process_exec", "os.popen": "process_exec", "subprocess.Popen": "process_exec",
    "subprocess.call": "process_exec", "subprocess.run": "process_exec", "subprocess.check_output": "process_exec",
    "subprocess.check_call": "process_exec", "exec": "dynamic_exec", "eval": "dynamic_exec",
    "compile": "dynamic_exec", "__import__": "dynamic_exec", "urllib.request.urlopen": "network",
    "urlopen": "network", "requests.get": "network", "requests.post": "network", "socket.socket": "network",
    "base64.b64decode": "obfuscation", "marshal.loads": "dynamic_exec", "zlib.decompress": "obfuscation",
}
_INSTALL_CMDS = {"install", "develop", "egg_info", "build_py", "build_ext", "sdist", "bdist_wheel", "build"}


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


def _analyze_setup_py(src: str) -> list[dict]:
    """Static AST analysis of setup.py - never executed."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return [dict(rule_id="setup-unparseable", severity="medium", title="setup.py does not parse",
                     detail="May be deliberately malformed or use non-Python payload")]
    found: list[dict] = []
    calls: dict[str, list[int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name in _DANGEROUS_CALLS:
                calls.setdefault(name, []).append(node.lineno)
        if isinstance(node, ast.ClassDef):
            bases = {_dotted(b).split(".")[-1] for b in node.bases}
            if bases & _INSTALL_CMDS:
                found.append(dict(rule_id="setup-cmdclass-override", severity="high",
                                  title=f"setup.py overrides the `{'/'.join(sorted(bases & _INSTALL_CMDS))}` command",
                                  detail="Custom install command classes run arbitrary code during pip install",
                                  evidence=[f"class {node.name}({', '.join(sorted(bases))}) line {node.lineno}"]))
    cats = {}
    for name, lines in calls.items():
        cats.setdefault(_DANGEROUS_CALLS[name], []).append(f"{name}() line {lines[0]}")
    for cat, ev in cats.items():
        sev = "high" if cat in ("process_exec", "dynamic_exec", "network") else "medium"
        found.append(dict(rule_id=f"setup-{cat}", severity=sev, title=f"setup.py performs {cat.replace('_', ' ')}",
                          evidence=ev[:5]))
    if {"network"} <= set(cats) and set(cats) & {"process_exec", "dynamic_exec"}:
        found.append(dict(rule_id="setup-download-exec", severity="critical",
                          title="setup.py downloads and executes code", evidence=sum(cats.values(), [])[:5]))
    return found
