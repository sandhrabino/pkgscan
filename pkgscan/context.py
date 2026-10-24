from __future__ import annotations

import difflib
import hashlib
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from pkgscan.http import Http
from pkgscan.models import PackageRef

CODE_EXT = {".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx", ".py", ".pyw", ".sh", ".bash", ".ps1",
            ".bat", ".cmd", ".vbs", ".pth"}
TEST_PARTS = {"test", "tests", "__tests__", "spec", "specs", "testing", "fixtures", "__mocks__", "e2e"}
BUNDLE_PARTS = {"dist", "build", "umd", "esm", "cjs", "bundle", "vendor", "plugins", "lib-cov", "min"}


def iter_files(root: Path):
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            yield p


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def is_probably_text(p: Path, sample: int = 8192) -> bool:
    try:
        with open(p, "rb") as fh:
            chunk = fh.read(sample)
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    try:
        chunk.decode("utf-8")
        return True
    except UnicodeDecodeError as e:
        return e.start > len(chunk) - 4  # truncated multibyte at the edge


def classify_path(rel: str) -> str:
    parts = {x.lower() for x in Path(rel).parts[:-1]}
    name = Path(rel).name.lower()
    if parts & TEST_PARTS or name.startswith(("test_", "test.")) or ".test." in name or ".spec." in name:
        return "test"
    if parts & BUNDLE_PARTS or ".min." in name or name.endswith(".bundle.js"):
        return "bundled"
    return "source"


@dataclass
class ScanContext:
    pkg: PackageRef
    cfg: dict
    out_dir: Path
    src_dir: Path
    mode: str = "full"  # full | diff | local
    http: Http | None = None
    client: object | None = None  # NpmClient | PyPIClient
    prev_version: str | None = None
    prev_src_dir: Path | None = None
    target_dir: Path | None = None  # what code rules scan
    changed: dict[str, str] = field(default_factory=dict)  # rel -> added|modified|deleted
    registry_meta: dict = field(default_factory=dict)  # npm packument / PyPI project JSON
    registry_base: str = ""
    version_meta: dict = field(default_factory=dict)
    archive_size: int | None = None
    archive_path: Path | None = None
    skipped_members: list[str] = field(default_factory=list)
    install_hooks: dict[str, str] = field(default_factory=dict)  # hook -> command
    install_hook_files: set[str] = field(default_factory=set)
    entry_files: set[str] = field(default_factory=set)

    def __post_init__(self):
        if self.target_dir is None:
            self.target_dir = self.src_dir

    def rel(self, p: Path, base: Path | None = None) -> str:
        return p.relative_to(base or self.src_dir).as_posix()

    def file_context(self, rel: str) -> str:
        if rel in self.install_hook_files:
            return "install-hook"
        if rel in self.entry_files:
            return "entrypoint"
        return classify_path(rel)


def compute_diff(old_root: Path, new_root: Path) -> dict[str, str]:
    old = {p.relative_to(old_root).as_posix(): p for p in iter_files(old_root)}
    new = {p.relative_to(new_root).as_posix(): p for p in iter_files(new_root)}
    changed: dict[str, str] = {}
    for rel, p in new.items():
        if rel not in old:
            changed[rel] = "added"
        elif p.stat().st_size != old[rel].stat().st_size or sha256_file(p) != sha256_file(old[rel]):
            changed[rel] = "modified"
    for rel in old:
        if rel not in new:
            changed[rel] = "deleted"
    return changed


def materialize_diff(ctx: ScanContext, work: Path) -> None:
    """Copy changed files into diff/new (and the old versions of modified files into diff/old)."""
    new_dir, old_dir = work / "diff" / "new", work / "diff" / "old"
    new_dir.mkdir(parents=True, exist_ok=True)
    old_dir.mkdir(parents=True, exist_ok=True)
    for rel, status in ctx.changed.items():
        if status in ("added", "modified"):
            dst = new_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ctx.src_dir / rel, dst)
        if status == "modified" and ctx.prev_src_dir:
            dst = old_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ctx.prev_src_dir / rel, dst)
    ctx.target_dir = new_dir


def _read_lines(p: Path) -> list[str]:
    try:
        return p.read_text(errors="replace").splitlines()
    except OSError:
        return []


def code_replacement_ratio(old_root: Path, new_root: Path) -> float | None:
    """Fraction of the old version's code lines that no longer exist in the new version."""
    old_lines: list[str] = []
    new_lines: set[str] = set()
    for p in iter_files(old_root):
        if p.suffix in CODE_EXT and classify_path(p.relative_to(old_root).as_posix()) != "bundled":
            old_lines += [ln.strip() for ln in _read_lines(p) if ln.strip()]
    for p in iter_files(new_root):
        if p.suffix in CODE_EXT and classify_path(p.relative_to(new_root).as_posix()) != "bundled":
            new_lines |= {ln.strip() for ln in _read_lines(p) if ln.strip()}
    if len(old_lines) < 20:
        return None
    gone = sum(1 for ln in old_lines if ln not in new_lines)
    return gone / len(old_lines)


def diff_excerpt(ctx: ScanContext, max_chars: int) -> str:
    """Unified diff of changed text files, install-hook/manifest files first, truncated."""
    if not ctx.prev_src_dir:
        return ""
    priority = lambda rel: (0 if rel in ctx.install_hook_files or Path(rel).name in
                                ("package.json", "setup.py", "setup.cfg", "pyproject.toml") else
                            1 if Path(rel).suffix in CODE_EXT and classify_path(rel) == "source" else
                            2 if Path(rel).suffix in CODE_EXT else 3, rel)
    out, used = [], 0
    for rel in sorted(ctx.changed, key=priority):
        status = ctx.changed[rel]
        new_p, old_p = ctx.src_dir / rel, ctx.prev_src_dir / rel
        p = new_p if status != "deleted" else old_p
        if not is_probably_text(p):
            chunk = f"--- {rel} ({status}, binary)\n"
        elif status == "deleted":
            chunk = f"--- {rel} (deleted)\n"
        else:
            a = _read_lines(old_p) if status == "modified" else []
            b = _read_lines(new_p)
            # never feed giant minified lines verbatim
            a = [ln[:400] for ln in a]
            b = [ln[:400] for ln in b]
            chunk = "\n".join(difflib.unified_diff(a, b, f"a/{rel}", f"b/{rel}", lineterm="", n=2)) + "\n"
        if used + len(chunk) > max_chars:
            out.append(f"... diff truncated ({len(ctx.changed)} changed files total)\n")
            break
        out.append(chunk)
        used += len(chunk)
    return "".join(out)
