"""Safe extraction of untrusted package archives. Nothing extracted is ever executed."""
from __future__ import annotations

import os
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


class UnsafeArchive(Exception):
    pass


def _safe_rel(name: str) -> PurePosixPath | None:
    p = PurePosixPath(name.replace("\\", "/"))
    if p.is_absolute() or any(part == ".." for part in p.parts) or not p.parts:
        return None
    if p.parts[0].endswith(":"):  # windows drive letter
        return None
    return p


def safe_extract(archive: Path, dest: Path, max_bytes: int, max_files: int) -> tuple[Path, list[str]]:
    """Extract regular files only (no links/devices), refusing traversal and zip bombs.

    Returns (package_root, skipped_member_notes).
    """
    dest.mkdir(parents=True, exist_ok=True)
    skipped: list[str] = []
    total = 0
    count = 0
    name = archive.name.lower()

    def write(rel: PurePosixPath, data_iter, mode: int | None):
        nonlocal total, count
        count += 1
        if count > max_files:
            raise UnsafeArchive(f"more than {max_files} files")
        out = dest.joinpath(*rel.parts)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as fh:
            for chunk in data_iter:
                total += len(chunk)
                if total > max_bytes:
                    raise UnsafeArchive(f"extracted size exceeds {max_bytes} bytes")
                fh.write(chunk)
        # keep the executable bit as a signal, never setuid/setgid
        perm = 0o644 | (0o111 if mode and mode & 0o111 else 0)
        os.chmod(out, perm)

    if zipfile.is_zipfile(archive) and (name.endswith((".zip", ".whl", ".egg"))):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                rel = _safe_rel(info.filename)
                mode = info.external_attr >> 16
                if rel is None:
                    skipped.append(f"unsafe path: {info.filename}")
                    continue
                if stat.S_ISLNK(mode):
                    skipped.append(f"symlink: {info.filename}")
                    continue
                with zf.open(info) as src:
                    write(rel, iter(lambda: src.read(1 << 16), b""), mode)
    else:
        with tarfile.open(archive, "r:*") as tf:
            for m in tf:
                if m.isdir():
                    continue
                rel = _safe_rel(m.name)
                if rel is None:
                    skipped.append(f"unsafe path: {m.name}")
                    continue
                if not m.isfile():
                    skipped.append(f"non-regular member ({'link' if m.issym() or m.islnk() else 'special'}): {m.name}")
                    continue
                src = tf.extractfile(m)
                if src is None:
                    continue
                with src:
                    write(rel, iter(lambda: src.read(1 << 16), b""), m.mode)

    entries = [p for p in dest.iterdir()]
    root = entries[0] if len(entries) == 1 and entries[0].is_dir() else dest
    return root, skipped
