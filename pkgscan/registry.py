"""npm / PyPI registry clients with mirror fallback and integrity verification."""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import semantic_version
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from pkgscan.archive import safe_extract
from pkgscan.http import Http


class NotFound(Exception):
    pass


class IntegrityError(Exception):
    pass


@dataclass
class Fetched:
    ecosystem: str
    name: str
    version: str
    src_root: Path
    archive_path: Path
    compressed_size: int
    version_meta: dict = field(default_factory=dict)
    skipped_members: list[str] = field(default_factory=list)


def _npm_semver(v: str) -> semantic_version.Version | None:
    try:
        return semantic_version.Version(v)
    except ValueError:
        return None


class NpmClient:
    ecosystem = "npm"

    def __init__(self, http: Http, cfg: dict):
        rc = cfg["registries"]["npm"]
        self.http = http
        self.cfg = cfg
        self.registries = [rc["primary"].rstrip("/")] + [m.rstrip("/") for m in rc.get("mirrors", [])]
        self.downloads_api = rc.get("downloads_api")
        self._cache: dict[tuple[str, str], dict] = {}

    @staticmethod
    def _enc(name: str) -> str:
        return quote(name, safe="@").replace("/", "%2F") if name.startswith("@") else quote(name, safe="")

    def packument_from(self, base: str, name: str) -> dict | None:
        key = (base, name)
        if key not in self._cache:
            _, data = self.http.get_json(f"{base}/{self._enc(name)}")
            if data is None:
                return None
            self._cache[key] = data
        return self._cache[key]

    def packument(self, name: str, version: str | None = None) -> tuple[dict, str]:
        """First registry that knows the package (and the version, if given)."""
        fallback = None
        for base in self.registries:
            data = self.packument_from(base, name)
            if not data or "versions" not in data:
                continue
            if version is None or version in data["versions"]:
                return data, base
            fallback = fallback or (data, base)
        if fallback and version is None:
            return fallback
        raise NotFound(f"npm package {name}{'@' + version if version else ''} not found in "
                       f"{', '.join(self.registries)}")

    def primary_packument(self, name: str) -> dict | None:
        return self.packument_from(self.registries[0], name)

    def sorted_versions(self, pack: dict) -> list[str]:
        vs = [(v, _npm_semver(v)) for v in pack.get("versions", {})]
        good = sorted((sv, v) for v, sv in vs if sv is not None)
        return [v for _, v in good]

    def resolve(self, name: str, spec: str) -> str | None:
        pack, _ = self.packument(name)
        if spec in pack.get("versions", {}):
            return spec
        tags = pack.get("dist-tags", {})
        if spec in tags:
            return tags[spec]
        try:
            npm_spec = semantic_version.NpmSpec(spec or "*")
        except ValueError:
            return None
        cands = [_npm_semver(v) for v in self.sorted_versions(pack)]
        best = npm_spec.select([c for c in cands if c is not None])
        return str(best) if best else None

    def previous_version(self, pack: dict, version: str) -> str | None:
        ordered = self.sorted_versions(pack)
        if version not in ordered:
            return None
        cur = _npm_semver(version)
        earlier = ordered[: ordered.index(version)]
        if cur and not cur.prerelease:
            earlier = [v for v in earlier if not _npm_semver(v).prerelease] or earlier
        return earlier[-1] if earlier else None

    def weekly_downloads(self, name: str) -> int | None:
        if not self.downloads_api:
            return None
        _, data = self.http.get_json(f"{self.downloads_api}/{name}")
        return data.get("downloads") if isinstance(data, dict) else None

    def fetch(self, name: str, version: str, workdir: Path) -> Fetched:
        limits = self.cfg["limits"]
        workdir.mkdir(parents=True, exist_ok=True)
        last_err: Exception | None = None
        for base in self.registries:
            pack = self.packument_from(base, name)
            meta = (pack or {}).get("versions", {}).get(version)
            if not meta:
                continue
            dist = meta.get("dist", {})
            url = dist.get("tarball")
            if not url:
                continue
            archive = workdir / f"{re.sub(r'[^A-Za-z0-9._-]', '_', name)}-{version}.tgz"
            try:
                size = self.http.download(url, archive, limits["max_download_bytes"])
                _verify_npm_integrity(archive, dist)
            except IntegrityError:
                raise
            except Exception as e:  # try the next mirror
                last_err = e
                continue
            root, skipped = safe_extract(archive, workdir / f"src-{version}", limits["max_extracted_bytes"],
                                         limits["max_files"])
            return Fetched("npm", name, version, root, archive, size, meta, skipped)
        raise NotFound(f"npm {name}@{version}: no downloadable tarball in any registry"
                       + (f" (last error: {last_err})" if last_err else ""))


def _verify_npm_integrity(archive: Path, dist: dict) -> None:
    data = archive.read_bytes()
    integrity = dist.get("integrity")
    if integrity and integrity.startswith("sha512-"):
        want = integrity.split("-", 1)[1]
        got = base64.b64encode(hashlib.sha512(data).digest()).decode()
        if got != want:
            raise IntegrityError(f"sha512 mismatch for {archive.name}")
    elif dist.get("shasum"):
        if hashlib.sha1(data).hexdigest() != dist["shasum"]:
            raise IntegrityError(f"sha1 mismatch for {archive.name}")


_SDIST_EXT = (".tar.gz", ".zip", ".tar.bz2", ".tgz")


class PyPIClient:
    ecosystem = "pypi"

    def __init__(self, http: Http, cfg: dict):
        rc = cfg["registries"]["pypi"]
        self.http = http
        self.cfg = cfg
        self.registries = [rc["primary"].rstrip("/")] + [m.rstrip("/") for m in rc.get("mirrors", [])]
        self.stats_api = rc.get("stats_api")
        self._cache: dict[tuple[str, str], dict] = {}

    def project_from(self, base: str, name: str) -> dict | None:
        key = (base, name)
        if key not in self._cache:
            _, data = self.http.get_json(f"{base}/pypi/{canonicalize_name(name)}/json")
            if data is None:
                # PEP 691 JSON simple API (most mirrors serve this)
                _, simple = self.http.get_json(f"{base}/simple/{canonicalize_name(name)}/",
                                               headers={"Accept": "application/vnd.pypi.simple.v1+json"})
                if simple is None:
                    return None
                data = _simple_to_project(name, simple)
            self._cache[key] = data
        return self._cache[key]

    def project(self, name: str, version: str | None = None) -> tuple[dict, str]:
        fallback = None
        for base in self.registries:
            data = self.project_from(base, name)
            if not data:
                continue
            if version is None or data.get("releases", {}).get(version):
                return data, base
            fallback = fallback or (data, base)
        if fallback and version is None:
            return fallback
        raise NotFound(f"pypi package {name}{'==' + version if version else ''} not found in "
                       f"{', '.join(self.registries)}")

    def primary_project(self, name: str) -> dict | None:
        return self.project_from(self.registries[0], name)

    @staticmethod
    def sorted_versions(proj: dict) -> list[str]:
        out = []
        for v, files in proj.get("releases", {}).items():
            try:
                out.append((Version(v), v))
            except InvalidVersion:
                continue
        return [v for _, v in sorted(out)]

    def resolve(self, name: str, spec: str) -> str | None:
        proj, _ = self.project(name)
        try:
            ss = SpecifierSet(spec or "")
        except InvalidSpecifier:
            return None
        cands = [v for v in self.sorted_versions(proj) if proj["releases"].get(v)]
        matching = [v for v in cands if Version(v) in ss and not Version(v).is_prerelease] or \
                   [v for v in cands if Version(v) in ss]
        return matching[-1] if matching else None

    def previous_version(self, proj: dict, version: str) -> str | None:
        ordered = [v for v in self.sorted_versions(proj) if proj["releases"].get(v)]
        if version not in ordered:
            return None
        earlier = ordered[: ordered.index(version)]
        if not Version(version).is_prerelease:
            earlier = [v for v in earlier if not Version(v).is_prerelease] or earlier
        return earlier[-1] if earlier else None

    def weekly_downloads(self, name: str) -> int | None:
        if not self.stats_api:
            return None
        _, data = self.http.get_json(f"{self.stats_api}/{canonicalize_name(name)}/recent")
        try:
            return int(data["data"]["last_week"])
        except (TypeError, KeyError, ValueError):
            return None

    @staticmethod
    def pick_artifact(files: list[dict]) -> dict | None:
        """Prefer the sdist (setup.py is where install-time hooks live), else a pure wheel."""
        sdists = [f for f in files if f.get("packagetype") == "sdist" or f["filename"].endswith(_SDIST_EXT)]
        if sdists:
            return sdists[0]
        wheels = [f for f in files if f["filename"].endswith(".whl")]
        wheels.sort(key=lambda f: (0 if "none-any" in f["filename"] else 1))
        return wheels[0] if wheels else None

    def fetch(self, name: str, version: str, workdir: Path) -> Fetched:
        limits = self.cfg["limits"]
        workdir.mkdir(parents=True, exist_ok=True)
        last_err: Exception | None = None
        for base in self.registries:
            proj = self.project_from(base, name)
            files = (proj or {}).get("releases", {}).get(version) or []
            art = self.pick_artifact(files)
            if not art:
                continue
            archive = workdir / art["filename"]
            try:
                size = self.http.download(art["url"], archive, limits["max_download_bytes"])
                want = (art.get("digests") or art.get("hashes") or {}).get("sha256")
                if want and hashlib.sha256(archive.read_bytes()).hexdigest() != want:
                    raise IntegrityError(f"sha256 mismatch for {art['filename']}")
            except IntegrityError:
                raise
            except Exception as e:
                last_err = e
                continue
            root, skipped = safe_extract(archive, workdir / f"src-{version}", limits["max_extracted_bytes"],
                                         limits["max_files"])
            meta = {"artifact": art, "info": (proj or {}).get("info", {}), "files": files}
            return Fetched("pypi", name, version, root, archive, size, meta, skipped)
        raise NotFound(f"pypi {name}=={version}: no downloadable artifact in any registry"
                       + (f" (last error: {last_err})" if last_err else ""))


_FILE_VER = re.compile(r"^(?P<name>.+?)-(?P<ver>\d[^-]*?)(?:\.tar\.gz|\.zip|\.tar\.bz2|\.tgz|-.*\.whl|\.whl)$")


def _simple_to_project(name: str, simple: dict) -> dict:
    """Shape a PEP 691 simple response like the PyPI JSON API (releases -> files)."""
    releases: dict[str, list] = {v: [] for v in simple.get("versions", [])}
    for f in simple.get("files", []):
        m = _FILE_VER.match(f.get("filename", ""))
        if not m:
            continue
        ver = m.group("ver")
        releases.setdefault(ver, []).append({
            "filename": f["filename"], "url": f["url"], "digests": f.get("hashes", {}),
            "packagetype": "bdist_wheel" if f["filename"].endswith(".whl") else "sdist",
            "upload_time_iso_8601": f.get("upload-time"), "size": f.get("size"),
            "yanked": bool(f.get("yanked")),
        })
    return {"info": {"name": name}, "releases": releases, "_source": "simple"}


def client_for(ecosystem: str, http: Http, cfg: dict):
    if ecosystem == "npm":
        return NpmClient(http, cfg)
    if ecosystem == "pypi":
        return PyPIClient(http, cfg)
    raise ValueError(f"unsupported ecosystem {ecosystem!r} (npm or pypi)")
