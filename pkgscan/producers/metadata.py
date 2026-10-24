"""Signal 1 - Package metadata / version history (signal_pkg_versions)."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta

import requests

from pkgscan.context import ScanContext, iter_files
from pkgscan.intel import domain_age_days, domain_matches, host_of
from pkgscan.models import ProducerOutput
from pkgscan.producers.base import Producer, clip

PLACEHOLDER = re.compile(r"^0\.0\.0(?:[-.+].*)?$|-(?:next|canary|placeholder|security)\b", re.I)
STAGED_TEXT = re.compile(r"temporary (?:holding version|placeholder)|awaiting a staged release|staged (?:publish|release)",
                         re.I)
INERT_FILES = {"package.json", "license", "licence", "changelog.md"}
PRERELEASE = re.compile(r"(?:-|\.|\d)(?:rc|alpha|beta|a|b|dev|pre|next|canary)\.?\d*", re.I)


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _major(v: str) -> int | None:
    m = re.match(r"^v?(\d+)", v)
    return int(m.group(1)) if m else None


def version_timeline(ctx: ScanContext) -> list[tuple[str, datetime]]:
    meta = ctx.registry_meta
    out = []
    if ctx.pkg.ecosystem == "npm":
        for v, t in (meta.get("time") or {}).items():
            if v in ("created", "modified"):
                continue
            d = _dt(t)
            if d:
                out.append((v, d))
    else:
        for v, files in (meta.get("releases") or {}).items():
            times = [_dt(f.get("upload_time_iso_8601")) for f in files]
            times = [t for t in times if t]
            if times:
                out.append((v, min(times)))
    return sorted(out, key=lambda x: x[1])


def repo_url(ctx: ScanContext) -> tuple[str | None, str | None]:
    if ctx.pkg.ecosystem == "npm":
        vm = ctx.version_meta
        repo = vm.get("repository") or ctx.registry_meta.get("repository")
        repo = repo.get("url") if isinstance(repo, dict) else repo
        home = vm.get("homepage") or ctx.registry_meta.get("homepage")
    else:
        info = ctx.registry_meta.get("info") or {}
        urls = info.get("project_urls") or {}
        repo = next((u for k, u in urls.items() if re.search(r"source|repo|code|github", k, re.I)), None)
        home = info.get("home_page") or urls.get("Homepage") or urls.get("homepage")
        if not repo and home and "github.com" in home:
            repo = home
    if isinstance(repo, str):
        repo = re.sub(r"^git\+", "", repo)
        repo = re.sub(r"^git://", "https://", repo)
        repo = re.sub(r"^git@github\.com:", "https://github.com/", repo)
        repo = re.sub(r"^github:", "https://github.com/", repo)
        if re.match(r"^[\w.-]+/[\w.-]+$", repo):
            repo = f"https://github.com/{repo}"
        repo = re.sub(r"\.git$", "", repo)
    return (repo if isinstance(repo, str) else None), (home if isinstance(home, str) else None)


class PackageMetadata(Producer):
    name = "package_metadata"
    title = "Package Metadata"
    signal_ref = "1"
    needs_registry = True

    def run(self, ctx: ScanContext) -> ProducerOutput:
        out = ProducerOutput()
        th = ctx.cfg["thresholds"]
        timeline = version_timeline(ctx)
        versions = [v for v, _ in timeline]
        vm = ctx.version_meta or {}
        f = out.facts
        f["version"] = ctx.pkg.version
        f["total_versions"] = len(versions)
        f["registry"] = ctx.registry_base
        f["publication_date"] = next((t.isoformat() for v, t in timeline if v == ctx.pkg.version), None)
        f["first_version"] = versions[0] if versions else None
        f["first_published"] = timeline[0][1].isoformat() if timeline else None

        if ctx.pkg.ecosystem == "npm":
            user = vm.get("_npmUser") or {}
            f["publisher_account_name"] = user.get("name")
            f["publisher_account_email"] = user.get("email")
            f["trusted_publisher"] = bool(user.get("trustedPublisher"))
            f["provenance_attestation"] = bool((vm.get("dist") or {}).get("attestations"))
            f["tags"] = ctx.registry_meta.get("dist-tags", {})
            f["artifacts"] = [(vm.get("dist") or {}).get("tarball")]
            f["unpacked_size"] = (vm.get("dist") or {}).get("unpackedSize")
            if vm.get("deprecated"):
                out.signals.append(self.sig("deprecated", "info", "Version is deprecated",
                                            evidence=[clip(vm["deprecated"])], category="metadata"))
            latest = (ctx.registry_meta.get("dist-tags") or {}).get("latest", "")
            if latest.endswith("-security") or ctx.pkg.version.endswith("-security"):
                out.signals.append(self.sig(
                    "npm-security-holder", "critical", "npm replaced this package with a security holding package",
                    detail="npm publishes `0.0.1-security` after removing a malicious package",
                    category="known_malicious", floor="critical", evidence=[f"latest={latest}"]))
        else:
            info = ctx.registry_meta.get("info") or {}
            f["publisher_account_name"] = info.get("author") or info.get("maintainer")
            f["publisher_account_email"] = info.get("author_email") or info.get("maintainer_email")
            own = ctx.registry_meta.get("ownership") or {}
            f["owners"] = [r.get("user") for r in own.get("roles", [])] if own else None
            files = (ctx.registry_meta.get("releases") or {}).get(ctx.pkg.version, [])
            f["artifacts"] = [x.get("filename") for x in files]
            f["provenance_attestation"] = self._pypi_provenance(ctx, files)
            f["trusted_publisher"] = f["provenance_attestation"]  # PyPI attestations come from Trusted Publishers
            if any(x.get("yanked") for x in files):
                out.signals.append(self.sig("yanked", "medium", "Release was yanked",
                                            evidence=[clip(files[0].get("yanked_reason") or "")], category="metadata"))

        self._version_patterns(ctx, timeline, out, th)
        if ctx.pkg.ecosystem == "npm":
            self._staged_placeholder(ctx, out)
        self._repo_checks(ctx, out, th)
        self._size_and_maintainer(ctx, out, th)
        if f.get("provenance_attestation"):
            out.signals.append(self.sig("provenance", "info", "Release has a provenance attestation (built in CI)",
                                        category="metadata", benign=True))
        return out

    def _pypi_provenance(self, ctx: ScanContext, files: list[dict]) -> bool:
        if not ctx.http or not files:
            return False
        fn = files[0].get("filename")
        status, _ = ctx.http.get_json(f"https://pypi.org/integrity/{ctx.pkg.name}/{ctx.pkg.version}/{fn}/provenance",
                                      headers={"Accept": "application/vnd.pypi.integrity.v1+json"})
        return status == 200

    def _staged_placeholder(self, ctx: ScanContext, out: ProducerOutput) -> None:
        """Code-less `"stub": true` package whose README says a real release is 'awaiting a staged release'.

        This is the staging step of a recurring npm malware campaign: the name is claimed with an empty package and
        the payload is published as a later version.
        """
        try:
            stub = json.loads((ctx.src_dir / "package.json").read_text()).get("stub") is True
        except (OSError, ValueError, AttributeError):
            return
        if not stub:
            return
        files = list(iter_files(ctx.src_dir))
        readmes = [p for p in files if p.name.lower().startswith("readme")]
        if any(p.name.lower() not in INERT_FILES and p not in readmes for p in files):
            return
        readme = "\n".join(p.read_text(errors="replace")[:2000] for p in readmes)
        if STAGED_TEXT.search(readme):
            out.signals.append(self.sig(
                "staged-placeholder-stub", "high",
                "Code-less staged placeholder package awaiting a later 'staged release'",
                detail="Name reservation with no code and an explicit `stub` marker: the staging pattern of a "
                       "recurring npm malware campaign, where the payload arrives in a later version.",
                category="metadata", floor="high", evidence=[clip(readme.strip(), 200)]))

    def _version_patterns(self, ctx, timeline, out, th) -> None:
        versions = [v for v, _ in timeline]
        if not timeline:
            return
        first = versions[0]
        fm = _major(first)
        if fm is not None and fm >= th["high_first_major"]:
            out.signals.append(self.sig("high-first-version", "medium",
                                        f"First published version is {first} (appears artificially established)",
                                        category="metadata"))
        if any(_major(v) is not None and _major(v) >= 99 for v in [ctx.pkg.version]) or \
                re.match(r"^9{2,}\.", ctx.pkg.version):
            out.signals.append(self.sig("dependency-confusion-version", "high",
                                        f"Version {ctx.pkg.version} is typical of dependency-confusion attacks",
                                        category="metadata"))
        # rapid bumping: versions published within 24h of the scanned version
        cur_t = dict(timeline).get(ctx.pkg.version)
        if cur_t:
            near = [v for v, t in timeline if abs(t - cur_t) <= timedelta(hours=24)]
            if len(near) > th["rapid_versions_24h"]:
                out.signals.append(self.sig("rapid-version-bumping", "medium",
                                            f"{len(near)} versions published within 24h of {ctx.pkg.version}",
                                            evidence=near[:8], category="metadata"))
        # placeholders
        ph = [v for v in versions if PLACEHOLDER.search(v)]
        if len(ph) >= 3:
            out.signals.append(self.sig("placeholder-version-spam", "medium",
                                        f"{len(ph)} placeholder versions (e.g. 0.0.0-next)",
                                        evidence=ph[:5], category="metadata"))
        flips = sum(1 for a, b in zip(versions, versions[1:]) if bool(PLACEHOLDER.search(a)) != bool(PLACEHOLDER.search(b)))
        if ph and flips >= 3:
            out.signals.append(self.sig("placeholder-alternation", "high",
                                        "Releases alternate between placeholder and real versions",
                                        category="metadata"))
        # gaps / cadence
        cur_idx = versions.index(ctx.pkg.version) if ctx.pkg.version in versions else None
        if cur_idx:
            gap = (timeline[cur_idx][1] - timeline[cur_idx - 1][1]).days
            if gap > th["stale_gap_days"]:
                out.signals.append(self.sig("dormant-then-release", "medium",
                                            f"Released after {gap} days of inactivity (abandoned package revived?)",
                                            category="metadata"))
        stable = [(v, t) for v, t in timeline if not PRERELEASE.search(v) and not PLACEHOLDER.search(v)]
        if len(stable) >= 6:
            gaps = [(b[1] - a[1]).days for a, b in zip(stable, stable[1:])]
            recent = gaps[-6:]
            if recent and max(recent) <= 120 and (timeline[-1][1] - timeline[0][1]).days > 365:
                out.signals.append(self.sig("steady-cadence", "info",
                                            "Steady release cadence over more than a year", category="metadata",
                                            benign=True))
        if cur_idx and PRERELEASE.search(versions[cur_idx - 1]) and not PRERELEASE.search(ctx.pkg.version):
            out.signals.append(self.sig("prerelease-then-stable", "info",
                                        "Stable release follows pre-releases (normal workflow)", category="metadata",
                                        benign=True))
        # separator change in version string
        if cur_idx:
            sep = lambda v: set(re.findall(r"[-_+]", v))
            prev = versions[cur_idx - 1]
            if sep(prev) != sep(ctx.pkg.version) and "_" in (sep(prev) ^ sep(ctx.pkg.version)):
                out.signals.append(self.sig("version-separator-change", "low",
                                            f"Version separators changed ({prev} -> {ctx.pkg.version})",
                                            category="metadata"))

    def _repo_checks(self, ctx, out, th) -> None:
        repo, home = repo_url(ctx)
        out.facts["repository"] = repo
        out.facts["homepage"] = home
        if not repo and not home:
            out.signals.append(self.sig("no-repository", "low", "No homepage or repository declared",
                                        category="metadata"))
        http = ctx.http
        if http and repo and repo.startswith("http"):
            m = re.match(r"https?://github\.com/([^/]+)/([^/#?]+)", repo)
            if m:
                headers = {"Authorization": f"Bearer {http.github_token}"} if http.github_token else None
                status, data = http.get_json(f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}", headers=headers)
                out.facts["repository_status"] = status
                if status == 404:
                    out.signals.append(self.sig("repository-404", "medium",
                                                "Declared GitHub repository does not exist (fake provenance)",
                                                evidence=[repo], category="metadata"))
                elif data is not None:
                    if data.get("size", 1) == 0:
                        out.signals.append(self.sig("repository-empty", "medium", "Declared repository is empty",
                                                    evidence=[repo], category="metadata"))
                    out.facts["repository_stars"] = data.get("stargazers_count")
                    out.facts["repository_created"] = data.get("created_at")
            else:
                try:
                    status = http.session.head(repo, timeout=http.timeout, allow_redirects=True).status_code
                except requests.RequestException:
                    status = 0
                out.facts["repository_status"] = status
                if status == 404:
                    out.signals.append(self.sig("repository-404", "medium", "Repository URL returns 404",
                                                evidence=[repo], category="metadata"))
        if http and home and home.startswith("http"):
            host = host_of(home)
            net = ctx.cfg["network"]
            free = domain_matches(host, net["free_hosting"])
            if free or host.rsplit(".", 1)[-1] in net["free_tlds"]:
                out.signals.append(self.sig("homepage-free-hosting", "low",
                                            f"Homepage on free-tier hosting/TLD ({host})", category="metadata"))
            elif host and not domain_matches(host, net["legit_domains"]):
                age = domain_age_days(http, host)
                out.facts["homepage_domain_age_days"] = age
                if age is not None and age < th["young_domain_days"]:
                    out.signals.append(self.sig("homepage-young-domain", "medium",
                                                f"Homepage domain registered {age} days ago", evidence=[host],
                                                category="metadata"))

    def _size_and_maintainer(self, ctx, out, th) -> None:
        if not ctx.prev_version or ctx.pkg.ecosystem != "npm":
            if ctx.prev_version and ctx.pkg.ecosystem == "pypi":
                rel = ctx.registry_meta.get("releases") or {}
                size = lambda v: max((x.get("size") or 0) for x in rel.get(v, [{}])) if rel.get(v) else 0
                a, b = size(ctx.prev_version), size(ctx.pkg.version)
                if a and b / a >= th["large_size_increase_ratio"]:
                    out.signals.append(self.sig("size-jump", "medium",
                                                f"Artifact size grew {b / a:.1f}x vs {ctx.prev_version}",
                                                category="metadata"))
            return
        prev = (ctx.registry_meta.get("versions") or {}).get(ctx.prev_version) or {}
        cur = ctx.version_meta or {}
        a = (prev.get("dist") or {}).get("unpackedSize") or 0
        b = (cur.get("dist") or {}).get("unpackedSize") or 0
        if a and b / a >= th["large_size_increase_ratio"]:
            out.signals.append(self.sig("size-jump", "medium",
                                        f"Unpacked size grew {b / a:.1f}x vs {ctx.prev_version} ({a} -> {b} bytes)",
                                        category="metadata"))
        pu, cu = (prev.get("_npmUser") or {}).get("name"), (cur.get("_npmUser") or {}).get("name")
        if pu and cu and pu != cu:
            out.signals.append(self.sig("publisher-changed", "medium",
                                        f"Publisher changed from {pu} to {cu} since {ctx.prev_version}",
                                        category="publisher"))
        pm = {m.get("name") for m in prev.get("maintainers") or []}
        cm = {m.get("name") for m in cur.get("maintainers") or []}
        if pm and cm and pm != cm:
            out.signals.append(self.sig("maintainers-changed", "medium", "Maintainer list changed",
                                        evidence=[f"added={sorted(cm - pm)} removed={sorted(pm - cm)}"],
                                        category="publisher"))
        if (prev.get("dist") or {}).get("attestations") and not (cur.get("dist") or {}).get("attestations"):
            out.signals.append(self.sig("provenance-dropped", "high",
                                        "Previous version had provenance, this one was published without it "
                                        "(likely published from a stolen token, not CI)", category="publisher"))
