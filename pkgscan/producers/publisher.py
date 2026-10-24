"""Signal 3 - Publisher account."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from pkgscan.config import read_list
from pkgscan.context import ScanContext
from pkgscan.models import ProducerOutput
from pkgscan.producers.base import Producer
from pkgscan.producers.metadata import _dt, version_timeline

EMAIL = re.compile(r"^[^@\s<>]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")


class PublisherAccount(Producer):
    name = "publisher_account"
    title = "Publisher Account"
    signal_ref = "3"
    needs_registry = True

    def run(self, ctx: ScanContext) -> ProducerOutput:
        out = ProducerOutput()
        th = ctx.cfg["thresholds"]
        now = datetime.now(timezone.utc)
        if ctx.pkg.ecosystem == "npm":
            user = (ctx.version_meta or {}).get("_npmUser") or {}
            name, email = user.get("name"), user.get("email")
            out.facts["maintainers"] = [m.get("name") for m in ctx.registry_meta.get("maintainers") or []]
            out.facts["ownership_transfers"] = self._npm_transfers(ctx)
            if name and ctx.http:
                count, oldest = self._npm_account(ctx, name)
                out.facts["publisher_package_count"] = count
                if oldest:
                    age = (now - oldest).days
                    out.facts["publisher_account_age_days"] = age
                    if age < th["young_account_days"]:
                        out.signals.append(self.sig("young-account", "medium",
                                                    f"Publisher {name}'s oldest package is {age} days old",
                                                    category="publisher"))
                    elif age > 730:
                        out.signals.append(self.sig("established-account", "info",
                                                    f"Publisher active for {age // 365} years", category="publisher",
                                                    benign=True))
                if count is not None and count >= 20:
                    out.signals.append(self.sig("prolific-publisher", "info",
                                                f"Publisher maintains {count} packages", category="publisher",
                                                benign=True))
            if out.facts["ownership_transfers"]:
                recent = out.facts["ownership_transfers"][-1]
                out.signals.append(self.sig("ownership-transfer", "medium" if recent.get("is_current") else "low",
                                            "Publishing account changed across versions",
                                            evidence=[str(t) for t in out.facts["ownership_transfers"][-3:]],
                                            category="publisher"))
        else:
            info = ctx.registry_meta.get("info") or {}
            name = info.get("author") or info.get("maintainer")
            email = info.get("author_email") or info.get("maintainer_email")
            if email and "<" in email:
                m = re.search(r"<([^>]+)>", email)
                email = m.group(1) if m else email
            own = ctx.registry_meta.get("ownership") or {}
            out.facts["owners"] = [r.get("user") for r in own.get("roles", [])] if own else None
            out.facts["organization"] = own.get("organization") if own else None
            timeline = version_timeline(ctx)
            if timeline:
                age = (now - timeline[0][1]).days
                out.facts["project_age_days"] = age
                if age < th["young_account_days"]:
                    out.signals.append(self.sig("young-project", "medium", f"Project first released {age} days ago",
                                                category="publisher"))
        out.facts["publisher_account_name"] = name
        out.facts["publisher_account_email"] = email
        if ctx.client and ctx.http:
            dl = ctx.client.weekly_downloads(ctx.pkg.name)
            out.facts["weekly_downloads"] = dl
            if dl is not None and dl >= ctx.cfg["thresholds"]["popular_dep_weekly_downloads"]:
                out.signals.append(self.sig("popular-package", "info", f"{dl:,} weekly downloads",
                                            category="publisher", benign=True))
        self._email(email, out)
        return out

    def _email(self, email: str | None, out: ProducerOutput) -> None:
        if not email:
            return
        email = email.split(",")[0].strip()
        if not EMAIL.match(email):
            out.signals.append(self.sig("invalid-email", "low", "Publisher email is malformed",
                                        evidence=[email], category="publisher"))
            return
        domain = email.rsplit("@", 1)[1].lower()
        disposable = set(read_list("disposable_email_domains.txt"))
        if domain in disposable or any(domain.endswith("." + d) for d in disposable):
            out.signals.append(self.sig("disposable-email", "high", f"Publisher uses a disposable email ({domain})",
                                        evidence=[email], category="publisher"))

    def _npm_transfers(self, ctx: ScanContext) -> list[dict]:
        versions = ctx.registry_meta.get("versions") or {}
        times = ctx.registry_meta.get("time") or {}
        ordered = sorted((v for v in versions if v in times), key=lambda v: times[v])
        transfers, last = [], None
        for v in ordered:
            u = (versions[v].get("_npmUser") or {}).get("name")
            if u and last and u != last:
                transfers.append({"version": v, "from": last, "to": u, "is_current": v == ctx.pkg.version})
            last = u or last
        return transfers

    def _npm_account(self, ctx: ScanContext, user: str) -> tuple[int | None, datetime | None]:
        base = ctx.cfg["registries"]["npm"]["primary"].rstrip("/")
        _, data = ctx.http.get_json(f"{base}/-/v1/search?text=maintainer:{user}&size=250")
        if not data:
            return None, None
        objs = data.get("objects", [])
        total = data.get("total", len(objs))
        dates = sorted((d, o["package"]["name"]) for o in objs if (d := _dt(o["package"].get("date"))))
        if not dates:
            return total, None
        if total > 50:  # prolific account: the earliest last-publish date is a sufficient lower bound
            return total, dates[0][0]
        oldest = None
        for _, name in dates[:10]:
            pack = ctx.client.primary_packument(name) if ctx.client else None
            created = _dt((pack or {}).get("time", {}).get("created"))
            if created and (oldest is None or created < oldest):
                oldest = created
        return total, oldest or dates[0][0]
