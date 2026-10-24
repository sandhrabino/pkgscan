"""Known-bad indicators (package@version, file hashes, wallets) from data/iocs.json."""
from __future__ import annotations

import hashlib

from pkgscan.context import ScanContext, iter_files
from pkgscan.intel import load_iocs
from pkgscan.models import ProducerOutput
from pkgscan.producers.base import Producer


class KnownIOCs(Producer):
    name = "known_iocs"
    title = "Known malicious indicators"
    signal_ref = "IOC"

    def run(self, ctx: ScanContext) -> ProducerOutput:
        out = ProducerOutput()
        iocs = load_iocs()
        floor = ctx.cfg["verdict"]["ioc_floor"]
        pkgs = set(iocs.get(f"{ctx.pkg.ecosystem}_packages", []))
        if f"{ctx.pkg.name}@{ctx.pkg.version}" in pkgs or ctx.pkg.name in pkgs:
            out.signals.append(self.sig("ioc-package", "critical",
                                        f"{ctx.pkg.name}@{ctx.pkg.version} is on the known-malicious list",
                                        category="known_malicious", floor=floor))
        hashes = set(h.lower() for h in iocs.get("sha256", []))
        wallets = set(iocs.get("wallets", []))
        if hashes or wallets:
            for p in iter_files(ctx.src_dir):
                data = p.read_bytes()
                if hashes and hashlib.sha256(data).hexdigest() in hashes:
                    out.signals.append(self.sig("ioc-sha256", "critical", f"Known-malicious file {ctx.rel(p)}",
                                                category="known_malicious", floor=floor, locations=[ctx.rel(p)]))
                for w in wallets:
                    if w.encode() in data:
                        out.signals.append(self.sig("ioc-wallet", "critical", f"Known attacker wallet in {ctx.rel(p)}",
                                                    category="known_malicious", floor=floor, evidence=[w]))
        out.facts["ioc_entries"] = {k: len(v) for k, v in iocs.items() if isinstance(v, list)}
        return out
