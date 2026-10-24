"""Signal 5.2 - Network IOC extraction (URLs, domains, IPs, ports, User-Agents) + reputation."""
from __future__ import annotations

import re
from collections import defaultdict

from pkgscan.context import CODE_EXT, ScanContext, iter_files
from pkgscan.intel import domain_matches, host_of, ip_kind, load_iocs, vt_domain
from pkgscan.models import ProducerOutput
from pkgscan.producers.base import Producer

URL = re.compile(r"\b(?:https?|wss?|ftp|tcp)://[^\s\"'`<>)\]}\\]{3,300}", re.I)
IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
IP_CONTEXT = re.compile(r"[\"'`/@]\s*$|host\s*[:=]\s*[\"'`]?$", re.I)
UA = re.compile(r"User-Agent[\"']?\s*[:=,]\s*[\"'`]([^\"'`]{3,200})", re.I)
PORT = re.compile(r"\bport\s*[:=]\s*(\d{2,5})\b", re.I)
SCAN_EXT = CODE_EXT | {".json", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".html"}


class NetworkIOCs(Producer):
    name = "network_iocs"
    title = "Network Behavior / IOC extraction"
    signal_ref = "5.2"

    def run(self, ctx: ScanContext) -> ProducerOutput:
        out = ProducerOutput()
        net = ctx.cfg["network"]
        urls: dict[str, set[str]] = defaultdict(set)
        ips: dict[str, set[str]] = defaultdict(set)
        uas, ports = set(), set()
        for p in iter_files(ctx.target_dir):
            if p.suffix.lower() not in SCAN_EXT or p.stat().st_size > ctx.cfg["limits"]["max_scan_file_bytes"]:
                continue
            rel = p.relative_to(ctx.target_dir).as_posix()
            if rel.endswith(("package-lock.json", ".map")):
                continue
            text = p.read_text(errors="replace")
            for m in URL.finditer(text):
                urls[m.group(0).rstrip(".,;")].add(rel)
            for m in IPV4.finditer(text):
                before = text[max(0, m.start() - 12): m.start()]
                if IP_CONTEXT.search(before) or text[m.end(): m.end() + 1] == ":":
                    if ip_kind(m.group(0)) not in (None, "loopback", "reserved"):
                        ips[m.group(0)].add(rel)
            uas |= {m.group(1) for m in UA.finditer(text)}
            ports |= {int(m.group(1)) for m in PORT.finditer(text)}

        hosts: dict[str, set[str]] = defaultdict(set)
        for u, files in urls.items():
            h = host_of(u)
            if h:
                hosts[h] |= files
                pm = re.match(r"^[a-z]+://[^/:]+:(\d{2,5})", u, re.I)
                if pm:
                    ports.add(int(pm.group(1)))
            if h and ip_kind(h):
                ips[h] |= files
        iocs = load_iocs()
        exfil, short, unknown, legit = [], [], [], []
        for h, files in sorted(hosts.items()):
            if ip_kind(h):
                continue
            loc = sorted(files)[:3]
            if domain_matches(h, iocs.get("domains", [])):
                out.signals.append(self.sig("ioc-domain", "critical", f"Known-malicious domain {h}",
                                            category="known_malicious", locations=loc, floor="critical"))
            elif domain_matches(h, net["exfil_domains"]):
                exfil.append(h)
                out.signals.append(self.sig("exfil-host", "high", f"Anonymous exfil/tunnel service: {h}",
                                            category="network", locations=loc,
                                            context=ctx.file_context(loc[0])))
            elif domain_matches(h, net["shorteners"]):
                short.append(h)
                out.signals.append(self.sig("shortened-url", "medium", f"URL shortener: {h}", category="network",
                                            locations=loc, context=ctx.file_context(loc[0])))
            elif domain_matches(h, net["legit_domains"]):
                legit.append(h)
            else:
                unknown.append(h)
        for ip, files in sorted(ips.items()):
            kind = ip_kind(ip)
            loc = sorted(files)[:3]
            if ip in iocs.get("ips", []):
                out.signals.append(self.sig("ioc-ip", "critical", f"Known-malicious IP {ip}",
                                            category="known_malicious", locations=loc, floor="critical"))
            elif kind == "public":
                out.signals.append(self.sig("hardcoded-public-ip", "medium", f"Hardcoded public IP {ip}",
                                            category="network", locations=loc, context=ctx.file_context(loc[0])))
            elif kind in ("private", "link-local"):
                sev = "high" if ip.startswith("169.254.169.254") else "low"
                out.signals.append(self.sig("hardcoded-private-ip", sev, f"Hardcoded {kind} IP {ip}",
                                            category="network", locations=loc))
        odd = sorted(p for p in ports if p in net["nonstandard_ports_alert"])
        if odd:
            out.signals.append(self.sig("nonstandard-port", "medium", f"Non-standard ports referenced: {odd}",
                                        category="network"))
        # VirusTotal reputation for unknown hosts
        vt = {}
        if ctx.http and ctx.http.vt_key:
            for h in unknown[: ctx.cfg["virustotal"]["max_domain_lookups"]]:
                r = vt_domain(ctx.http, h)
                if r:
                    vt[h] = r
                    if r["malicious"] > ctx.cfg["thresholds"]["vt_domain_min_detections"]:
                        out.signals.append(self.sig("vt-malicious-domain", "high",
                                                    f"VirusTotal: {r['malicious']}/{r['total']} flag {h}",
                                                    category="network", locations=sorted(hosts[h])[:3],
                                                    floor="high"))
        if legit and not unknown and not exfil and not short and not ips:
            out.signals.append(self.sig("only-known-domains", "info",
                                        "Only references well-known registries/CDNs/docs", category="network",
                                        benign=True))
        out.facts.update({"urls": sorted(urls)[:40], "unknown_domains": unknown[:30], "known_domains": legit[:20],
                          "exfil_domains": exfil, "shorteners": short, "ips": sorted(ips)[:20],
                          "ports": sorted(ports)[:20], "user_agents": sorted(uas)[:10], "virustotal": vt})
        return out
