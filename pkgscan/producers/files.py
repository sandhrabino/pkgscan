"""Signal 2 - Package files analysis (hashes, sizes, binaries, VirusTotal)."""
from __future__ import annotations

import hashlib
import json
import os
import re

from pkgscan.context import ScanContext, iter_files
from pkgscan.intel import vt_file
from pkgscan.models import ProducerOutput
from pkgscan.producers.base import Producer

MAGIC = [(b"\x7fELF", "ELF"), (b"MZ", "PE"), (b"\xcf\xfa\xed\xfe", "Mach-O"), (b"\xce\xfa\xed\xfe", "Mach-O"),
         (b"\xca\xfe\xba\xbe", "Mach-O universal"), (b"\x00asm", "WebAssembly"), (b"PK\x03\x04", "zip"),
         (b"\x1f\x8b", "gzip"), (b"7z\xbc\xaf", "7z"), (b"Rar!", "rar")]
DOC_EXT = r"pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip"
EXE_EXT = r"exe|scr|bat|cmd|com|pif|vbs|js|jse|ps1|msi|dll|sh|app|jar"
DOUBLE_EXT = re.compile(rf"\.(?:{DOC_EXT})\.(?:{EXE_EXT})$", re.I)
ASCII_STRINGS = re.compile(rb"[\x20-\x7e]{8,}")
UTF16LE_STRINGS = re.compile(rb"(?:[\x20-\x7e]\x00){8,}")
BINARY_MARKERS = {
    "network": re.compile(r"https?://|urldownloadtofile|internetopenurl|winhttpopenrequest|internetreadfile", re.I),
    "execution": re.compile(r"createprocess|shellexecute|winexec|powershell|cmd\.exe|/bin/(?:ba)?sh|execve\s*\(", re.I),
    "credentials": re.compile(r"_authtoken|npm_token|\.npmrc|id_rsa|\.aws/credentials|ssh/private", re.I),
}


def _binary_capabilities(data: bytes) -> tuple[list[str], list[str]]:
    strings = "\n".join(m.group().decode("ascii", "ignore") for m in ASCII_STRINGS.finditer(data))
    strings += "\n" + "\n".join(m.group().decode("utf-16le", "ignore") for m in UTF16LE_STRINGS.finditer(data))
    capabilities = [name for name, pattern in BINARY_MARKERS.items() if pattern.search(strings)]
    return capabilities, capabilities


def magic_kind(head: bytes) -> str | None:
    for sig, kind in MAGIC:
        if head.startswith(sig):
            if kind == "PE" and len(head) < 64:
                continue
            return kind
    return None


class PackageFiles(Producer):
    name = "package_files"
    title = "Package Files Analysis"
    signal_ref = "2"

    def run(self, ctx: ScanContext) -> ProducerOutput:
        out = ProducerOutput()
        root = ctx.src_dir
        files, binaries = [], []
        total = 0
        for p in iter_files(root):
            rel = ctx.rel(p)
            data = p.read_bytes()
            total += len(data)
            entry = {"path": rel, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                     "md5": hashlib.md5(data).hexdigest()}
            kind = magic_kind(data[:64])
            if kind or p.suffix == ".node":
                entry["binary"] = kind or "native-addon"
                binaries.append(entry)
                binary_kind = kind or "native-addon"
                if binary_kind in ("ELF", "PE", "Mach-O", "Mach-O universal", "native-addon"):
                    capabilities, evidence = _binary_capabilities(data)
                    if "credentials" in capabilities and len(capabilities) >= 2:
                        out.signals.append(self.sig(
                            "binary-suspicious-capabilities", "high",
                            f"Opaque {binary_kind} contains credential indicators and another risky capability",
                            category="binary", context="bundled", locations=[rel], floor="high", evidence=evidence))
                    elif {"network", "execution"} <= set(capabilities):
                        out.signals.append(self.sig(
                            "binary-network-execution", "medium",
                            f"Opaque {binary_kind} contains both network and process-execution indicators",
                            category="binary", context="bundled", locations=[rel], evidence=evidence))
            files.append(entry)
            name = p.name
            executable = bool(os.stat(p).st_mode & 0o111) or data.startswith(b"#!")
            if name.startswith(".") and (kind or executable) and name not in (".husky",):
                out.signals.append(self.sig("hidden-executable", "high", f"Hidden executable file {rel}",
                                            category="binary", locations=[rel], evidence=[kind or "executable"]))
            if DOUBLE_EXT.search(name):
                out.signals.append(self.sig("double-extension", "high", f"Double extension disguises executable: {rel}",
                                            category="binary", locations=[rel]))
        out.facts.update({
            "artifact": ctx.archive_path.name if ctx.archive_path else None,
            "artifact_sha256": hashlib.sha256(ctx.archive_path.read_bytes()).hexdigest() if ctx.archive_path else None,
            "compressed_bytes": ctx.archive_size,
            "uncompressed_bytes": total,
            "file_count": len(files),
            "binaries": [{k: b[k] for k in ("path", "binary", "size", "sha256")} for b in binaries][:30],
        })
        (ctx.out_dir / "files.json").write_text(json.dumps(files, indent=1))
        if ctx.skipped_members:
            out.signals.append(self.sig("archive-anomalies", "medium", "Archive contains links/unsafe paths (skipped)",
                                        evidence=ctx.skipped_members[:5], category="binary"))

        is_native = ctx.pkg.ecosystem == "npm" and ((root / "binding.gyp").exists() or
                                                    '"gypfile"' in _read(root / "package.json"))
        for b in binaries:
            rel, kind = b["path"], b["binary"]
            if kind in ("zip", "gzip", "7z", "rar", "WebAssembly"):
                sev, why = "low", f"Embedded {kind} archive/module"
            elif kind == "native-addon" or rel.endswith(".node"):
                sev = "low" if is_native or "prebuild" in rel else "medium"
                why = "Native addon" + ("" if is_native else " in a package with no native build config")
            else:
                sev = "medium" if ctx.pkg.ecosystem == "npm" else "low"
                why = f"Bundled {kind} executable"
            out.signals.append(self.sig("bundled-binary", sev, f"{why}: {rel}", category="binary", locations=[rel],
                                        context=ctx.file_context(rel), evidence=[f"sha256={b['sha256']}"]))
        self._virustotal(ctx, binaries, out)
        return out

    def _virustotal(self, ctx: ScanContext, binaries: list[dict], out: ProducerOutput) -> None:
        if not ctx.http or not ctx.http.vt_key or not binaries:
            return
        th = ctx.cfg["thresholds"]["vt_file_min_detections"]
        results = {}
        for b in binaries[: ctx.cfg["virustotal"]["max_file_lookups"]]:
            r = vt_file(ctx.http, b["sha256"])
            if r is None:
                continue
            results[b["path"]] = r
            if r.get("not_found"):
                continue
            if r["score"] > th:
                out.signals.append(self.sig(
                    "virustotal-detection", "critical" if r["score"] >= 10 else "high",
                    f"VirusTotal: {r['score']}/{r['total']} engines flag {b['path']}",
                    category="binary", locations=[b["path"]], floor="high",
                    evidence=[f"label={r.get('popular_threat_classification')}",
                              f"category={r.get('popular_threat_category')}", f"tags={r.get('tags')}",
                              f"sandbox={r.get('sandbox_verdicts')}"]))
            elif any(v in ("malicious", "suspicious") for v in (r.get("sandbox_verdicts") or {}).values()):
                out.signals.append(self.sig("virustotal-sandbox", "medium",
                                            f"VirusTotal sandbox flags {b['path']}", category="binary",
                                            evidence=[str(r["sandbox_verdicts"])]))
        out.facts["virustotal"] = results


def _read(p) -> str:
    try:
        return p.read_text(errors="replace")
    except OSError:
        return ""
