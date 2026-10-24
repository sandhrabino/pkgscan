"""Signal 5 (+7) - Semgrep and YARA scans. Both emit SARIF; findings become grouped signals.

In diff mode both complete versions are scanned so unchanged findings remain visible and can be marked
introduced or pre-existing against a full baseline.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path

import yara

from pkgscan.config import RULES_DIR
from pkgscan.context import ScanContext, iter_files
from pkgscan.models import ProducerOutput
from pkgscan.producers.base import Producer, clip

SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
# categories whose hits are only "info" unless they occur at install time
WEAK_RULES = {"js-outbound-request", "py-outbound-request", "js-base64-decode", "py-base64-decode", "js-hex-decode",
              "py-hex-decode", "hardcoded-eth-address", "hardcoded-btc-address", "js-clipboard-access",
              "shell-clipboard-access", "process-enumeration", "cred-registry-tokens"}


def _norm(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())[:200]


def _line_at(path: Path, line: int) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            for i, ln in enumerate(fh, 1):
                if i == line:
                    return ln.rstrip("\n")
    except OSError:
        pass
    return ""


class Finding(dict):
    """rule, file, line, snippet, category, severity, tags"""


def group_findings(producer: Producer, ctx: ScanContext, findings: list[Finding], baseline: set[tuple[str, str]],
                   diff_mode: bool) -> list:
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        f["context"] = ctx.file_context(f["file"])
        f["introduced"] = (f["rule"], _norm(f["snippet"])) not in baseline if diff_mode else None
        groups[(f["rule"], f["context"])].append(f)
    signals = []
    for (rule, context), items in sorted(groups.items()):
        first = items[0]
        sev = first["severity"]
        if rule in WEAK_RULES and context != "install-hook":
            sev = "info"
        if context == "bundled" and rule in {"js-eval-string-concat", "js-function-constructor",
                                               "js-base64-decode", "js-hex-decode", "Obf_Hex_Escape_Run",
                                               "Obf_Unicode_Escape_Run"}:
            sev = "low" if sev == "high" else "info"
        if context == "install-hook" and sev in ("low", "medium"):
            sev = {"low": "medium", "medium": "high"}[sev]
        if context == "test" and sev in ("medium", "high"):
            sev = {"medium": "low", "high": "medium"}[sev]
        introduced = any(i["introduced"] for i in items) if diff_mode else None
        signals.append(producer.sig(
            rule, sev, f"{first['message']} ({len(items)} hit{'s' if len(items) > 1 else ''}, {context})",
            category=first["category"], context=context, introduced=introduced,
            floor=first.get("floor"),
            locations=[f"{i['file']}:{i['line']}" for i in items[:8]],
            evidence=[clip(i["snippet"], 200) for i in items[:3]]))
    return signals


class SemgrepRules(Producer):
    name = "semgrep_rules"
    title = "Semgrep rules (5.1-5.7)"
    signal_ref = "5"

    def run(self, ctx: ScanContext) -> ProducerOutput:
        out = ProducerOutput()
        exe = shutil.which("semgrep")
        if not exe:
            out.error = "semgrep not installed (pip install semgrep)"
            return out
        sarif_dir = ctx.out_dir / "sarif"
        sarif_dir.mkdir(exist_ok=True)
        meta = self._rule_meta()
        diff_mode = ctx.mode == "diff"
        scan_dir = ctx.src_dir if diff_mode else ctx.target_dir
        findings = self._scan(ctx, exe, scan_dir, sarif_dir / "semgrep.sarif", meta, out)
        out.sarif.append(sarif_dir / "semgrep.sarif")
        baseline: set[tuple[str, str]] = set()
        if diff_mode and ctx.prev_src_dir:
            old = self._scan(ctx, exe, ctx.prev_src_dir, sarif_dir / "semgrep-baseline.sarif", meta, out)
            baseline = {(f["rule"], _norm(f["snippet"])) for f in old}
        out.signals = group_findings(self, ctx, findings, baseline, diff_mode)
        out.facts["findings"] = len(findings)
        out.facts["rules_hit"] = sorted({f["rule"] for f in findings})
        return out

    @staticmethod
    def _rule_meta() -> dict:
        import yaml
        meta = {}
        for f in (RULES_DIR / "semgrep").glob("*.yaml"):
            for r in yaml.safe_load(f.read_text()).get("rules", []):
                metadata = r.get("metadata", {})
                meta[r["id"]] = {"category": metadata.get("category", "general"),
                                 "severity": SEMGREP_SEV.get(r.get("severity", "INFO"), "low"),
                                 "message": r.get("message", r["id"]), "floor": metadata.get("floor")}
        return meta

    def _scan(self, ctx, exe, target: Path, sarif: Path, meta: dict, out: ProducerOutput) -> list[Finding]:
        sarif = sarif.resolve()
        json_out = sarif.with_suffix(".json")
        # Override semgrep's default ignore list (which skips tests/, *.min.js, node_modules...)
        (target / ".semgrepignore").write_text("# pkgscan: scan everything\n")
        cmd = [exe, "scan", "--config", str(RULES_DIR / "semgrep"), "--metrics=off", "--disable-version-check",
               "--no-git-ignore", "--max-target-bytes", str(ctx.cfg["limits"]["max_scan_file_bytes"]),
               "--timeout", "30", "--quiet", f"--sarif-output={sarif}", f"--json-output={json_out}", "."]
        env = dict(os.environ, SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
        try:
            r = subprocess.run(cmd, cwd=target, capture_output=True, text=True, env=env,
                               timeout=ctx.cfg["limits"]["semgrep_timeout"])
        except subprocess.TimeoutExpired:
            out.error = "semgrep timed out"
            return []
        finally:
            (target / ".semgrepignore").unlink(missing_ok=True)
        if not json_out.exists():
            out.error = f"semgrep failed (exit {r.returncode}): {clip(r.stderr, 300)}"
            return []
        data = json.loads(json_out.read_text())
        found = []
        for res in data.get("results", []):
            rid = res["check_id"].rsplit(".", 1)[-1]
            m = meta.get(rid, {"category": "general", "severity": "low", "message": rid})
            rel = Path(res["path"]).as_posix().lstrip("./")
            line = res["start"]["line"]
            found.append(Finding(rule=rid, file=rel, line=line, snippet=_line_at(target / rel, line)[:300],
                                 category=m["category"], severity=m["severity"], message=m["message"],
                                 floor=m.get("floor")))
        return found


class YaraRules(Producer):
    name = "yara_rules"
    title = "YARA rules (5.1 obfuscation, 7 high-confidence)"
    signal_ref = "5/7"

    _compiled = None

    @classmethod
    def rules(cls):
        if cls._compiled is None:
            files = {p.stem: str(p) for p in (RULES_DIR / "yara").glob("*.yar")}
            cls._compiled = yara.compile(filepaths=files)
        return cls._compiled

    def run(self, ctx: ScanContext) -> ProducerOutput:
        out = ProducerOutput()
        sarif_dir = ctx.out_dir / "sarif"
        sarif_dir.mkdir(exist_ok=True)
        floor = ctx.cfg["verdict"]["high_confidence_floor"]
        diff_mode = ctx.mode == "diff"
        scan_dir = ctx.src_dir if diff_mode else ctx.target_dir
        findings = self._scan(ctx, scan_dir, floor)
        baseline: set = set()
        if diff_mode and ctx.prev_src_dir:
            baseline = {(f["rule"], _norm(f["snippet"])) for f in self._scan(ctx, ctx.prev_src_dir, floor)}
        write_sarif(sarif_dir / "yara.sarif", "pkgscan-yara", findings)
        out.sarif.append(sarif_dir / "yara.sarif")
        out.signals = group_findings(self, ctx, findings, baseline, diff_mode)
        # a high-confidence signature that already existed in the previous version keeps its floor
        out.facts["rules_hit"] = sorted({f["rule"] for f in findings})
        return out

    def _scan(self, ctx: ScanContext, root: Path, floor: str) -> list[Finding]:
        rules = self.rules()
        limit = ctx.cfg["limits"]["max_scan_file_bytes"]
        found = []
        for p in iter_files(root):
            if p.stat().st_size > limit or p.name == ".semgrepignore":
                continue
            data = p.read_bytes()
            try:
                matches = rules.match(data=data, timeout=60)
            except yara.Error:
                continue
            rel = p.relative_to(root).as_posix()
            for m in matches:
                offset = 0
                matched = b""
                if m.strings and m.strings[0].instances:
                    inst = m.strings[0].instances[0]
                    offset, matched = inst.offset, inst.matched_data
                line = data.count(b"\n", 0, offset) + 1
                hc = "high_confidence" in m.tags
                found.append(Finding(
                    rule=m.rule, file=rel, line=line,
                    snippet=matched[:200].decode("utf-8", "backslashreplace"),
                    category=m.meta.get("category", "general"), severity=m.meta.get("severity", "medium"),
                    message=m.meta.get("description", m.rule), floor=floor if hc else None,
                    tags=list(m.tags)))
        return found


def write_sarif(path: Path, tool: str, findings: list[Finding]) -> None:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules = {}
    results = []
    for f in findings:
        rules.setdefault(f["rule"], {"id": f["rule"], "shortDescription": {"text": f["message"]},
                                     "properties": {"category": f["category"], "tags": f.get("tags", [])}})
        results.append({
            "ruleId": f["rule"], "level": level.get(f["severity"], "warning"),
            "message": {"text": f["message"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                                "region": {"startLine": f["line"],
                                                           "snippet": {"text": f["snippet"]}}}}],
        })
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": tool, "rules": list(rules.values())}}, "results": results}]}
    path.write_text(json.dumps(sarif, indent=1))
