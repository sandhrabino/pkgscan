"""Signal 5.1 - Obfuscation metrics that need counting/entropy rather than pattern matching."""
from __future__ import annotations

import math
import re
from collections import Counter

from pkgscan.context import CODE_EXT, ScanContext, iter_files
from pkgscan.models import ProducerOutput
from pkgscan.producers.base import Producer, clip

B64_LITERAL = re.compile(rb"[\"'`]([A-Za-z0-9+/]{200,}={0,2})[\"'`]")
HEX_LITERAL = re.compile(rb"[\"'`]((?:[0-9a-fA-F]{2}){100,})[\"'`]")
STRING_LIT = re.compile(rb"[\"'`]([^\"'`\n]{100,})[\"'`]")
HEX_IDENT = re.compile(rb"\b_0x[a-f0-9]{4,6}\b")
L1_IDENT = re.compile(rb"\b[lI][lI1]{7,}\b")
ESCAPES = re.compile(rb"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}")
DECODE_CALLS = re.compile(rb"\batob\(|base64\.b64decode\(|Buffer\.from\([^)]{0,200}['\"]base64['\"]|bytes\.fromhex\(|"
                          rb"Buffer\.from\([^)]{0,200}['\"]hex['\"]")
DEAD_CODE = re.compile(rb"\bif\s*\(\s*(?:false|0|!1|!!\[\]\s*===?\s*false|\"[a-z]+\"\s*===\s*\"[a-z]+\")\s*\)|"
                       rb"\bif\s+(?:False|0)\s*:")
INVISIBLE = re.compile("[​-‏⁠-⁤﻿ㅤ︀-️\U000e0100-\U000e01ef]")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


class ObfuscationStats(Producer):
    name = "obfuscation_stats"
    title = "Code Obfuscation Metrics"
    signal_ref = "5.1"

    def run(self, ctx: ScanContext) -> ProducerOutput:
        out = ProducerOutput()
        th = ctx.cfg["thresholds"]
        per_file = []
        for p in iter_files(ctx.target_dir):
            if p.suffix not in CODE_EXT or p.stat().st_size > ctx.cfg["limits"]["max_scan_file_bytes"]:
                continue
            rel = p.relative_to(ctx.target_dir).as_posix()
            data = p.read_bytes()
            lines = data.split(b"\n")
            longest = max((len(ln) for ln in lines), default=0)
            b64 = [m.group(1) for m in B64_LITERAL.finditer(data)]
            hexes = [m.group(1) for m in HEX_LITERAL.finditer(data)]
            high_ent = [s for s in (m.group(1) for m in STRING_LIT.finditer(data))
                        if entropy(s) >= th["entropy_threshold"]]
            st = {
                "file": rel, "context": ctx.file_context(rel), "bytes": len(data),
                "decode_calls": len(DECODE_CALLS.findall(data)),
                "b64_literals": len(b64), "b64_max": max((len(x) for x in b64), default=0),
                "hex_literals": len(hexes), "hex_max": max((len(x) for x in hexes), default=0),
                "hex_identifiers": len(HEX_IDENT.findall(data)), "l1_identifiers": len(L1_IDENT.findall(data)),
                "escapes": len(ESCAPES.findall(data)), "high_entropy_strings": len(high_ent),
                "longest_line": longest, "minified": longest >= th["minified_line_chars"] and len(lines) < 50,
                "dead_branches": len(DEAD_CODE.findall(data)),
                "invisible_chars": len(INVISIBLE.findall(data.decode("utf-8", "ignore"))),
                "sample": clip((high_ent or b64 or [b""])[0][:120].decode("utf-8", "replace"), 120),
            }
            st["score"] = (min(st["decode_calls"], 10) + 3 * min(st["b64_literals"], 5) + 2 * min(st["hex_literals"], 5)
                           + (5 if st["hex_identifiers"] > 25 else 0) + (5 if st["l1_identifiers"] > 15 else 0)
                           + (3 if st["escapes"] > 100 else 0) + 2 * min(st["high_entropy_strings"], 5)
                           + (3 if st["dead_branches"] > 3 else 0) + (10 if st["invisible_chars"] >= 10 else 0))
            per_file.append(st)

        per_file.sort(key=lambda s: -s["score"])
        out.facts["files_analyzed"] = len(per_file)
        out.facts["top_files"] = [{k: v for k, v in s.items() if k != "sample"} for s in per_file[:8] if s["score"]]
        for st in per_file[:15]:
            ctx_name, rel = st["context"], st["file"]
            strong_indicator = any((st["decode_calls"], st["b64_literals"], st["hex_literals"],
                                    st["hex_identifiers"] > 25, st["l1_identifiers"] > 15,
                                    st["dead_branches"] > 3, st["invisible_chars"] >= 10))
            obfuscated = st["score"] >= 10 and (strong_indicator or st["score"] >= 18)
            if st["b64_max"] >= th["long_base64_chars"]:
                out.signals.append(self.sig("long-base64-blob", "high" if ctx_name in ("source", "install-hook", "entrypoint") else "medium",
                                            f"{st['b64_max']}-char base64 literal in {rel}", category="obfuscation",
                                            context=ctx_name, locations=[rel], evidence=[st["sample"]]))
            if obfuscated:
                sev = "high" if ctx_name in ("install-hook", "entrypoint", "source") else "low"
                if ctx_name == "install-hook":
                    sev = "critical"
                parts = [f"{k}={st[k]}" for k in ("decode_calls", "b64_literals", "hex_literals", "hex_identifiers",
                                                  "l1_identifiers", "escapes", "high_entropy_strings",
                                                  "dead_branches", "invisible_chars") if st[k]]
                out.signals.append(self.sig("obfuscation-density", sev,
                                            f"Obfuscation indicators in {rel} (score {st['score']})",
                                            category="obfuscation", context=ctx_name, locations=[rel],
                                            detail=", ".join(parts), evidence=[st["sample"]] if st["sample"] else []))
                if st["dead_branches"] > 3:
                    out.signals.append(self.sig("dead-code-plus-obfuscation", "medium",
                                                f"Constant-false branches alongside obfuscation in {rel}",
                                                category="obfuscation", context=ctx_name, locations=[rel]))
            if st["minified"] and ctx_name in ("source", "install-hook", "entrypoint"):
                out.signals.append(self.sig("minified-source", "medium" if ctx_name != "source" else "low",
                                            f"Minified code outside a dist/build folder: {rel}",
                                            category="obfuscation", context=ctx_name, locations=[rel]))
        return out
