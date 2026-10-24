"""Per-producer markdown files - each is a prompt fragment handed to the correlator."""
from __future__ import annotations

import json
from pathlib import Path

from pkgscan.models import SEV_RANK, ProducerOutput


def _fence(s: str) -> str:
    # neutralise anything in package content that could close our fences / tags
    return s.replace("```", "ʼʼʼ").replace("</untrusted", "<\\/untrusted")


def producer_markdown(name: str, title: str, ref: str, out: ProducerOutput) -> str:
    lines = [f"## Signal producer: {title} (`{name}`, doc section {ref})", ""]
    if out.error:
        lines += [f"**Producer error:** {out.error}", ""]
    if out.facts:
        lines += ["### Extracted", "```json", _fence(json.dumps(out.facts, indent=1, default=str)[:6000]), "```", ""]
    sigs = sorted(out.signals, key=lambda s: (-SEV_RANK[s.severity], s.rule_id))
    lines.append("### Signals")
    if not sigs:
        lines.append("- none")
    for s in sigs:
        tags = [s.severity.upper(), s.category]
        if s.context:
            tags.append(f"ctx={s.context}")
        if s.introduced is not None:
            tags.append("NEW-in-this-version" if s.introduced else "pre-existing")
        if s.benign:
            tags.append("LIKELY-LEGIT")
        if s.floor:
            tags.append(f"floor={s.floor}")
        lines.append(f"- [{' | '.join(tags)}] `{s.rule_id}`: {_fence(s.title)}")
        if s.detail:
            lines.append(f"  - detail: {_fence(s.detail)}")
        if s.locations:
            lines.append(f"  - at: {', '.join(s.locations[:6])}")
        for e in s.evidence[:3]:
            lines.append(f"  - evidence: `{_fence(e)}`")
    return "\n".join(lines) + "\n"


def write_producer_md(out_dir: Path, name: str, md: str) -> Path:
    d = out_dir / "signals"
    d.mkdir(exist_ok=True)
    p = d / f"{name}.md"
    p.write_text(md)
    return p
