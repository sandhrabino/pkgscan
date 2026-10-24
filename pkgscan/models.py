from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
VERDICTS = ["benign", "low", "medium", "high", "critical"]
VERDICT_RANK = {v: i for i, v in enumerate(VERDICTS)}


def max_verdict(a: str, b: str | None) -> str:
    if not b:
        return a
    return a if VERDICT_RANK[a] >= VERDICT_RANK[b] else b


def verdict_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "benign"


@dataclass(frozen=True)
class PackageRef:
    ecosystem: str  # "npm" | "pypi"
    name: str
    version: str

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}"

    @property
    def slug(self) -> str:
        return re.sub(r"[^A-Za-z0-9._@-]+", "_", f"{self.ecosystem}__{self.name}@{self.version}")

    def __str__(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


@dataclass
class Signal:
    producer: str
    rule_id: str
    severity: str  # one of SEVERITIES
    title: str
    category: str = "general"
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)
    context: str = ""  # install-hook | entrypoint | source | test | bundled | metadata
    introduced: bool | None = None  # diff mode: True if not present in the previous version
    benign: bool = False  # a "likely legit" indicator
    floor: str | None = None  # minimum verdict this signal forces

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProducerOutput:
    signals: list[Signal] = field(default_factory=list)
    facts: dict = field(default_factory=dict)  # "what we extract"
    sarif: list[Path] = field(default_factory=list)
    error: str | None = None


@dataclass
class Verdict:
    package: str
    ecosystem: str
    version: str
    previous_version: str | None
    mode: str  # full | diff | local | unscannable
    verdict: str
    score: int
    reasoning: str
    key_signals: list[str] = field(default_factory=list)
    source: str = "heuristic"  # llm | heuristic | cached | error
    floor_applied: str | None = None
    llm_error: str | None = None
    blocked: bool = False
    output_dir: str = ""
    scan_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
