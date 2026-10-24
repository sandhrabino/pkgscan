from __future__ import annotations

from pkgscan.context import ScanContext
from pkgscan.models import ProducerOutput, Signal


class Producer:
    name = "base"
    title = ""
    signal_ref = ""  # section number in the Signal Producers document
    needs_registry = False  # skipped in `local` mode
    needs_prev = False  # only runs in diff mode

    def run(self, ctx: ScanContext) -> ProducerOutput:  # pragma: no cover
        raise NotImplementedError

    def sig(self, rule_id: str, severity: str, title: str, **kw) -> Signal:
        return Signal(producer=self.name, rule_id=rule_id, severity=severity, title=title, **kw)


def clip(s: str, n: int = 240) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"
