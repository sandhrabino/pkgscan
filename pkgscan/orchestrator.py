from __future__ import annotations

import json
import logging
import shutil
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pkgscan.context import ScanContext, compute_diff, diff_excerpt, materialize_diff
from pkgscan.correlate import LLMError, build_prompt, call_claude, heuristic, reconcile
from pkgscan.http import Http
from pkgscan.models import (SEV_RANK, VERDICT_RANK, VERDICTS, PackageRef, ProducerOutput, Signal, Verdict,
                            max_verdict, verdict_from_score)
from pkgscan.producers import ALL_PRODUCERS, discover_entrypoints
from pkgscan.producers.base import Producer
from pkgscan.registry import IntegrityError, NotFound, client_for
from pkgscan.report import producer_markdown, write_producer_md

log = logging.getLogger("pkgscan")


def _trim(s: str, n: int) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _run_producer(p: Producer, ctx: ScanContext) -> ProducerOutput:
    t = time.monotonic()
    try:
        out = p.run(ctx)
    except Exception as e:  # one broken producer must not hide the others
        log.exception("producer %s failed", p.name)
        out = ProducerOutput(error=f"{type(e).__name__}: {e}")
    out.facts.setdefault("_elapsed_s", round(time.monotonic() - t, 2))
    return out


def diff_rescan_signals(outputs: dict[str, ProducerOutput], cfg: dict) -> list[Signal]:
    """Signal 6 'rescan the diff with step 5': summarise rule hits that are new in this version."""
    new = [s for name in ("semgrep_rules", "yara_rules") for s in outputs.get(name, ProducerOutput()).signals
           if s.introduced]
    res: list[Signal] = []
    rules = {s.rule_id for s in new if SEV_RANK[s.severity] >= SEV_RANK["low"]}
    if len(rules) > cfg["thresholds"]["new_api_alert"]:
        res.append(Signal("code_diff_rescan", "many-new-sensitive-apis", "medium",
                          f"{len(rules)} new sensitive API/rule hits introduced in this version",
                          category="diff", introduced=True, evidence=sorted(rules)[:10]))
    labels = {"persistence": "persistence mechanism", "crypto_wallet": "crypto-wallet targeting",
              "dynamic_exec": "dynamic code execution", "credential_access": "credential access",
              "process_exec": "process execution", "network": "network exfil indicator"}
    for cat, label in labels.items():
        hits = [s for s in new if s.category == cat and SEV_RANK[s.severity] >= SEV_RANK["medium"]]
        if hits:
            res.append(Signal("code_diff_rescan", f"new-{cat}", "high", f"New {label} introduced in this version",
                              category=cat, introduced=True, locations=sum((h.locations[:2] for h in hits), [])[:6],
                              evidence=[h.rule_id for h in hits][:6]))
    return res


def run_producers(ctx: ScanContext, local: bool) -> dict[str, ProducerOutput]:
    producers = [P() for P in ALL_PRODUCERS
                 if not (P.needs_registry and local) and not (P.needs_prev and ctx.mode != "diff")]
    with ThreadPoolExecutor(max_workers=ctx.cfg["scan"]["max_parallel_producers"]) as pool:
        futures = {p.name: (p, pool.submit(_run_producer, p, ctx)) for p in producers}
        outputs = {name: f.result() for name, (p, f) in futures.items()}
    for name, (p, _) in futures.items():
        write_producer_md(ctx.out_dir, name, producer_markdown(name, p.title, p.signal_ref, outputs[name]))
    if ctx.mode == "diff":
        rescan = ProducerOutput(signals=diff_rescan_signals(outputs, ctx.cfg))
        outputs["code_diff_rescan"] = rescan
        write_producer_md(ctx.out_dir, "code_diff_rescan",
                          producer_markdown("code_diff_rescan", "Code Diff rescan (rule hits new in this version)",
                                            "6", rescan))
    return outputs


def correlate(ctx: ScanContext, outputs: dict[str, ProducerOutput], use_llm: bool) -> Verdict:
    cfg = ctx.cfg
    signals = [s for o in outputs.values() for s in o.signals]
    h_score, floor = heuristic(signals)
    v = Verdict(package=ctx.pkg.name, ecosystem=ctx.pkg.ecosystem, version=ctx.pkg.version,
                previous_version=ctx.prev_version, mode=ctx.mode, verdict=verdict_from_score(h_score),
                score=h_score, reasoning="", source="heuristic", floor_applied=floor, output_dir=str(ctx.out_dir))
    top = sorted((s for s in signals if not s.benign), key=lambda s: -SEV_RANK[s.severity])[:6]
    v.key_signals = [f"{s.producer}:{s.rule_id}" for s in top if SEV_RANK[s.severity] >= SEV_RANK["low"]]
    v.reasoning = _trim("Heuristic: " + ("; ".join(f"{s.rule_id} ({s.severity})" for s in top[:5]) or
                                         "no suspicious signals"), cfg["llm"]["reasoning_max_chars"])
    errors = {n: o.error for n, o in outputs.items() if o.error}
    v.scan_errors = [f"{name}: {errors[name]}" for name in ("semgrep_rules", "yara_rules") if name in errors]
    if v.scan_errors:
        v.verdict, v.score, v.source, v.blocked = "high", 60, "scan-error", True
        v.reasoning = _trim(f"Required static analysis incomplete ({'; '.join(v.scan_errors)}). "
                            "Retry after fixing the analyzer error.", cfg["llm"]["reasoning_max_chars"])
        return v

    noteworthy = any(SEV_RANK[s.severity] >= SEV_RANK["low"] and not s.benign for s in signals)
    if use_llm and cfg["llm"]["enabled"] and (noteworthy or not cfg["llm"]["skip_when_clean"] or errors):
        header = {"ecosystem": ctx.pkg.ecosystem, "package": ctx.pkg.name, "version": ctx.pkg.version,
                  "previous_version": ctx.prev_version, "scan_mode": ctx.mode, "registry": ctx.registry_base,
                  "install_hooks": json.dumps(ctx.install_hooks) if ctx.install_hooks else None,
                  "producer_errors": json.dumps(errors) if errors else None,
                  "heuristic_score": h_score, "deterministic_floor": floor}
        mds = [p.read_text() for p in sorted((ctx.out_dir / "signals").glob("*.md"))]
        diff_text = diff_excerpt(ctx, cfg["limits"]["diff_excerpt_chars"]) if ctx.mode == "diff" else ""
        if diff_text:
            (ctx.out_dir / "diff.patch").write_text(diff_text)
        prompt = build_prompt(header, mds, diff_text, cfg["llm"]["max_prompt_chars"])
        (ctx.out_dir / "prompt.md").write_text(prompt)
        try:
            res, raw = call_claude(prompt, cfg, ctx.out_dir)
            (ctx.out_dir / "llm_raw.json").write_text(json.dumps(raw, indent=1))
            min_allowed = None
            if ctx.pkg.key not in cfg["llm"]["trusted_override_packages"]:
                rank = VERDICT_RANK[verdict_from_score(h_score)] - cfg["llm"]["max_downgrade_bands"]
                min_allowed = VERDICTS[max(0, rank)] if rank > 0 else None
            v.verdict, v.score = reconcile(res["verdict"], res["score"], max_verdict(floor or "benign", min_allowed))
            if min_allowed and VERDICT_RANK[res["verdict"]] < VERDICT_RANK[min_allowed]:
                res["reasoning"] = f"[LLM said {res['verdict']}; capped at {v.verdict} by rule score {h_score}] " + res["reasoning"]
            v.reasoning = _trim(res["reasoning"], cfg["llm"]["reasoning_max_chars"])
            v.key_signals = res["key_signals"] or v.key_signals
            v.source = "llm"
        except LLMError as e:
            v.llm_error = str(e)
            v.source = "llm-error"
            v.reasoning = _trim(f"LLM unavailable ({e}). {v.reasoning}", cfg["llm"]["reasoning_max_chars"])
    v.blocked = (v.verdict in cfg["verdict"]["block_on"] or
                 (v.source == "llm-error" and cfg["llm"]["fail_closed"]))
    return v


def write_verdict(out_dir: Path, v: Verdict) -> None:
    (out_dir / "verdict.json").write_text(json.dumps(v.to_dict(), indent=2))
    (out_dir / "verdict.md").write_text(
        f"# {v.ecosystem}:{v.package}@{v.version}\n\n"
        f"- **Verdict:** {v.verdict.upper()}  (score {v.score}/100, source: {v.source})\n"
        f"- **Blocked:** {'yes' if v.blocked else 'no'}\n"
        f"- **Mode:** {v.mode}" + (f" (diff vs {v.previous_version})" if v.previous_version else "") + "\n"
        + (f"- **Deterministic floor:** {v.floor_applied}\n" if v.floor_applied else "")
        + (f"- **LLM error:** {v.llm_error}\n" if v.llm_error else "")
        + (f"- **Scan errors:** {'; '.join(v.scan_errors)}\n" if v.scan_errors else "")
        + f"\n**Reasoning:** {v.reasoning}\n\n**Key signals:** {', '.join(v.key_signals) or '-'}\n")


def scan_package(cfg: dict, ecosystem: str, name: str, version: str, out_root: Path, *,
                 previous: str | None = None, diff_previous: bool = False, use_llm: bool = True,
                 http: Http | None = None, keep_workdir: bool = False) -> Verdict:
    """Fetch (never execute) a package version, optionally diff it against `previous`, run all producers."""
    http = http or Http(cfg["limits"]["http_timeout"])
    client = client_for(ecosystem, http, cfg)
    pkg = PackageRef(ecosystem, name, version)
    out_dir = out_root / pkg.slug
    out_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="pkgscan-"))
    try:
        try:
            meta, base = (client.packument(name, version) if ecosystem == "npm" else client.project(name, version))
        except NotFound as e:
            return _not_found(cfg, client, pkg, out_dir, str(e))
        try:
            cur = client.fetch(name, version, work / "cur")
        except IntegrityError as e:
            v = Verdict(name, ecosystem, version, None, "full", "high", 60, _trim(f"Integrity check failed: {e}", 400),
                        ["registry:integrity-mismatch"], "heuristic", "high", None, True, str(out_dir))
            write_verdict(out_dir, v)
            return v
        ctx = ScanContext(pkg=pkg, cfg=cfg, out_dir=out_dir, src_dir=cur.src_root, http=http, client=client,
                          registry_meta=meta, registry_base=base, version_meta=cur.version_meta,
                          archive_size=cur.compressed_size, archive_path=cur.archive_path,
                          skipped_members=cur.skipped_members)
        if diff_previous and not previous:
            previous = client.previous_version(meta, version)
        if previous and previous != version:
            try:
                prev = client.fetch(name, previous, work / "prev")
                ctx.prev_version, ctx.prev_src_dir, ctx.mode = previous, prev.src_root, "diff"
            except (NotFound, IntegrityError) as e:
                log.warning("previous version %s unavailable (%s) - falling back to full scan", previous, e)
        discover_entrypoints(ctx)
        if ctx.mode == "diff":
            ctx.changed = compute_diff(ctx.prev_src_dir, ctx.src_dir)
            materialize_diff(ctx, work)
        log.info("scanning %s (%s%s)", pkg, ctx.mode, f" vs {ctx.prev_version}" if ctx.prev_version else "")
        outputs = run_producers(ctx, local=False)
        v = correlate(ctx, outputs, use_llm)
        write_verdict(out_dir, v)
        return v
    finally:
        if not keep_workdir:
            shutil.rmtree(work, ignore_errors=True)


def _not_found(cfg, client, pkg: PackageRef, out_dir: Path, err: str) -> Verdict:
    """Missing everywhere. If npm replaced it with a security holder, that is a confirmed malware takedown."""
    from pkgscan.intel import load_iocs
    known = set(load_iocs().get(f"{pkg.ecosystem}_packages", []))
    if f"{pkg.name}@{pkg.version}" in known or pkg.name in known:
        v = Verdict(pkg.name, pkg.ecosystem, pkg.version, None, "unscannable", "critical", 100,
                    f"{pkg.name}@{pkg.version} is on the known-malicious IOC list (and no longer downloadable).",
                    ["known_iocs:ioc-package"], "heuristic", cfg["verdict"]["ioc_floor"], None, True, str(out_dir))
        write_verdict(out_dir, v)
        return v
    holder = None
    if pkg.ecosystem == "npm":
        p = client.primary_packument(pkg.name)
        latest = ((p or {}).get("dist-tags") or {}).get("latest", "")
        if latest.endswith("-security"):
            holder = latest
    if holder:
        v = Verdict(pkg.name, pkg.ecosystem, pkg.version, None, "unscannable", "critical", 95,
                    f"npm removed {pkg.name} for security reasons (now {holder}); {pkg.version} was malicious.",
                    ["package_metadata:npm-security-holder"], "heuristic", "critical", None, True, str(out_dir))
    else:
        v = Verdict(pkg.name, pkg.ecosystem, pkg.version, None, "unscannable", "medium", 45,
                    _trim(f"Not found in registry or mirrors ({err}). Possible dependency confusion or removed "
                          "package; verify manually.", 400), [], "heuristic", None, None,
                    "medium" in cfg["verdict"]["block_on"], str(out_dir))
    write_verdict(out_dir, v)
    return v


def scan_local(cfg: dict, path: Path, ecosystem: str, name: str, version: str, out_root: Path,
               use_llm: bool = True) -> Verdict:
    """Scan an already-extracted package directory (no registry lookups)."""
    pkg = PackageRef(ecosystem, name, version)
    out_dir = out_root / pkg.slug
    out_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="pkgscan-local-"))
    try:
        # copy so semgrep's temporary ignore file never touches the user's directory
        src = work / "src"
        shutil.copytree(path, src, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        ctx = ScanContext(pkg=pkg, cfg=cfg, out_dir=out_dir, src_dir=src, mode="full")
        discover_entrypoints(ctx)
        outputs = run_producers(ctx, local=True)
        v = correlate(ctx, outputs, use_llm)
        v.mode = "local"
        write_verdict(out_dir, v)
        return v
    finally:
        shutil.rmtree(work, ignore_errors=True)
