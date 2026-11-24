"""The hunt: scan -> plan -> write harness -> fuzz -> (fix harness) -> triage -> verify repro."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from .analyze import Candidate, find_package_root, scan
from .llm import Brain, LLMRefusal, Triage
from .runner import fuzz_until_quiet, run_script


@dataclass
class Finding:
    target: str
    signature: list[str]
    exc_type: str
    message: str
    input: str
    traceback: str
    harness_path: str
    triage: Triage | None = None
    repro_outcome: str = "not run"   # raised | hung | clean | not run
    also_hit_by: list[str] = field(default_factory=list)

    @property
    def is_bug(self) -> bool:
        return self.triage is not None and self.triage.verdict in ("bug", "likely_bug")


@dataclass
class TargetLog:
    target: str
    status: str
    examples: int = 0
    harness_attempts: int = 0
    note: str = ""


@dataclass
class HuntResult:
    package: str
    findings: list[Finding]
    targets: list[TargetLog]
    seconds: float
    cost: float
    calls: int
    model: str
    sandbox: str
    cost_note: str = ""
    interrupted: bool = False


def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-")[:60]


def hunt(
    target: Path,
    out: Path,
    *,
    n_targets: int = 5,
    brain: Brain,
    max_examples: int = 2000,
    rounds: int = 3,
    timeout: int = 180,
    per_call_timeout: float = 2.0,
    sandbox: bool = True,
    sandbox_label: str = "",
    console: Console | None = None,
) -> HuntResult:
    console = console or Console()
    t0 = time.time()
    root = find_package_root(target)
    target_dir = root if root.is_dir() else root.parent
    out.mkdir(parents=True, exist_ok=True)

    cands = scan(target)
    if not cands:
        raise SystemExit("No fuzzable public functions found.")
    by_id = {c.target_id: c for c in cands}
    console.print(f"[bold]scan[/] {len(cands)} candidate entry points in [cyan]{root.name}[/]")

    with console.status("asking Claude which targets look most fragile..."):
        plan = brain.plan(cands, n_targets)
    for t in plan.targets:
        console.print(f"  [green]→[/] {t.target_id}  [dim]{t.why}[/]")

    findings: dict[tuple, Finding] = {}
    logs: list[TargetLog] = []

    interrupted = False
    try:
        for pick in plan.targets:
            c: Candidate = by_id[pick.target_id]
            work = out / "targets" / slug(c.target_id)
            work.mkdir(parents=True, exist_ok=True)
            log = TargetLog(c.target_id, "pending")
            logs.append(log)
            console.rule(f"[bold]{c.target_id}")
            try:
                with console.status("writing harness..."):
                    h, convo = brain.write_harness(c, pick)
                result = None
                for attempt in range(3):
                    log.harness_attempts = attempt + 1
                    hp = work / "harness.py"
                    hp.write_text(h.harness_code)
                    with console.status(f"fuzzing (attempt {attempt + 1}, up to {max_examples} examples/round)..."):
                        result = fuzz_until_quiet(
                            hp, target_dir, work / "run", rounds=rounds, max_examples=max_examples,
                            timeout=timeout, per_call_timeout=per_call_timeout, sandbox=sandbox,
                        )
                    log.examples += result.examples
                    if result.status == "harness_error" and attempt < 2:
                        console.print("  [yellow]harness broke, asking Claude to fix it[/]")
                        with console.status("fixing harness..."):
                            h, convo = brain.fix_harness(convo, result.error or result.stderr)
                        continue
                    break
            except Exception as e:  # refusal, CLI timeout, API/schema error: skip this target, keep hunting
                log.status = "skipped" if isinstance(e, LLMRefusal) else "error"
                log.note = str(e)
                console.print(f"  [yellow]{log.status}:[/] {e}")
                continue

            log.status = result.status
            if result.status in ("harness_error", "timeout", "killed"):
                log.note = (result.error or result.stderr or "")[-300:]
                console.print(f"  [red]{result.status}[/] [dim]{log.note.strip().splitlines()[-1] if log.note.strip() else ''}[/]")
                continue
            if not result.findings:
                console.print(f"  [green]clean[/] after {result.examples} examples")
                continue

            for raw in result.findings:
                key = tuple(raw["signature"])
                if key in findings:
                    findings[key].also_hit_by.append(c.target_id)
                    continue
                f = Finding(target=c.target_id, signature=raw["signature"], exc_type=raw["exc_type"],
                            message=raw["message"], input=raw["input"], traceback=raw["traceback"],
                            harness_path=str(work / "harness.py"))
                findings[key] = f
                console.print(f"  [red]✗[/] {f.exc_type.split('.')[-1]} at {f.signature[1]}  input={f.input[:60]}")
                try:
                    with console.status("triaging..."):
                        f.triage = brain.triage(c, h.harness_code, raw)
                except Exception as e:
                    console.print(f"    [yellow]triage skipped:[/] {e}")
                    continue
                # independent check: does Claude's repro actually reproduce it?
                rp = work / f"repro_{len(findings)}.py"
                rp.write_text(f.triage.repro_code)
                f.repro_outcome, _ = run_script(rp, target_dir, work / "run", sandbox=sandbox)
                color = "red" if f.is_bug else "dim"
                console.print(f"    [{color}]{f.triage.verdict}/{f.triage.severity}[/]: {f.triage.title} "
                              f"[dim](repro: {f.repro_outcome})[/]")

    except KeyboardInterrupt:
        interrupted = True
        console.print("\n[yellow]interrupted, writing a report with what was found so far[/]")
    except Exception as e:  # never lose findings already made because of a later crash
        interrupted = True
        if logs:
            logs[-1].status, logs[-1].note = "error", f"{type(e).__name__}: {e}"
        console.print(f"\n[red]hunt stopped by {type(e).__name__}: {e}[/]\nwriting a partial report")

    return HuntResult(
        package=root.name, findings=list(findings.values()), targets=logs,
        seconds=time.time() - t0, cost=brain.usage.cost(brain.model), calls=brain.usage.calls,
        model=getattr(brain, "model_name", brain.model), sandbox=sandbox_label,
        cost_note=getattr(brain, "billing_note", ""),
        interrupted=interrupted,
    )
