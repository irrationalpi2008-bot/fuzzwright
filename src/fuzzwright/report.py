"""Write REPORT.md, one markdown file per finding, and findings.json."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .pipeline import Finding, HuntResult, slug

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
VERDICT_ORDER = {"bug": 0, "likely_bug": 1, "expected_behavior": 2, "harness_artifact": 3}


def _sort_key(f: Finding):
    t = f.triage
    if t is None:
        return (5, 5)
    return (VERDICT_ORDER[t.verdict], SEV_ORDER[t.severity])


def finding_md(i: int, f: Finding) -> str:
    t = f.triage
    head = f"# {i:02d}. {t.title if t else f.exc_type}\n\n"
    meta = (
        f"| | |\n|---|---|\n"
        f"| Target | `{f.target}` |\n"
        f"| Failure | `{f.exc_type}` at `{f.signature[1]}` |\n"
        + (f"| Verdict | **{t.verdict}** ({t.severity}) |\n" if t else "")
        + f"| Repro verified | {f.repro_outcome} |\n"
        + (f"| Also reached from | {', '.join(f'`{x}`' for x in f.also_hit_by)} |\n" if f.also_hit_by else "")
    )
    body = f"\n## Minimal input\n\n```python\n{f.input}\n```\n"
    if t:
        body += (
            f"\n## What happens\n\n{t.summary}\n\n## Root cause\n\n{t.root_cause}\n"
            f"\n## Reproduce\n\n```python\n{t.repro_code}\n```\n"
            f"\n## Suggested fix\n\n{t.suggested_fix}\n"
        )
    body += f"\n## Traceback\n\n```\n{f.traceback.strip()}\n```\n"
    body += f"\nHarness: `{f.harness_path}`\n"
    return head + meta + body


def write(result: HuntResult, out: Path) -> Path:
    fdir = out / "findings"
    fdir.mkdir(parents=True, exist_ok=True)
    ordered = sorted(result.findings, key=_sort_key)
    rows = []
    for i, f in enumerate(ordered, 1):
        name = f"{i:02d}-{slug(f.triage.title if f.triage else f.exc_type)}.md"
        (fdir / name).write_text(finding_md(i, f))
        t = f.triage
        rows.append(
            f"| {i} | {t.verdict if t else '?'} | {t.severity if t else '?'} | "
            f"[{(t.title if t else f.exc_type).replace('|', '/')}](findings/{name}) | `{f.target}` | {f.repro_outcome} |"
        )
    bugs = sum(f.is_bug for f in result.findings)
    total_examples = sum(t.examples for t in result.targets)
    md = [
        f"# fuzzwright report: `{result.package}`\n",
        f"**{bugs} likely bug(s)** out of {len(result.findings)} unique failure(s), "
        f"{len(result.targets)} targets, {total_examples:,} generated inputs, "
        f"{result.seconds:.0f}s, ~${result.cost:.2f} in API calls ({result.calls} calls, `{result.model}`).\n",
        f"Sandbox: {result.sandbox}\n",
        "## Findings\n",
        "| # | Verdict | Severity | Title | Target | Repro |\n|---|---|---|---|---|---|",
        *(rows or ["| – | – | – | no failures found | – | – |"]),
        "\n## Targets\n",
        "| Target | Status | Inputs | Harness attempts | Note |\n|---|---|---|---|---|",
        *[
            f"| `{t.target}` | {t.status} | {t.examples:,} | {t.harness_attempts} | "
            f"{t.note.strip().splitlines()[-1][:120].replace('|', '/') if t.note.strip() else ''} |"
            for t in result.targets
        ],
        "\n---\n",
        "Verdicts are written by an LLM. Confirm each one by hand before filing it. "
        "If a finding could be a security issue, report it privately to the maintainers "
        "(check the project's SECURITY.md) instead of opening a public issue.\n",
    ]
    report = out / "REPORT.md"
    report.write_text("\n".join(md))
    (out / "findings.json").write_text(json.dumps(
        [{**asdict(f), "triage": f.triage.model_dump() if f.triage else None} for f in ordered],
        indent=2,
    ))
    return report
