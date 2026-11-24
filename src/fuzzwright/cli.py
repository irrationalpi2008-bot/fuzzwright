"""fuzzwright command line."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import __version__

console = Console()


def cmd_scan(a):
    from .analyze import scan
    cands = scan(Path(a.target), limit=a.limit)
    t = Table(title="fuzzable entry points (heuristic ranking)")
    for col in ("score", "target", "signature"):
        t.add_column(col)
    for c in cands:
        t.add_row(str(c.score), c.target_id, c.signature)
    console.print(t)


def cmd_run(a):
    from .analyze import find_package_root
    from .runner import fuzz_until_quiet, sandbox_name
    root = find_package_root(Path(a.target))
    target_dir = root if root.is_dir() else root.parent
    console.print(f"sandbox: {sandbox_name(not a.no_sandbox)}")
    r = fuzz_until_quiet(Path(a.harness), target_dir, Path(a.out) / "run", rounds=a.rounds,
                         max_examples=a.examples, timeout=a.timeout, sandbox=not a.no_sandbox)
    console.print(f"[bold]{r.status}[/] after {r.examples} examples")
    if r.error:
        console.print(r.error)
    for f in r.findings:
        console.print(f"[red]✗ {f['exc_type']}[/] at {f['signature'][1]}\n  input: {f['input'][:200]}\n  {f['message'][:200]}")
    sys.exit(1 if r.findings else 0)


def pick_backend(choice: str) -> str:
    """auto: API credentials (env var or `ant auth login` profile) win; else Claude Code if installed; else API."""
    import os
    import shutil
    if choice != "auto":
        return choice
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return "api"
    cfg = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    if os.environ.get("ANTHROPIC_PROFILE") or os.path.isdir(os.path.join(cfg, "anthropic")):
        return "api"  # `ant auth login` profile: the SDK picks it up
    if shutil.which("claude"):
        return "claude-code"
    return "api"


def cmd_hunt(a):
    from .llm import Brain, ClaudeCodeBrain
    from .pipeline import hunt
    from .report import write
    from .runner import sandbox_name

    import anthropic
    if a.no_sandbox:
        console.print("[yellow]warning:[/] running LLM-written code without bubblewrap isolation")
    label = sandbox_name(not a.no_sandbox)
    backend = pick_backend(a.backend)
    if a.backend == "auto":
        why = "API credentials found" if backend == "api" else "no API credentials, `claude` is installed"
        console.print(f"[dim]backend auto -> {backend} ({why})[/]")
    console.print(f"[bold]fuzzwright {__version__}[/]  backend={backend}  "
                  f"model={a.model or 'default'}  sandbox={label}")
    try:
        if backend == "claude-code":
            brain = ClaudeCodeBrain(model=a.model, effort=a.effort)
        else:
            brain = Brain(model=a.model, effort=a.effort)
        res = hunt(Path(a.target), Path(a.out), n_targets=a.targets, brain=brain,
                   max_examples=a.examples, rounds=a.rounds, timeout=a.timeout,
                   sandbox=not a.no_sandbox, sandbox_label=label, console=console)
    except anthropic.AuthenticationError:
        console.print("[red]No valid Anthropic credentials.[/] Set ANTHROPIC_API_KEY or run `ant auth login`.")
        sys.exit(2)
    except TypeError as e:
        if "authentication" not in str(e):
            raise
        console.print("[red]No Anthropic credentials found.[/] Set ANTHROPIC_API_KEY or run `ant auth login`.")
        sys.exit(2)
    except anthropic.APIConnectionError:
        console.print("[red]Could not reach the Anthropic API.[/] Check your connection and retry.")
        sys.exit(2)
    except (RuntimeError, anthropic.APIError) as e:  # e.g. Claude Code not logged in, before any target ran
        console.print(f"[red]{e}[/]")
        sys.exit(2)
    report = write(res, Path(a.out))
    bugs = sum(f.is_bug for f in res.findings)
    console.rule()
    console.print(f"[bold]{bugs} likely bug(s)[/], {len(res.findings)} unique failure(s) "
                  f"in {res.seconds:.0f}s, ~${res.cost:.2f} ({res.cost_note})")
    console.print(f"report: [cyan]{report}[/]")
    sys.exit(1 if bugs else 0)


def main(argv=None):
    p = argparse.ArgumentParser(prog="fuzzwright", description="LLM-guided fuzzing for Python packages.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("hunt", help="find bugs: pick targets, write harnesses, fuzz, triage")
    h.add_argument("target", help="package dir, module file, or project dir")
    h.add_argument("-n", "--targets", type=int, default=5, help="how many functions to fuzz (default 5)")
    h.add_argument("--examples", type=int, default=2000, help="inputs per fuzz round (default 2000)")
    h.add_argument("--rounds", type=int, default=3, help="re-runs that skip known crashes (default 3)")
    h.add_argument("--timeout", type=int, default=180, help="seconds per fuzz round (default 180)")
    h.add_argument("--backend", default="auto", choices=["auto", "api", "claude-code"],
                   help="api = Anthropic API key; claude-code = your Claude Code login/subscription "
                        "(auto: API if ANTHROPIC_API_KEY is set, else Claude Code)")
    h.add_argument("--model", default=None,
                   help="model id or alias (default: claude-opus-5-5 for api, your plan's default for claude-code)")
    h.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    h.add_argument("-o", "--out", default="fuzzwright-out")
    h.add_argument("--no-sandbox", action="store_true", help="skip bubblewrap (not recommended)")
    h.set_defaults(fn=cmd_hunt)

    s = sub.add_parser("scan", help="list fuzzable entry points (no API calls)")
    s.add_argument("target")
    s.add_argument("--limit", type=int, default=40)
    s.set_defaults(fn=cmd_scan)

    r = sub.add_parser("run", help="run your own harness file (no API calls)")
    r.add_argument("harness")
    r.add_argument("--target", required=True, help="package the harness imports")
    r.add_argument("--examples", type=int, default=2000)
    r.add_argument("--rounds", type=int, default=3)
    r.add_argument("--timeout", type=int, default=180)
    r.add_argument("-o", "--out", default="fuzzwright-out")
    r.add_argument("--no-sandbox", action="store_true")
    r.set_defaults(fn=cmd_run)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
