"""Runs a harness in a locked-down subprocess and collects crashes.

Isolation layers (best available is used automatically):
  * bubblewrap (Linux): read-only filesystem, no network, private /tmp and PID namespace
  * always: scrubbed environment (no API keys / tokens), CPU + memory rlimits, wall-clock timeout
"""

from __future__ import annotations

import json
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

CHILD = Path(__file__).with_name("_child.py")
SECRET_ENV = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|COOKIE|SESSION", re.I)


@dataclass
class RunResult:
    status: str                    # ok | crash | harness_error | timeout | killed
    examples: int = 0
    error: str | None = None
    findings: list[dict] = field(default_factory=list)
    stderr: str = ""


@cache
def bwrap_ok() -> bool:
    exe = shutil.which("bwrap")
    if not exe:
        return False
    try:
        r = subprocess.run(
            [exe, "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-net", "--", "true"],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def sandbox_name(enabled: bool) -> str:
    if enabled and bwrap_ok():
        return "bubblewrap (no network, read-only fs)"
    return "rlimits + scrubbed env only"


def _clean_env(pythonpath: list[str], workdir: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not SECRET_ENV.search(k)}
    env["PYTHONPATH"] = os.pathsep.join(pythonpath)
    env["HOME"] = str(workdir)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONSTARTUP", None)
    return env


def _limits(mem_mb: int, cpu_s: int):
    def apply():
        os.setsid()
        resource.setrlimit(resource.RLIMIT_AS, (mem_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s + 5))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def run_harness(
    harness: Path,
    target_dir: Path,
    workdir: Path,
    *,
    python: str = sys.executable,
    max_examples: int = 2000,
    per_call_timeout: float = 2.0,
    timeout: int = 180,
    mem_mb: int = 1024,
    ignore: list[list[str]] | None = None,
    sandbox: bool = True,
) -> RunResult:
    workdir.mkdir(parents=True, exist_ok=True)
    harness, target_dir, workdir = harness.resolve(), target_dir.resolve(), workdir.resolve()
    if harness.parent != workdir:  # the sandbox only exposes workdir as writable/visible scratch
        dst = workdir / harness.name
        shutil.copyfile(harness, dst)
        harness = dst
    cfg = {
        "harness": str(harness),
        "target_dir": str(target_dir),
        "workdir": str(workdir),
        "max_examples": max_examples,
        "per_call_timeout": per_call_timeout,
        "ignore": ignore or [],
    }
    cmd = [python, "-X", "faulthandler", str(CHILD), json.dumps(cfg)]
    if sandbox and bwrap_ok():
        cmd = [
            "bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
            "--tmpfs", "/tmp", "--ro-bind", str(target_dir.parent), str(target_dir.parent),
            "--bind", str(workdir), str(workdir),
            "--unshare-net", "--unshare-pid", "--unshare-ipc", "--die-with-parent",
            "--new-session", "--chdir", str(workdir), "--",
        ] + cmd
    # the import root of the target goes first so the local checkout wins over any installed copy
    env = _clean_env([str(target_dir.parent), str(harness.parent)], workdir)
    try:
        p = subprocess.run(
            cmd, cwd=workdir, env=env, capture_output=True, text=True, timeout=timeout,
            preexec_fn=_limits(mem_mb, timeout), errors="replace",
        )
    except subprocess.TimeoutExpired as e:
        return RunResult("timeout", error=f"harness run exceeded {timeout}s",
                         stderr=(e.stderr or "")[-4000:] if isinstance(e.stderr, str) else "")

    for line in reversed(p.stdout.splitlines()):
        if line.startswith("__FW_RESULT__"):
            d = json.loads(line[len("__FW_RESULT__"):])
            return RunResult(d["status"], d.get("examples", 0), d.get("error"), d.get("findings", []),
                             p.stderr[-4000:])

    # No result line: the interpreter itself died (segfault, abort, OOM-kill...)
    cur = workdir / "current_input.txt"
    last_input = cur.read_text(errors="replace") if cur.exists() else "<unknown>"
    if p.returncode < 0:
        signame = signal.Signals(-p.returncode).name
        return RunResult("crash", findings=[{
            "signature": [signame, "native"],
            "exc_type": f"signal.{signame}",
            "message": f"interpreter killed by {signame} (native crash or resource kill)",
            "input": last_input,
            "traceback": p.stderr[-8000:],
        }], stderr=p.stderr[-4000:])
    return RunResult("killed", error=f"exit code {p.returncode} with no result", stderr=p.stderr[-4000:])


def run_script(script: Path, target_dir: Path, workdir: Path, *, python: str = sys.executable,
               timeout: int = 20, mem_mb: int = 1024, sandbox: bool = True) -> tuple[str, str]:
    """Run a standalone repro script in the same sandbox. Returns (outcome, stderr tail).

    outcome: 'raised' (non-zero exit), 'hung' (timed out), 'clean' (exit 0).
    """
    workdir.mkdir(parents=True, exist_ok=True)
    script, target_dir, workdir = script.resolve(), target_dir.resolve(), workdir.resolve()
    cmd = [python, str(script)]
    if sandbox and bwrap_ok():
        cmd = [
            "bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
            "--ro-bind", str(target_dir.parent), str(target_dir.parent),
            "--bind", str(workdir), str(workdir), "--unshare-net", "--unshare-pid",
            "--die-with-parent", "--new-session", "--chdir", str(workdir), "--",
        ] + cmd
    env = _clean_env([str(target_dir.parent)], workdir)
    try:
        p = subprocess.run(cmd, cwd=workdir, env=env, capture_output=True, text=True, timeout=timeout,
                           preexec_fn=_limits(mem_mb, timeout), errors="replace")
    except subprocess.TimeoutExpired:
        return "hung", ""
    return ("raised" if p.returncode != 0 else "clean"), p.stderr[-3000:]


def fuzz_until_quiet(harness: Path, target_dir: Path, workdir: Path, rounds: int = 3, **kw) -> RunResult:
    """Re-run, ignoring bugs already found, so one shallow crash can't hide deeper ones."""
    total = RunResult("ok")
    ignore: list[list[str]] = []
    for _ in range(rounds):
        r = run_harness(harness, target_dir, workdir, ignore=ignore, **kw)
        total.examples += r.examples
        total.stderr = r.stderr
        if r.status in ("harness_error", "timeout", "killed"):
            if not total.findings:
                return r
            break
        new = [f for f in r.findings if f["signature"] not in ignore]
        if not new:
            break
        total.findings.extend(new)
        total.status = "crash"
        ignore.extend(f["signature"] for f in new)
        if any(f["signature"][1] == "native" for f in new):
            break  # can't skip past a native crash by signature
    return total
