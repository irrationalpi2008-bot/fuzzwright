"""Runs INSIDE the sandboxed subprocess. Loads one harness and fuzzes it with Hypothesis.

Kept dependency-free apart from Hypothesis, and never imported by the parent process.
Prints one line `__FW_RESULT__{json}` on stdout.

A harness module must define:
    STRATEGY  - a Hypothesis strategy producing one input
    check(x)  - calls the target with x; may assert properties (AssertionError = finding)
    EXPECTED  - optional tuple of exception types that are documented / acceptable
"""

import faulthandler
import importlib.util
import json
import os
import signal
import sys
import traceback

faulthandler.enable()
cfg = json.loads(sys.argv[1])
RESULT = "__FW_RESULT__"


def emit(obj):
    sys.stdout.write("\n" + RESULT + json.dumps(obj) + "\n")
    sys.stdout.flush()


class FuzzHang(Exception):
    pass


def _alarm(*_):
    raise FuzzHang(f"single call exceeded {cfg['per_call_timeout']}s (possible hang / catastrophic slowness)")


harness_path = os.path.realpath(cfg["harness"])
target_dir = os.path.realpath(cfg["target_dir"])

try:
    spec = importlib.util.spec_from_file_location("fw_harness", harness_path)
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    strategy = h.STRATEGY
    check = h.check
    expected = tuple(getattr(h, "EXPECTED", ()) or ())
except BaseException:
    emit({"status": "harness_error", "phase": "import", "error": traceback.format_exc(limit=8)})
    sys.exit(0)

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis.errors import HypothesisException  # noqa: E402

ignore = {tuple(s) for s in cfg.get("ignore", [])}
seen = {}          # signature -> finding dict (keeps the smallest input)
first_harness_bug = {}
examples = [0]


def frames_of(exc):
    return [(os.path.realpath(f.filename), f.lineno, f.name) for f in traceback.extract_tb(exc.__traceback__)]


def signature(exc, frames):
    etype = type(exc).__qualname__
    if isinstance(exc, FuzzHang):
        return ("Hang", "check")
    in_target = [f for f in frames if f[0].startswith(target_dir + os.sep) or f[0] == target_dir]
    if in_target:
        fn, line, name = in_target[-1]
        return (etype, f"{os.path.relpath(fn, target_dir)}:{name}:{line}")
    if frames:
        fn, line, name = frames[-1]
        return (etype, f"{os.path.basename(fn)}:{name}:{line}")
    return (etype, "?")


def is_harness_bug(exc, frames):
    """Errors raised by the harness's own code (not an assertion, not inside the target)."""
    if isinstance(exc, (AssertionError, FuzzHang, RecursionError, MemoryError)):
        return False
    if not frames:
        return False
    return frames[-1][0] == harness_path


cur_path = os.path.join(cfg["workdir"], "current_input.txt")
signal.signal(signal.SIGALRM, _alarm)


def run_one(x):
    examples[0] += 1
    r = repr(x)
    try:  # survive segfaults: the parent reads this if we die
        with open(cur_path, "w") as fp:
            fp.write(r[:20000])
    except OSError:
        pass
    signal.setitimer(signal.ITIMER_REAL, cfg["per_call_timeout"])
    try:
        check(x)
    except expected:
        return
    except KeyboardInterrupt:
        raise
    except BaseException as e:  # SystemExit from a library is a finding too
        signal.setitimer(signal.ITIMER_REAL, 0)
        frames = frames_of(e)
        if is_harness_bug(e, frames):
            if not first_harness_bug:
                first_harness_bug.update(error="".join(traceback.format_exception(e, limit=8)), input=r[:2000])
            raise
        sig = signature(e, frames)
        if sig in ignore:
            return
        prev = seen.get(sig)
        if prev is None or len(r) < len(prev["input"]):
            seen[sig] = {
                "signature": list(sig),
                "exc_type": type(e).__module__ + "." + type(e).__qualname__,
                "message": str(e)[:2000],
                "input": r[:20000],
                "traceback": "".join(traceback.format_exception(e, limit=30))[-8000:],
            }
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


@settings(
    max_examples=cfg["max_examples"],
    deadline=None,
    database=None,
    derandomize=False,
    print_blob=False,
    suppress_health_check=list(HealthCheck),
)
@given(strategy)
def fuzz(x):
    run_one(x)


status = "ok"
error = None
try:
    fuzz()
except HypothesisException:
    if not seen and not first_harness_bug:
        status, error = "harness_error", traceback.format_exc(limit=8)
except BaseException:
    pass  # failures are already recorded in `seen`

if first_harness_bug and not seen:
    status, error = "harness_error", first_harness_bug["error"]

emit({
    "status": "crash" if seen else status,
    "error": error,
    "examples": examples[0],
    "findings": list(seen.values()),
})
