from pathlib import Path
import textwrap

from fuzzwright.analyze import scan, import_root
from fuzzwright.runner import fuzz_until_quiet, run_harness

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "examples" / "buggylib" / "buggylib"


def write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "harness.py"
    p.write_text(textwrap.dedent(body))
    return p


def test_scan_ranks_parsers():
    names = [c.qualname for c in scan(TARGET)]
    assert "parse_kv" in names and "parse_duration" in names
    assert import_root(TARGET) == TARGET.parent


def test_finds_undocumented_exception(tmp_path):
    h = write(tmp_path, """
        from hypothesis import strategies as st
        import buggylib
        STRATEGY = st.text(alphabet="ab=;", max_size=20)
        EXPECTED = (buggylib.ParseError,)
        def check(x):
            buggylib.parse_kv(x)
    """)
    r = run_harness(h, TARGET, tmp_path / "w", max_examples=300)
    assert r.status == "crash", r
    f = r.findings[0]
    assert f["exc_type"].endswith("ValueError")
    assert "__init__.py:parse_kv" in f["signature"][1]


def test_finds_hang(tmp_path):
    h = write(tmp_path, """
        from hypothesis import strategies as st
        import buggylib
        STRATEGY = st.lists(st.sampled_from([0, 1, 2]), max_size=8).map(bytes)
        EXPECTED = (buggylib.ParseError,)
        def check(x):
            buggylib.decode_rle(x)
    """)
    r = run_harness(h, TARGET, tmp_path / "w", max_examples=300, per_call_timeout=0.5)
    assert r.status == "crash"
    assert r.findings[0]["signature"] == ["Hang", "check"]


def test_property_violation_and_multiple_rounds(tmp_path):
    h = write(tmp_path, """
        from hypothesis import strategies as st
        import buggylib
        STRATEGY = st.text(alphabet="a\\\\;=", max_size=10)
        def check(x):
            assert buggylib.unescape(buggylib.escape(x)) == x
    """)
    r = fuzz_until_quiet(h, TARGET, tmp_path / "w", max_examples=300)
    assert r.status == "crash"
    assert r.findings[0]["exc_type"].endswith("AssertionError")


def test_harness_bug_is_not_a_finding(tmp_path):
    h = write(tmp_path, """
        from hypothesis import strategies as st
        import buggylib
        STRATEGY = st.text()
        def check(x):
            undefined_name(x)
    """)
    r = run_harness(h, TARGET, tmp_path / "w", max_examples=50)
    assert r.status == "harness_error"
    assert "undefined_name" in r.error


def test_import_error(tmp_path):
    h = write(tmp_path, "import does_not_exist\n")
    r = run_harness(h, TARGET, tmp_path / "w")
    assert r.status == "harness_error" and "does_not_exist" in r.error


def test_secrets_not_passed(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-not-leak")
    h = write(tmp_path, """
        import os
        from hypothesis import strategies as st
        STRATEGY = st.just(0)
        def check(x):
            assert "ANTHROPIC_API_KEY" not in os.environ
    """)
    r = run_harness(h, TARGET, tmp_path / "w", max_examples=1)
    assert r.status == "ok", r


def test_sandbox_blocks_network(tmp_path):
    import pytest
    from fuzzwright.runner import bwrap_ok
    if not bwrap_ok():
        pytest.skip("bubblewrap not available")
    h = write(tmp_path, """
        import socket
        from hypothesis import strategies as st
        STRATEGY = st.just(0)
        def check(x):
            try:
                socket.create_connection(("1.1.1.1", 53), timeout=2)
            except OSError:
                return
            raise AssertionError("network reachable from sandbox")
    """)
    r = run_harness(h, TARGET, tmp_path / "w", max_examples=1)
    assert r.status == "ok", r
