"""ClaudeCodeBrain against a fake `claude` executable (no network, no login needed)."""

import json
import os
import stat
from pathlib import Path

import pytest

from fuzzwright.llm import ClaudeCodeBrain, Harness, LLMRefusal, flatten

FAKE = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if args[:2] == ["auth", "status"]:
    print(json.dumps({"loggedIn": True, "authMethod": os.environ.get("FAKE_AUTH", "claude.ai"),
                      "apiProvider": "firstParty"}))
    sys.exit(0)
prompt = sys.stdin.read()
log = os.environ["FAKE_LOG"]
with open(log, "a") as f:
    f.write(json.dumps({"args": args, "prompt": prompt,
                        "has_key": "ANTHROPIC_API_KEY" in os.environ,
                        "has_base": "ANTHROPIC_BASE_URL" in os.environ, "cwd": os.getcwd()}) + "\n")
mode = os.environ.get("FAKE_MODE", "ok")
if mode == "badschema":
    print(json.dumps({"is_error": False, "structured_output": {"reasoning": "only"}}))
    sys.exit(0)
out = {"type": "result", "is_error": False, "stop_reason": "end_turn", "terminal_reason": "completed",
       "total_cost_usd": 0.01, "safety_stops": 0,
       "modelUsage": {"claude-sonnet-5-5": {"inputTokens": 10, "outputTokens": 20,
                                           "cacheReadInputTokens": 0, "cacheCreationInputTokens": 5}},
       "structured_output": {"reasoning": "r", "expected_exceptions_note": "n",
                             "harness_code": "STRATEGY = None"}}
if mode == "login":
    out.update(is_error=True, result="Not logged in · Please run /login", structured_output=None)
if mode == "refusal":
    out.update(stop_reason="refusal", structured_output=None)
print(json.dumps(out))
'''


@pytest.fixture
def fake_claude(tmp_path, monkeypatch):
    exe = tmp_path / "claude"
    exe.write_text(FAKE)
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "log.jsonl"
    monkeypatch.setenv("FAKE_LOG", str(log))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-must-not-be-passed")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://proxy.invalid")
    return str(exe), log


def calls(log: Path):
    return [json.loads(l) for l in log.read_text().splitlines()]


def test_structured_call_and_flags(fake_claude):
    exe, log = fake_claude
    b = ClaudeCodeBrain(model="sonnet", effort="medium", exe=exe)
    h, turn = b._ask(Harness, [{"role": "user", "content": "write a harness"}])
    assert h.harness_code == "STRATEGY = None"
    assert json.loads(turn)["reasoning"] == "r"
    c = calls(log)[0]
    a = c["args"]
    assert a[0] == "-p" and "--json-schema" in a and "--no-session-persistence" in a
    assert a[a.index("--tools") + 1] == ""
    assert a[a.index("--model") + 1] == "sonnet" and a[a.index("--effort") + 1] == "medium"
    assert "harness_code" in a[a.index("--json-schema") + 1]
    assert c["prompt"] == "write a harness"
    assert not c["has_key"], "API key must be stripped so the subscription is used"
    assert not c["has_base"], "a proxy base URL must not receive the subscription token"
    assert a[a.index("--setting-sources") + 1] == "local"
    assert "subscription" in b.billing_note
    assert c["cwd"] != os.getcwd()
    assert b.usage.calls == 1 and b.usage.usd == 0.01 and b.model_name == "claude-sonnet-5-5"


def test_multi_turn_is_flattened(fake_claude):
    exe, log = fake_claude
    b = ClaudeCodeBrain(exe=exe)
    msgs = [{"role": "user", "content": "first"}, {"role": "assistant", "content": '{"x":1}'},
            {"role": "user", "content": "fix it"}]
    b._ask(Harness, msgs)
    p = calls(log)[0]["prompt"]
    assert "<user>\nfirst" in p and '<assistant>\n{"x":1}' in p and p.rstrip().endswith("fix it")


def test_login_error_is_clear(fake_claude, monkeypatch):
    exe, _ = fake_claude
    monkeypatch.setenv("FAKE_MODE", "login")
    with pytest.raises(RuntimeError, match="not logged in"):
        ClaudeCodeBrain(exe=exe)._ask(Harness, [{"role": "user", "content": "x"}])


def test_refusal(fake_claude, monkeypatch):
    exe, _ = fake_claude
    monkeypatch.setenv("FAKE_MODE", "refusal")
    with pytest.raises(LLMRefusal):
        ClaudeCodeBrain(exe=exe)._ask(Harness, [{"role": "user", "content": "x"}])


def test_flatten_handles_content_blocks():
    msgs = [{"role": "user", "content": "a"},
            {"role": "assistant", "content": [{"type": "thinking", "thinking": ""}, {"type": "text", "text": "b"}]},
            {"role": "user", "content": "c"}]
    out = flatten(msgs)
    assert "<assistant>\nb" in out and "thinking" not in out


def test_match_targets_tolerates_id_variants():
    from fuzzwright.analyze import scan
    from fuzzwright.llm import TargetPick, match_targets
    cands = scan(Path(__file__).resolve().parent.parent / "examples" / "buggylib")
    picks = [TargetPick(target_id=t, why="", bug_classes=[]) for t in
             ["buggylib.parse_kv", "[buggylib:decode_rle]", "parse_nested", "`buggylib:parse_kv`", "nope:zzz"]]
    got = [p.target_id for p in match_targets(picks, cands)]
    assert got == ["buggylib:parse_kv", "buggylib:decode_rle", "buggylib:parse_nested"]


def test_transient_error_is_retried(fake_claude, monkeypatch, tmp_path):
    exe, log = fake_claude
    # fail on the first call only
    flag = tmp_path / "failed_once"
    wrapper = tmp_path / "flaky"
    wrapper.write_text(f"""#!/bin/sh
if [ ! -e {flag} ]; then touch {flag}; echo '{{"is_error": true, "result": "overloaded"}}'; exit 1; fi
exec {exe} "$@"
""")
    wrapper.chmod(0o755)
    monkeypatch.setattr("fuzzwright.llm.time.sleep", lambda s: None)
    h, _ = ClaudeCodeBrain(exe=str(wrapper))._ask(Harness, [{"role": "user", "content": "x"}])
    assert h.harness_code == "STRATEGY = None"


def test_billing_note_for_console_login(fake_claude, monkeypatch):
    exe, _ = fake_claude
    monkeypatch.setenv("FAKE_AUTH", "console")
    note = ClaudeCodeBrain(exe=exe).billing_note
    assert "not billed" not in note and "console" in note


def test_schema_mismatch_is_retried_then_runtime_error(fake_claude, monkeypatch):
    exe, _ = fake_claude
    monkeypatch.setenv("FAKE_MODE", "badschema")
    monkeypatch.setattr("fuzzwright.llm.time.sleep", lambda s: None)
    with pytest.raises(RuntimeError, match="did not match the schema"):
        ClaudeCodeBrain(exe=exe)._ask(Harness, [{"role": "user", "content": "x"}])


def test_match_targets_prefers_exact_case():
    from fuzzwright.analyze import Candidate
    from fuzzwright.llm import TargetPick, match_targets
    mk = lambda q: Candidate(module="m", qualname=q, signature="", docstring="", source="", file="", lineno=1, score=1)
    cands = [mk("Parse"), mk("parse")]
    got = match_targets([TargetPick(target_id="m:Parse", why="", bug_classes=[])], cands)
    assert [p.target_id for p in got] == ["m:Parse"]
