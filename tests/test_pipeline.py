"""End-to-end pipeline test with a scripted stand-in for Claude (no API calls)."""

from pathlib import Path

from fuzzwright.llm import Harness, Plan, TargetPick, Triage, Usage
from fuzzwright.pipeline import hunt
from fuzzwright.report import write

TARGET = Path(__file__).resolve().parent.parent / "examples" / "buggylib" / "buggylib"

GOOD = """
from hypothesis import strategies as st
from buggylib import parse_nested, ParseError
STRATEGY = st.text(alphabet="[],0123", max_size=12)
EXPECTED = (ParseError,)
def check(x):
    parse_nested(x)
"""
BROKEN = "from hypothesis import strategies as st\nSTRATEGY = st.text()\ndef check(x):\n    nope(x)\n"


class FakeBrain:
    model = "claude-opus-5-5"

    def __init__(self):
        self.usage = Usage()
        self.fixed = False

    def plan(self, cands, n):
        return Plan(targets=[TargetPick(target_id="buggylib:parse_nested", why="recursive parser",
                                        bug_classes=["IndexError"])])

    def write_harness(self, c, hint):
        return Harness(reasoning="", expected_exceptions_note="", harness_code=BROKEN), []

    def fix_harness(self, convo, error):
        assert "nope" in error
        self.fixed = True
        return Harness(reasoning="", expected_exceptions_note="", harness_code=GOOD), convo

    def triage(self, c, code, finding):
        return Triage(verdict="bug", severity="medium", title="IndexError on unterminated list",
                      summary="s", root_cause="r", suggested_fix="f",
                      repro_code="from buggylib import parse_nested\nparse_nested('[')\n")


def test_hunt_end_to_end(tmp_path):
    brain = FakeBrain()
    res = hunt(TARGET, tmp_path, n_targets=1, brain=brain, max_examples=300, rounds=2)
    assert brain.fixed, "broken harness should be sent back for a fix"
    assert len(res.findings) >= 1
    f = res.findings[0]
    assert f.exc_type.endswith("IndexError")
    assert f.repro_outcome == "raised"
    report = write(res, tmp_path)
    text = report.read_text()
    assert "IndexError on unterminated list" in text
    assert (tmp_path / "findings.json").exists()


class ExplodingBrain(FakeBrain):
    """Second target's harness request blows up with a non-RuntimeError."""
    def plan(self, cands, n):
        return Plan(targets=[TargetPick(target_id="buggylib:parse_nested", why="", bug_classes=[]),
                             TargetPick(target_id="buggylib:parse_kv", why="", bug_classes=[])])

    def write_harness(self, c, hint):
        if c.qualname == "parse_kv":
            raise ValueError("schema mismatch from the model")
        return Harness(reasoning="", expected_exceptions_note="", harness_code=GOOD), []


def test_one_target_error_does_not_lose_other_findings(tmp_path):
    res = hunt(TARGET, tmp_path, n_targets=2, brain=ExplodingBrain(), max_examples=300, rounds=1)
    assert res.findings, "findings from the first target must survive"
    assert [t.status for t in res.targets][1] == "error"
