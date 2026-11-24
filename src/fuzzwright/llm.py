"""Claude calls: pick targets, write harnesses, triage crashes. All structured outputs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal

import anthropic
from pydantic import BaseModel

from .analyze import Candidate
from . import prompts

DEFAULT_MODEL = "claude-opus-5-5"
# $ per million tokens (input, output, cache read) — used for the cost line only
PRICES = {
    "claude-opus-5-5": (4.0, 20.0, 0.20),
    "claude-sonnet-5-5": (2.0, 10.0, 0.10),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),
    "claude-fable-5-2": (8.0, 40.0, 0.20),
}


class LLMRefusal(RuntimeError):
    pass


# ---------- schemas ----------

class TargetPick(BaseModel):
    target_id: str
    why: str
    bug_classes: list[str]


class Plan(BaseModel):
    targets: list[TargetPick]


class Harness(BaseModel):
    reasoning: str
    expected_exceptions_note: str
    harness_code: str


class Triage(BaseModel):
    verdict: Literal["bug", "likely_bug", "expected_behavior", "harness_artifact"]
    severity: Literal["critical", "high", "medium", "low", "none"]
    title: str
    summary: str
    root_cause: str
    suggested_fix: str
    repro_code: str


# ---------- client ----------

@dataclass
class Usage:
    input: int = 0
    output: int = 0
    cache_read: int = 0
    calls: int = 0

    def cost(self, model: str) -> float:
        pi, po, pc = PRICES.get(model, PRICES[DEFAULT_MODEL])
        return (self.input * pi + self.output * po + self.cache_read * pc) / 1e6


class Brain:
    def __init__(self, model: str = DEFAULT_MODEL, effort: str = "high"):
        self.client = anthropic.Anthropic()
        self.model = model
        self.effort = effort
        self.usage = Usage()

    def _ask(self, schema: type[BaseModel], messages: list[dict], effort: str | None = None):
        kwargs = {}
        if self.model in ("claude-opus-5-5", "claude-sonnet-5-5", "claude-fable-5-2"):
            # if a safety classifier declines (fuzzing can look "cyber"), retry server-side on a fallback model
            kwargs = {"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"}
        resp = self.client.beta.messages.parse(
            model=self.model,
            max_tokens=16000,
            system=[{"type": "text", "text": prompts.SYSTEM, "cache_control": {"type": "ephemeral"}}],
            output_config={"effort": effort or self.effort},
            output_format=schema,
            messages=messages,
            **kwargs,
        )
        u = resp.usage
        self.usage.calls += 1
        self.usage.input += (u.input_tokens or 0) + (getattr(u, "cache_creation_input_tokens", 0) or 0)
        self.usage.output += u.output_tokens or 0
        self.usage.cache_read += getattr(u, "cache_read_input_tokens", 0) or 0
        if resp.stop_reason == "refusal":
            why = resp.stop_details.explanation if resp.stop_details else ""
            raise LLMRefusal(f"model declined: {why}")
        if resp.stop_reason == "max_tokens" or resp.parsed_output is None:
            raise RuntimeError(f"no structured output (stop_reason={resp.stop_reason})")
        return resp.parsed_output, resp

    # --- steps ---

    def plan(self, cands: list[Candidate], n: int) -> Plan:
        listing = "\n\n".join(
            f"[{c.target_id}] score={c.score}\n{c.signature}\n{(c.docstring or '(no docstring)')[:400]}"
            for c in cands
        )
        msg = prompts.PLAN.format(n=n, listing=listing)
        plan, _ = self._ask(Plan, [{"role": "user", "content": msg}], effort="medium")
        known = {c.target_id for c in cands}
        plan.targets = [t for t in plan.targets if t.target_id in known][:n]
        return plan

    def write_harness(self, c: Candidate, hint: TargetPick | None) -> tuple[Harness, list[dict]]:
        helpers = "\n\n".join(c.helpers.values()) or "(none)"
        msg = prompts.HARNESS.format(
            module=c.module, qualname=c.qualname, signature=c.signature,
            source=c.source, helpers=helpers,
            hint=(f"Why it was picked: {hint.why}\nSuspected bug classes: {', '.join(hint.bug_classes)}"
                  if hint else ""),
        )
        messages = [{"role": "user", "content": msg}]
        h, resp = self._ask(Harness, messages)
        messages.append({"role": "assistant", "content": resp.content})
        return h, messages

    def fix_harness(self, messages: list[dict], error: str) -> tuple[Harness, list[dict]]:
        messages = messages + [{"role": "user", "content": prompts.FIX.format(error=error[-4000:])}]
        h, resp = self._ask(Harness, messages)
        messages.append({"role": "assistant", "content": resp.content})
        return h, messages

    def triage(self, c: Candidate, harness_code: str, finding: dict) -> Triage:
        msg = prompts.TRIAGE.format(
            module=c.module, qualname=c.qualname, source=c.source,
            docstring=c.docstring or "(none)", harness=harness_code,
            exc_type=finding["exc_type"], message=finding["message"],
            input=finding["input"][:4000], traceback=finding["traceback"][-5000:],
        )
        t, _ = self._ask(Triage, [{"role": "user", "content": msg}])
        return t


def dump(obj) -> str:
    return json.dumps(obj, indent=2, default=str)
