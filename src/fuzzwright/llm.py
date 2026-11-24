"""Claude calls: pick targets, write harnesses, triage crashes. All structured outputs."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Literal

import anthropic
from pydantic import BaseModel, ValidationError

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


def _norm(tid: str) -> str:
    return tid.strip().strip("[]`'\"").replace(":", ".").lower()


def match_targets(picks: list[TargetPick], cands: list[Candidate]) -> list[TargetPick]:
    """Map the model's target ids back to real candidates, tolerating `pkg.func` vs `pkg:func`,
    brackets/backticks, or a bare qualname. Drops unknown ids and duplicates."""
    real = {c.target_id for c in cands}
    normed: dict[str, list[str]] = {}
    by_qual: dict[str, list[str]] = {}
    for c in cands:
        normed.setdefault(_norm(c.target_id), []).append(c.target_id)
        by_qual.setdefault(c.qualname.lower(), []).append(c.target_id)
    out, seen = [], set()
    for p in picks:
        raw = p.target_id.strip().strip("[]`'\"")
        key = _norm(p.target_id)
        tid = raw if raw in real else None          # exact id always wins
        if tid is None and len(normed.get(key, [])) == 1:
            tid = normed[key][0]                     # normalized match only when unambiguous
        if tid is None:
            for qual, ids in by_qual.items():
                if len(ids) == 1 and (key == qual or key.endswith("." + qual)):
                    tid = ids[0]
                    break
        if tid and tid not in seen:
            seen.add(tid)
            out.append(p.model_copy(update={"target_id": tid}))
    return out


# ---------- client ----------

@dataclass
class Usage:
    input: int = 0
    output: int = 0
    cache_read: int = 0
    calls: int = 0
    usd: float = 0.0  # cost reported by the backend itself, when it reports one

    def cost(self, model: str) -> float:
        if self.usd:
            return self.usd
        pi, po, pc = PRICES.get(model, PRICES[DEFAULT_MODEL])
        return (self.input * pi + self.output * po + self.cache_read * pc) / 1e6


class Brain:
    """Talks to the Anthropic API directly (pay-as-you-go API key)."""

    label = "API"
    billing_note = "billed to your Anthropic API key"

    def __init__(self, model: str | None = None, effort: str = "high"):
        self.client = anthropic.Anthropic()
        self.model = model or DEFAULT_MODEL
        self.effort = effort
        self.usage = Usage()

    def _ask(self, schema: type[BaseModel], messages: list[dict], effort: str | None = None):
        """Return (parsed_output, assistant_turn_content) for one structured request."""
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
        return resp.parsed_output, resp.content

    # --- steps ---

    def plan(self, cands: list[Candidate], n: int) -> Plan:
        listing = "\n\n".join(
            f"[{c.target_id}] score={c.score}\n{c.signature}\n{(c.docstring or '(no docstring)')[:400]}"
            for c in cands
        )
        msg = prompts.PLAN.format(n=n, listing=listing)
        plan, _ = self._ask(Plan, [{"role": "user", "content": msg}], effort="medium")
        plan.targets = match_targets(plan.targets, cands)[:n]
        if not plan.targets:  # model returned ids we can't map: fall back to the heuristic ranking
            plan.targets = [TargetPick(target_id=c.target_id, why="top heuristic score", bug_classes=[])
                            for c in cands[:n]]
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
        h, turn = self._ask(Harness, messages)
        messages.append({"role": "assistant", "content": turn})
        return h, messages

    def fix_harness(self, messages: list[dict], error: str) -> tuple[Harness, list[dict]]:
        messages = messages + [{"role": "user", "content": prompts.FIX.format(error=error[-4000:])}]
        h, turn = self._ask(Harness, messages)
        messages.append({"role": "assistant", "content": turn})
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


# ---------- Claude Code backend (uses your Claude subscription, no API key) ----------

def _turn_text(content) -> str:
    """Flatten a message's content (string or content blocks) to plain text."""
    if isinstance(content, str):
        return content
    parts = []
    for b in content:
        t = getattr(b, "type", None) or (b.get("type") if isinstance(b, dict) else None)
        if t == "text":
            parts.append(getattr(b, "text", None) or b.get("text", ""))
    return "\n".join(parts)


def flatten(messages: list[dict]) -> str:
    """Render a multi-turn conversation as one prompt for a single-shot CLI call."""
    if len(messages) == 1:
        return _turn_text(messages[0]["content"])
    lines = ["Earlier in this conversation:\n"]
    for m in messages[:-1]:
        lines.append(f"<{m['role']}>\n{_turn_text(m['content'])}\n</{m['role']}>\n")
    lines.append("Now respond to this message:\n")
    lines.append(_turn_text(messages[-1]["content"]))
    return "\n".join(lines)


class ClaudeCodeBrain(Brain):
    """Runs each request through `claude -p`, so it uses the Claude Code login you already have.

    Isolation: no tools, no MCP servers, no saved session, only local settings from an empty
    temp directory (so user hooks, settings env and apiKeyHelper are not loaded), and our own
    system prompt. API-key / auth-token / base-URL variables are removed from the child's
    environment so a stray key or proxy can't be used. Whether that ends up on a subscription
    depends on how Claude Code itself is logged in; `billing_note` reports what we detected.
    """

    label = "Claude Code"
    STRIP_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL")

    def __init__(self, model: str | None = None, effort: str = "high", exe: str = "claude", timeout: int = 900):
        self.model = model  # None = whatever your plan defaults to
        self.effort = effort
        self.exe = exe
        self.timeout = timeout
        self.usage = Usage()
        self.models_seen: set[str] = set()
        self._cwd = tempfile.mkdtemp(prefix="fuzzwright-cc-")
        self.env = {k: v for k, v in os.environ.items() if k not in self.STRIP_ENV}
        self.billing_note = self._detect_billing()

    def _detect_billing(self) -> str:
        """Ask Claude Code how it is logged in (no model call)."""
        try:
            p = subprocess.run([self.exe, "auth", "status"], capture_output=True, text=True,
                               timeout=30, env=self.env, cwd=self._cwd)
            st = json.loads(p.stdout)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return "billed according to your Claude Code login (could not detect which)"
        if not st.get("loggedIn"):
            return "Claude Code reports it is not logged in"
        method, provider = st.get("authMethod"), st.get("apiProvider")
        if method == "claude.ai" and provider == "firstParty":
            return "used your Claude subscription; cost shown is the API-equivalent, not billed"
        return (f"billed through your Claude Code login (authMethod={method}, provider={provider}); "
                "cost shown is at API list prices")

    def _ask(self, schema: type[BaseModel], messages: list[dict], effort: str | None = None):
        cmd = [
            self.exe, "-p",
            "--output-format", "json",
            "--json-schema", json.dumps(schema.model_json_schema()),
            "--tools", "",
            "--strict-mcp-config",
            "--no-session-persistence",
            "--setting-sources", "local",
            "--system-prompt", prompts.SYSTEM,
            "--effort", effort or self.effort,
        ]
        if self.model:
            cmd += ["--model", self.model]
        env = self.env
        prompt = flatten(messages)
        last_err: Exception | None = None
        for attempt in range(3):  # claude -p occasionally fails transiently; retry before giving up
            try:
                return self._run_once(cmd, prompt, env, schema)
            except LLMRefusal:
                raise
            except RuntimeError as e:
                if "not logged in" in str(e) or "not found" in str(e):
                    raise
                last_err = e
                time.sleep(3 * (attempt + 1))
        raise last_err

    def _run_once(self, cmd, prompt, env, schema):
        try:
            p = subprocess.run(cmd, input=prompt, capture_output=True, text=True,
                               cwd=self._cwd, env=env, timeout=self.timeout)
        except FileNotFoundError:
            raise RuntimeError("`claude` not found. Install Claude Code or use --backend api.") from None
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"claude -p took longer than {self.timeout}s") from None
        try:
            d = json.loads(p.stdout)
        except json.JSONDecodeError:
            raise RuntimeError(f"claude -p failed (exit {p.returncode}): {(p.stderr or p.stdout)[-500:]}") from None

        self.usage.calls += 1
        self.usage.usd += d.get("total_cost_usd") or 0.0
        for name, mu in (d.get("modelUsage") or {}).items():
            self.models_seen.add(name)
            self.usage.input += (mu.get("inputTokens") or 0) + (mu.get("cacheCreationInputTokens") or 0)
            self.usage.output += mu.get("outputTokens") or 0
            self.usage.cache_read += mu.get("cacheReadInputTokens") or 0

        reason = f"{d.get('stop_reason')} {d.get('terminal_reason')}"
        if "refusal" in reason or d.get("safety_stops"):
            raise LLMRefusal(f"model declined: {str(d.get('result'))[:300]}")
        if d.get("is_error"):
            msg = str(d.get("result") or d.get("api_error_status") or "unknown error")
            if "login" in msg.lower():
                raise RuntimeError(f"Claude Code is not logged in: {msg}. Run `claude` once and /login.")
            detail = f"subtype={d.get('subtype')} terminal_reason={d.get('terminal_reason')} exit={p.returncode}"
            raise RuntimeError(f"claude -p error: {msg[:400]} ({detail}) {p.stderr.strip()[-200:]}")
        out = d.get("structured_output")
        if out is None:
            raise RuntimeError(f"claude -p returned no structured output (stop_reason={d.get('stop_reason')})")
        try:
            parsed = schema.model_validate(out)
        except ValidationError as e:  # retryable, like any other malformed reply
            raise RuntimeError(f"claude -p output did not match the schema: {str(e)[:300]}") from None
        return parsed, json.dumps(out)

    @property
    def model_name(self) -> str:
        return ", ".join(sorted(self.models_seen)) or (self.model or "plan default")
