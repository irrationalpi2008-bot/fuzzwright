"""Prompt text. Kept in one place so it is easy to tune."""

SYSTEM = """\
You are fuzzwright, a senior software engineer who helps maintainers find bugs in their
own Python code before users do. You write property-based fuzz harnesses with Hypothesis,
read crash traces, and separate real defects from noise. You are precise and skeptical:
a finding is only a bug if the code breaks its own contract (docstring, type hints,
obvious intent, or an invariant such as round-tripping).
"""

PLAN = """\
Below are candidate functions from a Python package, found by a static heuristic.
Pick the {n} most promising targets for fuzzing: functions that take external input
(text, bytes, structured data) and have non-trivial parsing / decoding / transformation
logic where edge cases are likely to crash, hang, or return wrong results.

Prefer: parsers, decoders, deserializers, format converters, tokenizers, validators,
and pairs of functions with an inverse relationship (encode/decode, dump/load).
Avoid: trivial wrappers, functions needing network/filesystem/global setup.

Return target_id exactly as shown in brackets.

{listing}
"""

HARNESS = """\
Write a Hypothesis fuzz harness for `{module}.{qualname}`.

{hint}

Target signature: {signature}

Target source:
```python
{source}
```

Same-module helpers it calls:
```python
{helpers}
```

The harness is a single Python module that MUST define exactly:
  * `STRATEGY` — a Hypothesis strategy producing ONE value per example (use st.tuples /
    st.fixed_dictionaries if the target needs several arguments).
  * `check(x)` — calls the target with x. Let unexpected exceptions propagate. You MAY
    `assert` properties that the code clearly promises (round-trip with its inverse,
    idempotence, output type, length bounds, "never returns None", sorted output...).
    A failed assertion is reported as a bug, so only assert real contracts.
  * `EXPECTED` — tuple of exception CLASSES that are the documented / intended way to
    reject bad input (e.g. the library's own ParseError, or ValueError if the docstring
    says so). Do NOT put broad classes like Exception here, and do NOT add exception types
    just because they might happen: an undocumented IndexError/KeyError/TypeError leaking
    from a parser is exactly what we want to find.

Strategy guidance (this matters most — random noise rarely reaches deep code):
  * Mix valid-looking and broken inputs: st.one_of(<grammar-shaped strategy>, <raw noise>).
  * Build grammar-shaped inputs from the source: use the delimiters, keywords, digits and
    escape characters the parser looks for (st.from_regex, st.recursive, st.sampled_from
    of tokens joined together). Include empty input, boundary numbers, unterminated
    constructs, deep nesting, duplicated delimiters, unicode, NUL bytes.
  * Keep sizes small (max_size around 50, nesting depth around 5) so thousands of examples run fast.
  * No file, network, subprocess, or environment access. No randomness outside Hypothesis.
  * If the target is a method, construct the instance in the simplest valid way inside check().
  * Import the target as `from {module} import ...` (the package is on sys.path).

Return the complete harness module in `harness_code`.
"""

FIX = """\
Running your harness failed before it could test the target. The error is below.
Fix the harness (not the target). Return the complete corrected module.

```
{error}
```
"""

TRIAGE = """\
A fuzz harness made `{module}.{qualname}` fail. Decide whether this is a real bug.

Docstring:
{docstring}

Target source:
```python
{source}
```

Harness:
```python
{harness}
```

Failure: {exc_type}: {message}
Minimal input (Python repr): {input}

Traceback:
```
{traceback}
```

Verdicts:
  * bug — the code violates its documented or clearly intended contract.
  * likely_bug — probably a bug, but the contract is ambiguous.
  * expected_behavior — the code is behaving as designed; the harness was too strict.
  * harness_artifact — the failure comes from the harness itself, not the target.
"Hang" means one call ran past the per-call time limit; judge whether an input of this
size should reasonably finish that fast (an infinite loop is a bug; slow-but-finite on a
huge input may not be).

Severity is about impact on real users (crash on attacker-controlled input or silent
data corruption is high; an ugly exception type on garbage input is low).

`repro_code` must be a short, standalone Python snippet that reproduces the failure using
the minimal input. `suggested_fix` should be concrete (a small diff or code change).
"""
